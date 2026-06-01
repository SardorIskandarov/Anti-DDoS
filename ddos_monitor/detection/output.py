"""
output.py — build the WireMessage the collector's row-writers already consume.

After cutover the Python detector replaces the C-computed wire message: instead
of parsing a 468-byte socket message, the collector reads a raw snapshot, runs
the detector, and calls build_wire_message() to produce the SAME WireMessage
shape. The collector's _to_service_stats_row / _to_phase_transition_row /
_to_temporal_rows then work byte-for-byte unchanged, so the ClickHouse schema
and dashboard are untouched.

Field provenance:
  * raw counters / identity     -> the snapshot record (rec)
  * phase / scores / tier0-risk -> the detector SlotState (st)
  * ttl_mean / ttl_stddev       -> Bessel compute_mean_stddev, matching the C
                                   wire serializer (l2fwd_service_wire.c:233-244)
  * bw_*_z_last                 -> the slot's current burst-window z (st)
  * temporal windows            -> the per-slot TemporalState

WireMessage lives in the (legacy) wire_parser module today; it is the stable
row-shape contract. `import wire_parser` resolves because ddos_monitor is on
sys.path in the collector process.
"""

import math

import wire_parser as _wp
from . import config as C
from . import primitives as M  # noqa: F401 — kept for future Welford helpers


def _decode_name(raw) -> str:
    if isinstance(raw, bytes):
        b = raw
    else:                                  # numpy bytes scalar / array
        b = bytes(raw)
    return b.rstrip(b"\x00").decode("ascii", errors="replace")


def _twin(temporal, size_seconds: int) -> "_wp.TemporalWindow":
    w = temporal.window(size_seconds)
    # peak_pps is a uint32 column on the wire/DB -> integer.
    return _wp.TemporalWindow(
        window_seconds=size_seconds,
        total_pkts=int(w.total_pkts),
        peak_pps=int(w.peak_pps),
        attack_seconds=int(w.attack_seconds),
    )


def build_wire_message(rec, st, temporal, *, ts_ns: int, slot_id: int,
                       sequence_num: int) -> "_wp.WireMessage":
    """Assemble a WireMessage from a snapshot record + detector state +
    temporal windows. `rec` is a snapshot record (NumPy row or dict); `st` is
    the detector SlotState after process_record; `temporal` its TemporalState."""

    def ri(f):   # raw int field
        return int(rec[f])

    target_ip = ri("target_ip")
    proto_kind = ri("proto_kind")
    inbound = ri("inbound_pkts")

    # Welford-true: the snapshot ships ttl_mean + ttl_M2 directly. Recover the
    # legacy ttl_sum / ttl_sum_sq ClickHouse columns by closed-form identity
    # (sum = n·mean, sum_sq = M2 + n·mean²) so the schema/dashboard are
    # unchanged.
    ttl_mean = float(rec["ttl_mean"])
    ttl_M2 = float(rec["ttl_M2"])
    ttl_stddev = (math.sqrt(ttl_M2 / (inbound - 1)) if inbound > 1 else 0.0)
    ttl_sum = int(round(ttl_mean * inbound))
    ttl_sum_sq = int(round(ttl_M2 + inbound * ttl_mean * ttl_mean))

    return _wp.WireMessage(
        # Header
        timestamp_ns=int(ts_ns),
        timestamp_unix=int(ts_ns) / 1e9,
        slot_id=int(slot_id),
        sequence_num=int(sequence_num),
        # Identity
        target_ip=target_ip,
        target_ip_str=_wp._socket.inet_ntoa(target_ip.to_bytes(4, "big")),
        port=ri("port"),
        proto_kind=proto_kind,
        proto_kind_str=_wp.proto_kind_name(proto_kind),
        is_catchall=bool(ri("is_catchall")),
        profile_name=_decode_name(rec["profile_name"]),
        # Phase state (Python-computed verdict)
        phase=st.phase,
        phase_str=_wp.phase_name(st.phase),
        prev_phase=st.prev_phase,
        prev_phase_str=_wp.phase_name(st.prev_phase),
        warmup_remaining=st.warmup_remaining,
        consecutive_attack_windows=st.consecutive_attack_windows,
        baseline_freeze_remaining=st.baseline_freeze_remaining,
        thaw_cooldown_remaining=st.thaw_cooldown_remaining,
        windows_seen=st.windows_seen,
        absolute_floor_fired=bool(st.last_absolute_floor_fired),
        # Raw counters (passthrough)
        inbound_pkts=inbound,
        inbound_bytes=ri("inbound_bytes"),
        off_proto_pkts=ri("off_proto_pkts"),
        ip_frag_pkts=ri("ip_frag_pkts"),
        ttl_sum=ttl_sum,
        ttl_sum_sq=ttl_sum_sq,
        out_pkts=ri("out_pkts"),
        out_bytes=ri("out_bytes"),
        out_tcp_pkts=ri("out_tcp_pkts"),
        out_udp_pkts=ri("out_udp_pkts"),
        out_icmp_pkts=ri("out_icmp_pkts"),
        # Proto counters (passthrough)
        tcp_pkts=ri("tcp_pkts"),
        tcp_bytes=ri("tcp_bytes"),
        syn_pkts=ri("syn_pkts"),
        syn_ack_pkts=ri("syn_ack_pkts"),
        fin_ack_pkts=ri("fin_ack_pkts"),
        rst_pkts=ri("rst_pkts"),
        ack_data_pkts=ri("ack_data_pkts"),
        empty_ack_pkts=ri("empty_ack_pkts"),
        zero_window_pkts=ri("zero_window_pkts"),
        udp_pkts=ri("udp_pkts"),
        udp_bytes=ri("udp_bytes"),
        icmp_pkts=ri("icmp_pkts"),
        # Features
        unique_src_ips=float(rec["est_unique_src_ips"]),
        unique_flows=float(rec["est_unique_flows"]),
        src_24_top1_share=float(rec["src_24_top1_share"]),
        src_24_entropy=float(rec["src_24_entropy"]),
        ttl_mean=ttl_mean,
        ttl_stddev=ttl_stddev,
        bw_pps_z_last=st.bw_pps_z_last,
        bw_bps_z_last=st.bw_bps_z_last,
        # Scores (Python-computed)
        tier0_score=st.last_tier0_score,
        tier1_tcp_score=st.t1_tcp,
        tier1_udp_score=st.t1_udp,
        tier1_icmp_score=st.t1_icmp,
        tier1_dist_score=st.t1_dist,
        tier1_l3_score=st.t1_l3,
        tier1_offproto_score=st.t1_offproto,
        tier1_final_score=st.t1_final,
        # Temporal
        win_10s=_twin(temporal, 10),
        win_60s=_twin(temporal, 60),
        win_300s=_twin(temporal, 300),
        # Tier-0 per-channel risk vector + dominant
        tier0_risk_pps=st.r_pps,
        tier0_risk_bps=st.r_bps,
        tier0_risk_fps=st.r_fps,
        tier0_risk_burst_pps=st.r_burst_pps,
        tier0_risk_burst_bps=st.r_burst_bps,
        tier0_risk_burst_fps=st.r_burst_fps,
        dominant_channel=st.dominant_channel,
        dominant_channel_str=_wp.dominant_name(st.dominant_channel),
    )
