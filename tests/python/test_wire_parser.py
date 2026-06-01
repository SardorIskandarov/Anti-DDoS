#!/usr/bin/env python3
"""
test_wire_parser.py — test harness for ddos_monitor/wire_parser.py (P12).

Runnable two ways:
    python3 -m pytest tests/python/test_wire_parser.py -v
    python3 tests/python/test_wire_parser.py

The harness hand-constructs 468-byte wire messages in pure Python
(matching l2fwd_service_wire.c byte-for-byte), so it has no dependency
on a built C engine or a running ClickHouse. It exercises:

  * a fully-populated message: every field round-trips with the expected
    value
  * BadMagicError      on corrupted magic
  * BadVersionError    on version != 1
  * BadMsgTypeError    on msg_type != 1
  * BadCRCError        on a single corrupted payload byte
  * BadPayloadLengthError on short / empty / None buffers, and on a
    tampered header payload_len field
  * a zeroed-but-valid message (the WARMUP-slot heartbeat shape)
"""

import os
import struct
import sys
import zlib

# --- make the flat ddos_monitor modules importable -------------------------
# tests/python/<file> -> repo root is three levels up.
_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(_REPO_ROOT, "ddos_monitor"))

import config  # noqa: E402
from wire_parser import (  # noqa: E402
    parse_message,
    WireMessage,
    TemporalWindow,
    DOMINANT_NAMES,
    WireParseError,
    BadMagicError,
    BadVersionError,
    BadMsgTypeError,
    BadCRCError,
    BadPayloadLengthError,
)

MSG_SIZE = config.WIRE_MSG_SIZE         # 416
HEADER_SIZE = config.WIRE_HEADER_SIZE   # 32


# ===========================================================================
# Message builder — constructs a valid 468-byte buffer from field values.
# Mirrors the layout in l2fwd_service_wire.c exactly.
# ===========================================================================

def build_message(**kw):
    """Build a valid 468-byte wire message. Any field can be overridden via
    kwargs; everything else takes a deterministic default."""
    d = dict(
        # header
        version=config.WIRE_VERSION,
        msg_type=config.WIRE_MSGTYPE_SNAP,
        flags_byte=0,                   # header flags @ offset 6 (bit0 = abs floor)
        timestamp_ns=1_700_000_000_000_000_000,
        slot_id=42,
        payload_len=config.WIRE_PAYLOAD_SIZE,
        sequence_num=9001,
        # identity
        target_ip=0x0A0B0C0D,           # 10.11.12.13
        port=443,
        proto_kind=4,                   # CATCHALL_TCP
        is_catchall=1,
        profile_name=b"prof_xy",
        # phase
        phase=2, prev_phase=1,
        warmup_remaining=17,
        consecutive_attack_windows=4,
        baseline_freeze_remaining=30,
        thaw_cooldown_remaining=5,
        windows_seen=12345,
        # counters
        inbound_pkts=1000, inbound_bytes=1_500_000,
        off_proto_pkts=3, ip_frag_pkts=1,
        ttl_sum=64_000, ttl_sum_sq=4_096_000,
        out_pkts=50, out_bytes=75_000,
        out_tcp_pkts=40, out_udp_pkts=8, out_icmp_pkts=2,
        # proto
        tcp_pkts=1000, tcp_bytes=1_500_000,
        syn_pkts=200, syn_ack_pkts=10, fin_ack_pkts=8, rst_pkts=5,
        ack_data_pkts=700, empty_ack_pkts=70, zero_window_pkts=0,
        udp_pkts=0, udp_bytes=0, icmp_pkts=0,
        # features (doubles)
        unique_src_ips=300.5, unique_flows=512.25,
        src_24_top1_share=0.27, src_24_entropy=8.94,
        ttl_mean=64.0, ttl_stddev=0.0,
        bw_pps_z_last=1.15, bw_bps_z_last=-0.5,
        # scores (doubles)
        tier0_score=0.42, tier1_tcp_score=0.50, tier1_udp_score=0.10,
        tier1_icmp_score=0.05, tier1_dist_score=0.65, tier1_l3_score=0.30,
        tier1_offproto_score=0.20, tier1_final_score=0.65,
        # temporal windows: (total_pkts, peak_pps, attack_seconds)
        win_10s=(10_000, 1200, 2),
        win_60s=(50_000, 1200, 7),
        win_300s=(200_000, 1200, 12),
        # v2 tail: Tier-0 risk vector (6 doubles) + dominant channel byte
        tier0_risk_pps=0.0, tier0_risk_bps=0.0, tier0_risk_fps=0.0,
        tier0_risk_burst_pps=0.0, tier0_risk_burst_bps=0.0,
        tier0_risk_burst_fps=0.0,
        dominant_channel=0,
    )
    d.update(kw)

    buf = bytearray(MSG_SIZE)

    # ---- header (32 B) ----
    buf[0:4] = config.WIRE_MAGIC
    buf[4] = d["version"]
    buf[5] = d["msg_type"]
    buf[6] = d["flags_byte"]   # header flags byte (bit0 = absolute floor)
    # buf[7] reserved
    struct.pack_into(">Q", buf, 8, d["timestamp_ns"])
    struct.pack_into(">H", buf, 16, d["slot_id"])
    struct.pack_into(">H", buf, 18, d["payload_len"])
    struct.pack_into(">Q", buf, 20, d["sequence_num"])
    # buf[28:32] reserved

    pl = HEADER_SIZE  # payload base offset

    # ---- identity (16 B) @ pl+0 ----
    struct.pack_into(">I", buf, pl + 0, d["target_ip"])
    struct.pack_into(">H", buf, pl + 4, d["port"])
    buf[pl + 6] = d["proto_kind"]
    buf[pl + 7] = d["is_catchall"]
    name = d["profile_name"][:8]
    buf[pl + 8:pl + 8 + len(name)] = name   # null-padded by the zero init

    # ---- phase state (24 B) @ pl+16 ----
    buf[pl + 16] = d["phase"]
    buf[pl + 17] = d["prev_phase"]
    # pl+18..19 reserved
    struct.pack_into(">I", buf, pl + 20, d["warmup_remaining"])
    struct.pack_into(">I", buf, pl + 24, d["consecutive_attack_windows"])
    struct.pack_into(">I", buf, pl + 28, d["baseline_freeze_remaining"])
    struct.pack_into(">I", buf, pl + 32, d["thaw_cooldown_remaining"])
    struct.pack_into(">I", buf, pl + 36, d["windows_seen"])

    # ---- raw counters (80 B) @ pl+40 ----
    struct.pack_into(">Q", buf, pl + 40, d["inbound_pkts"])
    struct.pack_into(">Q", buf, pl + 48, d["inbound_bytes"])
    struct.pack_into(">Q", buf, pl + 56, d["off_proto_pkts"])
    struct.pack_into(">Q", buf, pl + 64, d["ip_frag_pkts"])
    struct.pack_into(">Q", buf, pl + 72, d["ttl_sum"])
    struct.pack_into(">Q", buf, pl + 80, d["ttl_sum_sq"])
    struct.pack_into(">Q", buf, pl + 88, d["out_pkts"])
    struct.pack_into(">Q", buf, pl + 96, d["out_bytes"])
    struct.pack_into(">I", buf, pl + 104, d["out_tcp_pkts"])
    struct.pack_into(">I", buf, pl + 108, d["out_udp_pkts"])
    struct.pack_into(">I", buf, pl + 112, d["out_icmp_pkts"])
    # pl+116..119 reserved

    # ---- proto-specific (96 B) @ pl+120 ----
    struct.pack_into(">Q", buf, pl + 120, d["tcp_pkts"])
    struct.pack_into(">Q", buf, pl + 128, d["tcp_bytes"])
    struct.pack_into(">Q", buf, pl + 136, d["syn_pkts"])
    struct.pack_into(">Q", buf, pl + 144, d["syn_ack_pkts"])
    struct.pack_into(">Q", buf, pl + 152, d["fin_ack_pkts"])
    struct.pack_into(">Q", buf, pl + 160, d["rst_pkts"])
    struct.pack_into(">Q", buf, pl + 168, d["ack_data_pkts"])
    struct.pack_into(">Q", buf, pl + 176, d["empty_ack_pkts"])
    struct.pack_into(">Q", buf, pl + 184, d["zero_window_pkts"])
    struct.pack_into(">Q", buf, pl + 192, d["udp_pkts"])
    struct.pack_into(">Q", buf, pl + 200, d["udp_bytes"])
    struct.pack_into(">Q", buf, pl + 208, d["icmp_pkts"])

    # ---- features (64 B = 8 doubles) @ pl+216 ----
    struct.pack_into(">dddddddd", buf, pl + 216,
                     d["unique_src_ips"], d["unique_flows"],
                     d["src_24_top1_share"], d["src_24_entropy"],
                     d["ttl_mean"], d["ttl_stddev"],
                     d["bw_pps_z_last"], d["bw_bps_z_last"])

    # ---- scores (64 B = 8 doubles) @ pl+280 ----
    struct.pack_into(">dddddddd", buf, pl + 280,
                     d["tier0_score"], d["tier1_tcp_score"],
                     d["tier1_udp_score"], d["tier1_icmp_score"],
                     d["tier1_dist_score"], d["tier1_l3_score"],
                     d["tier1_offproto_score"], d["tier1_final_score"])

    # ---- temporal (36 B = 3 windows x 12 B) @ pl+344 ----
    for i, win in enumerate((d["win_10s"], d["win_60s"], d["win_300s"])):
        struct.pack_into(">III", buf, pl + 344 + i * 12, *win)

    # ---- v2 tail: Tier-0 risk vector (48 B = 6 doubles) @ pl+380 ----
    struct.pack_into(">dddddd", buf, pl + 380,
                     d["tier0_risk_pps"], d["tier0_risk_bps"],
                     d["tier0_risk_fps"], d["tier0_risk_burst_pps"],
                     d["tier0_risk_burst_bps"], d["tier0_risk_burst_fps"])
    # ---- dominant channel byte @ pl+428 (3 reserved bytes follow) ----
    buf[pl + 428] = d["dominant_channel"]

    # ---- footer: CRC32 over the header+payload region [0:464] ----
    crc_region = HEADER_SIZE + config.WIRE_PAYLOAD_SIZE   # 464 in v2
    crc = zlib.crc32(bytes(buf[0:crc_region])) & 0xFFFFFFFF
    struct.pack_into(">I", buf, crc_region, crc)

    return bytes(buf)


# ===========================================================================
# Tiny assertion shim — lets the file run standalone AND under pytest.
# Under pytest each test_* function is collected normally; standalone the
# __main__ block runs them and tallies pass/fail.
# ===========================================================================

class _Fail(AssertionError):
    pass


def _eq(actual, expected, what):
    if actual != expected:
        raise _Fail(f"{what}: expected {expected!r}, got {actual!r}")


def _close(actual, expected, what, tol=1e-9):
    if abs(actual - expected) > tol:
        raise _Fail(f"{what}: expected ~{expected!r}, got {actual!r}")


def _raises(exc_type, fn, what):
    try:
        fn()
    except exc_type:
        return
    except Exception as e:  # noqa: BLE001
        raise _Fail(f"{what}: expected {exc_type.__name__}, "
                    f"got {type(e).__name__}: {e}")
    raise _Fail(f"{what}: expected {exc_type.__name__}, no exception raised")


# ===========================================================================
# Tests
# ===========================================================================

def test_parse_known_good_message():
    """A fully-populated message round-trips every field correctly."""
    buf = build_message()
    m = parse_message(buf)
    assert isinstance(m, WireMessage)

    # header
    _eq(m.timestamp_ns, 1_700_000_000_000_000_000, "timestamp_ns")
    _close(m.timestamp_unix, 1.7e9, "timestamp_unix", tol=1.0)
    _eq(m.slot_id, 42, "slot_id")
    _eq(m.sequence_num, 9001, "sequence_num")

    # identity
    _eq(m.target_ip, 0x0A0B0C0D, "target_ip")
    _eq(m.target_ip_str, "10.11.12.13", "target_ip_str")
    _eq(m.port, 443, "port")
    _eq(m.proto_kind, 4, "proto_kind")
    _eq(m.proto_kind_str, "CATCHALL_TCP", "proto_kind_str")
    _eq(m.is_catchall, True, "is_catchall")
    _eq(m.profile_name, "prof_xy", "profile_name")

    # phase state
    _eq(m.phase, 2, "phase")
    _eq(m.phase_str, "SUSPICIOUS", "phase_str")
    _eq(m.prev_phase, 1, "prev_phase")
    _eq(m.prev_phase_str, "NORMAL", "prev_phase_str")
    _eq(m.warmup_remaining, 17, "warmup_remaining")
    _eq(m.consecutive_attack_windows, 4, "consecutive_attack_windows")
    _eq(m.baseline_freeze_remaining, 30, "baseline_freeze_remaining")
    _eq(m.thaw_cooldown_remaining, 5, "thaw_cooldown_remaining")
    _eq(m.windows_seen, 12345, "windows_seen")
    _eq(m.absolute_floor_fired, False, "absolute_floor_fired (default msg)")

    # raw counters
    _eq(m.inbound_pkts, 1000, "inbound_pkts")
    _eq(m.inbound_bytes, 1_500_000, "inbound_bytes")
    _eq(m.off_proto_pkts, 3, "off_proto_pkts")
    _eq(m.ip_frag_pkts, 1, "ip_frag_pkts")
    _eq(m.ttl_sum, 64_000, "ttl_sum")
    _eq(m.ttl_sum_sq, 4_096_000, "ttl_sum_sq")
    _eq(m.out_pkts, 50, "out_pkts")
    _eq(m.out_bytes, 75_000, "out_bytes")
    _eq(m.out_tcp_pkts, 40, "out_tcp_pkts")
    _eq(m.out_udp_pkts, 8, "out_udp_pkts")
    _eq(m.out_icmp_pkts, 2, "out_icmp_pkts")

    # proto-specific
    _eq(m.tcp_pkts, 1000, "tcp_pkts")
    _eq(m.tcp_bytes, 1_500_000, "tcp_bytes")
    _eq(m.syn_pkts, 200, "syn_pkts")
    _eq(m.syn_ack_pkts, 10, "syn_ack_pkts")
    _eq(m.fin_ack_pkts, 8, "fin_ack_pkts")
    _eq(m.rst_pkts, 5, "rst_pkts")
    _eq(m.ack_data_pkts, 700, "ack_data_pkts")
    _eq(m.empty_ack_pkts, 70, "empty_ack_pkts")
    _eq(m.zero_window_pkts, 0, "zero_window_pkts")
    _eq(m.udp_pkts, 0, "udp_pkts")
    _eq(m.udp_bytes, 0, "udp_bytes")
    _eq(m.icmp_pkts, 0, "icmp_pkts")

    # features
    _close(m.unique_src_ips, 300.5, "unique_src_ips")
    _close(m.unique_flows, 512.25, "unique_flows")
    _close(m.src_24_top1_share, 0.27, "src_24_top1_share")
    _close(m.src_24_entropy, 8.94, "src_24_entropy")
    _close(m.ttl_mean, 64.0, "ttl_mean")
    _close(m.ttl_stddev, 0.0, "ttl_stddev")
    _close(m.bw_pps_z_last, 1.15, "bw_pps_z_last")
    _close(m.bw_bps_z_last, -0.5, "bw_bps_z_last")

    # scores
    _close(m.tier0_score, 0.42, "tier0_score")
    _close(m.tier1_tcp_score, 0.50, "tier1_tcp_score")
    _close(m.tier1_udp_score, 0.10, "tier1_udp_score")
    _close(m.tier1_icmp_score, 0.05, "tier1_icmp_score")
    _close(m.tier1_dist_score, 0.65, "tier1_dist_score")
    _close(m.tier1_l3_score, 0.30, "tier1_l3_score")
    _close(m.tier1_offproto_score, 0.20, "tier1_offproto_score")
    _close(m.tier1_final_score, 0.65, "tier1_final_score")

    # temporal windows
    for win, (tp, peak, atk), wsec in (
        (m.win_10s, (10_000, 1200, 2), 10),
        (m.win_60s, (50_000, 1200, 7), 60),
        (m.win_300s, (200_000, 1200, 12), 300),
    ):
        assert isinstance(win, TemporalWindow)
        _eq(win.window_seconds, wsec, f"win_{wsec}s.window_seconds")
        _eq(win.total_pkts, tp, f"win_{wsec}s.total_pkts")
        _eq(win.peak_pps, peak, f"win_{wsec}s.peak_pps")
        _eq(win.attack_seconds, atk, f"win_{wsec}s.attack_seconds")


def test_tier0_risk_and_dominant():
    """v2 tail: the six Tier-0 risk doubles round-trip bit-exactly and
    dominant_channel maps to the enum string."""
    risks = dict(
        tier0_risk_pps=0.11, tier0_risk_bps=0.22, tier0_risk_fps=0.33,
        tier0_risk_burst_pps=0.44, tier0_risk_burst_bps=0.55,
        tier0_risk_burst_fps=0.66,
    )
    m = parse_message(build_message(dominant_channel=2, **risks))   # 2 = BPS

    # Bit-exact: build_message packed these as IEEE-754 BE, parse reads them
    # back the same way, so exact equality must hold (no tolerance).
    for name, val in risks.items():
        got = getattr(m, name)
        assert got == val, f"{name}: expected {val!r}, got {got!r}"

    _eq(m.dominant_channel, 2, "dominant_channel")
    _eq(m.dominant_channel_str, "BPS", "dominant_channel_str")
    _eq(m.dominant_channel_str, DOMINANT_NAMES[2],
        "dominant_channel_str matches enum mapping")

    # Out-of-range dominant -> UNKNOWN (mirrors service_scoring_dominant_name).
    m_bad = parse_message(build_message(dominant_channel=200))
    _eq(m_bad.dominant_channel, 200, "dominant_channel (out of range)")
    _eq(m_bad.dominant_channel_str, "UNKNOWN", "out-of-range -> UNKNOWN")


def test_zeroed_warmup_heartbeat():
    """A near-zero message (WARMUP-slot heartbeat) parses cleanly."""
    buf = build_message(
        phase=0, prev_phase=0, warmup_remaining=400,
        consecutive_attack_windows=0, baseline_freeze_remaining=0,
        thaw_cooldown_remaining=0, windows_seen=1,
        inbound_pkts=0, inbound_bytes=0, off_proto_pkts=0, ip_frag_pkts=0,
        ttl_sum=0, ttl_sum_sq=0, out_pkts=0, out_bytes=0,
        out_tcp_pkts=0, out_udp_pkts=0, out_icmp_pkts=0,
        tcp_pkts=0, tcp_bytes=0, syn_pkts=0, syn_ack_pkts=0,
        fin_ack_pkts=0, rst_pkts=0, ack_data_pkts=0, empty_ack_pkts=0,
        zero_window_pkts=0, udp_pkts=0, udp_bytes=0, icmp_pkts=0,
        unique_src_ips=0.0, unique_flows=0.0, src_24_top1_share=0.0,
        src_24_entropy=0.0, ttl_mean=0.0, ttl_stddev=0.0,
        bw_pps_z_last=0.0, bw_bps_z_last=0.0,
        tier0_score=0.0, tier1_tcp_score=0.0, tier1_udp_score=0.0,
        tier1_icmp_score=0.0, tier1_dist_score=0.0, tier1_l3_score=0.0,
        tier1_offproto_score=0.0, tier1_final_score=0.0,
        win_10s=(0, 0, 0), win_60s=(0, 0, 0), win_300s=(0, 0, 0),
        profile_name=b"",
    )
    m = parse_message(buf)
    _eq(m.phase, 0, "phase")
    _eq(m.phase_str, "WARMUP", "phase_str")
    _eq(m.warmup_remaining, 400, "warmup_remaining")
    _eq(m.inbound_pkts, 0, "inbound_pkts")
    _eq(m.profile_name, "", "profile_name (empty)")
    _eq(m.win_300s.total_pkts, 0, "win_300s.total_pkts")
    _eq(m.absolute_floor_fired, False, "absolute_floor_fired (zero msg)")


def test_absolute_floor_flag():
    """Header flags byte (offset 6) bit 0 -> WireMessage.absolute_floor_fired."""
    m_on = parse_message(build_message(flags_byte=0x01))
    _eq(m_on.absolute_floor_fired, True, "flags_byte=0x01 -> True")

    m_off = parse_message(build_message(flags_byte=0x00))
    _eq(m_off.absolute_floor_fired, False, "flags_byte=0x00 -> False")


def test_bad_magic():
    buf = bytearray(build_message())
    buf[0] = ord("X")
    _raises(BadMagicError, lambda: parse_message(bytes(buf)),
            "corrupted magic byte 0")


def test_bad_version():
    buf = build_message(version=99)
    _raises(BadVersionError, lambda: parse_message(buf),
            "version=99")


def test_bad_msgtype():
    buf = build_message(msg_type=0x77)
    _raises(BadMsgTypeError, lambda: parse_message(buf),
            "msg_type=0x77")


def test_bad_crc():
    """Flip one payload byte WITHOUT recomputing the CRC -> BadCRCError."""
    buf = bytearray(build_message())
    buf[200] ^= 0x01     # deep in the payload
    _raises(BadCRCError, lambda: parse_message(bytes(buf)),
            "single corrupted payload byte")


def test_bad_payload_length_short():
    _raises(BadPayloadLengthError, lambda: parse_message(b"\x00" * 400),
            "400-byte buffer")


def test_bad_payload_length_empty():
    _raises(BadPayloadLengthError, lambda: parse_message(b""),
            "empty buffer")


def test_bad_payload_length_none():
    _raises(BadPayloadLengthError, lambda: parse_message(None),
            "None buffer")


def test_bad_payload_length_header_field():
    """A tampered header payload_len field is rejected (after CRC, so we
    recompute the CRC to isolate the payload_len check)."""
    buf = bytearray(build_message())
    struct.pack_into(">H", buf, 18, 379)            # wrong payload_len
    crc_region = HEADER_SIZE + config.WIRE_PAYLOAD_SIZE  # 464 in v2
    crc = zlib.crc32(bytes(buf[0:crc_region])) & 0xFFFFFFFF  # keep CRC valid
    struct.pack_into(">I", buf, crc_region, crc)
    _raises(BadPayloadLengthError, lambda: parse_message(bytes(buf)),
            "header payload_len=379")


def test_crc_is_zlib_compatible():
    """The parser must accept exactly what zlib.crc32 produces — this is
    the contract with the C engine's service_wire_crc32."""
    buf = build_message()
    # parse_message would raise BadCRCError if the CRC didn't match.
    m = parse_message(buf)
    assert m is not None


def test_roundtrip_via_decode_reference():
    """Cross-check: the production parser and the reference decoder
    (scripts/decode_wire_message.py) agree on a built message."""
    sys.path.insert(0, os.path.join(_REPO_ROOT, "scripts"))
    import decode_wire_message as ref  # noqa: E402

    buf = build_message(slot_id=7, target_ip=0xC0A80101, phase=3,
                        tier1_final_score=0.97)
    m = parse_message(buf)
    r = ref.decode_message(buf)

    _eq(m.slot_id, r["slot_id"], "slot_id agree")
    _eq(m.target_ip_str, r["target_ip"], "target_ip_str agree")
    _eq(m.phase, r["phase"], "phase agree")
    _eq(m.sequence_num, r["sequence_num"], "sequence_num agree")
    _close(m.tier1_final_score, r["tier1_final_score"],
           "tier1_final_score agree")
    _eq(m.inbound_pkts, r["inbound_pkts"], "inbound_pkts agree")


# ===========================================================================
# Standalone runner
# ===========================================================================

def _all_tests():
    return sorted(
        (name, obj) for name, obj in globals().items()
        if name.startswith("test_") and callable(obj)
    )


def main():
    print("\n*** wire_parser P12 test harness ***\n")
    npass = nfail = 0
    for name, fn in _all_tests():
        try:
            fn()
            print(f"  [PASS] {name}")
            npass += 1
        except Exception as e:  # noqa: BLE001
            print(f"  [FAIL] {name}: {e}")
            nfail += 1
    print(f"\n=== SUMMARY: {npass} PASS, {nfail} FAIL ===")
    return 0 if nfail == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
