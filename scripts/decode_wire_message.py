#!/usr/bin/env python3
"""
Standalone decoder for L2FW wire protocol v1 (P10).

Reads 416-byte messages from a file or stdin and prints them as
human-readable text. Used for engine-side validation of the binary
emit; the full collector consumer lives under ddos_monitor/ once
P12 ships.

Usage:
    python3 decode_wire_message.py /tmp/captured_messages.bin
    cat messages.bin | python3 decode_wire_message.py
    python3 decode_wire_message.py --json /tmp/captured_messages.bin

Exit codes:
    0  all messages decoded cleanly
    1  one or more messages failed to decode
    2  bad arguments / file open error
"""

import json
import socket as sock_mod
import struct
import sys
import zlib
from typing import Any, Dict

# Wire-protocol constants — must match l2fwd_service_wire.h byte-for-byte.
MAGIC    = b"L2FW"
VERSION  = 0x01
MSG_TYPE = 0x01
MSG_SIZE = 416

HEADER_SIZE  = 32
PAYLOAD_SIZE = 380
FOOTER_SIZE  = 4

# Payload section offsets (relative to payload start).
PL_IDENTITY_OFF  = 0
PL_PHASE_OFF     = 16
PL_COUNTERS_OFF  = 40
PL_PROTO_OFF     = 120
PL_FEATURES_OFF  = 216
PL_SCORES_OFF    = 280
PL_TEMPORAL_OFF  = 344

PHASE_NAMES = {0: "WARMUP", 1: "NORMAL", 2: "SUSPICIOUS", 3: "ATTACK"}

PROTO_KIND_NAMES = {
    1: "TCP",
    2: "UDP",
    3: "ICMP",
    4: "CATCHALL_TCP",
    5: "CATCHALL_UDP",
    6: "CATCHALL_ICMP",
    7: "CATCHALL_OTHER",
}


def decode_message(buf: bytes) -> Dict[str, Any]:
    """Decode one 416-byte buffer. Raises ValueError on any framing error."""
    if len(buf) != MSG_SIZE:
        raise ValueError(f"expected {MSG_SIZE} bytes, got {len(buf)}")

    # Header.
    if buf[0:4] != MAGIC:
        raise ValueError(f"bad magic: {buf[0:4]!r}")
    version = buf[4]
    msg_type = buf[5]
    if version != VERSION:
        raise ValueError(f"unsupported version: {version}")
    if msg_type != MSG_TYPE:
        raise ValueError(f"unexpected msg_type: {msg_type}")

    (timestamp_ns,) = struct.unpack(">Q", buf[8:16])
    (slot_id,)      = struct.unpack(">H", buf[16:18])
    (payload_len,)  = struct.unpack(">H", buf[18:20])
    (seq_num,)      = struct.unpack(">Q", buf[20:28])

    if payload_len != PAYLOAD_SIZE:
        raise ValueError(f"unexpected payload_len: {payload_len}")

    # CRC32 check (matches engine's service_wire_crc32).
    expected_crc = struct.unpack(">I", buf[412:416])[0]
    actual_crc   = zlib.crc32(buf[0:412])
    if expected_crc != actual_crc:
        raise ValueError(
            f"CRC mismatch: expected 0x{expected_crc:08X}, "
            f"computed 0x{actual_crc:08X}")

    pl = buf[HEADER_SIZE:HEADER_SIZE + PAYLOAD_SIZE]

    # Identity (16 B).
    id_off = PL_IDENTITY_OFF
    (target_ip_int, port, proto_kind, is_catchall) = struct.unpack(
        ">IHBB", pl[id_off:id_off + 8])
    target_ip = sock_mod.inet_ntoa(struct.pack(">I", target_ip_int))
    profile_name = pl[id_off + 8:id_off + 16].rstrip(b"\x00") \
                      .decode("ascii", errors="replace")

    # Phase state (24 B).
    ph_off = PL_PHASE_OFF
    phase, prev_phase = pl[ph_off], pl[ph_off + 1]
    (warmup, consec, freeze, thaw, windows_seen) = struct.unpack(
        ">IIIII", pl[ph_off + 4:ph_off + 24])

    # Raw counters (80 B).
    c_off = PL_COUNTERS_OFF
    (in_pkts, in_bytes, off_proto, ip_frag, ttl_sum, ttl_sum_sq,
     out_pkts, out_bytes) = struct.unpack(">QQQQQQQQ", pl[c_off:c_off + 64])
    (out_tcp, out_udp, out_icmp) = struct.unpack(
        ">III", pl[c_off + 64:c_off + 76])

    # Proto-specific (96 B).
    p_off = PL_PROTO_OFF
    (tcp_pkts, tcp_bytes, syn, syn_ack, fin_ack, rst,
     ack_data, empty_ack, zero_win) = struct.unpack(
        ">QQQQQQQQQ", pl[p_off:p_off + 72])
    (udp_pkts, udp_bytes) = struct.unpack(
        ">QQ", pl[p_off + 72:p_off + 88])
    (icmp_pkts,) = struct.unpack(">Q", pl[p_off + 88:p_off + 96])

    # Features (64 B = 8 doubles).
    f_off = PL_FEATURES_OFF
    (src_ip_card, flow_card, top1_share, entropy, ttl_mean,
     ttl_stddev, bw_pps_z, bw_bps_z) = struct.unpack(
        ">dddddddd", pl[f_off:f_off + 64])

    # Scores (64 B = 8 doubles).
    s_off = PL_SCORES_OFF
    (t0, t1_tcp, t1_udp, t1_icmp, t1_dist, t1_l3,
     t1_off, t1_final) = struct.unpack(
        ">dddddddd", pl[s_off:s_off + 64])

    # Temporal (3 × 12 B).
    tw_off = PL_TEMPORAL_OFF
    windows = []
    for i in range(3):
        block = pl[tw_off + i * 12:tw_off + (i + 1) * 12]
        tp, peak, attack_sec = struct.unpack(">III", block)
        windows.append({
            "total_pkts":     tp,
            "peak_pps":       peak,
            "attack_seconds": attack_sec,
        })

    return {
        "timestamp_ns":      timestamp_ns,
        "slot_id":           slot_id,
        "sequence_num":      seq_num,
        "target_ip":         target_ip,
        "port":              port,
        "proto_kind":        proto_kind,
        "proto_kind_name":   PROTO_KIND_NAMES.get(proto_kind, f"UNKNOWN({proto_kind})"),
        "is_catchall":       bool(is_catchall),
        "profile_name":      profile_name,
        "phase":             phase,
        "phase_name":        PHASE_NAMES.get(phase, f"UNKNOWN({phase})"),
        "prev_phase":        prev_phase,
        "warmup_remaining":          warmup,
        "consecutive_attack_windows": consec,
        "baseline_freeze_remaining":  freeze,
        "thaw_cooldown_remaining":    thaw,
        "windows_seen":      windows_seen,
        "inbound_pkts":      in_pkts,
        "inbound_bytes":     in_bytes,
        "off_proto_pkts":    off_proto,
        "ip_frag_pkts":      ip_frag,
        "ttl_sum":           ttl_sum,
        "ttl_sum_sq":        ttl_sum_sq,
        "outbound_pkts":     out_pkts,
        "outbound_bytes":    out_bytes,
        "out_tcp_pkts":      out_tcp,
        "out_udp_pkts":      out_udp,
        "out_icmp_pkts":     out_icmp,
        "tcp_pkts":          tcp_pkts,
        "tcp_bytes":         tcp_bytes,
        "syn_pkts":          syn,
        "syn_ack_pkts":      syn_ack,
        "fin_ack_pkts":      fin_ack,
        "rst_pkts":          rst,
        "ack_data_pkts":     ack_data,
        "empty_ack_pkts":    empty_ack,
        "zero_window_pkts":  zero_win,
        "udp_pkts":          udp_pkts,
        "udp_bytes":         udp_bytes,
        "icmp_pkts":         icmp_pkts,
        "unique_src_ips":    src_ip_card,
        "unique_flows":      flow_card,
        "src_24_top1_share": top1_share,
        "src_24_entropy":    entropy,
        "ttl_mean":          ttl_mean,
        "ttl_stddev":        ttl_stddev,
        "bw_pps_z_last":     bw_pps_z,
        "bw_bps_z_last":     bw_bps_z,
        "tier0_score":       t0,
        "tier1_tcp_score":   t1_tcp,
        "tier1_udp_score":   t1_udp,
        "tier1_icmp_score":  t1_icmp,
        "tier1_dist_score":  t1_dist,
        "tier1_l3_score":    t1_l3,
        "tier1_offproto_score": t1_off,
        "tier1_final_score": t1_final,
        "temporal_windows":  windows,
    }


def format_message(m: Dict[str, Any]) -> str:
    return (
        f"[#{m['sequence_num']:6d}] "
        f"slot={m['slot_id']:3d} "
        f"{m['target_ip']:>15s}:{m['port']:<5d} "
        f"proto={m['proto_kind_name']:<14s} "
        f"{'(catchall)' if m['is_catchall'] else '         '} "
        f"phase={m['phase_name']:<10s} "
        f"in_pkts={m['inbound_pkts']:>8d} "
        f"t0={m['tier0_score']:.3f} "
        f"t1={m['tier1_final_score']:.3f}"
    )


def main(argv: list) -> int:
    json_mode = False
    args = list(argv[1:])
    if args and args[0] == "--json":
        json_mode = True
        args = args[1:]

    if args:
        try:
            stream = open(args[0], "rb")
        except OSError as e:
            print(f"ERROR: cannot open {args[0]}: {e}", file=sys.stderr)
            return 2
    else:
        stream = sys.stdin.buffer

    count = 0
    errors = 0
    try:
        while True:
            buf = stream.read(MSG_SIZE)
            if not buf:
                break
            if len(buf) != MSG_SIZE:
                print(f"WARN: short read ({len(buf)} bytes) at message "
                      f"#{count}; discarding tail", file=sys.stderr)
                errors += 1
                break
            try:
                m = decode_message(buf)
                if json_mode:
                    print(json.dumps(m))
                else:
                    print(format_message(m))
                count += 1
            except ValueError as e:
                print(f"ERROR at message #{count}: {e}", file=sys.stderr)
                errors += 1
    finally:
        if stream is not sys.stdin.buffer:
            stream.close()

    print(f"\nDecoded {count} messages, {errors} errors", file=sys.stderr)
    return 0 if errors == 0 else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv))
