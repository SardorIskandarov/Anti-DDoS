"""
wire_parser.py — production parser for the L2FW wire protocol v1 (P12).

Parses the 416-byte big-endian binary messages the C engine emits on
ENGINE_SOCKET_PATH. This is the production sibling of the reference
decoder at scripts/decode_wire_message.py: same byte layout, but it
returns a typed dataclass, raises specific exceptions instead of
printing, and carries no CLI scaffolding.

Byte layout is LOCKED — it must match l2fwd_service_wire.h /
l2fwd_service_wire.c exactly. Any change there bumps WIRE_VERSION and
requires a paired update here.

Import convention: this module is part of the flat ddos_monitor package
(`import config`), consistent with the legacy collector.py / database.py.
"""

import logging
import socket as _socket
import struct
import zlib
from dataclasses import dataclass

import config

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Exceptions — one subclass per distinct framing failure so the collector
# can count / log them separately.
# ---------------------------------------------------------------------------


class WireParseError(Exception):
    """Base class for all wire-protocol parse failures."""


class BadPayloadLengthError(WireParseError):
    """Buffer was not exactly WIRE_MSG_SIZE bytes."""


class BadMagicError(WireParseError):
    """First 4 bytes were not the L2FW magic."""


class BadVersionError(WireParseError):
    """Version byte did not match WIRE_VERSION."""


class BadMsgTypeError(WireParseError):
    """msg_type byte did not match WIRE_MSGTYPE_SNAP."""


class BadCRCError(WireParseError):
    """CRC32 footer did not match the computed CRC over bytes [0..411]."""


# ---------------------------------------------------------------------------
# Phase / proto-kind name maps (mirrors enum service_detection_phase and
# enum service_proto_kind on the C side).
# ---------------------------------------------------------------------------

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


def phase_name(phase: int) -> str:
    return PHASE_NAMES.get(phase, f"UNKNOWN({phase})")


def proto_kind_name(kind: int) -> str:
    return PROTO_KIND_NAMES.get(kind, f"UNKNOWN({kind})")


# ---------------------------------------------------------------------------
# Dataclasses
# ---------------------------------------------------------------------------


@dataclass
class TemporalWindow:
    """One of the three rolling windows (10s / 60s / 300s)."""
    window_seconds: int     # 10, 60, or 300
    total_pkts: int
    peak_pps: int
    attack_seconds: int


@dataclass
class WireMessage:
    """A fully-parsed 416-byte slot snapshot."""

    # Header
    timestamp_ns: int
    timestamp_unix: float
    slot_id: int
    sequence_num: int

    # Identity
    target_ip: int                 # uint32, host byte order
    target_ip_str: str             # dotted quad
    port: int
    proto_kind: int
    proto_kind_str: str
    is_catchall: bool
    profile_name: str

    # Phase state
    phase: int
    phase_str: str
    prev_phase: int
    prev_phase_str: str
    warmup_remaining: int
    consecutive_attack_windows: int
    baseline_freeze_remaining: int
    thaw_cooldown_remaining: int
    windows_seen: int
    # Header flags (offset 6, bit 0): the transition into ATTACK was forced by
    # the absolute volumetric floor, bypassing the gated cascade.
    absolute_floor_fired: bool

    # Raw counters — common + outbound
    inbound_pkts: int
    inbound_bytes: int
    off_proto_pkts: int
    ip_frag_pkts: int
    ttl_sum: int
    ttl_sum_sq: int
    out_pkts: int
    out_bytes: int
    out_tcp_pkts: int
    out_udp_pkts: int
    out_icmp_pkts: int

    # Proto-specific counters
    tcp_pkts: int
    tcp_bytes: int
    syn_pkts: int
    syn_ack_pkts: int
    fin_ack_pkts: int
    rst_pkts: int
    ack_data_pkts: int
    empty_ack_pkts: int
    zero_window_pkts: int
    udp_pkts: int
    udp_bytes: int
    icmp_pkts: int

    # Computed features (doubles)
    unique_src_ips: float
    unique_flows: float
    src_24_top1_share: float
    src_24_entropy: float
    ttl_mean: float
    ttl_stddev: float
    bw_pps_z_last: float
    bw_bps_z_last: float

    # Scores (doubles, [0,1])
    tier0_score: float
    tier1_tcp_score: float
    tier1_udp_score: float
    tier1_icmp_score: float
    tier1_dist_score: float
    tier1_l3_score: float
    tier1_offproto_score: float
    tier1_final_score: float

    # Temporal aggregates
    win_10s: TemporalWindow
    win_60s: TemporalWindow
    win_300s: TemporalWindow


# ---------------------------------------------------------------------------
# Section offsets — relative to the start of the 416-byte buffer.
# Mirrors the L2FWD_WIRE_PL_*_OFF macros (payload starts at byte 32).
# ---------------------------------------------------------------------------

_HEADER_SIZE = config.WIRE_HEADER_SIZE      # 32
_PAYLOAD_SIZE = config.WIRE_PAYLOAD_SIZE    # 380
_MSG_SIZE = config.WIRE_MSG_SIZE            # 416

# Payload-relative offsets (added to _HEADER_SIZE for absolute positions).
_PL_IDENTITY = 0
_PL_PHASE = 16
_PL_COUNTERS = 40
_PL_PROTO = 120
_PL_FEATURES = 216
_PL_SCORES = 280
_PL_TEMPORAL = 344


def parse_message(buf: bytes) -> WireMessage:
    """
    Parse a 416-byte wire message into a WireMessage.

    Raises a WireParseError subclass on any framing failure:
        BadPayloadLengthError  — wrong size
        BadMagicError          — magic mismatch
        BadVersionError        — version mismatch
        BadMsgTypeError        — msg_type mismatch
        BadCRCError            — CRC32 footer mismatch
    """
    if buf is None or len(buf) != _MSG_SIZE:
        raise BadPayloadLengthError(
            f"expected {_MSG_SIZE} bytes, got "
            f"{0 if buf is None else len(buf)}")

    # --- Header validation ---
    if buf[0:4] != config.WIRE_MAGIC:
        raise BadMagicError(f"bad magic: {buf[0:4]!r}")
    if buf[4] != config.WIRE_VERSION:
        raise BadVersionError(f"unsupported version: {buf[4]}")
    if buf[5] != config.WIRE_MSGTYPE_SNAP:
        raise BadMsgTypeError(f"unexpected msg_type: {buf[5]}")

    # --- Header flags byte (offset 6) ---
    absolute_floor_fired = bool(buf[6] & config.WIRE_FLAG_ABSOLUTE_FLOOR)

    # --- CRC32 over bytes [0..411] (matches engine's service_wire_crc32,
    #     which is the standard zlib/Ethernet CRC) ---
    expected_crc = struct.unpack(">I", buf[412:416])[0]
    actual_crc = zlib.crc32(buf[0:412]) & 0xFFFFFFFF
    if expected_crc != actual_crc:
        raise BadCRCError(
            f"CRC mismatch: expected 0x{expected_crc:08X}, "
            f"computed 0x{actual_crc:08X}")

    # --- Header fields ---
    (timestamp_ns,) = struct.unpack(">Q", buf[8:16])
    (slot_id,) = struct.unpack(">H", buf[16:18])
    (payload_len,) = struct.unpack(">H", buf[18:20])
    (sequence_num,) = struct.unpack(">Q", buf[20:28])
    if payload_len != _PAYLOAD_SIZE:
        raise BadPayloadLengthError(
            f"header payload_len {payload_len} != {_PAYLOAD_SIZE}")

    pl = buf[_HEADER_SIZE:_HEADER_SIZE + _PAYLOAD_SIZE]

    # --- Identity (16 B) ---
    o = _PL_IDENTITY
    (target_ip, port, proto_kind, is_catchall) = struct.unpack(
        ">IHBB", pl[o:o + 8])
    target_ip_str = _socket.inet_ntoa(struct.pack(">I", target_ip))
    profile_name = pl[o + 8:o + 16].rstrip(b"\x00").decode(
        "ascii", errors="replace")

    # --- Phase state (24 B) ---
    o = _PL_PHASE
    phase = pl[o]
    prev_phase = pl[o + 1]
    # pl[o+2:o+4] reserved
    (warmup_remaining,
     consecutive_attack_windows,
     baseline_freeze_remaining,
     thaw_cooldown_remaining,
     windows_seen) = struct.unpack(">IIIII", pl[o + 4:o + 24])

    # --- Raw counters (80 B) ---
    o = _PL_COUNTERS
    (inbound_pkts, inbound_bytes, off_proto_pkts, ip_frag_pkts,
     ttl_sum, ttl_sum_sq, out_pkts, out_bytes) = struct.unpack(
        ">QQQQQQQQ", pl[o:o + 64])
    (out_tcp_pkts, out_udp_pkts, out_icmp_pkts) = struct.unpack(
        ">III", pl[o + 64:o + 76])
    # pl[o+76:o+80] reserved

    # --- Proto-specific counters (96 B) ---
    o = _PL_PROTO
    (tcp_pkts, tcp_bytes, syn_pkts, syn_ack_pkts, fin_ack_pkts,
     rst_pkts, ack_data_pkts, empty_ack_pkts, zero_window_pkts) = \
        struct.unpack(">QQQQQQQQQ", pl[o:o + 72])
    (udp_pkts, udp_bytes) = struct.unpack(">QQ", pl[o + 72:o + 88])
    (icmp_pkts,) = struct.unpack(">Q", pl[o + 88:o + 96])

    # --- Computed features (64 B = 8 doubles) ---
    o = _PL_FEATURES
    (unique_src_ips, unique_flows, src_24_top1_share, src_24_entropy,
     ttl_mean, ttl_stddev, bw_pps_z_last, bw_bps_z_last) = struct.unpack(
        ">dddddddd", pl[o:o + 64])

    # --- Scores (64 B = 8 doubles) ---
    o = _PL_SCORES
    (tier0_score, tier1_tcp_score, tier1_udp_score, tier1_icmp_score,
     tier1_dist_score, tier1_l3_score, tier1_offproto_score,
     tier1_final_score) = struct.unpack(">dddddddd", pl[o:o + 64])

    # --- Temporal aggregates (3 windows x 12 B) ---
    o = _PL_TEMPORAL
    win_sizes = (10, 60, 300)
    windows = []
    for i, wsec in enumerate(win_sizes):
        block = pl[o + i * 12:o + (i + 1) * 12]
        total_pkts, peak_pps, attack_seconds = struct.unpack(">III", block)
        windows.append(TemporalWindow(
            window_seconds=wsec,
            total_pkts=total_pkts,
            peak_pps=peak_pps,
            attack_seconds=attack_seconds,
        ))

    return WireMessage(
        timestamp_ns=timestamp_ns,
        timestamp_unix=timestamp_ns / 1e9,
        slot_id=slot_id,
        sequence_num=sequence_num,
        target_ip=target_ip,
        target_ip_str=target_ip_str,
        port=port,
        proto_kind=proto_kind,
        proto_kind_str=proto_kind_name(proto_kind),
        is_catchall=bool(is_catchall),
        profile_name=profile_name,
        phase=phase,
        phase_str=phase_name(phase),
        prev_phase=prev_phase,
        prev_phase_str=phase_name(prev_phase),
        warmup_remaining=warmup_remaining,
        consecutive_attack_windows=consecutive_attack_windows,
        baseline_freeze_remaining=baseline_freeze_remaining,
        thaw_cooldown_remaining=thaw_cooldown_remaining,
        windows_seen=windows_seen,
        absolute_floor_fired=absolute_floor_fired,
        inbound_pkts=inbound_pkts,
        inbound_bytes=inbound_bytes,
        off_proto_pkts=off_proto_pkts,
        ip_frag_pkts=ip_frag_pkts,
        ttl_sum=ttl_sum,
        ttl_sum_sq=ttl_sum_sq,
        out_pkts=out_pkts,
        out_bytes=out_bytes,
        out_tcp_pkts=out_tcp_pkts,
        out_udp_pkts=out_udp_pkts,
        out_icmp_pkts=out_icmp_pkts,
        tcp_pkts=tcp_pkts,
        tcp_bytes=tcp_bytes,
        syn_pkts=syn_pkts,
        syn_ack_pkts=syn_ack_pkts,
        fin_ack_pkts=fin_ack_pkts,
        rst_pkts=rst_pkts,
        ack_data_pkts=ack_data_pkts,
        empty_ack_pkts=empty_ack_pkts,
        zero_window_pkts=zero_window_pkts,
        udp_pkts=udp_pkts,
        udp_bytes=udp_bytes,
        icmp_pkts=icmp_pkts,
        unique_src_ips=unique_src_ips,
        unique_flows=unique_flows,
        src_24_top1_share=src_24_top1_share,
        src_24_entropy=src_24_entropy,
        ttl_mean=ttl_mean,
        ttl_stddev=ttl_stddev,
        bw_pps_z_last=bw_pps_z_last,
        bw_bps_z_last=bw_bps_z_last,
        tier0_score=tier0_score,
        tier1_tcp_score=tier1_tcp_score,
        tier1_udp_score=tier1_udp_score,
        tier1_icmp_score=tier1_icmp_score,
        tier1_dist_score=tier1_dist_score,
        tier1_l3_score=tier1_l3_score,
        tier1_offproto_score=tier1_offproto_score,
        tier1_final_score=tier1_final_score,
        win_10s=windows[0],
        win_60s=windows[1],
        win_300s=windows[2],
    )
