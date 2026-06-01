"""
snapshot.py — Python mirror of the C↔Python raw-telemetry snapshot contract.

This is the Python side of l2fwd_service_snapshot.h. The C data plane publishes
one fixed-size RAW snapshot record per active slot, once per 1 Hz tick, into a
double-buffered POSIX shared-memory region (/dev/shm/anti_ddos_snapshot). This
module mirrors that layout byte-for-byte and provides a zero-copy reader.

Unlike the legacy socket wire (wire_parser.py), this channel carries RAW
counters + sketch ESTIMATES (scalars) — never computed scores. The Python
detector (detector.py, P2) consumes these records and owns all derived state.

LAYOUT AUTHORITY
----------------
This file is the AUTHORITATIVE definition of the record field table: the
FNV-1a layout hash is computed here and baked into the C header as
SERVICE_SNAPSHOT_LAYOUT_HASH. The C producer recomputes the same hash from its
own field table at init and refuses to start on mismatch. So any drift between
the two layouts becomes a loud, immediate failure rather than silent
mis-parsing.

Same-host shared memory ⇒ NATIVE little-endian, no byte-swapping (contrast the
socket wire, which is big-endian for portability).

Run `python3 ddos_monitor/detection/snapshot.py` to print the contract constants
(record size, layout hash, total shm bytes) — those are the values to bake into
l2fwd_service_snapshot.h and assert in the producer.
"""

import mmap
import os
import struct

import numpy as np

# ---------------------------------------------------------------------------
# Contract constants — MUST match l2fwd_service_snapshot.h
# ---------------------------------------------------------------------------

SHM_PATH = "/dev/shm/anti_ddos_snapshot"

MAGIC = b"ADS1"
FORMAT_VERSION = 1
RECORD_VERSION = 2   # v2: ttl/tcp/udp pkt-size sums → Welford mean/M2 (same offsets)
RECORD_SIZE = 384
HEADER_SIZE = 128
PROFILE_NAME_LEN = 8

# Field-table "kind" codes — fed into the layout hash so a type change (even at
# the same offset/size) is detected. Keep in sync with the C field table (P1).
_K_U64 = 1
_K_U32 = 2
_K_U16 = 3
_K_U8 = 4
_K_F64 = 5
_K_BYTES = 6

# (name, offset, size_bytes, kind) in ascending offset order. This single list
# drives BOTH the NumPy dtype and the layout hash — one source of truth.
RECORD_FIELDS = (
    # 8-byte raw u64 counters --------------------------------------------
    ("inbound_pkts", 0, 8, _K_U64),
    ("inbound_bytes", 8, 8, _K_U64),
    ("off_proto_pkts", 16, 8, _K_U64),
    ("ip_frag_pkts", 24, 8, _K_U64),
    ("ttl_mean", 32, 8, _K_F64),
    ("ttl_M2", 40, 8, _K_F64),
    ("out_pkts", 48, 8, _K_U64),
    ("out_bytes", 56, 8, _K_U64),
    ("out_tcp_pkts", 64, 8, _K_U64),
    ("out_udp_pkts", 72, 8, _K_U64),
    ("out_icmp_pkts", 80, 8, _K_U64),
    ("tcp_pkts", 88, 8, _K_U64),
    ("tcp_bytes", 96, 8, _K_U64),
    ("syn_pkts", 104, 8, _K_U64),
    ("syn_ack_pkts", 112, 8, _K_U64),
    ("fin_ack_pkts", 120, 8, _K_U64),
    ("rst_pkts", 128, 8, _K_U64),
    ("ack_data_pkts", 136, 8, _K_U64),
    ("empty_ack_pkts", 144, 8, _K_U64),
    ("zero_window_pkts", 152, 8, _K_U64),
    ("small_window_pkts", 160, 8, _K_U64),
    ("tcp_pkt_size_mean", 168, 8, _K_F64),
    ("tcp_pkt_size_M2", 176, 8, _K_F64),
    ("tcp_cm_src_port_top_count", 184, 8, _K_U64),
    ("tcp_cm_src_port_total", 192, 8, _K_U64),
    ("udp_pkts", 200, 8, _K_U64),
    ("udp_bytes", 208, 8, _K_U64),
    ("udp_pkt_size_mean", 216, 8, _K_F64),
    ("udp_pkt_size_M2", 224, 8, _K_F64),
    ("udp_cm_src_port_top_count", 232, 8, _K_U64),
    ("udp_cm_src_port_total", 240, 8, _K_U64),
    ("icmp_pkts", 248, 8, _K_U64),
    ("icmp_echo_pkts", 256, 8, _K_U64),
    ("icmp_bytes", 264, 8, _K_U64),
    ("other_pkts", 272, 8, _K_U64),
    ("other_bytes", 280, 8, _K_U64),
    # 8-byte sketch estimates (doubles) ----------------------------------
    ("est_unique_src_ips", 288, 8, _K_F64),
    ("est_unique_flows", 296, 8, _K_F64),
    ("src_24_top1_share", 304, 8, _K_F64),
    ("src_24_entropy", 312, 8, _K_F64),
    ("est_tcp_new_flows", 320, 8, _K_F64),
    ("est_udp_flows", 328, 8, _K_F64),
    ("est_other_dst_ports", 336, 8, _K_F64),
    # 4-byte --------------------------------------------------------------
    ("target_ip", 344, 4, _K_U32),
    ("window_count", 348, 4, _K_U32),
    # 2-byte --------------------------------------------------------------
    ("port", 352, 2, _K_U16),
    # 1-byte --------------------------------------------------------------
    ("proto_kind", 354, 1, _K_U8),
    ("is_catchall", 355, 1, _K_U8),
    ("absolute_floor_fired", 356, 1, _K_U8),
    ("profile_name", 357, PROFILE_NAME_LEN, _K_BYTES),
    # bytes 365..383 are reserved padding (not a named field).
)

# NumPy "kind code → little-endian dtype string" map.
_KIND_TO_NPY = {
    _K_U64: "<u8",
    _K_U32: "<u4",
    _K_U16: "<u2",
    _K_U8: "u1",
    _K_F64: "<f8",
    _K_BYTES: f"S{PROFILE_NAME_LEN}",
}


def _build_record_dtype() -> np.dtype:
    """Structured dtype with explicit offsets and the fixed 384-byte stride."""
    names = [f[0] for f in RECORD_FIELDS]
    formats = [_KIND_TO_NPY[f[3]] for f in RECORD_FIELDS]
    offsets = [f[1] for f in RECORD_FIELDS]
    return np.dtype({
        "names": names,
        "formats": formats,
        "offsets": offsets,
        "itemsize": RECORD_SIZE,
    })


RECORD_DTYPE = _build_record_dtype()


def compute_layout_hash() -> int:
    """FNV-1a 32-bit over the field table: for each field in offset order,
    feed offset(u16-LE), size(u16-LE), kind(u8). Must match the C producer's
    service_snapshot_compute_layout_hash()."""
    h = 0x811C9DC5
    for _name, off, size, kind in RECORD_FIELDS:
        for b in struct.pack("<HHB", off, size, kind):
            h ^= b
            h = (h * 0x01000193) & 0xFFFFFFFF
    return h


LAYOUT_HASH = compute_layout_hash()

# Shm header layout (128 B), native little-endian. Field order mirrors
# struct service_snapshot_shm_header.
HEADER_DTYPE = np.dtype({
    "names": [
        "magic", "format_version", "record_version", "record_size",
        "layout_hash", "capacity", "n_active", "active_bank",
        "registry_epoch", "seq_bank0", "seq_bank1", "produced_ts_ns",
    ],
    "formats": [
        "S4", "<u4", "<u4", "<u4",
        "<u4", "<u4", "<u4", "<u4",
        "<u8", "<u8", "<u8", "<u8",
    ],
    "offsets": [0, 4, 8, 12, 16, 20, 24, 28, 32, 40, 48, 56],
    "itemsize": HEADER_SIZE,
})


# ---------------------------------------------------------------------------
# Reader
# ---------------------------------------------------------------------------


class SnapshotLayoutError(RuntimeError):
    """The shm header does not match this build's expected contract."""


class SnapshotReader:
    """Zero-copy reader for the double-buffered snapshot shm region.

    Open once; call read_latest() each tick. Returns the freshly-published bank
    as a NumPy structured array (a view into shared memory — copy if you need to
    retain it past the next publish). Tolerates the producer not having created
    the region yet (open() raises FileNotFoundError; the caller retries).
    """

    def __init__(self, path: str = SHM_PATH):
        self._path = path
        self._fd = -1
        self._mm: mmap.mmap | None = None
        self._capacity = 0
        self._last_seq = 0

    def open(self) -> None:
        """Map the region read-only and validate the header contract."""
        self._fd = os.open(self._path, os.O_RDONLY)
        size = os.fstat(self._fd).st_size
        self._mm = mmap.mmap(self._fd, size, prot=mmap.PROT_READ)

        hdr = self._read_header()
        if bytes(hdr["magic"]) != MAGIC:
            raise SnapshotLayoutError(f"bad magic: {bytes(hdr['magic'])!r}")
        if int(hdr["format_version"]) != FORMAT_VERSION:
            raise SnapshotLayoutError(
                f"format_version {int(hdr['format_version'])} != {FORMAT_VERSION}")
        if int(hdr["record_version"]) != RECORD_VERSION:
            raise SnapshotLayoutError(
                f"record_version {int(hdr['record_version'])} != {RECORD_VERSION}")
        if int(hdr["record_size"]) != RECORD_SIZE:
            raise SnapshotLayoutError(
                f"record_size {int(hdr['record_size'])} != {RECORD_SIZE}")
        if int(hdr["layout_hash"]) != LAYOUT_HASH:
            raise SnapshotLayoutError(
                f"layout_hash 0x{int(hdr['layout_hash']):08X} != "
                f"0x{LAYOUT_HASH:08X} (C/Python record layouts disagree)")

        self._capacity = int(hdr["capacity"])
        expected = HEADER_SIZE + 2 * self._capacity * RECORD_SIZE
        if size < expected:
            raise SnapshotLayoutError(
                f"shm too small: {size} < {expected} "
                f"(capacity={self._capacity})")

    def _read_header(self) -> np.void:
        return np.frombuffer(self._mm, dtype=HEADER_DTYPE, count=1, offset=0)[0]

    def read_latest(self, copy: bool = True):
        """Return (header_dict, records) for the currently-published bank, or
        None if no new data since the last call.

        records is the FULL-capacity NumPy structured array. The producer writes
        record[i] for slot i and zeroes inactive slots, so the array index IS
        the slot_id and active slots are identified by
        ``records['proto_kind'] != 0`` — never assume active records are packed
        at the front.

        copy defaults to True: at 1 Hz / ~126 KB the per-tick copy is free and
        it gives the detector a private snapshot, decoupled from the shared
        buffer and from reader lifecycle (a live zero-copy view would block
        close()/munmap). Pass copy=False only for read-and-discard inspection
        within a single tick, and drop the array before calling close().
        """
        if self._mm is None:
            raise RuntimeError("SnapshotReader.open() not called")

        hdr = self._read_header()
        active = int(hdr["active_bank"]) & 1
        seq = int(hdr["seq_bank0"] if active == 0 else hdr["seq_bank1"])
        if seq == self._last_seq:
            return None  # nothing new
        self._last_seq = seq

        n_active = int(hdr["n_active"])
        bank_off = HEADER_SIZE + active * self._capacity * RECORD_SIZE
        recs = np.frombuffer(
            self._mm, dtype=RECORD_DTYPE, count=self._capacity, offset=bank_off)
        if copy:
            recs = recs.copy()

        header_dict = {
            "registry_epoch": int(hdr["registry_epoch"]),
            "produced_ts_ns": int(hdr["produced_ts_ns"]),
            "seq": seq,
            "active_bank": active,
            "n_active": n_active,
            "capacity": self._capacity,
        }
        return header_dict, recs

    def close(self) -> None:
        if self._mm is not None:
            self._mm.close()
            self._mm = None
        if self._fd >= 0:
            os.close(self._fd)
            self._fd = -1


# ---------------------------------------------------------------------------
# Self-test / contract dump
# ---------------------------------------------------------------------------


def _selftest() -> int:
    print("=== snapshot contract ===")
    print(f"RECORD_SIZE       = {RECORD_SIZE}")
    print(f"dtype.itemsize    = {RECORD_DTYPE.itemsize}")
    print(f"HEADER_SIZE       = {HEADER_SIZE}")
    print(f"header.itemsize   = {HEADER_DTYPE.itemsize}")
    print(f"RECORD_VERSION    = {RECORD_VERSION}")
    print(f"FORMAT_VERSION    = {FORMAT_VERSION}")
    print(f"LAYOUT_HASH       = 0x{LAYOUT_HASH:08X}")
    print(f"fields            = {len(RECORD_FIELDS)}")

    ok = True
    if RECORD_DTYPE.itemsize != RECORD_SIZE:
        print(f"  FAIL: dtype itemsize {RECORD_DTYPE.itemsize} != {RECORD_SIZE}")
        ok = False
    if HEADER_DTYPE.itemsize != HEADER_SIZE:
        print(f"  FAIL: header itemsize {HEADER_DTYPE.itemsize} != {HEADER_SIZE}")
        ok = False
    # No overlapping/oversized fields.
    for name, off, size, _kind in RECORD_FIELDS:
        if off + size > RECORD_SIZE:
            print(f"  FAIL: field {name} overruns record ({off}+{size})")
            ok = False
    # Offsets strictly increasing (no overlaps).
    prev_end = 0
    for name, off, size, _kind in RECORD_FIELDS:
        if off < prev_end:
            print(f"  FAIL: field {name} at {off} overlaps previous end {prev_end}")
            ok = False
        prev_end = off + size

    print(f"total shm bytes (capacity=328) = "
          f"{HEADER_SIZE + 2 * 328 * RECORD_SIZE}")
    print("RESULT:", "OK" if ok else "FAILED")
    print()
    print("Bake into l2fwd_service_snapshot.h:")
    print(f"  #define SERVICE_SNAPSHOT_LAYOUT_HASH  0x{LAYOUT_HASH:08X}u")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(_selftest())
