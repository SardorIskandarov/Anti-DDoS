"""
shadow.py — run the Python detection brain against the LIVE shared-memory
snapshot, alongside the still-authoritative C engine, before cutover.

Two roles:

  ShadowRunner — opens the snapshot shm, and on each new publish runs the
    DetectionPipeline to produce WireMessages. An optional on_message callback
    lets a caller record / forward / compare them. Tolerates the producer not
    being up yet (retries the open).

  DiffLogger — compares a Python WireMessage against the C engine's verdict for
    the same (slot, window) and appends any divergence to a plain log file
    (NOT a new ClickHouse table, by design). Used during shadow validation; the
    C verdict comes from whatever source the operator wires in (e.g. the legacy
    collector's parsed wire messages, or recorded ClickHouse rows).

This module is the pre-cutover safety net. Full bit-exact verdict parity is
already proven offline (tests/python/test_detector_parity.py); shadow mode
confirms it on live traffic and timing.
"""

import logging
import time

from .config import DetectionConfig
from .pipeline import DetectionPipeline
from .snapshot import SnapshotReader, SnapshotLayoutError, SHM_PATH

logger = logging.getLogger("detection.shadow")

# WireMessage fields compared by DiffLogger. Floats use a tolerance; the rest
# are exact. These are the verdict-bearing fields (raw counters are passthrough
# and identical by construction, so they are not compared here).
_FLOAT_FIELDS = (
    "tier0_score", "tier1_tcp_score", "tier1_udp_score", "tier1_icmp_score",
    "tier1_dist_score", "tier1_l3_score", "tier1_offproto_score",
    "tier1_final_score", "tier0_risk_pps", "tier0_risk_bps", "tier0_risk_fps",
    "tier0_risk_burst_pps", "tier0_risk_burst_bps", "tier0_risk_burst_fps",
)
_INT_FIELDS = (
    "phase", "prev_phase", "dominant_channel", "warmup_remaining",
    "consecutive_attack_windows", "baseline_freeze_remaining",
    "thaw_cooldown_remaining",
)
_FLOAT_TOL = 1e-9


class DiffLogger:
    """Append per-field Python-vs-C divergences to a file. Cheap no-op when the
    two verdicts agree."""

    def __init__(self, path: str):
        self.path = path
        self.compared = 0
        self.mismatched = 0
        self._fh = open(path, "a", buffering=1)  # line-buffered

    def compare(self, py_msg, c_verdict) -> bool:
        """c_verdict: any object exposing the same attributes as a WireMessage
        (e.g. a parsed C wire message). Returns True if they match."""
        self.compared += 1
        diffs = []
        for f in _INT_FIELDS:
            a, b = getattr(py_msg, f), getattr(c_verdict, f)
            if a != b:
                diffs.append(f"{f}: py={a} c={b}")
        for f in _FLOAT_FIELDS:
            a, b = float(getattr(py_msg, f)), float(getattr(c_verdict, f))
            if abs(a - b) > _FLOAT_TOL + _FLOAT_TOL * max(abs(a), abs(b)):
                diffs.append(f"{f}: py={a!r} c={b!r}")
        if diffs:
            self.mismatched += 1
            self._fh.write(
                f"MISMATCH slot={py_msg.slot_id} {py_msg.target_ip_str}:"
                f"{py_msg.port} ts={py_msg.timestamp_ns} :: "
                + "; ".join(diffs) + "\n")
            return False
        return True

    def close(self):
        try:
            self._fh.close()
        except OSError:
            pass


class ShadowRunner:
    """Drive the DetectionPipeline from the live snapshot shm."""

    def __init__(self, config: DetectionConfig, shm_path: str = SHM_PATH,
                 on_message=None):
        self.pipe = DetectionPipeline(config)
        self.reader = SnapshotReader(shm_path)
        self.on_message = on_message
        self._opened = False
        self.snapshots_seen = 0
        self.messages_emitted = 0

    def open(self) -> bool:
        """Attach to the shm region. Returns False if not present yet."""
        try:
            self.reader.open()
            self._opened = True
            logger.info("shadow attached to %s", self.reader._path)
            return True
        except FileNotFoundError:
            return False
        except SnapshotLayoutError:
            logger.exception("snapshot layout mismatch — refusing to attach")
            raise

    def run_once(self) -> int:
        """Process the latest published bank if it is new. Returns the number of
        active-slot messages produced (0 if no new publish)."""
        if not self._opened:
            return 0
        res = self.reader.read_latest()
        if res is None:
            return 0
        header, records = res
        self.snapshots_seen += 1
        msgs = self.pipe.process_snapshot(header, records)
        self.messages_emitted += len(msgs)
        if self.on_message is not None:
            for m in msgs:
                self.on_message(m)
        return len(msgs)

    def run(self, stop_event, poll_interval: float = 0.2,
            open_retry: float = 1.0) -> None:
        """Loop until stop_event is set. Polls slightly faster than the 1 Hz
        publish so a new bank is picked up promptly without busy-spinning."""
        while not stop_event.is_set():
            if not self._opened and not self.open():
                stop_event.wait(open_retry)
                continue
            try:
                self.run_once()
            except Exception:  # noqa: BLE001 — keep the shadow alive
                logger.exception("shadow run_once error")
            stop_event.wait(poll_interval)

    def close(self):
        self.reader.close()
