"""
pipeline.py — the integration glue the collector drives.

Owns the Detector (verdict) + one TemporalState per slot + a monotonic sequence
counter, and turns a published snapshot bank into the list of WireMessages the
collector's ClickHouse writers already consume. Also handles checkpointing so a
restart resumes from learned baselines instead of a ~400-window cold warmup.

Usage (collector, P4):
    pipe = DetectionPipeline(load_config(json.load(open(services_json))))
    pipe.load_checkpoint(CKPT_PATH)            # best-effort; cold start if absent
    ...
    hdr, recs = reader.read_latest()
    for msg in pipe.process_snapshot(hdr, recs):
        enqueue(msg)
    ...periodically and on shutdown:
    pipe.save_checkpoint(CKPT_PATH)
"""

import logging
import os
import pickle
import tempfile

from . import config as C
from .detector import Detector
from .temporal import TemporalState
from .output import build_wire_message

logger = logging.getLogger("detection.pipeline")

_CKPT_VERSION = 2  # v2: tier0_history_bits + score-then-update pipeline


class DetectionPipeline:
    def __init__(self, config: C.DetectionConfig):
        self.config = config
        self.detector = Detector(config)
        self._temporal = {}          # (ip, port, kind) -> TemporalState
        self._seq = 0

    def process_snapshot(self, header: dict, records) -> list:
        """Advance every active slot in a published bank and return the
        WireMessages. The record index IS the slot_id (the producer writes
        record[i] for slot i and zeroes inactive slots → proto_kind == 0)."""
        ts_ns = int(header.get("produced_ts_ns", 0))
        out = []
        for slot_id in range(len(records)):
            rec = records[slot_id]
            kind = int(rec["proto_kind"])
            if kind == 0:
                continue  # inactive slot
            ip = int(rec["target_ip"])
            port = int(rec["port"])
            key = (ip, port, kind)

            self.detector.process_record(rec)
            st = self.detector._slots[key]

            temporal = self._temporal.get(key)
            if temporal is None:
                temporal = TemporalState()
                self._temporal[key] = temporal
            est_flows = float(rec["est_unique_flows"])
            flows = int(est_flows) if est_flows > 0.0 else 0
            temporal.push(int(rec["inbound_pkts"]), int(rec["inbound_bytes"]),
                          flows, st.phase)

            self._seq += 1
            out.append(build_wire_message(rec, st, temporal,
                                          ts_ns=ts_ns, slot_id=slot_id,
                                          sequence_num=self._seq))
        return out

    # -- checkpointing ----------------------------------------------------

    def save_checkpoint(self, path: str) -> bool:
        """Atomically persist detector + temporal state. Best-effort: logs and
        returns False on failure (telemetry, not transactional)."""
        blob = {
            "version": _CKPT_VERSION,
            "seq": self._seq,
            "slots": self.detector._slots,
            "temporal": self._temporal,
        }
        try:
            d = os.path.dirname(path) or "."
            os.makedirs(d, exist_ok=True)
            fd, tmp = tempfile.mkstemp(dir=d, prefix=".ckpt-")
            try:
                with os.fdopen(fd, "wb") as f:
                    pickle.dump(blob, f, protocol=pickle.HIGHEST_PROTOCOL)
                os.replace(tmp, path)        # atomic
            finally:
                if os.path.exists(tmp):
                    os.unlink(tmp)
            return True
        except Exception:                    # noqa: BLE001 — never crash on ckpt
            logger.exception("checkpoint save failed (%s)", path)
            return False

    def load_checkpoint(self, path: str) -> bool:
        """Restore state from a checkpoint. Returns True on success; on any
        problem (missing/corrupt/version-mismatch) logs and cold-starts — a
        slightly stale baseline self-heals via EWMA, which beats a full warmup.

        Long-term state (EWMAs, burst windows, phase, freezes, warmup
        remaining) survives the restart — that's the whole point. But
        short-term transient state (5-bit rolling history, CUSUM
        accumulators) describes "the last few seconds before this exact
        tick" — its meaning evaporates across a restart gap. Reset it
        on load so a slot that was mid-attack at save-time doesn't
        instant-fire on the first post-restore tick from stale bits."""
        if not os.path.exists(path):
            return False
        try:
            with open(path, "rb") as f:
                blob = pickle.load(f)
            if blob.get("version") != _CKPT_VERSION:
                logger.warning("checkpoint version %r != %d; cold start",
                               blob.get("version"), _CKPT_VERSION)
                return False
            self.detector._slots = blob["slots"]
            self._temporal = blob["temporal"]
            self._seq = int(blob.get("seq", 0))

            # Drain transient state on every restored slot. attack_freeze_active
            # and warmup_remaining are intentionally preserved — those describe
            # the slot's long-term posture, not a "last 5 seconds" memory.
            for st in self.detector._slots.values():
                st.tier0_history_bits = 0
                st.consecutive_attack_windows = 0
                st.cusum_pps.S_plus = 0.0
                st.cusum_bps.S_plus = 0.0
                st.cusum_fps.S_plus = 0.0

            logger.info("checkpoint restored: %d slots, %d temporal, seq=%d "
                        "(transient state drained)",
                        len(self.detector._slots), len(self._temporal), self._seq)
            return True
        except Exception:                    # noqa: BLE001
            logger.exception("checkpoint load failed (%s); cold start", path)
            return False
