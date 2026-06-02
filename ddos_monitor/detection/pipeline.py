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

import json
import logging
import os
import pickle
import tempfile

from . import config as C
from . import primitives as M
from .detector import Detector
from .temporal import TemporalState
from .output import build_wire_message

logger = logging.getLogger("detection.pipeline")

_CKPT_VERSION = 2  # v2: tier0_history_bits + score-then-update pipeline


class DetectionPipeline:
    def __init__(self, config: C.DetectionConfig,
                 services_json_path: str = None):
        """services_json_path: optional path used for hot-reload. If set, the
        pipeline watches `registry_epoch` in each snapshot header; when the
        engine bumps it (after a successful SIGHUP reload), the pipeline
        re-loads services.json from this path and re-binds every existing
        slot's profile params. Leave None to disable reload entirely."""
        self.config = config
        self.detector = Detector(config)
        self._temporal = {}          # (ip, port, kind) -> TemporalState
        self._seq = 0
        # Hot-reload bookkeeping.
        self._services_json_path = services_json_path
        self._last_registry_epoch = 0
        # Per-tick command queue: (callable_taking_self, response_future).
        # Drained at the top of process_snapshot before any scoring. Lets the
        # control socket safely mutate state without racing the reader thread.
        import queue as _queue
        self._cmd_queue = _queue.Queue()

    # ------------------------------------------------------------------
    # Hot reload (Phase 1) — driven by the engine's registry_epoch bump
    # ------------------------------------------------------------------

    def _apply_reload(self) -> bool:
        """Re-read services.json and re-bind every existing slot's params.
        Called at the top of process_snapshot, never mid-tick. On any
        parse/validation failure, keeps the previous config and logs."""
        if not self._services_json_path:
            return False
        try:
            with open(self._services_json_path) as f:
                new_cfg = C.load_config(json.load(f))
        except Exception:        # noqa: BLE001
            logger.exception("reload: failed to load %s; keeping old config",
                             self._services_json_path)
            return False

        # Re-bind params on every existing slot. Tricky cases:
        #   - fix_fps_source toggled: ewma_fps was trained on the old source,
        #     baseline is now meaningless — clear it so it re-seeds.
        #   - fix_frag_zscore toggled: same for ewma_frag_ratio.
        #   - warmup_windows changed: only affects NEW slots; existing slots
        #     keep their current warmup_remaining (no surprise auto-promote).
        n_rebound = 0
        for key, st in self.detector._slots.items():
            new_params = new_cfg.params_for(*key)
            if st.params.fix_fps_source != new_params.fix_fps_source:
                st.ewma_fps = M.EwmaState()
            if st.params.fix_frag_zscore != new_params.fix_frag_zscore:
                st.ewma_frag_ratio = M.EwmaState()
            st.params = new_params
            n_rebound += 1
        self.config = new_cfg
        self.detector.config = new_cfg
        logger.info("reload applied: %d slots re-bound, learning_mode=%s",
                    n_rebound, new_cfg.learning_mode)
        return True

    def submit_command(self, fn) -> "concurrent.futures.Future":
        """Queue a callable to be executed at the next tick boundary. The
        callable receives `self` (the pipeline) and may mutate any state.
        Returns a Future whose result is the callable's return value (or
        exception). Used by the control socket (Phase 2)."""
        import concurrent.futures as _f
        fut = _f.Future()
        self._cmd_queue.put((fn, fut))
        return fut

    def _drain_command_queue(self):
        """Run every queued command. Called at the top of process_snapshot."""
        import queue as _queue
        while True:
            try:
                fn, fut = self._cmd_queue.get_nowait()
            except _queue.Empty:
                return
            try:
                fut.set_result(fn(self))
            except Exception as e:    # noqa: BLE001
                fut.set_exception(e)

    def process_snapshot(self, header: dict, records) -> list:
        """Advance every active slot in a published bank and return the
        WireMessages. The record index IS the slot_id (the producer writes
        record[i] for slot i and zeroes inactive slots → proto_kind == 0).

        Drains any queued commands (control socket) and watches
        registry_epoch for hot-reload before processing this batch."""
        # Apply any pending control-socket commands at tick boundary.
        self._drain_command_queue()

        # Watch the engine's registry_epoch. When it bumps (SIGHUP reload
        # succeeded on the C side), re-load our config and re-bind slot
        # params. First snapshot after startup primes _last_registry_epoch
        # without triggering a reload (we already loaded at startup).
        new_epoch = int(header.get("registry_epoch", 0))
        if (self._last_registry_epoch != 0
                and new_epoch != self._last_registry_epoch):
            self._apply_reload()
        self._last_registry_epoch = new_epoch

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
