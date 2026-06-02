#!/usr/bin/env python3
"""
test_detector_pipeline.py — integration test for the detection pipeline:
snapshot bank -> WireMessages, plus checkpoint round-trip.

Verifies:
  * process_snapshot skips inactive slots (proto_kind == 0), uses the record
    index as slot_id, and emits a well-formed WireMessage the collector's
    row-writers accept (we actually call _to_service_stats_row on it);
  * a checkpoint save -> fresh-pipeline load resumes IDENTICALLY to a pipeline
    that never restarted (baselines preserved), proving warmup is not reset.

Run:  python3 tests/python/test_detector_pipeline.py
"""

import os
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(ROOT, "ddos_monitor"))

import numpy as np                                  # noqa: E402
from detection import config as C                   # noqa: E402
from detection.pipeline import DetectionPipeline    # noqa: E402
from detection.snapshot import RECORD_DTYPE         # noqa: E402
import collector                                    # noqa: E402  (row-writer)

KEY = (0x01020304, 443, C.PROTO_TCP)
PARAMS = C.ProfileParams(
    name="t", alpha=0.05, variance_ceiling=3.0, baseline_freeze_windows=8,
    thaw_cooldown_windows=6, warmup_windows=3,
    absolute_pps_threshold=500.0, absolute_bps_threshold=0.0,
    absolute_fps_threshold=0.0)


def make_bank(active_specs):
    """Build a capacity-sized record array; active_specs = {slot_id: {field:val}}."""
    recs = np.zeros(8, dtype=RECORD_DTYPE)
    for sid, fields in active_specs.items():
        for f, v in fields.items():
            recs[sid][f] = v
    header = {"produced_ts_ns": 123 * 10**9, "registry_epoch": 1,
              "n_active": len(active_specs), "capacity": 8}
    return header, recs


def tcp_window(pps, syn):
    return {"target_ip": 0x01020304, "port": 443, "proto_kind": C.PROTO_TCP,
            "inbound_pkts": pps, "inbound_bytes": pps * 64, "tcp_pkts": pps,
            "syn_pkts": syn, "est_unique_flows": pps, "est_tcp_new_flows": pps,
            "est_unique_src_ips": 80}


def cfg():
    return C.DetectionConfig(learning_mode=False, by_key={KEY: PARAMS}, profiles={})


def test_process_and_writer():
    pipe = DetectionPipeline(cfg())
    # Active slot at index 5 (sparse) — slot_id must be 5, not 0.
    hdr, recs = make_bank({5: tcp_window(100, 5)})
    msgs = pipe.process_snapshot(hdr, recs)
    assert len(msgs) == 1, f"expected 1 active msg, got {len(msgs)}"
    m = msgs[0]
    assert m.slot_id == 5, f"slot_id should equal record index, got {m.slot_id}"
    assert m.target_ip_str == "1.2.3.4" and m.port == 443
    # The collector's row-writer must accept it unchanged.
    row = collector._to_service_stats_row(m)
    assert row["slot_id"] == 5 and row["inbound_pkts"] == 100
    assert set(collector.SERVICE_STATS_COLUMNS) <= set(row.keys()), \
        "WireMessage is missing columns the writer needs"
    print("  [PASS] process_snapshot + collector row-writer accept the message")


def test_checkpoint_roundtrip():
    # Run pipeline A through warmup + baseline + an attack window.
    seq = ([tcp_window(100, 5)] * 3            # warmup
           + [tcp_window(100 + i % 5, 5) for i in range(20)]   # baseline
           + [tcp_window(1000, 950)])          # floor -> ATTACK
    pipeA = DetectionPipeline(cfg())
    for i, w in enumerate(seq):
        hdr, recs = make_bank({0: w})
        pipeA.process_snapshot(hdr, recs)

    # Checkpoint after window N, then split: A continues; B loads ckpt + continues.
    with tempfile.NamedTemporaryFile(suffix=".ckpt", delete=False) as tf:
        ckpt = tf.name
    try:
        assert pipeA.save_checkpoint(ckpt)
        pipeB = DetectionPipeline(cfg())
        assert pipeB.load_checkpoint(ckpt), "checkpoint failed to load"

        # load_checkpoint drains transient state (bitmask + CUSUM) on
        # pipeB — that's the Phase 6 hygiene. Drain pipeA's transient
        # state too so both pipelines start the comparison from the
        # same place (otherwise the first post-restore tick would
        # legitimately diverge by exactly the drained state).
        for st in pipeA.detector._slots.values():
            st.tier0_history_bits = 0
            st.consecutive_attack_windows = 0
            st.cusum_pps.S_plus = 0.0
            st.cusum_bps.S_plus = 0.0
            st.cusum_fps.S_plus = 0.0

        # Feed both the SAME further windows; outputs must stay identical.
        more = [tcp_window(100, 5)] * 5 + [tcp_window(1000, 950)] * 2
        for w in more:
            hdr, recs = make_bank({0: w})
            ma = pipeA.process_snapshot(hdr, recs)[0]
            mb = pipeB.process_snapshot(hdr, recs)[0]
            assert ma.phase == mb.phase, f"phase diverged: {ma.phase} vs {mb.phase}"
            assert abs(ma.tier0_score - mb.tier0_score) < 1e-12, "R0 diverged"
            assert abs(ma.tier1_final_score - mb.tier1_final_score) < 1e-12
            assert ma.windows_seen == mb.windows_seen
            assert (ma.win_300s.total_pkts == mb.win_300s.total_pkts), "temporal diverged"
        print("  [PASS] checkpoint round-trip: restarted pipeline resumes identically")
    finally:
        os.unlink(ckpt)


def test_checkpoint_drains_transient_state():
    """Phase 6 fix: a slot that was mid-attack at save-time must NOT
    instant-fire on the first post-restore tick from stale bitmask /
    CUSUM accumulators. Long-term state (baselines, phase, freezes,
    warmup_remaining) survives; transient state drains."""
    pipeA = DetectionPipeline(cfg())
    # Warmup + a clear attack to load up transient state.
    for w in [tcp_window(100, 5)] * 3:        # warmup
        hdr, recs = make_bank({0: w})
        pipeA.process_snapshot(hdr, recs)
    for w in [tcp_window(1000, 950)] * 3:     # sustained flood
        hdr, recs = make_bank({0: w})
        pipeA.process_snapshot(hdr, recs)

    # Confirm pre-save: slot has nonzero transient state.
    stA = pipeA.detector._slots[KEY]
    assert stA.tier0_history_bits != 0, "expected nonzero history pre-save"
    assert stA.cusum_pps.S_plus > 0, "expected nonzero CUSUM pre-save"

    # Save + load.
    with tempfile.NamedTemporaryFile(suffix=".ckpt", delete=False) as tf:
        ckpt = tf.name
    try:
        assert pipeA.save_checkpoint(ckpt)
        pipeB = DetectionPipeline(cfg())
        assert pipeB.load_checkpoint(ckpt)

        stB = pipeB.detector._slots[KEY]

        # Transient state must be drained on pipeB.
        assert stB.tier0_history_bits == 0, (
            f"bitmask not drained on load; got {stB.tier0_history_bits:#07b}")
        assert stB.consecutive_attack_windows == 0
        assert stB.cusum_pps.S_plus == 0.0
        assert stB.cusum_bps.S_plus == 0.0
        assert stB.cusum_fps.S_plus == 0.0

        # Long-term state must be PRESERVED.
        assert stB.ewma_pps.initialized, "baseline mean should survive restore"
        assert stB.phase == stA.phase, "phase should survive restore"
        assert stB.attack_freeze_active == stA.attack_freeze_active

        print(f"  [PASS] checkpoint drains transient state on load "
              f"(baselines + phase preserved, bits + CUSUM cleared)")
    finally:
        os.unlink(ckpt)


def main():
    test_process_and_writer()
    test_checkpoint_roundtrip()
    test_checkpoint_drains_transient_state()
    print("RESULT: pipeline + checkpoint OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
