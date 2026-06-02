#!/usr/bin/env python3
"""
test_detector_reload.py — Phase 1 of the interactive-dashboard work.

The Python brain hot-reloads its per-profile ProfileParams when the engine's
`registry_epoch` bumps in the snapshot header (which happens after a
successful SIGHUP reload on the C side). This file pins down:

  * ProfileParams is mutable (drop @dataclass(frozen=True)).
  * The first snapshot after startup primes the epoch tracker without
    triggering a spurious reload.
  * A genuine epoch bump rereads services.json, swaps the config, and
    re-binds every existing slot's params to the new profile values.
  * Tricky cases are handled: toggling fix_fps_source / fix_frag_zscore
    clears the now-stale EWMA so it re-seeds; warmup_remaining is NOT
    reset on a profile-level warmup_windows change.
  * A malformed services.json keeps the previous config (defensive).
"""

import json
import os
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(ROOT, "ddos_monitor"))

from detection import config as C                # noqa: E402
from detection.pipeline import DetectionPipeline  # noqa: E402
from detection.snapshot import RECORD_DTYPE       # noqa: E402

import numpy as np                                # noqa: E402


# Identity used throughout this file.
IP, PORT, KIND = 0x01020304, 443, C.PROTO_TCP
KEY = (IP, PORT, KIND)


def _profile_json(name, **kw):
    """Build a profiles dict for one named profile with overrides."""
    p = {
        "tier0": {
            "alpha": 0.05,
            "variance_ceiling_factor": 6.0,
            "absolute_pps_threshold": 0.0,
            "absolute_bps_threshold": 0.0,
            "absolute_fps_threshold": 0.0,
        },
        "tier1": {
            "baseline_freeze_windows": 8,
            "thaw_cooldown_windows": 6,
            "warmup_windows": 3,
        },
        "detection_fixes": {
            "fps_source": False,
            "frag_zscore": False,
        },
    }
    # Apply overrides at any depth via dotted path.
    for k, v in kw.items():
        if "." in k:
            sec, key = k.split(".", 1)
            p[sec][key] = v
        else:
            p[k] = v
    return {name: p}


def _services_json(profile_overrides=None, learning_mode=False):
    """Build a services.json content with one profile and one service."""
    return {
        "learning_mode": learning_mode,
        "profiles": _profile_json("p", **(profile_overrides or {})),
        "services": [
            {"target_ip": "1.2.3.4", "port": 443, "proto": "TCP",
             "profile": "p"},
        ],
    }


def _write_services_json(content):
    fd, path = tempfile.mkstemp(suffix=".json", prefix="svc-")
    os.close(fd)
    with open(path, "w") as f:
        json.dump(content, f)
    return path


def _make_record(ip=IP, port=PORT, kind=KIND, inbound_pkts=50):
    """One snapshot record."""
    recs = np.zeros(8, dtype=RECORD_DTYPE)
    recs[0]["target_ip"] = ip
    recs[0]["port"] = port
    recs[0]["proto_kind"] = kind
    recs[0]["inbound_pkts"] = inbound_pkts
    recs[0]["inbound_bytes"] = inbound_pkts * 64
    recs[0]["tcp_pkts"] = inbound_pkts
    return recs


def _header(epoch):
    return {"produced_ts_ns": 1 * 10**9,
            "registry_epoch": epoch,
            "n_active": 1, "capacity": 8}


def _build_pipeline(services_json_path):
    """Build a pipeline that reads its config from services.json on disk."""
    with open(services_json_path) as f:
        sj = json.load(f)
    cfg = C.load_config(sj)
    return DetectionPipeline(cfg, services_json_path=services_json_path)


# ----------------------------------------------------------------------------
# Tests
# ----------------------------------------------------------------------------

def test_profile_params_is_mutable():
    """The dataclass(frozen=True) was dropped — instances can be reassigned
    in place. This is what lets _apply_reload re-bind st.params without
    constructing new SlotState objects."""
    p = C.ProfileParams.from_json("p", {})
    # Mutation should now succeed (was an error under frozen=True).
    p.alpha = 0.5
    assert p.alpha == 0.5
    p.absolute_pps_threshold = 1000.0
    assert p.absolute_pps_threshold == 1000.0
    print("  [PASS] ProfileParams is mutable")


def test_first_snapshot_primes_epoch_no_reload():
    """The very first snapshot after startup must NOT trigger a reload —
    we have no prior epoch to compare to. Just record it and move on."""
    path = _write_services_json(_services_json({"tier0.alpha": 0.05}))
    try:
        pipe = _build_pipeline(path)
        # Mutate the JSON on disk so a reload WOULD be visible if it happened.
        with open(path, "w") as f:
            json.dump(_services_json({"tier0.alpha": 0.5}), f)
        # First snapshot with epoch = 7 (any non-zero starting value).
        pipe.process_snapshot(_header(7), _make_record())
        # The slot was just created — its alpha should still be the
        # original 0.05, because we never reloaded.
        st = pipe.detector._slots[KEY]
        assert abs(st.params.alpha - 0.05) < 1e-9, (
            f"first snapshot should NOT have reloaded; got alpha={st.params.alpha}")
        assert pipe._last_registry_epoch == 7
        print("  [PASS] first snapshot primes epoch without reload")
    finally:
        os.unlink(path)


def test_epoch_bump_triggers_reload_and_rebinds_params():
    """When the engine bumps registry_epoch, the pipeline must re-read
    services.json AND re-bind st.params on every existing slot."""
    path = _write_services_json(_services_json({"tier0.alpha": 0.05}))
    try:
        pipe = _build_pipeline(path)
        # Tick 1: prime epoch = 1, slot created with alpha=0.05.
        pipe.process_snapshot(_header(1), _make_record())
        st = pipe.detector._slots[KEY]
        assert abs(st.params.alpha - 0.05) < 1e-9

        # Operator edits services.json to bump alpha.
        with open(path, "w") as f:
            json.dump(_services_json({"tier0.alpha": 0.42}), f)

        # Engine reloads, publishes a snapshot with epoch = 2.
        pipe.process_snapshot(_header(2), _make_record())
        # Existing slot must now see the new alpha.
        st = pipe.detector._slots[KEY]
        assert abs(st.params.alpha - 0.42) < 1e-9, (
            f"existing slot's params not rebound; got alpha={st.params.alpha}")
        print(f"  [PASS] epoch bump rebinds slot params (alpha 0.05 → {st.params.alpha})")
    finally:
        os.unlink(path)


def test_reload_failure_keeps_old_config():
    """If services.json is corrupt at reload time, keep the previous config —
    operator confusion is preferable to detection going dark."""
    path = _write_services_json(_services_json({"tier0.alpha": 0.05}))
    try:
        pipe = _build_pipeline(path)
        pipe.process_snapshot(_header(1), _make_record())
        st = pipe.detector._slots[KEY]
        original_alpha = st.params.alpha

        # Corrupt the file.
        with open(path, "w") as f:
            f.write("{ this is not valid json")

        # Epoch bumps — reload is attempted, fails, but engine stays up.
        pipe.process_snapshot(_header(2), _make_record())
        st = pipe.detector._slots[KEY]
        assert abs(st.params.alpha - original_alpha) < 1e-9, (
            f"corrupt JSON should preserve old config; got alpha={st.params.alpha}")
        print(f"  [PASS] corrupt services.json keeps old config "
              f"(alpha still {st.params.alpha})")
    finally:
        os.unlink(path)


def test_fix_fps_source_toggle_clears_ewma_fps():
    """Toggling fix_fps_source flips the source the fps EWMA learns from
    (proto-specific vs common). The previously-learned mean/variance is
    meaningless under the new source — clear it so the slot re-seeds
    from the very next tick instead of dragging the stale baseline."""
    # Build a record where the two sources give visibly different fps values.
    # fps_proto (= est_tcp_new_flows for TCP) and fps_obs (= est_unique_flows)
    # are read separately, so we can set them to distinct numbers.
    def _rec_with_distinct_fps(proto_flows, common_flows):
        recs = np.zeros(8, dtype=RECORD_DTYPE)
        recs[0]["target_ip"] = IP
        recs[0]["port"] = PORT
        recs[0]["proto_kind"] = KIND
        recs[0]["inbound_pkts"] = 100
        recs[0]["inbound_bytes"] = 6400
        recs[0]["tcp_pkts"] = 100
        recs[0]["est_tcp_new_flows"] = float(proto_flows)
        recs[0]["est_unique_flows"] = float(common_flows)
        return recs

    path = _write_services_json(_services_json(
        {"detection_fixes.fps_source": False,
         "tier1.warmup_windows": 1}))   # short warmup so we exit it fast
    try:
        pipe = _build_pipeline(path)
        # Drive 5 ticks at proto=80, common=200. With the fix OFF, the EWMA
        # learns the PROTO source → ewma_fps.mean trends to 80.
        for _ in range(5):
            pipe.process_snapshot(_header(1), _rec_with_distinct_fps(80, 200))
        st = pipe.detector._slots[KEY]
        assert st.ewma_fps.initialized
        pre_reload_mean = st.ewma_fps.mean
        assert 70 < pre_reload_mean < 90, (
            f"pre-reload mean should track proto=80; got {pre_reload_mean}")

        # Toggle the fix flag on. Now the EWMA should learn from common (=200).
        with open(path, "w") as f:
            json.dump(_services_json(
                {"detection_fixes.fps_source": True,
                 "tier1.warmup_windows": 1}), f)

        # Epoch bump → reload → ewma_fps cleared → re-seeds from this tick's
        # NEW source (common=200), not from the stale proto-trained 80.
        pipe.process_snapshot(_header(2), _rec_with_distinct_fps(80, 200))
        st = pipe.detector._slots[KEY]
        post_reload_mean = st.ewma_fps.mean
        assert abs(post_reload_mean - 200.0) < 1.0, (
            f"post-reload mean should re-seed at common=200, not stick at "
            f"pre_reload={pre_reload_mean}; got {post_reload_mean}")
        assert st.params.fix_fps_source is True
        print(f"  [PASS] fix_fps_source toggle re-seeds ewma_fps "
              f"({pre_reload_mean:.1f} → {post_reload_mean:.1f}, "
              f"now tracking common source)")
    finally:
        os.unlink(path)


def test_warmup_in_progress_not_reset_on_warmup_windows_change():
    """A slot with warmup_remaining=2 must KEEP its in-progress warmup state
    even if the operator changes warmup_windows. Surprise auto-promote (or
    surprise re-warmup) would be confusing — the change only affects NEW
    slots created after the reload."""
    path = _write_services_json(_services_json({"tier1.warmup_windows": 10}))
    try:
        pipe = _build_pipeline(path)
        # Drive 3 ticks; warmup_remaining was 10, now 7.
        for _ in range(3):
            pipe.process_snapshot(_header(1), _make_record())
        st = pipe.detector._slots[KEY]
        assert st.warmup_remaining == 7, (
            f"expected warmup_remaining=7 after 3 ticks; got {st.warmup_remaining}")

        # Operator shortens warmup_windows to 2.
        with open(path, "w") as f:
            json.dump(_services_json({"tier1.warmup_windows": 2}), f)

        # Reload — existing slot's warmup_remaining must NOT jump.
        pipe.process_snapshot(_header(2), _make_record())
        st = pipe.detector._slots[KEY]
        assert st.warmup_remaining == 6, (
            f"warmup_remaining should keep counting down (7-1=6); "
            f"got {st.warmup_remaining}")
        # But the slot's params now reflect the new warmup_windows.
        assert st.params.warmup_windows == 2
        print(f"  [PASS] warmup_remaining preserved across profile change "
              f"(remaining={st.warmup_remaining}, new windows=2)")
    finally:
        os.unlink(path)


def test_learning_mode_toggle_via_reload():
    """Toggling top-level learning_mode in services.json must take effect
    after reload — the detector reads self.config.learning_mode every tick."""
    path = _write_services_json(_services_json(learning_mode=False))
    try:
        pipe = _build_pipeline(path)
        pipe.process_snapshot(_header(1), _make_record())
        assert pipe.config.learning_mode is False

        with open(path, "w") as f:
            json.dump(_services_json(learning_mode=True), f)

        pipe.process_snapshot(_header(2), _make_record())
        assert pipe.config.learning_mode is True
        assert pipe.detector.config.learning_mode is True
        print("  [PASS] learning_mode toggle via reload")
    finally:
        os.unlink(path)


def test_submit_command_runs_at_tick_boundary():
    """The control-socket scaffolding queues commands that run between ticks.
    Verify the basic shape: submit a callable that mutates pipeline state,
    confirm it ran on the next process_snapshot."""
    path = _write_services_json(_services_json())
    try:
        pipe = _build_pipeline(path)
        pipe.process_snapshot(_header(1), _make_record())

        # Submit a no-op that returns a recognizable value.
        sentinel = {"ran": False}
        def cmd(p):
            sentinel["ran"] = True
            return p._seq

        fut = pipe.submit_command(cmd)
        # Not run yet — queued, awaiting next snapshot.
        assert not fut.done(), "command should be queued, not run"

        pipe.process_snapshot(_header(2), _make_record())
        assert fut.done()
        assert sentinel["ran"] is True
        assert fut.result() >= 1
        print(f"  [PASS] submit_command runs at next tick boundary "
              f"(seq returned: {fut.result()})")
    finally:
        os.unlink(path)


def main():
    test_profile_params_is_mutable()
    test_first_snapshot_primes_epoch_no_reload()
    test_epoch_bump_triggers_reload_and_rebinds_params()
    test_reload_failure_keeps_old_config()
    test_fix_fps_source_toggle_clears_ewma_fps()
    test_warmup_in_progress_not_reset_on_warmup_windows_change()
    test_learning_mode_toggle_via_reload()
    test_submit_command_runs_at_tick_boundary()
    print("RESULT: Phase 1 reload mechanism OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
