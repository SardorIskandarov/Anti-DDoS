#!/usr/bin/env python3
"""
test_collector_shm.py — P4 cutover integration test.

Validates the collector's shm-detector reader path end to end WITHOUT
ClickHouse: a C harness publishes a known bank to the real /dev/shm, then the
collector's own _shm_read_once() reads it through the DetectionPipeline and
enqueues WireMessages onto the collector's message_queue — exactly as the
running collector would. We then confirm those messages convert to ClickHouse
rows via the (unchanged) writer-side row builder.

Run:  python3 tests/python/test_collector_shm.py
"""

import os
import queue
import subprocess
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(ROOT, "ddos_monitor"))

ENGINE = os.path.join(ROOT, "engine")

import config                                       # noqa: E402
import collector                                    # noqa: E402
from detection.config import DetectionConfig        # noqa: E402
from detection.pipeline import DetectionPipeline    # noqa: E402
from detection.snapshot import SnapshotReader, SHM_PATH  # noqa: E402


def _publish_bank():
    pbin = os.path.join(tempfile.gettempdir(), "shadow_pub_c")
    subprocess.run(
        ["gcc", "-D_GNU_SOURCE", "-I", ENGINE, "-std=c11", "-O2",
         os.path.join(ROOT, "tests", "c", "shadow_publish_harness.c"),
         os.path.join(ENGINE, "l2fwd_service_snapshot.c"),
         os.path.join(ENGINE, "l2fwd_service_features.c"),
         "-lm", "-lrt", "-o", pbin],
        check=True, cwd=ROOT)
    subprocess.run([pbin], check=True, capture_output=True, text=True)


def _drain():
    out = []
    while True:
        try:
            out.append(collector.message_queue.get_nowait())
        except queue.Empty:
            return out


def main():
    _publish_bank()
    try:
        # Empty config -> every slot uses the default profile (fine for plumbing).
        pipe = DetectionPipeline(DetectionConfig(False, by_key={}, profiles={}))
        reader = SnapshotReader(SHM_PATH)
        reader.open()

        n = collector._shm_read_once(pipe, reader)
        assert n == 2, f"expected 2 enqueued messages, got {n}"
        msgs = _drain()
        assert len(msgs) == 2
        by_id = {m.slot_id: m for m in msgs}
        assert set(by_id) == {2, 6}, f"slot_ids {sorted(by_id)} != [2, 6]"
        assert by_id[2].target_ip_str == "1.2.3.4" and by_id[2].tcp_pkts == 1200
        assert by_id[6].target_ip_str == "5.6.7.8" and by_id[6].udp_pkts == 500

        # The (unchanged) writer row builder must accept the detector's messages.
        row = collector._to_service_stats_row(by_id[2])
        assert row["slot_id"] == 2 and row["inbound_pkts"] == 1234
        assert set(collector.SERVICE_STATS_COLUMNS) <= set(row)
        # phase-transition + temporal row builders too (writer path coverage).
        trow = collector._to_temporal_rows(by_id[6])
        assert len(trow) == 3 and {r["window_seconds"] for r in trow} == {10, 60, 300}

        # No new publish -> second read enqueues nothing.
        assert collector._shm_read_once(pipe, reader) == 0
        reader.close()
        print("  [PASS] collector._shm_read_once: shm -> pipeline -> queue -> "
              "row builders; sparse slot_ids 2,6; idempotent on no-new-data")
        print("RESULT: P4 collector shm-reader integration OK")
        return 0
    finally:
        try:
            os.unlink(SHM_PATH)
        except OSError:
            pass


if __name__ == "__main__":
    raise SystemExit(main())
