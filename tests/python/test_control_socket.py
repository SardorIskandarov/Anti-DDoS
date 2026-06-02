#!/usr/bin/env python3
"""
test_control_socket.py — Phase 2 of the interactive-dashboard work.

Verifies the Unix-socket control channel end-to-end:
  * ping / engine_pid run inline on the listener thread (no tick wait)
  * slot_info is queued and runs at the next tick boundary, returning
    a JSON-safe SlotState dump
  * unknown actions return a clean error reply, not a crash
  * invalid JSON gets a structured error
  * the listener cleans up the socket file on stop()
"""

import json
import os
import socket
import sys
import tempfile
import threading
import time

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(ROOT, "ddos_monitor"))

from detection import config as C                # noqa: E402
from detection.pipeline import DetectionPipeline  # noqa: E402
from detection.snapshot import RECORD_DTYPE       # noqa: E402
from control_socket import ControlSocketServer    # noqa: E402

import numpy as np                                # noqa: E402


IP, PORT, KIND = 0x01020304, 443, C.PROTO_TCP
KEY = (IP, PORT, KIND)


def _records(inbound=50):
    recs = np.zeros(8, dtype=RECORD_DTYPE)
    recs[0]["target_ip"] = IP
    recs[0]["port"] = PORT
    recs[0]["proto_kind"] = KIND
    recs[0]["inbound_pkts"] = inbound
    recs[0]["inbound_bytes"] = inbound * 64
    recs[0]["tcp_pkts"] = inbound
    return recs


def _header(epoch=1):
    return {"produced_ts_ns": 1 * 10**9,
            "registry_epoch": epoch,
            "n_active": 1, "capacity": 8}


def _build_pipeline():
    """Pipeline with one slot pre-warmed."""
    p = C.ProfileParams(
        name="t", alpha=0.05, variance_ceiling=6.0,
        baseline_freeze_windows=8, thaw_cooldown_windows=6,
        warmup_windows=2,
        absolute_pps_threshold=0.0, absolute_bps_threshold=0.0,
        absolute_fps_threshold=0.0)
    cfg = C.DetectionConfig(learning_mode=False,
                            by_key={KEY: p}, profiles={})
    pipe = DetectionPipeline(cfg)
    # Prime one slot.
    for _ in range(3):
        pipe.process_snapshot(_header(), _records())
    return pipe


def _send_command(sock_path: str, request: dict, timeout: float = 5.0) -> dict:
    """Connect, send one JSON line, read one reply, close. Returns parsed
    response or raises on protocol error."""
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as s:
        s.settimeout(timeout)
        s.connect(sock_path)
        s.sendall((json.dumps(request) + "\n").encode("utf-8"))
        buf = b""
        while not buf.endswith(b"\n"):
            chunk = s.recv(4096)
            if not chunk:
                break
            buf += chunk
        return json.loads(buf.decode("utf-8").strip())


def _send_with_tick_driver(pipe, sock_path, request, timeout=5.0):
    """For queued actions: drive process_snapshot in a background thread
    so the pipeline's command queue actually drains. In production the
    engine drives ticks at 1 Hz; in unit tests we need to fake it."""
    stop = threading.Event()

    def tick_driver():
        while not stop.is_set():
            try:
                pipe.process_snapshot(_header(), _records())
            except Exception:        # noqa: BLE001
                pass
            time.sleep(0.02)

    driver = threading.Thread(target=tick_driver, daemon=True)
    driver.start()
    try:
        return _send_command(sock_path, request, timeout=timeout)
    finally:
        stop.set()
        driver.join(timeout=1.0)


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


def _make_server():
    pipe = _build_pipeline()
    fd, path = tempfile.mkstemp(suffix=".sock", prefix="ctrl-")
    os.close(fd)
    os.unlink(path)   # bind() will recreate
    server = ControlSocketServer(pipe, path=path)
    server.start()
    return pipe, server, path


def test_ping_returns_collector_pid():
    pipe, server, path = _make_server()
    try:
        resp = _send_command(path, {"action": "ping"})
        assert resp["ok"] is True, resp
        assert resp["result"]["pid"] == os.getpid()
        print(f"  [PASS] ping returns collector pid={resp['result']['pid']}")
    finally:
        server.stop()


def test_engine_pid_returns_int_or_null():
    pipe, server, path = _make_server()
    try:
        resp = _send_command(path, {"action": "engine_pid"})
        assert resp["ok"] is True, resp
        pid = resp["result"]["pid"]
        # Could be None in CI/lab without l2fwd running; can't assert the value
        # but must be int-or-null.
        assert pid is None or isinstance(pid, int)
        print(f"  [PASS] engine_pid returns {pid!r}")
    finally:
        server.stop()


def test_slot_info_returns_full_state():
    pipe, server, path = _make_server()
    try:
        # slot_info is a queued action — drive ticks in a thread so the
        # pipeline's command queue actually drains.
        resp = _send_with_tick_driver(
            pipe, path, {"action": "slot_info", "args": {"slot_id": 0}})
        assert resp["ok"] is True, resp
        s = resp["result"]
        # Sanity-check a few of the fields the dashboard will read.
        assert "phase" in s
        assert "ewma_pps_mean" in s
        assert "tier0_history_bits" in s
        assert "cusum_pps_S_plus" in s
        assert s["params"]["alpha"] == 0.05
        assert s["key"]["ip"] == IP and s["key"]["port"] == PORT
        print(f"  [PASS] slot_info returns full state "
              f"(phase={s['phase']}, alpha={s['params']['alpha']})")
    finally:
        server.stop()


def test_slot_info_by_explicit_triple():
    pipe, server, path = _make_server()
    try:
        resp = _send_with_tick_driver(
            pipe, path, {"action": "slot_info",
                         "args": {"ip": IP, "port": PORT, "kind": KIND}})
        assert resp["ok"] is True, resp
        assert resp["result"]["key"]["ip"] == IP
        print("  [PASS] slot_info by explicit (ip, port, kind) triple")
    finally:
        server.stop()


def test_slot_info_missing_slot_returns_error():
    pipe, server, path = _make_server()
    try:
        resp = _send_with_tick_driver(
            pipe, path, {"action": "slot_info",
                         "args": {"ip": 0x99999999,
                                  "port": 1, "kind": 1}})
        assert resp["ok"] is False
        assert "no slot" in resp["error"].lower()
        print(f"  [PASS] slot_info missing slot -> error: {resp['error']}")
    finally:
        server.stop()


def test_unknown_action_returns_error():
    pipe, server, path = _make_server()
    try:
        resp = _send_command(path, {"action": "definitely_not_a_real_action"})
        assert resp["ok"] is False
        assert "unknown action" in resp["error"]
        print(f"  [PASS] unknown action -> error: {resp['error']}")
    finally:
        server.stop()


def test_invalid_json_returns_error():
    pipe, server, path = _make_server()
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as s:
            s.settimeout(5.0)
            s.connect(path)
            s.sendall(b"{ this is broken \n")
            buf = b""
            while not buf.endswith(b"\n"):
                chunk = s.recv(4096)
                if not chunk:
                    break
                buf += chunk
        resp = json.loads(buf.decode("utf-8").strip())
        assert resp["ok"] is False
        assert "invalid json" in resp["error"].lower()
        print(f"  [PASS] invalid JSON -> error: {resp['error']}")
    finally:
        server.stop()


def test_queued_action_runs_at_tick_boundary():
    """slot_info goes through the command queue, which drains at the top
    of process_snapshot. Verify a request blocks until the next tick is
    driven, then completes."""
    pipe, server, path = _make_server()
    try:
        result_holder = {}

        def call():
            try:
                resp = _send_command(
                    path, {"action": "slot_info", "args": {"slot_id": 0}},
                    timeout=3.0)
                result_holder["resp"] = resp
            except Exception as e:        # noqa: BLE001
                result_holder["err"] = repr(e)

        t = threading.Thread(target=call)
        t.start()
        # Give it a moment to land in the queue.
        time.sleep(0.1)
        # Drive a tick — this drains the queue.
        pipe.process_snapshot(_header(), _records())
        t.join(timeout=3.0)
        assert "resp" in result_holder, (
            f"queued action never completed: {result_holder}")
        assert result_holder["resp"]["ok"] is True
        print("  [PASS] queued action drains at next process_snapshot")
    finally:
        server.stop()


def test_socket_file_cleaned_up_on_stop():
    pipe, server, path = _make_server()
    assert os.path.exists(path)
    server.stop()
    assert not os.path.exists(path), "socket file should be unlinked on stop"
    print(f"  [PASS] socket file cleaned up on stop ({path})")


def main():
    test_ping_returns_collector_pid()
    test_engine_pid_returns_int_or_null()
    test_slot_info_returns_full_state()
    test_slot_info_by_explicit_triple()
    test_slot_info_missing_slot_returns_error()
    test_unknown_action_returns_error()
    test_invalid_json_returns_error()
    test_queued_action_runs_at_tick_boundary()
    test_socket_file_cleaned_up_on_stop()
    print("RESULT: Phase 2 control socket OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
