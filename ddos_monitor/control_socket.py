"""
control_socket.py — Unix-socket control channel for the running collector.

The dashboard (web.py) connects to this socket to send small JSON commands
that mutate or inspect the live DetectionPipeline state. The socket is the
ONLY way a separate process can influence the running detector — every
mutation is serialised through the pipeline's command queue, so commands
run between snapshots, never mid-tick.

Protocol
========
Newline-delimited JSON. One request per connection, one response, close.

Request:
    {"action": "<name>", "args": {...}}

Response (success):
    {"ok": true, "result": ...}

Response (error):
    {"ok": false, "error": "<message>"}

Actions (Phase 2 — minimal scaffolding):
    ping        → {ok: true, result: {"pid": <collector pid>}}
    engine_pid  → {ok: true, result: {"pid": <l2fwd pid>|null}}
    slot_info   → args {"slot_id": int} OR {"ip","port","kind"}
                  returns full SlotState as a JSON-serialisable dict

Later phases add: request_reload, force_ewma_freeze, force_attack_freeze,
release_freezes, reset_transient, set_learning_mode, save_checkpoint,
load_checkpoint.

Concurrency
===========
Listener runs in its own daemon thread. Each accepted connection is handled
synchronously on the listener thread (one client at a time; lab-scale is
fine — Apache-style worker pools would be overkill). Commands that mutate
pipeline state are submitted via `pipe.submit_command(...)` and the listener
waits on the returned Future — the reader thread runs them at the next
tick boundary. Read-only inspections (`ping`, `engine_pid`) skip the queue
entirely.

Socket lifecycle
================
- Created at the path passed to `start()` (default /tmp/anti-ddos-control.sock)
- chmod 0660 — readable by group members (the dashboard runs as the same
  user or in the same group in lab)
- Removed on `stop()` and on process exit
- If the socket file already exists at start (previous run crashed), it
  is unlinked and recreated
"""

import json
import logging
import os
import socket
import subprocess
import threading
from typing import Optional

logger = logging.getLogger("control_socket")

DEFAULT_SOCKET_PATH = "/tmp/anti-ddos-control.sock"


def _slot_state_to_dict(st) -> dict:
    """Serialise a SlotState to JSON-friendly primitives. Keep this list
    explicit so we never leak un-serialisable objects (EWMA states have
    __slots__ but no default repr)."""
    return {
        "phase": int(st.phase),
        "prev_phase": int(st.prev_phase),
        "warmup_remaining": int(st.warmup_remaining),
        "warmup_windows_completed": int(st.warmup_windows_completed),
        "tier0_history_bits": int(st.tier0_history_bits),
        "consecutive_attack_windows": int(st.consecutive_attack_windows),
        "ewma_freeze_remaining": int(st.ewma_freeze_remaining),
        "consecutive_normal_windows": int(st.consecutive_normal_windows),
        "attack_freeze_active": bool(st.attack_freeze_active),
        "windows_seen": int(st.windows_seen),
        "last_tier0_score": float(st.last_tier0_score),
        "t1_final": float(st.t1_final),
        "t1_tcp": float(st.t1_tcp),
        "t1_udp": float(st.t1_udp),
        "t1_icmp": float(st.t1_icmp),
        "t1_dist": float(st.t1_dist),
        "t1_l3": float(st.t1_l3),
        "t1_offproto": float(st.t1_offproto),
        "r_pps": float(st.r_pps),
        "r_bps": float(st.r_bps),
        "r_fps": float(st.r_fps),
        "r_burst_pps": float(st.r_burst_pps),
        "r_burst_bps": float(st.r_burst_bps),
        "r_burst_fps": float(st.r_burst_fps),
        "last_attack_evidence": float(st.last_attack_evidence),
        "dominant_channel": int(st.dominant_channel),
        "last_absolute_floor_fired": bool(st.last_absolute_floor_fired),
        "baseline_freeze_remaining": int(st.baseline_freeze_remaining),
        "thaw_cooldown_remaining": int(st.thaw_cooldown_remaining),
        "cusum_pps_S_plus": float(st.cusum_pps.S_plus),
        "cusum_bps_S_plus": float(st.cusum_bps.S_plus),
        "cusum_fps_S_plus": float(st.cusum_fps.S_plus),
        "ewma_pps_mean": float(st.ewma_pps.mean),
        "ewma_pps_variance": float(st.ewma_pps.variance),
        "params": {
            "name": st.params.name,
            "alpha": st.params.alpha,
            "variance_ceiling": st.params.variance_ceiling,
            "baseline_freeze_windows": st.params.baseline_freeze_windows,
            "thaw_cooldown_windows": st.params.thaw_cooldown_windows,
            "warmup_windows": st.params.warmup_windows,
            "absolute_pps_threshold": st.params.absolute_pps_threshold,
            "absolute_bps_threshold": st.params.absolute_bps_threshold,
            "absolute_fps_threshold": st.params.absolute_fps_threshold,
            "fix_fps_source": st.params.fix_fps_source,
            "fix_frag_zscore": st.params.fix_frag_zscore,
        },
    }


def _find_engine_pid() -> Optional[int]:
    """Best-effort: look for the l2fwd process. Returns None if not found."""
    try:
        out = subprocess.check_output(
            ["pgrep", "-f", "l2fwd"], text=True, stderr=subprocess.DEVNULL
        ).strip()
    except (subprocess.CalledProcessError, FileNotFoundError):
        return None
    for line in out.splitlines():
        line = line.strip()
        if line and line.isdigit():
            return int(line)
    return None


# ---------------------------------------------------------------------------
# Action dispatch
# ---------------------------------------------------------------------------


def _action_ping(pipe, args: dict) -> dict:
    return {"pid": os.getpid()}


def _action_engine_pid(pipe, args: dict) -> dict:
    return {"pid": _find_engine_pid()}


def _action_slot_info(pipe, args: dict) -> dict:
    """Return the full SlotState for a slot. Args accepts either
    {"slot_id": int} (matches the record index used by the dashboard's
    services API) OR {"ip": int, "port": int, "kind": int} for explicit
    triple-keying."""
    # Slot-id form: walk the keys in insertion order and pick the Nth.
    # Slots are added by _state_for the first time a record is seen, so
    # this matches the record-index → key mapping for slots already alive.
    # (For runtime tooling this is fine; later we can add a registry-side
    # mapping if a strict slot_id index is needed.)
    slots = pipe.detector._slots

    if "slot_id" in args:
        slot_id = int(args["slot_id"])
        keys = list(slots.keys())
        if not (0 <= slot_id < len(keys)):
            raise KeyError(f"slot_id {slot_id} out of range "
                           f"(have {len(keys)} slots)")
        key = keys[slot_id]
        st = slots[key]
    elif "ip" in args and "port" in args and "kind" in args:
        key = (int(args["ip"]), int(args["port"]), int(args["kind"]))
        st = slots.get(key)
        if st is None:
            raise KeyError(f"no slot for {key}")
    else:
        raise ValueError("slot_info needs slot_id OR (ip,port,kind)")

    out = _slot_state_to_dict(st)
    out["key"] = {"ip": key[0], "port": key[1], "kind": key[2]}
    return out


# Read-only actions — run inline on the listener thread.
_INLINE_ACTIONS = {
    "ping":        _action_ping,
    "engine_pid":  _action_engine_pid,
}

# Mutating / inspection actions that need the pipeline lock — submitted to
# the command queue and run at the next tick boundary.
_QUEUED_ACTIONS = {
    "slot_info":   _action_slot_info,
}


def _dispatch(pipe, req: dict) -> dict:
    """Look up the action handler and run it. Returns the result dict.
    Raises on unknown action or handler exception."""
    action = req.get("action")
    args = req.get("args") or {}
    if action in _INLINE_ACTIONS:
        return _INLINE_ACTIONS[action](pipe, args)
    if action in _QUEUED_ACTIONS:
        handler = _QUEUED_ACTIONS[action]
        fut = pipe.submit_command(lambda p, h=handler, a=args: h(p, a))
        # Bounded wait: a healthy pipeline drains at the next 1Hz tick.
        # 5s gives generous slack for bursty workloads.
        return fut.result(timeout=5.0)
    raise ValueError(f"unknown action: {action!r}")


# ---------------------------------------------------------------------------
# Listener thread
# ---------------------------------------------------------------------------


def _handle_client(pipe, conn: socket.socket):
    """Read one JSON line, dispatch, write one JSON line, close."""
    try:
        buf = b""
        while not buf.endswith(b"\n"):
            chunk = conn.recv(4096)
            if not chunk:
                return  # client hung up
            buf += chunk
            if len(buf) > 65536:
                resp = {"ok": False, "error": "request too large"}
                conn.sendall((json.dumps(resp) + "\n").encode("utf-8"))
                return
        line = buf.decode("utf-8", errors="replace").strip()
        if not line:
            return
        try:
            req = json.loads(line)
        except json.JSONDecodeError as e:
            resp = {"ok": False, "error": f"invalid JSON: {e}"}
            conn.sendall((json.dumps(resp) + "\n").encode("utf-8"))
            return

        try:
            result = _dispatch(pipe, req)
            resp = {"ok": True, "result": result}
        except Exception as e:    # noqa: BLE001
            logger.exception("control action failed: %r", req)
            resp = {"ok": False, "error": str(e)}

        conn.sendall((json.dumps(resp) + "\n").encode("utf-8"))
    finally:
        try:
            conn.close()
        except OSError:
            pass


class ControlSocketServer:
    """Lifecycle-managed Unix-socket listener. Call start() once; the
    listener runs in a daemon thread until stop() is called or the
    process exits."""

    def __init__(self, pipe, path: str = DEFAULT_SOCKET_PATH):
        self.pipe = pipe
        self.path = path
        self._sock: Optional[socket.socket] = None
        self._thread: Optional[threading.Thread] = None
        self._stop = threading.Event()

    def start(self):
        """Create the socket, bind, listen, spawn listener thread."""
        # Clean up any stale socket from a previous crashed run.
        try:
            os.unlink(self.path)
        except FileNotFoundError:
            pass

        self._sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self._sock.bind(self.path)
        try:
            os.chmod(self.path, 0o660)
        except OSError:
            pass    # best-effort; FS may not support
        self._sock.listen(8)

        self._thread = threading.Thread(
            target=self._run, name="control-socket", daemon=True)
        self._thread.start()
        logger.info("control socket listening on %s", self.path)

    def _run(self):
        assert self._sock is not None
        self._sock.settimeout(0.5)   # so we can poll the stop flag
        while not self._stop.is_set():
            try:
                conn, _addr = self._sock.accept()
            except socket.timeout:
                continue
            except OSError:
                return  # socket closed
            try:
                _handle_client(self.pipe, conn)
            except Exception:    # noqa: BLE001
                logger.exception("control socket client handler crashed")

    def stop(self):
        """Stop the listener and unlink the socket file."""
        self._stop.set()
        if self._sock is not None:
            try:
                self._sock.close()
            except OSError:
                pass
            self._sock = None
        if self._thread is not None:
            self._thread.join(timeout=2.0)
            self._thread = None
        try:
            os.unlink(self.path)
        except FileNotFoundError:
            pass
        logger.info("control socket stopped")
