"""
collector.py — per-service binary collector (P12 complete rewrite).

Consumes the L2FW wire-protocol v1 stream the C engine emits and lands
it in ClickHouse. Replaces the legacy CSV/text collector entirely.

Architecture (threading, NOT asyncio):

    reader thread   socket(server) -> parse -> bounded queue
    writer thread   queue -> batch -> ClickHouse (3 tables)
    stats thread    periodic stats line every COLLECTOR_STATS_INTERVAL_S
    main thread     signal handling + thread lifecycle

Socket role: the C engine's hotpath connects as a CLIENT to
ENGINE_SOCKET_PATH, so this collector is the SERVER — it binds,
listens, and accepts. (The P11/P12 prompt sketch had the collector
calling connect(); that would be backwards for this codebase. The
engine is locked and is the client, so the collector must be the
server. Operational note: start the collector BEFORE the engine — the
engine attempts a single non-blocking connect at startup and does not
retry.)

Backpressure: the queue is bounded. When the writer can't keep up and
the queue fills, the reader drops the OLDEST queued message to make
room for the newest. The reader never blocks on the queue — losing the
socket read cadence would lose engine messages outright, which is
worse than dropping a stale queued one.

Durability: telemetry, not transactional data. On a ClickHouse insert
failure the current batch is dropped (logged), the client is forced to
reconnect, and the collector keeps reading. Losing a few seconds of
stats during a DB outage is acceptable; unbounded re-queue growth is
not.

systemd-friendly: SIGTERM / SIGINT set a shutdown event; threads drain
and exit; main() returns 0 on clean shutdown.
"""

import logging
import os
import queue
import signal
import socket
import sys
import threading
import time

import config
from wire_parser import (
    parse_message,
    WireMessage,
    WireParseError,
)

logger = logging.getLogger("collector")

# ---------------------------------------------------------------------------
# Shared state
# ---------------------------------------------------------------------------

shutdown_event = threading.Event()
message_queue: "queue.Queue[WireMessage]" = queue.Queue(
    maxsize=config.COLLECTOR_QUEUE_MAX_SIZE)

# slot_id -> last observed phase. Used by the writer to detect transitions.
# Only the writer thread touches this, but a lock is kept for clarity and
# in case a future admin endpoint wants to read it.
phase_state_cache = {}
phase_cache_lock = threading.Lock()

stats = {
    "msgs_read": 0,
    "msgs_parsed": 0,
    "msgs_dropped_parse_error": 0,
    "msgs_dropped_queue_full": 0,
    "msgs_inserted": 0,
    "phase_transitions": 0,
    "temporal_rows_inserted": 0,
    "clickhouse_errors": 0,
    "batches_dropped": 0,
    "reconnects": 0,
    "accepts": 0,
}
stats_lock = threading.Lock()

# Rate-limit the "queue full" warning to once per minute.
_last_qfull_warn = 0.0
_qfull_warn_lock = threading.Lock()


def _bump(key, n=1):
    with stats_lock:
        stats[key] += n


# ---------------------------------------------------------------------------
# ClickHouse insert column lists.
#
# DEFAULT-valued columns in the schema (timestamp_dt, *_str, inserted_at)
# are intentionally omitted — ClickHouse fills them. The lists below are
# the exact set of columns the collector supplies, in a fixed order.
# ---------------------------------------------------------------------------

SERVICE_STATS_COLUMNS = (
    "timestamp_ns", "slot_id", "sequence_num",
    "target_ip", "port", "proto_kind", "is_catchall", "profile_name",
    "phase", "prev_phase", "warmup_remaining",
    "consecutive_attack_windows", "baseline_freeze_remaining",
    "thaw_cooldown_remaining", "windows_seen",
    "inbound_pkts", "inbound_bytes", "off_proto_pkts", "ip_frag_pkts",
    "ttl_sum", "ttl_sum_sq", "out_pkts", "out_bytes",
    "out_tcp_pkts", "out_udp_pkts", "out_icmp_pkts",
    "tcp_pkts", "tcp_bytes", "syn_pkts", "syn_ack_pkts", "fin_ack_pkts",
    "rst_pkts", "ack_data_pkts", "empty_ack_pkts", "zero_window_pkts",
    "udp_pkts", "udp_bytes", "icmp_pkts",
    "unique_src_ips", "unique_flows", "src_24_top1_share",
    "src_24_entropy", "ttl_mean", "ttl_stddev",
    "bw_pps_z_last", "bw_bps_z_last",
    "tier0_score", "tier1_tcp_score", "tier1_udp_score",
    "tier1_icmp_score", "tier1_dist_score", "tier1_l3_score",
    "tier1_offproto_score", "tier1_final_score",
    "win_10s_total_pkts", "win_10s_peak_pps", "win_10s_attack_seconds",
    "win_60s_total_pkts", "win_60s_peak_pps", "win_60s_attack_seconds",
    "win_300s_total_pkts", "win_300s_peak_pps", "win_300s_attack_seconds",
)

PHASE_TRANSITION_COLUMNS = (
    "timestamp_ns", "slot_id", "target_ip", "port", "proto_kind",
    "profile_name", "from_phase", "from_phase_str", "to_phase",
    "to_phase_str", "tier0_score", "tier1_final_score",
    "attack_evidence", "consecutive_attack_windows",
)

TEMPORAL_AGGREGATE_COLUMNS = (
    "timestamp_ns", "slot_id", "target_ip", "port", "proto_kind",
    "window_seconds", "total_pkts", "peak_pps", "attack_seconds",
)

_INSERT_SERVICE_STATS = (
    f"INSERT INTO {config.CH_DB}.{config.TABLE_SERVICE_STATS} "
    f"({', '.join(SERVICE_STATS_COLUMNS)}) VALUES"
)
_INSERT_PHASE_TRANSITIONS = (
    f"INSERT INTO {config.CH_DB}.{config.TABLE_PHASE_TRANSITIONS} "
    f"({', '.join(PHASE_TRANSITION_COLUMNS)}) VALUES"
)
_INSERT_TEMPORAL_AGGREGATES = (
    f"INSERT INTO {config.CH_DB}.{config.TABLE_TEMPORAL_AGGREGATES} "
    f"({', '.join(TEMPORAL_AGGREGATE_COLUMNS)}) VALUES"
)


# ---------------------------------------------------------------------------
# Row-conversion helpers — WireMessage -> ClickHouse row dict
# ---------------------------------------------------------------------------


def _to_service_stats_row(m: WireMessage) -> dict:
    """Map a WireMessage to a service_stats row (dict keyed by column)."""
    return {
        "timestamp_ns": m.timestamp_ns,
        "slot_id": m.slot_id,
        "sequence_num": m.sequence_num,
        "target_ip": m.target_ip,
        "port": m.port,
        "proto_kind": m.proto_kind,
        "is_catchall": 1 if m.is_catchall else 0,
        "profile_name": m.profile_name,
        "phase": m.phase,
        "prev_phase": m.prev_phase,
        "warmup_remaining": m.warmup_remaining,
        "consecutive_attack_windows": m.consecutive_attack_windows,
        "baseline_freeze_remaining": m.baseline_freeze_remaining,
        "thaw_cooldown_remaining": m.thaw_cooldown_remaining,
        "windows_seen": m.windows_seen,
        "inbound_pkts": m.inbound_pkts,
        "inbound_bytes": m.inbound_bytes,
        "off_proto_pkts": m.off_proto_pkts,
        "ip_frag_pkts": m.ip_frag_pkts,
        "ttl_sum": m.ttl_sum,
        "ttl_sum_sq": m.ttl_sum_sq,
        "out_pkts": m.out_pkts,
        "out_bytes": m.out_bytes,
        "out_tcp_pkts": m.out_tcp_pkts,
        "out_udp_pkts": m.out_udp_pkts,
        "out_icmp_pkts": m.out_icmp_pkts,
        "tcp_pkts": m.tcp_pkts,
        "tcp_bytes": m.tcp_bytes,
        "syn_pkts": m.syn_pkts,
        "syn_ack_pkts": m.syn_ack_pkts,
        "fin_ack_pkts": m.fin_ack_pkts,
        "rst_pkts": m.rst_pkts,
        "ack_data_pkts": m.ack_data_pkts,
        "empty_ack_pkts": m.empty_ack_pkts,
        "zero_window_pkts": m.zero_window_pkts,
        "udp_pkts": m.udp_pkts,
        "udp_bytes": m.udp_bytes,
        "icmp_pkts": m.icmp_pkts,
        "unique_src_ips": m.unique_src_ips,
        "unique_flows": m.unique_flows,
        "src_24_top1_share": m.src_24_top1_share,
        "src_24_entropy": m.src_24_entropy,
        "ttl_mean": m.ttl_mean,
        "ttl_stddev": m.ttl_stddev,
        "bw_pps_z_last": m.bw_pps_z_last,
        "bw_bps_z_last": m.bw_bps_z_last,
        "tier0_score": m.tier0_score,
        "tier1_tcp_score": m.tier1_tcp_score,
        "tier1_udp_score": m.tier1_udp_score,
        "tier1_icmp_score": m.tier1_icmp_score,
        "tier1_dist_score": m.tier1_dist_score,
        "tier1_l3_score": m.tier1_l3_score,
        "tier1_offproto_score": m.tier1_offproto_score,
        "tier1_final_score": m.tier1_final_score,
        "win_10s_total_pkts": m.win_10s.total_pkts,
        "win_10s_peak_pps": m.win_10s.peak_pps,
        "win_10s_attack_seconds": m.win_10s.attack_seconds,
        "win_60s_total_pkts": m.win_60s.total_pkts,
        "win_60s_peak_pps": m.win_60s.peak_pps,
        "win_60s_attack_seconds": m.win_60s.attack_seconds,
        "win_300s_total_pkts": m.win_300s.total_pkts,
        "win_300s_peak_pps": m.win_300s.peak_pps,
        "win_300s_attack_seconds": m.win_300s.attack_seconds,
    }


def _to_phase_transition_row(m: WireMessage, prev_phase: int) -> dict:
    """Build a phase-transition row for a slot whose phase changed.

    attack_evidence mirrors the engine's combination rule
    (max of Tier-0 and the final Tier-1 score)."""
    from wire_parser import phase_name
    return {
        "timestamp_ns": m.timestamp_ns,
        "slot_id": m.slot_id,
        "target_ip": m.target_ip,
        "port": m.port,
        "proto_kind": m.proto_kind,
        "profile_name": m.profile_name,
        "from_phase": prev_phase,
        "from_phase_str": phase_name(prev_phase),
        "to_phase": m.phase,
        "to_phase_str": m.phase_str,
        "tier0_score": m.tier0_score,
        "tier1_final_score": m.tier1_final_score,
        "attack_evidence": max(m.tier0_score, m.tier1_final_score),
        "consecutive_attack_windows": m.consecutive_attack_windows,
    }


def _to_temporal_rows(m: WireMessage) -> list:
    """Build three temporal-aggregate rows — one per 10s/60s/300s window."""
    rows = []
    for win in (m.win_10s, m.win_60s, m.win_300s):
        rows.append({
            "timestamp_ns": m.timestamp_ns,
            "slot_id": m.slot_id,
            "target_ip": m.target_ip,
            "port": m.port,
            "proto_kind": m.proto_kind,
            "window_seconds": win.window_seconds,
            "total_pkts": win.total_pkts,
            "peak_pps": win.peak_pps,
            "attack_seconds": win.attack_seconds,
        })
    return rows


# ---------------------------------------------------------------------------
# Reader thread — socket server, parse, enqueue
# ---------------------------------------------------------------------------


def _enqueue_drop_oldest(msg: WireMessage):
    """Put msg on the queue; if full, drop the oldest to make room."""
    try:
        message_queue.put_nowait(msg)
        return
    except queue.Full:
        pass

    # Drop-oldest: pop one, then retry the put.
    try:
        message_queue.get_nowait()
    except queue.Empty:
        pass
    try:
        message_queue.put_nowait(msg)
    except queue.Full:
        # Writer is keeping the queue saturated; this newest message is
        # also lost. Counted the same way.
        pass

    _bump("msgs_dropped_queue_full")
    global _last_qfull_warn
    now = time.time()
    with _qfull_warn_lock:
        if now - _last_qfull_warn >= 60.0:
            _last_qfull_warn = now
            with stats_lock:
                dropped = stats["msgs_dropped_queue_full"]
            logger.warning(
                "queue full — dropping oldest messages "
                "(total dropped so far: %d)", dropped)


def _handle_connection(conn: socket.socket):
    """Read 416-byte messages off an accepted connection until it closes."""
    conn.settimeout(1.0)   # so shutdown_event is checked at least every 1s
    buffer = b""
    msg_size = config.WIRE_MSG_SIZE
    while not shutdown_event.is_set():
        try:
            chunk = conn.recv(65536)
        except socket.timeout:
            continue
        except OSError as exc:
            logger.warning("recv error: %s; closing connection", exc)
            return
        if not chunk:
            logger.info("engine closed the connection")
            return

        buffer += chunk
        while len(buffer) >= msg_size:
            msg_bytes = buffer[:msg_size]
            buffer = buffer[msg_size:]
            _bump("msgs_read")
            try:
                msg = parse_message(msg_bytes)
            except WireParseError as exc:
                _bump("msgs_dropped_parse_error")
                with stats_lock:
                    n = stats["msgs_dropped_parse_error"]
                # Log the first error and then 1-in-100 to avoid spam.
                if n == 1 or n % 100 == 0:
                    logger.warning("parse error (#%d): %s", n, exc)
                continue
            _bump("msgs_parsed")
            _enqueue_drop_oldest(msg)


def reader_thread():
    """Bind the engine socket, accept connections, feed the queue.

    Loops forever (until shutdown) so an engine restart is handled
    transparently: when the engine reconnects, accept() returns again.
    """
    sock_path = config.ENGINE_SOCKET_PATH
    while not shutdown_event.is_set():
        server = None
        try:
            # Remove any stale socket file from a previous run / crash.
            if os.path.exists(sock_path):
                try:
                    os.unlink(sock_path)
                except OSError as exc:
                    logger.warning("could not unlink stale socket %s: %s",
                                   sock_path, exc)

            server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            server.bind(sock_path)
            server.listen(1)
            server.settimeout(1.0)   # interruptible accept()
            logger.info("listening on %s (collector is the socket server; "
                        "the engine connects as client)", sock_path)

            while not shutdown_event.is_set():
                try:
                    conn, _ = server.accept()
                except socket.timeout:
                    continue
                except OSError as exc:
                    logger.warning("accept error: %s", exc)
                    break
                _bump("accepts")
                logger.info("engine connected")
                try:
                    _handle_connection(conn)
                finally:
                    try:
                        conn.close()
                    except OSError:
                        pass
                if not shutdown_event.is_set():
                    logger.info("waiting for the engine to reconnect ...")
        except OSError as exc:
            logger.warning("socket setup error: %s; retrying in %.1fs",
                           exc, config.COLLECTOR_RECONNECT_DELAY_S)
            _bump("reconnects")
            shutdown_event.wait(config.COLLECTOR_RECONNECT_DELAY_S)
        except Exception:  # noqa: BLE001 — last-resort guard, keep thread alive
            logger.exception("unexpected reader error; retrying")
            _bump("reconnects")
            shutdown_event.wait(config.COLLECTOR_RECONNECT_DELAY_S)
        finally:
            if server is not None:
                try:
                    server.close()
                except OSError:
                    pass

    # Clean up the socket file on graceful exit.
    if os.path.exists(sock_path):
        try:
            os.unlink(sock_path)
        except OSError:
            pass
    logger.info("reader thread exiting")


# ---------------------------------------------------------------------------
# Writer thread — drain queue, batch, insert into ClickHouse
# ---------------------------------------------------------------------------


def _connect_clickhouse():
    """Open a ClickHouse client. Lazy-imports clickhouse_driver so the
    module still imports (and py_compiles) on hosts without it."""
    from clickhouse_driver import Client
    client = Client(
        host=config.CH_HOST,
        port=config.CH_PORT,
        user=config.CH_USER,
        password=config.CH_PASSWORD,
        database=config.CH_DB,
        settings={"use_numpy": False},
    )
    logger.info("connected to ClickHouse at %s:%s/%s",
                config.CH_HOST, config.CH_PORT, config.CH_DB)
    return client


def _collect_batch():
    """Pull up to COLLECTOR_BATCH_SIZE messages, flushing a partial batch
    after COLLECTOR_BATCH_TIMEOUT_S. Returns a (possibly empty) list."""
    batch = []
    deadline = time.time() + config.COLLECTOR_BATCH_TIMEOUT_S
    while (not shutdown_event.is_set()
           and len(batch) < config.COLLECTOR_BATCH_SIZE):
        timeout = deadline - time.time()
        if timeout <= 0:
            break
        try:
            batch.append(message_queue.get(timeout=timeout))
        except queue.Empty:
            break
    return batch


def _flush_batch(client, batch):
    """Insert one batch into all three tables. Detects phase transitions.

    Returns True on success, False if any insert raised (caller forces a
    reconnect and drops the batch on False)."""
    # --- service_stats ---
    stats_rows = [_to_service_stats_row(m) for m in batch]
    client.execute(_INSERT_SERVICE_STATS, stats_rows)
    _bump("msgs_inserted", len(stats_rows))

    # --- phase transitions (compare against the per-slot cache) ---
    transitions = []
    with phase_cache_lock:
        for m in batch:
            prev = phase_state_cache.get(m.slot_id)
            if prev is not None and prev != m.phase:
                transitions.append((_to_phase_transition_row(m, prev), m))
            phase_state_cache[m.slot_id] = m.phase
    if transitions:
        client.execute(_INSERT_PHASE_TRANSITIONS,
                       [row for row, _ in transitions])
        _bump("phase_transitions", len(transitions))
        for row, m in transitions:
            logger.info(
                "phase transition: slot=%d %s:%d %s -> %s "
                "(t0=%.3f t1=%.3f evidence=%.3f)",
                row["slot_id"], m.target_ip_str, row["port"],
                row["from_phase_str"], row["to_phase_str"],
                row["tier0_score"], row["tier1_final_score"],
                row["attack_evidence"])

    # --- temporal aggregates (3 rows per message) ---
    temporal_rows = []
    for m in batch:
        temporal_rows.extend(_to_temporal_rows(m))
    if temporal_rows:
        client.execute(_INSERT_TEMPORAL_AGGREGATES, temporal_rows)
        _bump("temporal_rows_inserted", len(temporal_rows))

    return True


def writer_thread():
    """Drain the queue, batch, and insert into ClickHouse."""
    client = None
    while not shutdown_event.is_set():
        try:
            if client is None:
                client = _connect_clickhouse()

            batch = _collect_batch()
            if not batch:
                continue

            _flush_batch(client, batch)

        except Exception:  # noqa: BLE001 — telemetry: log, drop, reconnect
            logger.exception(
                "ClickHouse insert failed; dropping this batch and "
                "reconnecting")
            _bump("clickhouse_errors")
            _bump("batches_dropped")
            if client is not None:
                try:
                    client.disconnect()
                except Exception:  # noqa: BLE001
                    pass
            client = None
            shutdown_event.wait(1.0)

    # Drain whatever is left so a clean SIGTERM doesn't silently lose a
    # full queue. Best-effort: one final batch flush if we have a client.
    if client is not None:
        try:
            leftovers = []
            while True:
                try:
                    leftovers.append(message_queue.get_nowait())
                except queue.Empty:
                    break
                if len(leftovers) >= config.COLLECTOR_BATCH_SIZE:
                    _flush_batch(client, leftovers)
                    leftovers = []
            if leftovers:
                _flush_batch(client, leftovers)
        except Exception:  # noqa: BLE001
            logger.warning("final drain insert failed; %d messages lost",
                           message_queue.qsize())
        finally:
            try:
                client.disconnect()
            except Exception:  # noqa: BLE001
                pass

    logger.info("writer thread exiting")


# ---------------------------------------------------------------------------
# Stats thread — periodic one-line summary
# ---------------------------------------------------------------------------


def stats_thread():
    """Emit a periodic stats line. Daemon thread — no graceful drain needed."""
    interval = config.COLLECTOR_STATS_INTERVAL_S
    while not shutdown_event.wait(interval):
        with stats_lock:
            snap = dict(stats)
        logger.info(
            "[stats] read=%d parsed=%d inserted=%d transitions=%d "
            "temporal_rows=%d queue_depth=%d parse_errors=%d "
            "queue_drops=%d clickhouse_errors=%d batches_dropped=%d "
            "accepts=%d reconnects=%d",
            snap["msgs_read"], snap["msgs_parsed"], snap["msgs_inserted"],
            snap["phase_transitions"], snap["temporal_rows_inserted"],
            message_queue.qsize(), snap["msgs_dropped_parse_error"],
            snap["msgs_dropped_queue_full"], snap["clickhouse_errors"],
            snap["batches_dropped"], snap["accepts"], snap["reconnects"])


# ---------------------------------------------------------------------------
# Lifecycle
# ---------------------------------------------------------------------------


def _signal_handler(signum, _frame):
    logger.info("received signal %d; shutting down", signum)
    shutdown_event.set()


def main():
    """Entry point. Returns 0 on clean shutdown (systemd-friendly)."""
    logging.basicConfig(
        level=getattr(logging, config.COLLECTOR_LOG_LEVEL, logging.INFO),
        format="%(asctime)s %(levelname)s [%(threadName)s] %(message)s",
    )
    logger.info("=== Anti-DDoS per-service collector starting ===")
    logger.info("socket=%s queue_max=%d batch_size=%d batch_timeout=%.1fs",
                config.ENGINE_SOCKET_PATH, config.COLLECTOR_QUEUE_MAX_SIZE,
                config.COLLECTOR_BATCH_SIZE, config.COLLECTOR_BATCH_TIMEOUT_S)

    signal.signal(signal.SIGTERM, _signal_handler)
    signal.signal(signal.SIGINT, _signal_handler)

    reader = threading.Thread(target=reader_thread, name="reader",
                              daemon=False)
    writer = threading.Thread(target=writer_thread, name="writer",
                              daemon=False)
    stats_t = threading.Thread(target=stats_thread, name="stats",
                               daemon=True)

    reader.start()
    writer.start()
    stats_t.start()

    # Park the main thread on the shutdown event so signals are handled
    # promptly (signal delivery wakes the wait()).
    while not shutdown_event.wait(1.0):
        pass

    reader.join(timeout=10.0)
    writer.join(timeout=10.0)

    with stats_lock:
        snap = dict(stats)
    logger.info("final stats: read=%d parsed=%d inserted=%d transitions=%d",
                snap["msgs_read"], snap["msgs_parsed"],
                snap["msgs_inserted"], snap["phase_transitions"])
    logger.info("=== collector exited cleanly ===")
    return 0


if __name__ == "__main__":
    sys.exit(main())
