# LEGACY — PRESERVED FOR REFERENCE. Reads from shared_state buffers that
# the post-P12 collector no longer populates. Replaced by web.py (P14)
# which reads from ClickHouse. Do not import or launch this file.

from dataclasses import asdict, is_dataclass
from flask import Flask, render_template, jsonify, request
import ipaddress
import threading
import shared_state
import config
from datetime import datetime, timedelta

# Optional clickhouse-driver import for the new /api/temporal/* endpoints.
# We do NOT import database.py here because database.get_db_client() runs
# CREATE TABLE statements as a side-effect, which we don't want to repeat
# from the web layer. _get_ch_client() below opens its own thin read-only
# Client instead, lazily and behind a lock.
try:
    from clickhouse_driver import Client as _CHClient   # type: ignore
except Exception:                                       # pragma: no cover
    _CHClient = None
_CH_CLIENT = None
_CH_CLIENT_LOCK = threading.Lock()


def _get_ch_client():
    """Lazily build a read-only ClickHouse client for API use.

    Returns None if the driver is not installed or the broker can't be
    reached. Callers MUST handle None and fall back to RAM where
    possible — the existing IP CSV path is unaffected either way.
    """
    global _CH_CLIENT
    if _CH_CLIENT is not None:
        return _CH_CLIENT
    if _CHClient is None:
        return None
    with _CH_CLIENT_LOCK:
        if _CH_CLIENT is not None:
            return _CH_CLIENT
        try:
            _CH_CLIENT = _CHClient(
                host=config.CH_HOST,
                port=config.CH_PORT,
                user=config.CH_USER,
                password=config.CH_PASSWORD,
                settings={'use_numpy': False},
            )
            print(f"[Web] ClickHouse client ready for /api/temporal/* "
                  f"({config.CH_HOST}:{config.CH_PORT})")
        except Exception as e:
            print(f"[Web] ClickHouse client init failed: {e}")
            _CH_CLIENT = None
        return _CH_CLIENT


def _is_valid_ip(ip_str):
    """Strict IPv4/IPv6 string validation. Used as a SQL-injection guard
    for parameters that flow into ClickHouse queries even though the
    driver also parameterises them — defense in depth."""
    try:
        ipaddress.ip_address(ip_str)
        return True
    except (ValueError, TypeError):
        return False


_TEMPORAL_VALID_WINDOWS = (10, 60, 300)
_TEMPORAL_ALERT_STATES = ('WATCH', 'SUSPICIOUS', 'STRONG')


def _temporal_state_rank(state):
    """Severity ranking for the locked 5-phase temporal state. Higher
    means more severe; used as a sort key for /api/temporal/summary."""
    return {
        'STRONG':     4,
        'SUSPICIOUS': 3,
        'WATCH':      2,
        'NORMAL':     1,
        'WARMUP':     0,
    }.get((state or 'WARMUP').upper(), 0)

# Cache the expanded configured target list. TARGET_PREFIXES is static at runtime,
# so we expand once and reuse — avoids re-expanding /27..//32 networks on every poll.
_CONFIGURED_TARGETS_CACHE = None


def _expand_configured_targets():
    """Expand config.TARGET_PREFIXES into a sorted, de-duplicated list of IP strings.

    Every host address inside each prefix is included because the detector treats
    every dst_ip as a possible target.
    """
    global _CONFIGURED_TARGETS_CACHE
    if _CONFIGURED_TARGETS_CACHE is not None:
        return _CONFIGURED_TARGETS_CACHE

    seen = set()
    for prefix in getattr(config, 'TARGET_PREFIXES', []) or []:
        try:
            net = ipaddress.ip_network(prefix, strict=False)
        except (ValueError, TypeError):
            continue
        # Use .hosts() for usable hosts on multi-host nets; for /32 (and /31)
        # iterate the network directly so the single address is still returned.
        if net.num_addresses <= 2:
            for addr in net:
                seen.add(str(addr))
        else:
            for addr in net.hosts():
                seen.add(str(addr))

    _CONFIGURED_TARGETS_CACHE = sorted(seen, key=lambda ip: ipaddress.ip_address(ip))
    return _CONFIGURED_TARGETS_CACHE

app = Flask(__name__)


def _serialize_timestamp(value):
    if isinstance(value, datetime):
        return value.isoformat()
    return str(value)


def _serialize_json_value(value):
    if is_dataclass(value):
        return _serialize_json_value(asdict(value))
    if isinstance(value, dict):
        return {key: _serialize_json_value(val) for key, val in value.items()}
    if isinstance(value, list):
        return [_serialize_json_value(item) for item in value]
    if isinstance(value, tuple):
        return [_serialize_json_value(item) for item in value]
    if isinstance(value, datetime):
        return value.isoformat()
    return value


def _state_rank(state):
    return {
        'ATTACK': 4,
        'SUSPICIOUS': 3,
        'WARMUP': 2,
        'NORMAL': 1,
    }.get((state or 'NORMAL').upper(), 0)


@app.route('/')
def index():
    """Render main dashboard page."""
    return render_template('index.html')


@app.route('/api/stats/<target_ip>')
def get_target_stats(target_ip):
    """Returns historical data for a specific destination IP for charting."""
    with shared_state.data_lock:
        # Filter RAM buffer for the specific IP
        filtered_data = [r for r in shared_state.latest_traffic_data if r.get('dst_ip') == target_ip]
        # Reverse so oldest is first (left side of chart), newest is last (right side)
        filtered_data.reverse()
        return jsonify(filtered_data)


@app.route('/api/targets')
def get_active_targets():
    """Returns a list of unique destination IPs currently being monitored."""
    with shared_state.data_lock:
        if not shared_state.latest_traffic_data:
            return jsonify([])
        
        targets = list(set(r.get('dst_ip') for r in shared_state.latest_traffic_data if r.get('dst_ip')))
        return jsonify(sorted(targets))


@app.route('/api/targets/configured')
def get_configured_targets():
    """Returns every IP from config.TARGET_PREFIXES (expanded), sorted.

    This is the full, static set of IPs the detector watches — independent of
    whether traffic for them is currently in the RAM buffer.
    """
    return jsonify(_expand_configured_targets())


@app.route('/api/targets/configured/summary')
def get_configured_targets_summary():
    """Per-IP summary for every configured target, merged with live RAM state.

    For each configured IP:
      - if there's a recent record in shared_state.latest_traffic_data, mark it
        active and surface last_seen/state/profile from that record;
      - otherwise return active=false and NORMAL/default/v1 as a safe default.
    """
    configured = _expand_configured_targets()

    with shared_state.data_lock:
        latest_by_ip = {}
        for record in shared_state.latest_traffic_data:
            dst_ip = record.get('dst_ip')
            if dst_ip and dst_ip not in latest_by_ip:
                latest_by_ip[dst_ip] = record

    out = []
    for dst_ip in configured:
        record = latest_by_ip.get(dst_ip)
        if record is not None:
            out.append({
                'dst_ip': dst_ip,
                'active': True,
                'last_seen': _serialize_timestamp(record.get('timestamp')),
                'detection_state': record.get('detection_state', 'NORMAL'),
                'profile_name': record.get('profile_name', 'default'),
                'profile_version': record.get('profile_version', 'v1'),
            })
        else:
            out.append({
                'dst_ip': dst_ip,
                'active': False,
                'last_seen': None,
                'detection_state': 'NORMAL',
                'profile_name': 'default',
                'profile_version': 'v1',
            })
    return jsonify(out)


@app.route('/api/targets/summary')
def get_targets_summary():
    """Returns the latest record per active target IP for situational awareness."""
    with shared_state.data_lock:
        latest_by_ip = {}

        for record in shared_state.latest_traffic_data:
            dst_ip = record.get('dst_ip')
            if dst_ip and dst_ip not in latest_by_ip:
                latest_by_ip[dst_ip] = record

        summaries = []
        for dst_ip, record in latest_by_ip.items():
            summaries.append({
                'dst_ip': dst_ip,
                'detection_state': record.get('detection_state', 'NORMAL'),
                'pps': record.get('pps', 0),
                'bps': record.get('bps', 0),
                'timestamp': _serialize_timestamp(record.get('timestamp')),
                'attack_type': record.get('attack_type'),
                'profile_name': record.get('profile_name', 'default'),
                'profile_version': record.get('profile_version', 'v1'),
            })

        summaries.sort(
            key=lambda item: (
                _state_rank(item.get('detection_state')),
                item.get('bps', 0),
                item.get('pps', 0),
            ),
            reverse=True
        )
        return jsonify(summaries)


@app.route('/api/debug/raw')
def get_debug_raw():
    """DEBUG: Returns the entire shared_state.latest_traffic_data array for inspection."""
    with shared_state.data_lock:
        return jsonify({
            'count': len(shared_state.latest_traffic_data),
            'sample': shared_state.latest_traffic_data[:3] if shared_state.latest_traffic_data else [],
            'unique_ips': list(set(r.get('dst_ip') for r in shared_state.latest_traffic_data if r.get('dst_ip')))
        })


@app.route('/api/alerts')
def get_recent_alerts():
    """Returns recent SUSPICIOUS and ATTACK detections across all IPs."""
    with shared_state.data_lock:
        alerts = []
        
        # Get last 100 records and filter for alerts
        recent_data = shared_state.latest_traffic_data[:100]
        
        for record in recent_data:
            state = record.get('detection_state', 'NORMAL')
            if state in ['SUSPICIOUS', 'ATTACK']:
                alerts.append({
                    'timestamp': record.get('timestamp').isoformat() if isinstance(record.get('timestamp'), datetime) else str(record.get('timestamp')),
                    'dst_ip': record.get('dst_ip', 'Unknown'),
                    'state': state,
                    'tier0_global_risk': record.get('tier0_global_risk', 0),
                    'tier1_final_score': record.get('tier1_final_score', 0),
                    'pps': record.get('pps', 0),
                    'bps': record.get('bps', 0),
                    'profile_name': record.get('profile_name', 'default'),
                    'profile_version': record.get('profile_version', 'v1'),
                })
        
        return jsonify(alerts)


@app.route('/api/alerts/<target_ip>')
def get_target_alerts(target_ip):
    """Returns current state for a specific IP - simplified for detection banner only."""
    with shared_state.data_lock:
        # Filter for specific IP
        ip_data = [r for r in shared_state.latest_traffic_data if str(r.get('dst_ip')) == str(target_ip)]
        
        if not ip_data:
            return jsonify({
                'state': 'NORMAL',
                'has_alert': False,
                'profile_name': 'default',
                'profile_version': 'v1',
            })

        # Get the most recent record
        latest = ip_data[0]
        state = latest.get('detection_state', 'NORMAL')

        return jsonify({
            'state': state,
            'has_alert': state in ['SUSPICIOUS', 'ATTACK'],
            'timestamp': _serialize_timestamp(latest.get('timestamp')),
            'tier0_global_risk': latest.get('tier0_global_risk', 0),
            'tier1_final_score': latest.get('tier1_final_score', 0),
            'pps': latest.get('pps', 0),
            'bps': latest.get('bps', 0),
            'profile_name': latest.get('profile_name', 'default'),
            'profile_version': latest.get('profile_version', 'v1'),
        })


@app.route('/api/events/<target_ip>')
def get_target_events(target_ip):
    """Returns recent alert windows and state transitions for a specific IP."""
    with shared_state.data_lock:
        ip_data = [
            r for r in shared_state.latest_traffic_data
            if str(r.get('dst_ip')) == str(target_ip)
        ]

        if not ip_data:
            return jsonify([])

        chronological = list(reversed(ip_data[:150]))
        prev_state = None
        events = []

        for record in chronological:
            state = record.get('detection_state', 'NORMAL')
            state_changed = (prev_state is not None and state != prev_state)

            if state in ['SUSPICIOUS', 'ATTACK'] or state_changed:
                events.append({
                    'timestamp': _serialize_timestamp(record.get('timestamp')),
                    'state': state,
                    'state_changed': state_changed,
                    'attack_type': record.get('attack_type'),
                    'tier0_global_risk': record.get('tier0_global_risk', 0),
                    'tier1_final_score': record.get('tier1_final_score', 0),
                    'pps': record.get('pps', 0),
                    'bps': record.get('bps', 0),
                    'profile_name': record.get('profile_name', 'default'),
                    'profile_version': record.get('profile_version', 'v1'),
                })

            prev_state = state

        return jsonify(list(reversed(events[-25:])))


@app.route('/api/live')
def get_live_data():
    """
    Returns data directly from RAM for zero latency.
    This endpoint provides real-time traffic data to the dashboard.
    """
    with shared_state.data_lock:
        # Return a copy to avoid race conditions
        return jsonify(shared_state.latest_traffic_data[:])


@app.route('/api/stats')
def get_stats():
    """
    Returns aggregated statistics from current data.
    """
    with shared_state.data_lock:
        data = shared_state.latest_traffic_data
        
        if not data:
            return jsonify({
                'total_pps': 0,
                'total_bps': 0,
                'total_flows': 0,
                'unique_ips': 0,
                'unique_src_ips': 0,
                'unique_dst_ports': 0,
                'record_count': 0
            })
        
        total_pps = sum(record.get('pps', 0) for record in data)
        total_bps = sum(record.get('bps', 0) for record in data)
        total_flows = sum(record.get('udp_flow_ratio', 0) for record in data)
        unique_src_ips = sum(record.get('unique_src_ips', 0) for record in data)
        unique_dst_ports = sum(record.get('unique_dst_ports', 0) for record in data)
        
        return jsonify({
            'total_pps': total_pps,
            'total_bps': total_bps,
            'total_flows': total_flows,
            'unique_ips': unique_src_ips,
            'unique_src_ips': unique_src_ips,
            'unique_dst_ports': unique_dst_ports,
            'record_count': len(data)
        })


# ============================================================================
# TEMPORAL OBSERVABILITY API (multi-timescale, shadow-only)
# ============================================================================
#
# These endpoints surface the dst_ip_temporal_stats data fed by C TEMP
# records through the dpdk_temporal_collector_thread. They are read-only
# views; nothing here feeds back into Layer-2 detection.
#
# RAM-first design:
#   shared_state.latest_temporal_data is a bounded ring of the most
#   recent TEMP records (newest-first). It covers every active dst_ip ×
#   window_sec under normal load, so /latest, /summary, and /alerts
#   answer from RAM with no DB hit. /history and the /summary fallback
#   path are the only callers that touch ClickHouse.


@app.route('/api/temporal/latest/<target_ip>')
def get_temporal_latest(target_ip):
    """Latest temporal record for `target_ip` at each of the three locked
    window scales (10 / 60 / 300 seconds). Reads exclusively from the
    RAM ring; never queries ClickHouse. Missing scales are returned as
    null instead of being omitted, so the dashboard can render a stable
    three-slot layout."""
    if not _is_valid_ip(target_ip):
        return jsonify({'error': 'invalid IP'}), 400

    out = {'10': None, '60': None, '300': None}
    with shared_state.temporal_data_lock:
        # The ring is newest-first, so the first hit per scale is the
        # most recent. Bail early when all three slots are filled.
        for record in shared_state.latest_temporal_data:
            if record.get('dst_ip') != target_ip:
                continue
            ws = record.get('window_sec')
            key = str(ws)
            if key in out and out[key] is None:
                out[key] = _serialize_json_value(record)
            if all(v is not None for v in out.values()):
                break

    return jsonify({
        'dst_ip': target_ip,
        'windows': out,
    })


@app.route('/api/temporal/history/<target_ip>')
def get_temporal_history(target_ip):
    """Historical temporal rows for `target_ip` at one window scale, over
    the last `minutes` minutes. Always queries dst_ip_temporal_stats.
    Returns oldest-first so the dashboard can plot left-to-right.

    Query parameters:
      window_sec : 10 | 60 | 300 (required, default 60)
      minutes    : 1 .. 1440  (default 60)

    SQL injection is prevented by strict argument validation AND
    parameterised query placeholders — defense in depth."""
    if not _is_valid_ip(target_ip):
        return jsonify({'error': 'invalid IP'}), 400

    try:
        window_sec = int(request.args.get('window_sec', 60))
    except (TypeError, ValueError):
        return jsonify({'error': 'window_sec must be an integer'}), 400
    if window_sec not in _TEMPORAL_VALID_WINDOWS:
        return jsonify({
            'error': f'window_sec must be one of {list(_TEMPORAL_VALID_WINDOWS)}'
        }), 400

    try:
        minutes = int(request.args.get('minutes', 60))
    except (TypeError, ValueError):
        return jsonify({'error': 'minutes must be an integer'}), 400
    minutes = max(1, min(minutes, 1440))

    client = _get_ch_client()
    if client is None:
        # DB unavailable — return an empty history rather than 500. The
        # dashboard can fall back to the RAM-served latest snapshot.
        return jsonify([])

    try:
        rows, cols = client.execute(
            f"""
            SELECT *
            FROM {config.CH_DB}.{config.CH_TEMPORAL_TABLE}
            WHERE dst_ip = %(ip)s
              AND window_sec = %(window_sec)s
              AND timestamp > now() - toIntervalMinute(%(minutes)s)
            ORDER BY timestamp ASC
            """,
            {
                'ip': target_ip,
                'window_sec': window_sec,
                'minutes': minutes,
            },
            with_column_types=True,
        )
    except Exception as e:
        print(f"[Web/Temporal] history query failed: {e}")
        return jsonify([])

    col_names = [c[0] for c in cols]
    return jsonify([
        _serialize_json_value(dict(zip(col_names, row)))
        for row in rows
    ])


@app.route('/api/temporal/summary')
def get_temporal_summary():
    """Latest temporal row per (dst_ip, window_sec), sorted by:
        1. temporal_state severity (STRONG > SUSPICIOUS > WATCH > NORMAL > WARMUP)
        2. temporal_score
        3. max_bps

    Tries RAM first; falls back to a bounded 1-hour ClickHouse window
    when RAM is empty (e.g. just after process restart).
    """
    summaries = []

    # ---- RAM path ----
    with shared_state.temporal_data_lock:
        latest_by_key = {}
        for record in shared_state.latest_temporal_data:
            dst_ip = record.get('dst_ip')
            window_sec = record.get('window_sec')
            if dst_ip is None or window_sec is None:
                continue
            key = (dst_ip, window_sec)
            if key not in latest_by_key:
                latest_by_key[key] = record
        if latest_by_key:
            summaries = list(latest_by_key.values())

    # ---- DB fallback when RAM is empty ----
    if not summaries:
        client = _get_ch_client()
        if client is not None:
            try:
                rows, cols = client.execute(
                    f"""
                    SELECT
                        dst_ip,
                        window_sec,
                        argMax(timestamp,      timestamp) AS timestamp,
                        argMax(temporal_state, timestamp) AS temporal_state,
                        argMax(temporal_score, timestamp) AS temporal_score,
                        argMax(baseline_ready, timestamp) AS baseline_ready,
                        argMax(valid_seconds,  timestamp) AS valid_seconds,
                        argMax(max_pps,        timestamp) AS max_pps,
                        argMax(max_bps,        timestamp) AS max_bps,
                        argMax(volume_score,         timestamp) AS volume_score,
                        argMax(protocol_shift_score, timestamp) AS protocol_shift_score,
                        argMax(persistence_score,    timestamp) AS persistence_score,
                        argMax(ramp_score,           timestamp) AS ramp_score
                    FROM {config.CH_DB}.{config.CH_TEMPORAL_TABLE}
                    WHERE timestamp > now() - toIntervalHour(1)
                    GROUP BY dst_ip, window_sec
                    """,
                    with_column_types=True,
                )
                col_names = [c[0] for c in cols]
                summaries = [dict(zip(col_names, row)) for row in rows]
            except Exception as e:
                print(f"[Web/Temporal] summary fallback query failed: {e}")
                summaries = []

    def _sort_key(record):
        # Negate so larger severity / score / bps sorts first.
        try:
            score = float(record.get('temporal_score', 0.0) or 0.0)
        except (TypeError, ValueError):
            score = 0.0
        try:
            mbps = float(record.get('max_bps', 0.0) or 0.0)
        except (TypeError, ValueError):
            mbps = 0.0
        return (
            -_temporal_state_rank(record.get('temporal_state', 'WARMUP')),
            -score,
            -mbps,
        )

    summaries.sort(key=_sort_key)
    return jsonify([_serialize_json_value(r) for r in summaries])


@app.route('/api/temporal/alerts')
def get_temporal_alerts():
    """Recent temporal records whose temporal_state is WATCH, SUSPICIOUS,
    or STRONG. RAM-only (bounded ring), newest-first. Capped at 200
    entries to keep the response small."""
    with shared_state.temporal_data_lock:
        alerts = [
            record for record in shared_state.latest_temporal_data
            if record.get('temporal_state') in _TEMPORAL_ALERT_STATES
        ]
    return jsonify([_serialize_json_value(r) for r in alerts[:200]])


def start_server():
    print(f"[Web] Starting Dashboard on http://{config.FLASK_HOST}:{config.FLASK_PORT}")
    app.run(
        host=config.FLASK_HOST,
        port=config.FLASK_PORT,
        debug=False,
        use_reloader=False,
        threaded=True
    )
