#!/usr/bin/env python3
"""
ddos_monitor/web.py — P14 per-service dashboard + JSON API.

Reads ALL state from ClickHouse (service_stats, service_phase_transitions,
service_temporal_aggregates, service_registry_snapshots). Does NOT depend
on shared_state or database.py. Runs as an independent process from the
collector.

Routes:
  /                          -> Overview tab
  /services                  -> All-services table
  /services/<int:slot_id>    -> Slot detail with time-series charts
  /registry                  -> Read-only view of services.json + reload audit
  /alerts                    -> Phase transitions history

JSON API:
  /api/overview              -> top-level dashboard stats
  /api/services              -> latest row per slot
  /api/services/<slot_id>    -> slot identity + latest row
  /api/services/<slot_id>/timeseries?window=300
                             -> per-slot score+pkts history over last N seconds
  /api/registry              -> parsed services.json content
  /api/registry/audit?limit=50
                             -> reload audit history
  /api/alerts?limit=100      -> phase transitions, most recent first
  /api/health                -> {"status":"ok","ch_reachable":true,"latest_timestamp":...}

Run:
  python3 ddos_monitor/web.py
"""

import os
import sys
import json
import logging
import threading
from datetime import datetime
from typing import Optional

# Flat-import bootstrap (matches collector.py / main.py / wire_parser.py)
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from flask import Flask, render_template, jsonify, request, redirect
import config
from wire_parser import phase_name, proto_kind_name, PHASE_NAMES, PROTO_KIND_NAMES

# Lazy clickhouse-driver import so py_compile works on a bare interpreter.
try:
    from clickhouse_driver import Client as _CHClient  # type: ignore
except ImportError:
    _CHClient = None

_CH_CLIENT = None
_CH_CLIENT_LOCK = threading.Lock()
logger = logging.getLogger(__name__)


def get_ch_client():
    """Lazy thread-safe ClickHouse client. Read-only usage.

    NEVER uses database.py.get_db_client() because that creates the
    legacy traffic_stats table as a side effect.
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
                database=config.CH_DB,
                settings={'use_numpy': False},
            )
            logger.info(
                "ClickHouse client ready (%s:%s/%s)",
                config.CH_HOST, config.CH_PORT, config.CH_DB)
        except Exception as e:  # noqa: BLE001
            logger.error("ClickHouse client init failed: %s", e)
            _CH_CLIENT = None
        return _CH_CLIENT


def fmt_peak_pps(v: Optional[int]) -> str:
    """UINT32_MAX is the engine's saturation sentinel; render as em-dash."""
    if v is None:
        return "—"
    try:
        v = int(v)
    except (TypeError, ValueError):
        return "—"
    if v >= 0xFFFFFFFF:
        return "—"
    return f"{v:,}"


def safe_int(v) -> int:
    """Robust int conversion, returns 0 on failure."""
    try:
        return int(v)
    except (TypeError, ValueError):
        return 0


def format_slot_display_title(slot_dict) -> str:
    """Human-readable slot title for the detail page header.

    Catch-all slots are keyed by protocol family (proto_kind 4..7);
    named services carry a profile + port. Reads target_ip_str for
    the IP. Falls back gracefully on unexpected proto_kind values.
    """
    ip = slot_dict.get('target_ip_str')
    if slot_dict.get('is_catchall'):
        catchall_labels = {
            4: 'Any TCP',
            5: 'Any UDP',
            6: 'Any ICMP',
            7: 'Other Protocols',
        }
        label = catchall_labels.get(safe_int(slot_dict.get('proto_kind')),
                                    'Catch-all')
        return f"{ip} — {label}"
    return (f"{ip} — {slot_dict.get('proto_kind_str')}/"
            f"{slot_dict.get('port')} ({slot_dict.get('profile_name')})")


# -------------------- Flask app + routes --------------------

_HERE = os.path.dirname(os.path.abspath(__file__))
app = Flask(
    __name__,
    template_folder=os.path.join(_HERE, 'templates'),
    static_folder=os.path.join(_HERE, 'static'),
)


@app.context_processor
def inject_template_globals():
    """Make config + label helpers available in every template."""
    return {
        'config': config,
        'phase_name': phase_name,
        'proto_kind_name': proto_kind_name,
        'fmt_peak_pps': fmt_peak_pps,
    }


# ====== HTML routes ======

@app.route('/')
def operations_view():
    """Operations tab — top-level dashboard (homepage)."""
    return render_template('operations.html', active_tab='operations')


@app.route('/slots')
def slots_view():
    """Slots tab — all slots in a table."""
    return render_template('slots.html', active_tab='slots')


@app.route('/slots/<int:slot_id>')
def slot_detail_view(slot_id: int):
    """Slot detail page with charts."""
    return render_template('slot_detail.html', slot_id=slot_id,
                           active_tab='slots')


@app.route('/config')
def config_view():
    """Config tab — view + (Phase 7) edit services.json + reload audit."""
    return render_template('config.html', active_tab='config')


@app.route('/audit')
def audit_view():
    """Audit tab — unified phase transitions + (Phase 6) config changes
    + admin actions timeline."""
    return render_template('audit.html', active_tab='audit')


@app.route('/system')
def system_view():
    """System tab — engine health + (Phase 8) runtime overrides."""
    return render_template('system.html', active_tab='system')


# --- Legacy URL redirects (one cycle of grace for any old bookmarks) ---
@app.route('/services')
def _legacy_services():
    return redirect('/slots', code=301)


@app.route('/services/<int:slot_id>')
def _legacy_service_detail(slot_id):
    return redirect(f'/slots/{slot_id}', code=301)


@app.route('/registry')
def _legacy_registry():
    return redirect('/config', code=301)


@app.route('/alerts')
def _legacy_alerts():
    return redirect('/audit', code=301)


# ====== JSON API ======

@app.route('/api/overview')
def api_overview():
    """Top-level stats: latest timestamp, per-phase counts, recent
    transition count, and the top-5 non-WARMUP slots by tier1 score."""
    ch = get_ch_client()
    if ch is None:
        return jsonify({'error': 'clickhouse unavailable'}), 503
    try:
        latest = ch.execute(
            f"SELECT max(timestamp_dt) FROM {config.TABLE_SERVICE_STATS}")
        latest_ts = latest[0][0] if latest and latest[0][0] else None

        recent = config.DASHBOARD_OVERVIEW_RECENT_SECONDS
        # Freshness gate for the per-slot views below: a slot must have
        # emitted a heartbeat within DASHBOARD_SLOT_FRESHNESS_SECONDS to
        # count. Excludes slots retired by a registry reconfiguration.
        fresh = config.DASHBOARD_SLOT_FRESHNESS_SECONDS
        phase_counts_rows = ch.execute(f"""
            SELECT phase_str, count() AS n
            FROM (
                SELECT slot_id,
                       argMax(phase_str, timestamp_ns) AS phase_str
                FROM {config.TABLE_SERVICE_STATS}
                WHERE inserted_at >= now() - INTERVAL {fresh} SECOND
                GROUP BY slot_id
            )
            GROUP BY phase_str
        """)
        phase_counts = {row[0]: row[1] for row in phase_counts_rows}
        for ph in ('WARMUP', 'NORMAL', 'SUSPICIOUS', 'ATTACK'):
            phase_counts.setdefault(ph, 0)

        trans_rows = ch.execute(f"""
            SELECT count() FROM {config.TABLE_PHASE_TRANSITIONS}
            WHERE timestamp_dt >= now() - INTERVAL {recent} SECOND
        """)
        transitions_recent = trans_rows[0][0] if trans_rows else 0

        top_rows = ch.execute(f"""
            SELECT slot_id, target_ip_str, port, proto_kind_str, phase_str,
                   tier1_final_score, tier0_score
            FROM (
                SELECT slot_id,
                       argMax(target_ip_str, timestamp_ns)     AS target_ip_str,
                       argMax(port, timestamp_ns)              AS port,
                       argMax(proto_kind_str, timestamp_ns)    AS proto_kind_str,
                       argMax(phase_str, timestamp_ns)         AS phase_str,
                       argMax(tier1_final_score, timestamp_ns) AS tier1_final_score,
                       argMax(tier0_score, timestamp_ns)       AS tier0_score
                FROM {config.TABLE_SERVICE_STATS}
                WHERE inserted_at >= now() - INTERVAL {fresh} SECOND
                GROUP BY slot_id
            )
            WHERE phase_str != 'WARMUP'
            ORDER BY tier1_final_score DESC
            LIMIT 5
        """)
        top_slots = [
            {
                'slot_id': r[0], 'target_ip': r[1], 'port': r[2],
                'proto_kind': r[3], 'phase': r[4],
                'tier1_final_score': float(r[5]),
                'tier0_score': float(r[6]),
            }
            for r in top_rows
        ]

        return jsonify({
            'latest_timestamp': latest_ts.isoformat() if latest_ts else None,
            'phase_counts': phase_counts,
            'transitions_recent': transitions_recent,
            'top_slots': top_slots,
            'recent_window_seconds': recent,
        })
    except Exception as e:  # noqa: BLE001
        logger.exception("api_overview failed")
        return jsonify({'error': str(e)}), 500


@app.route('/api/services')
def api_services():
    """Latest row per slot (argMax idiom), ordered by IP/port/proto."""
    ch = get_ch_client()
    if ch is None:
        return jsonify({'error': 'clickhouse unavailable'}), 503
    try:
        # Freshness gate: only slots that emitted a heartbeat within the
        # last DASHBOARD_SLOT_FRESHNESS_SECONDS are "active". Filtering on
        # inserted_at (collector insert time) excludes slots retired by a
        # registry reconfiguration, whose last rows linger in ClickHouse
        # until the 30-day TTL expires.
        fresh = config.DASHBOARD_SLOT_FRESHNESS_SECONDS
        rows = ch.execute(f"""
            SELECT slot_id,
                   argMax(target_ip_str, timestamp_ns)  AS target_ip,
                   argMax(port, timestamp_ns)           AS port,
                   argMax(proto_kind_str, timestamp_ns) AS proto_kind,
                   argMax(is_catchall, timestamp_ns)    AS is_catchall,
                   argMax(profile_name, timestamp_ns)   AS profile_name,
                   argMax(phase_str, timestamp_ns)      AS phase,
                   argMax(warmup_remaining, timestamp_ns) AS warmup_remaining,
                   argMax(consecutive_attack_windows, timestamp_ns) AS consec,
                   argMax(inbound_pkts, timestamp_ns)   AS inbound_pkts,
                   argMax(inbound_bytes, timestamp_ns)  AS inbound_bytes,
                   argMax(tier0_score, timestamp_ns)    AS tier0_score,
                   argMax(tier1_final_score, timestamp_ns) AS tier1_score,
                   argMax(unique_src_ips, timestamp_ns) AS unique_src_ips,
                   argMax(win_10s_peak_pps, timestamp_ns) AS peak_pps_10s,
                   max(timestamp_dt)                    AS latest_ts
            FROM {config.TABLE_SERVICE_STATS}
            WHERE inserted_at >= now() - INTERVAL {fresh} SECOND
            GROUP BY slot_id
            ORDER BY target_ip, port, proto_kind
        """)
        out = []
        for r in rows:
            out.append({
                'slot_id': r[0],
                'target_ip': r[1],
                'port': r[2],
                'proto_kind': r[3],
                'is_catchall': bool(r[4]),
                'profile_name': r[5],
                'phase': r[6],
                'warmup_remaining': r[7],
                'consecutive_attack_windows': r[8],
                'inbound_pkts': r[9],
                'inbound_bytes': r[10],
                'tier0_score': float(r[11]),
                'tier1_final_score': float(r[12]),
                'unique_src_ips': float(r[13]),
                'peak_pps_10s_raw': r[14],
                'peak_pps_10s': fmt_peak_pps(r[14]),
                'latest_timestamp': r[15].isoformat() if r[15] else None,
            })
        return jsonify(out)
    except Exception as e:  # noqa: BLE001
        logger.exception("api_services failed")
        return jsonify({'error': str(e)}), 500


@app.route('/api/services/<int:slot_id>')
def api_service_one(slot_id):
    """Single slot's latest snapshot — full field dump."""
    ch = get_ch_client()
    if ch is None:
        return jsonify({'error': 'clickhouse unavailable'}), 503
    try:
        rows = ch.execute(f"""
            SELECT * FROM {config.TABLE_SERVICE_STATS}
            WHERE slot_id = %(sid)s
            ORDER BY timestamp_ns DESC
            LIMIT 1
        """, {'sid': slot_id}, with_column_types=True)
        if not rows[0]:
            return jsonify({'error': 'slot not found'}), 404
        cols = [c[0] for c in rows[1]]
        row = rows[0][0]
        result = dict(zip(cols, row))
        for k, v in list(result.items()):
            if isinstance(v, datetime):
                result[k] = v.isoformat()
            elif isinstance(v, bytes):
                result[k] = v.decode('utf-8', errors='replace')
        for f in ('win_10s_peak_pps', 'win_60s_peak_pps',
                  'win_300s_peak_pps'):
            if (f in result and isinstance(result[f], int)
                    and result[f] >= 0xFFFFFFFF):
                result[f + '_display'] = '—'
            else:
                result[f + '_display'] = fmt_peak_pps(result.get(f))
        # Live "breaching the absolute floor this second" flag. SELECT * already
        # carries it once the column exists; normalize to 0/1 (UInt8 precedent,
        # like is_catchall) and guarantee the key is present even before the
        # additive column migration has run on this DB.
        result['absolute_floor_fired'] = (
            1 if result.get('absolute_floor_fired') else 0)
        result['display_title'] = format_slot_display_title(result)
        return jsonify(result)
    except Exception as e:  # noqa: BLE001
        logger.exception("api_service_one failed")
        return jsonify({'error': str(e)}), 500


@app.route('/api/services/<int:slot_id>/timeseries')
def api_slot_timeseries(slot_id):
    """Time series for charts. Query param: window=N seconds (10..3600)."""
    ch = get_ch_client()
    if ch is None:
        return jsonify({'error': 'clickhouse unavailable'}), 503
    try:
        window = safe_int(request.args.get(
            'window', config.DASHBOARD_TIMESERIES_WINDOW_SECONDS))
        window = max(10, min(window, 86400))  # clamp 10s..24h
        rows = ch.execute(f"""
            SELECT timestamp_dt,
                   inbound_pkts,
                   inbound_bytes,
                   unique_flows,
                   out_pkts,
                   out_bytes,
                   ip_frag_pkts,
                   off_proto_pkts,
                   tcp_pkts,
                   tcp_bytes,
                   syn_pkts,
                   syn_ack_pkts,
                   fin_ack_pkts,
                   rst_pkts,
                   ack_data_pkts,
                   empty_ack_pkts,
                   zero_window_pkts,
                   udp_pkts,
                   udp_bytes,
                   icmp_pkts,
                   unique_src_ips,
                   src_24_top1_share,
                   src_24_entropy,
                   ttl_mean,
                   ttl_stddev,
                   bw_pps_z_last,
                   bw_bps_z_last,
                   tier0_score,
                   tier1_tcp_score,
                   tier1_udp_score,
                   tier1_icmp_score,
                   tier1_dist_score,
                   tier1_l3_score,
                   tier1_offproto_score,
                   tier1_final_score,
                   phase
            FROM {config.TABLE_SERVICE_STATS}
            WHERE slot_id = %(sid)s
              AND timestamp_dt >= now() - INTERVAL %(w)s SECOND
            ORDER BY timestamp_ns ASC
        """, {'sid': slot_id, 'w': window})
        timestamps = [r[0].isoformat() for r in rows]
        # Column order MUST match the SELECT above; index is offset by 1
        # for timestamp_dt at r[0]. Caster: int for UInt64 counts,
        # float for Float stats and Decimal scores.
        series_cols = [
            ('inbound_pkts', int), ('inbound_bytes', int),
            ('unique_flows', int), ('out_pkts', int), ('out_bytes', int),
            ('ip_frag_pkts', int), ('off_proto_pkts', int),
            ('tcp_pkts', int), ('tcp_bytes', int), ('syn_pkts', int),
            ('syn_ack_pkts', int), ('fin_ack_pkts', int), ('rst_pkts', int),
            ('ack_data_pkts', int), ('empty_ack_pkts', int),
            ('zero_window_pkts', int), ('udp_pkts', int), ('udp_bytes', int),
            ('icmp_pkts', int), ('unique_src_ips', int),
            ('src_24_top1_share', float), ('src_24_entropy', float),
            ('ttl_mean', float), ('ttl_stddev', float),
            ('bw_pps_z_last', float), ('bw_bps_z_last', float),
            ('tier0_score', float), ('tier1_tcp_score', float),
            ('tier1_udp_score', float), ('tier1_icmp_score', float),
            ('tier1_dist_score', float), ('tier1_l3_score', float),
            ('tier1_offproto_score', float), ('tier1_final_score', float),
            ('phase', int),
        ]
        payload = {
            'slot_id': slot_id,
            'window_seconds': window,
            'timestamps': timestamps,
        }
        for idx, (name, caster) in enumerate(series_cols, start=1):
            payload[name] = [caster(r[idx]) for r in rows]
        return jsonify(payload)
    except Exception as e:  # noqa: BLE001
        logger.exception("api_slot_timeseries failed")
        return jsonify({'error': str(e)}), 500


@app.route('/api/registry')
def api_registry():
    """Return the parsed services.json from disk (read-only view).

    NOTE: kept as a legacy alias for callers that still hit /api/registry.
    The Config tab uses /api/config (Phase 7) which adds the backups
    list and accepts writes."""
    return api_config_get_internal()


def api_config_get_internal():
    path = config.SERVICES_JSON_PATH
    if not os.path.isfile(path):
        return jsonify({'error': f'registry file not found: {path}'}), 404
    try:
        with open(path) as f:
            content = json.load(f)
        backups = _list_config_backups(path)
        return jsonify({
            'path': path,
            'modified_time': datetime.fromtimestamp(
                os.path.getmtime(path)).isoformat(),
            'size_bytes': os.path.getsize(path),
            'content': content,
            'backups': backups,
        })
    except Exception as e:    # noqa: BLE001
        logger.exception("config get failed")
        return jsonify({'error': str(e)}), 500


def _list_config_backups(services_json_path):
    """Return [{filename, modified_time, size_bytes}, ...] for every
    services.json.bak.* alongside the live file. Newest first."""
    d = os.path.dirname(services_json_path) or "."
    base = os.path.basename(services_json_path)
    prefix = base + ".bak."
    out = []
    try:
        for entry in os.listdir(d):
            if not entry.startswith(prefix):
                continue
            full = os.path.join(d, entry)
            try:
                st = os.stat(full)
                out.append({
                    'filename': entry,
                    'modified_time': datetime.fromtimestamp(st.st_mtime).isoformat(),
                    'size_bytes': st.st_size,
                })
            except OSError:
                pass
    except OSError:
        return []
    out.sort(key=lambda b: b['modified_time'], reverse=True)
    return out


def _config_write_with_backup(services_json_path, new_content_obj):
    """Atomic write services.json with a timestamped .bak. Returns the
    backup filename (basename) created. Validates via ProfileParams
    before writing — invalid input raises ValueError."""
    # Structural validation — these checks catch obvious operator mistakes
    # that load_config() would silently accept. load_config is permissive
    # by design (.get with defaults everywhere) so the engine never crashes
    # on a half-written config; here we want to REJECT obvious garbage
    # before it ever reaches the engine.
    if not isinstance(new_content_obj, dict):
        raise ValueError("config must be a JSON object")
    if "profiles" not in new_content_obj:
        raise ValueError("config missing 'profiles' field")
    if not isinstance(new_content_obj.get("profiles"), dict):
        raise ValueError("'profiles' must be an object")
    if "services" not in new_content_obj:
        raise ValueError("config missing 'services' field")
    if not isinstance(new_content_obj.get("services"), list):
        raise ValueError("'services' must be an array")

    # Semantic validation — exercise every profile's from_json.
    from detection.config import load_config
    try:
        load_config(new_content_obj)
    except Exception as e:    # noqa: BLE001
        raise ValueError(f"validation failed: {e}")

    d = os.path.dirname(services_json_path) or "."
    base = os.path.basename(services_json_path)
    ts = datetime.now().strftime("%Y%m%d-%H%M%S")
    bak_name = f"{base}.bak.{ts}"
    bak_path = os.path.join(d, bak_name)

    # Copy current → backup (if the live file exists).
    if os.path.isfile(services_json_path):
        import shutil
        shutil.copy2(services_json_path, bak_path)

    # Atomic write of the new content.
    import tempfile as _tempfile
    fd, tmp = _tempfile.mkstemp(dir=d, prefix=".cfg-")
    try:
        with os.fdopen(fd, "w") as f:
            json.dump(new_content_obj, f, indent=2, sort_keys=False)
        os.replace(tmp, services_json_path)
    finally:
        if os.path.exists(tmp):
            os.unlink(tmp)

    # Prune old backups — keep 20 most recent.
    backups = _list_config_backups(services_json_path)
    for old in backups[20:]:
        try:
            os.unlink(os.path.join(d, old['filename']))
        except OSError:
            pass

    return bak_name


def _trigger_reload_via_socket():
    """Send {action: request_reload} to the collector's control socket.
    Returns the parsed reply dict. Raises on any IO/protocol error."""
    import socket as _socket
    sock_path = getattr(config, 'CONTROL_SOCKET_PATH',
                        '/tmp/anti-ddos-control.sock')
    s = _socket.socket(_socket.AF_UNIX, _socket.SOCK_STREAM)
    s.settimeout(10.0)
    s.connect(sock_path)
    try:
        s.sendall((json.dumps({"action": "request_reload"}) + "\n")
                  .encode("utf-8"))
        buf = b""
        while not buf.endswith(b"\n"):
            chunk = s.recv(4096)
            if not chunk:
                break
            buf += chunk
        return json.loads(buf.decode("utf-8").strip())
    finally:
        try:
            s.close()
        except OSError:
            pass


@app.route('/api/config', methods=['GET'])
def api_config_get():
    """Same shape as /api/registry — current services.json plus
    `backups` list."""
    return api_config_get_internal()


@app.route('/api/config', methods=['POST'])
def api_config_save():
    """Write a new services.json (after validation + auto-backup),
    then trigger the collector's reload via the control socket.

    Body: full services.json content (replaces the file).

    Response:
      200 ok: {ok: true, backup, reload: {engine_pid, epoch_after, ...}}
      400  : validation failure / bad content
      500  : write or reload failed (backup already taken — rollback automatic)
    """
    body = request.get_json(silent=True)
    if body is None:
        return jsonify({'error': 'POST body must be JSON'}), 400

    path = config.SERVICES_JSON_PATH

    # Phase 1: validate + write with backup.
    try:
        backup = _config_write_with_backup(path, body)
    except ValueError as e:
        return jsonify({'error': str(e)}), 400
    except Exception as e:    # noqa: BLE001
        logger.exception("config write failed")
        return jsonify({'error': str(e)}), 500

    # Phase 2: trigger reload via the control socket.
    try:
        resp = _trigger_reload_via_socket()
    except FileNotFoundError:
        return jsonify({
            'ok': True, 'backup': backup,
            'reload': {'ok': False,
                       'error': 'control socket not available; '
                                'engine will reload on next manual SIGHUP'},
        })
    except Exception as e:    # noqa: BLE001
        logger.exception("config reload trigger failed")
        # The file write succeeded but the reload didn't — that's not a
        # rollback case (the operator can retry from the System tab).
        return jsonify({
            'ok': True, 'backup': backup,
            'reload': {'ok': False, 'error': str(e)},
        })

    return jsonify({'ok': True, 'backup': backup, 'reload': resp})


@app.route('/api/config/restore', methods=['POST'])
def api_config_restore():
    """Restore a previously saved backup. Body: {filename}.

    Effectively re-runs api_config_save with the backup file's content,
    so the same backup/write/reload flow applies. The current live
    services.json is preserved as a fresh .bak before being overwritten,
    so the restore itself is reversible."""
    body = request.get_json(silent=True) or {}
    filename = body.get('filename')
    if not filename:
        return jsonify({'error': 'filename required'}), 400
    path = config.SERVICES_JSON_PATH
    d = os.path.dirname(path) or "."
    base = os.path.basename(path)
    prefix = base + ".bak."
    if not filename.startswith(prefix):
        return jsonify({'error': f'not a backup of {base}'}), 400
    bak_path = os.path.join(d, filename)
    if not os.path.isfile(bak_path):
        return jsonify({'error': f'backup not found: {filename}'}), 404
    try:
        with open(bak_path) as f:
            content = json.load(f)
    except Exception as e:    # noqa: BLE001
        return jsonify({'error': f'backup unreadable: {e}'}), 500

    # Same write-with-backup + reload flow as a regular save.
    try:
        backup = _config_write_with_backup(path, content)
    except ValueError as e:
        return jsonify({'error': str(e)}), 400
    except Exception as e:    # noqa: BLE001
        logger.exception("config restore write failed")
        return jsonify({'error': str(e)}), 500

    try:
        resp = _trigger_reload_via_socket()
    except Exception as e:    # noqa: BLE001
        return jsonify({
            'ok': True, 'restored_from': filename, 'backup': backup,
            'reload': {'ok': False, 'error': str(e)},
        })
    return jsonify({
        'ok': True, 'restored_from': filename, 'backup': backup,
        'reload': resp,
    })


@app.route('/api/registry/audit')
def api_registry_audit():
    """Read service_registry_snapshots (reload audit log)."""
    ch = get_ch_client()
    if ch is None:
        return jsonify({'error': 'clickhouse unavailable'}), 503
    try:
        limit = max(1, min(safe_int(request.args.get('limit', 50)), 500))
        rows = ch.execute(f"""
            SELECT timestamp_dt, event_type, source_path,
                   n_protected_ips, n_profiles, n_services, n_catchalls,
                   n_total_slots, reload_count, reload_failures,
                   error_message
            FROM {config.TABLE_REGISTRY_SNAPSHOTS}
            ORDER BY timestamp_dt DESC
            LIMIT %(lim)s
        """, {'lim': limit})
        return jsonify([
            {
                'timestamp': r[0].isoformat(),
                'event_type': r[1],
                'source_path': r[2],
                'n_protected_ips': r[3],
                'n_profiles': r[4],
                'n_services': r[5],
                'n_catchalls': r[6],
                'n_total_slots': r[7],
                'reload_count': r[8],
                'reload_failures': r[9],
                'error_message': r[10],
            }
            for r in rows
        ])
    except Exception as e:  # noqa: BLE001
        logger.exception("api_registry_audit failed")
        return jsonify({'error': str(e)}), 500


@app.route('/api/alerts')
def api_alerts():
    """Phase transitions, most recent first."""
    ch = get_ch_client()
    if ch is None:
        return jsonify({'error': 'clickhouse unavailable'}), 503
    try:
        limit = max(1, min(safe_int(request.args.get(
            'limit', config.DASHBOARD_ALERTS_LIMIT)), 1000))
        rows = ch.execute(f"""
            SELECT timestamp_dt, slot_id, target_ip_str, port, proto_kind,
                   profile_name, from_phase_str, to_phase_str,
                   tier0_score, tier1_final_score, attack_evidence,
                   consecutive_attack_windows, absolute_floor_fired
            FROM {config.TABLE_PHASE_TRANSITIONS}
            ORDER BY timestamp_ns DESC
            LIMIT %(lim)s
        """, {'lim': limit})
        return jsonify([
            {
                'timestamp': r[0].isoformat(),
                'slot_id': r[1],
                'target_ip': r[2],
                'port': r[3],
                'proto_kind': proto_kind_name(int(r[4])),
                'profile_name': r[5],
                'from_phase': r[6],
                'to_phase': r[7],
                'tier0_score': float(r[8]),
                'tier1_final_score': float(r[9]),
                'attack_evidence': float(r[10]),
                'consecutive_attack_windows': r[11],
                'absolute_floor_fired': bool(r[12]),
            }
            for r in rows
        ])
    except Exception as e:  # noqa: BLE001
        logger.exception("api_alerts failed")
        return jsonify({'error': str(e)}), 500


@app.route('/api/audit')
def api_audit():
    """Unified audit stream: phase_transitions ∪ admin_actions ∪
    registry_snapshots, with annotations joined onto transitions.

    Query params:
      limit (int, default 200)  — max rows total
      types (csv, default 'transition,admin,registry')  — event-type filter

    Each row has a `type` ('transition' | 'admin' | 'registry') and a
    `payload` dict with type-specific fields. Annotations on a
    transition appear as payload.annotation = {status, note,
    annotated_at}.
    """
    ch = get_ch_client()
    if ch is None:
        return jsonify({'error': 'clickhouse unavailable'}), 503
    try:
        limit = max(1, min(safe_int(request.args.get('limit', 200)), 1000))
        types_csv = request.args.get('types', 'transition,admin,registry')
        types = set(t.strip() for t in types_csv.split(',') if t.strip())

        events = []

        # --- Transitions (existing service_phase_transitions table) ---
        if 'transition' in types:
            rows = ch.execute(f"""
                SELECT t.timestamp_ns, t.timestamp_dt, t.slot_id,
                       t.target_ip_str, t.port, t.proto_kind, t.profile_name,
                       t.from_phase_str, t.to_phase_str,
                       t.tier0_score, t.tier1_final_score, t.attack_evidence,
                       t.consecutive_attack_windows, t.absolute_floor_fired,
                       a.status, a.note, a.annotated_at_ns
                FROM {config.TABLE_PHASE_TRANSITIONS} AS t
                LEFT JOIN (
                    SELECT transition_ts_ns, slot_id,
                           argMax(status, annotated_at_ns)         AS status,
                           argMax(note, annotated_at_ns)           AS note,
                           max(annotated_at_ns)                    AS annotated_at_ns
                    FROM {config.TABLE_ALERT_ANNOTATIONS}
                    GROUP BY transition_ts_ns, slot_id
                ) AS a
                ON  a.transition_ts_ns = t.timestamp_ns
                AND a.slot_id            = t.slot_id
                ORDER BY t.timestamp_ns DESC
                LIMIT {limit}
            """)
            for r in rows:
                payload = {
                    'slot_id': r[2], 'target_ip': r[3], 'port': r[4],
                    'proto_kind': proto_kind_name(int(r[5])),
                    'profile_name': r[6],
                    'from_phase': r[7], 'to_phase': r[8],
                    'tier0_score': float(r[9]),
                    'tier1_final_score': float(r[10]),
                    'attack_evidence': float(r[11]),
                    'consecutive_attack_windows': r[12],
                    'absolute_floor_fired': bool(r[13]),
                }
                if r[14]:  # annotation present
                    payload['annotation'] = {
                        'status': r[14], 'note': r[15] or '',
                        'annotated_at_ns': int(r[16]) if r[16] else 0,
                    }
                events.append({
                    'type': 'transition',
                    'ts_ns': int(r[0]),
                    'timestamp': r[1].isoformat() if r[1] else None,
                    'payload': payload,
                })

        # --- Admin actions (NEW service_admin_actions table) ---
        if 'admin' in types:
            try:
                rows = ch.execute(f"""
                    SELECT ts_ns, ts_dt, action, args_json,
                           status, result_json, duration_ms
                    FROM {config.TABLE_ADMIN_ACTIONS}
                    ORDER BY ts_ns DESC
                    LIMIT {limit}
                """)
                for r in rows:
                    events.append({
                        'type': 'admin',
                        'ts_ns': int(r[0]),
                        'timestamp': r[1].isoformat() if r[1] else None,
                        'payload': {
                            'action': r[2],
                            'args': json.loads(r[3]) if r[3] else {},
                            'status': r[4],
                            'result': json.loads(r[5]) if r[5] else {},
                            'duration_ms': int(r[6] or 0),
                        },
                    })
            except Exception:    # noqa: BLE001
                # Table may not exist yet on first run; silently skip.
                pass

        # --- Registry snapshots (existing reload audit log) ---
        if 'registry' in types:
            rows = ch.execute(f"""
                SELECT timestamp_dt, event_type, source_path,
                       n_protected_ips, n_profiles, n_services,
                       n_catchalls, n_total_slots,
                       reload_count, reload_failures, error_message
                FROM {config.TABLE_REGISTRY_SNAPSHOTS}
                ORDER BY timestamp_dt DESC
                LIMIT {limit}
            """)
            for r in rows:
                ts_dt = r[0]
                # registry_snapshots uses DateTime (second precision); fake ts_ns
                # for stable cross-source ordering.
                ts_ns = int(ts_dt.timestamp() * 1_000_000_000) if ts_dt else 0
                events.append({
                    'type': 'registry',
                    'ts_ns': ts_ns,
                    'timestamp': ts_dt.isoformat() if ts_dt else None,
                    'payload': {
                        'event_type': r[1],
                        'source_path': r[2],
                        'n_protected_ips': r[3], 'n_profiles': r[4],
                        'n_services': r[5], 'n_catchalls': r[6],
                        'n_total_slots': r[7],
                        'reload_count': r[8], 'reload_failures': r[9],
                        'error': r[10],
                    },
                })

        # Merge-sort by timestamp descending, truncate.
        events.sort(key=lambda e: e['ts_ns'], reverse=True)
        return jsonify(events[:limit])

    except Exception as e:    # noqa: BLE001
        logger.exception("api_audit failed")
        return jsonify({'error': str(e)}), 500


@app.route('/api/audit/annotate', methods=['POST'])
def api_audit_annotate():
    """Annotate a phase-transition event. Body:
       {transition_ts_ns: int, slot_id: int, status: str, note: str}

    status ∈ {'new', 'investigating', 'resolved', 'false_positive'}
    """
    ch = get_ch_client()
    if ch is None:
        return jsonify({'error': 'clickhouse unavailable'}), 503
    body = request.get_json(silent=True) or {}
    try:
        ts_ns = int(body.get('transition_ts_ns'))
        slot_id = int(body.get('slot_id'))
        status = str(body.get('status', 'investigating'))
        note = str(body.get('note', ''))
    except (TypeError, ValueError):
        return jsonify({'error': 'bad fields'}), 400
    if status not in ('new', 'investigating', 'resolved', 'false_positive'):
        return jsonify({'error': f'bad status: {status!r}'}), 400

    now_ns = int(datetime.now().timestamp() * 1_000_000_000)
    try:
        ch.execute(
            f"INSERT INTO {config.TABLE_ALERT_ANNOTATIONS} "
            f"(transition_ts_ns, slot_id, annotated_at_ns, status, note) "
            f"VALUES",
            [(ts_ns, slot_id, now_ns, status, note)])
        return jsonify({'ok': True, 'annotated_at_ns': now_ns})
    except Exception as e:    # noqa: BLE001
        logger.exception("api_audit_annotate failed")
        return jsonify({'error': str(e)}), 500


@app.route('/api/health')
def api_health():
    """Liveness + freshness probe. degraded if data is >5min stale."""
    ch = get_ch_client()
    if ch is None:
        return jsonify({'status': 'degraded', 'ch_reachable': False,
                        'error': 'driver unavailable'}), 503
    try:
        rows = ch.execute(
            f"SELECT max(timestamp_dt) FROM {config.TABLE_SERVICE_STATS}")
        latest = rows[0][0] if rows and rows[0][0] else None
        status = 'ok'
        if latest is None or (datetime.now() - latest).total_seconds() > 300:
            status = 'degraded'
        return jsonify({
            'status': status,
            'ch_reachable': True,
            'latest_timestamp': latest.isoformat() if latest else None,
        })
    except Exception as e:  # noqa: BLE001
        return jsonify({'status': 'error', 'ch_reachable': False,
                        'error': str(e)}), 503


def main():
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s %(levelname)s [%(name)s] %(message)s',
    )
    logger.info("=== Anti-DDoS dashboard starting on %s:%s ===",
                config.FLASK_HOST, config.FLASK_PORT)
    logger.info("ClickHouse: %s:%s/%s",
                config.CH_HOST, config.CH_PORT, config.CH_DB)
    app.run(
        host=config.FLASK_HOST,
        port=config.FLASK_PORT,
        debug=config.FLASK_DEBUG,
        use_reloader=False,
        threaded=True,
    )


if __name__ == '__main__':
    main()
