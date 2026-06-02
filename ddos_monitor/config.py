# ============================================================================
# CLICKHOUSE DATABASE CONFIGURATION
# ============================================================================
CH_HOST = 'localhost'
CH_PORT = 9000
CH_USER = 'default'
import os as _os
CH_PASSWORD = _os.environ.get('CH_PASSWORD')
if CH_PASSWORD is None:
    # Fall back to legacy hardcoded value ONLY for dev convenience.
    # In production (systemd), EnvironmentFile=/etc/anti-ddos/env supplies this.
    # Remove the fallback entirely after P15 verification.
    import sys as _sys
    print("[config] WARNING: CH_PASSWORD not set in environment. "
          "Production deployment requires /etc/anti-ddos/env. "
          "Falling back to dev default — DO NOT use in production.",
          file=_sys.stderr)
    CH_PASSWORD = 'sardor1217'
CH_DB = 'ddos_detection'
CH_TABLE = 'traffic_stats'

# Multi-timescale temporal observability table. Mirrors the locked
# 79-field TEMP record produced by C l2_temporal_update_1s(); see
# database.py for the column order and the unfilled-column note.
CH_TEMPORAL_TABLE = 'dst_ip_temporal_stats'

# ============================================================================
# UNIX SOCKET CONFIGURATION
# ============================================================================
SOCK_PATH = '/tmp/ddos_stats_socket'
BUFFER_SIZE = 65536

# Dedicated Unix-domain socket for TEMP records. Must match the
# TEMPORAL_SOCK_PATH define in l2fwd_ddos_collector.c — TEMP records
# are emitted only on this socket and never on SOCK_PATH.
TEMPORAL_SOCK_PATH = '/tmp/ddos_temporal_socket'

# ============================================================================
# BATCH PROCESSING CONFIGURATION
# ============================================================================
BATCH_SIZE = 100              # Records per database batch insert
RAM_BUFFER_SIZE = 1000        # Records to keep in RAM for dashboard

# Independent ring buffer for TEMP records served by the dashboard.
# Sized like RAM_BUFFER_SIZE; cadence is much lower (≤3 records per
# active dst_ip per 10s) so this is plenty of headroom.
TEMPORAL_RAM_BUFFER_SIZE = 1000

# Locked TEMP-line wire format. The C formatter emits exactly 79 fields
# (field 0 is the literal "TEMP" record-type token; fields 1..78 are
# the data columns persisted to dst_ip_temporal_stats). Any change to
# the C formatter MUST bump L2_TEMP_SCHEMA_VERSION on the C side and
# add the new value to TEMPORAL_SUPPORTED_SCHEMA_VERS here in the same
# commit.
TEMPORAL_EXPECTED_FIELDS = 79
TEMPORAL_SUPPORTED_SCHEMA_VERS = (1,)

# ============================================================================
# FLASK WEB SERVER CONFIGURATION
# ============================================================================
FLASK_HOST = '0.0.0.0'
FLASK_PORT = 5000
FLASK_DEBUG = False

# ============================================================================
# P11/P12 — PER-SERVICE COLLECTOR CONFIGURATION
#
# Added for the per-service architecture (P0-P10). The legacy constants
# above are PRESERVED unchanged — the legacy web.py / database.py still
# import them. The new collector (collector.py rewritten in P12) reads
# only the constants in this section plus the legacy CH_* credentials.
# ============================================================================

# Unix-domain socket the C engine emits binary wire-protocol messages on.
# Same path as the legacy SOCK_PATH — the engine's hotpath connects here
# as a CLIENT, so the collector binds it as a SERVER (see collector.py).
ENGINE_SOCKET_PATH = SOCK_PATH

# Wire protocol v2 constants — must match l2fwd_service_wire.h byte-for-byte.
WIRE_MAGIC        = b'L2FW'
WIRE_VERSION      = 0x02
WIRE_MSGTYPE_SNAP = 0x01
WIRE_MSG_SIZE     = 468
WIRE_HEADER_SIZE  = 32
WIRE_PAYLOAD_SIZE = 432
WIRE_FOOTER_SIZE  = 4

# Header flags byte at buffer offset 6 (mirrors L2FWD_WIRE_FLAG_* in
# l2fwd_service_wire.h). bit 0 = the transition into ATTACK was forced by the
# absolute volumetric floor (bypassed the gated cascade).
WIRE_FLAG_ABSOLUTE_FLOOR = 0x01

# Collector runtime tuning.
COLLECTOR_QUEUE_MAX_SIZE  = 10000   # bounded queue; drop-oldest under backpressure
COLLECTOR_BATCH_SIZE      = 100     # rows per ClickHouse INSERT
COLLECTOR_BATCH_TIMEOUT_S = 1.0     # flush a partial batch after N seconds
COLLECTOR_RECONNECT_DELAY_S = 1.0   # wait between socket reconnect attempts
COLLECTOR_LOG_LEVEL       = "INFO"
COLLECTOR_STATS_INTERVAL_S = 10     # periodic stats log cadence

# New per-service table names (created by scripts/migrate_clickhouse_schema.py).
TABLE_SERVICE_STATS       = "service_stats"
TABLE_PHASE_TRANSITIONS   = "service_phase_transitions"
TABLE_TEMPORAL_AGGREGATES = "service_temporal_aggregates"
TABLE_REGISTRY_SNAPSHOTS  = "service_registry_snapshots"
# Interactive-dashboard tables (created on demand via CREATE TABLE IF NOT EXISTS
# at collector startup — Phase 3+ of the interactive dashboard).
TABLE_ADMIN_ACTIONS       = "service_admin_actions"
TABLE_ALERT_ANNOTATIONS   = "service_alert_annotations"

# Path for the collector's control-socket listener (Phase 2 onwards).
CONTROL_SOCKET_PATH       = "/tmp/anti-ddos-control.sock"

# Legacy table preserved (renamed, never dropped) by the migration.
TABLE_TRAFFIC_STATS_LEGACY = "traffic_stats_legacy"

# ============================================================================
# DETECTION (Python brain off the shared-memory snapshot)
#
# Since the P5 cutover the collector reads the raw-telemetry snapshot from
# shared memory and runs the Python detection brain (ddos_monitor/detection);
# the verdict lands in the SAME ClickHouse tables (the writer is unchanged).
# The legacy C-engine wire path was removed — to revert the migration, use git.
# ============================================================================

# Shared-memory object the C snapshot producer publishes to (mirrors
# SERVICE_SNAPSHOT_SHM_PATH in engine/l2fwd_service_snapshot.h).
SHM_PATH = _os.environ.get("SHM_PATH", "/dev/shm/anti_ddos_snapshot")

# services.json the detector loads for per-slot profiles + learning_mode. MUST
# be the same file the engine runs with (the Makefile copies it to /tmp/svc.json
# and points both the engine and the collector at it).
SERVICES_JSON_PATH = _os.environ.get("SERVICES_JSON_PATH",
                                     "/etc/anti-ddos/services.json")

# Detector state checkpoint — survives collector restarts so we resume from
# learned baselines instead of a ~400-window cold warmup.
DETECTOR_CHECKPOINT_PATH = _os.environ.get(
    "DETECTOR_CHECKPOINT_PATH", "/var/lib/anti-ddos/detector_state.ckpt")
DETECTOR_CHECKPOINT_INTERVAL_S = 30   # periodic checkpoint cadence (seconds)

# Snapshot poll cadence — just above the engine's 1 Hz publish so a new bank is
# picked up promptly without busy-spinning.
SHM_POLL_INTERVAL_S = 0.2

# ============================================================================
# TARGET IP / SUBNET FILTER
# Only dst_ip addresses falling within these networks are processed.
# Entries can be single IPs ("1.2.3.4") or CIDR subnets ("1.2.3.0/24").
# ============================================================================
TARGET_PREFIXES = [

    "213.230.125.0/29",

    "185.203.236.180/30",

    "93.188.85.124/30",

    "93.188.85.232/30",

    "45.150.25.136/29",

    "213.230.125.240/29",

    "94.141.85.109/32",

    "94.141.85.110/32",

    "213.230.125.16/28",

    "213.230.125.48/30",

    "213.230.125.128/30",

    "89.249.63.92/30",

    "185.203.236.64/27",

    "213.230.125.64/29",

    "94.141.85.105/32",

    "93.188.85.220/30",

    "89.249.63.112/29",

    "89.249.62.16/29",

    "89.249.62.130/32",

    "89.249.62.131/32",

    "89.249.62.132/32",

    "89.249.62.133/32",

    "89.249.62.134/32",

    "89.249.63.128/29",

    "89.249.62.136/29",

    "89.249.62.156/30",

    "89.249.63.84/30",

    "185.203.236.96/29",

    "45.150.25.240/29",

    "185.203.236.224/30",

    "94.141.85.107/32",

    "94.141.85.108/32",

    "185.203.237.16/29",

    "45.150.25.192/29",

    "185.203.237.176/30",

    "45.150.25.0/28",

    "89.249.63.176/30",

    "89.249.63.196/30",

    "185.203.236.172/30",

    "185.203.237.180/30",

    "185.203.237.24/30",

    "45.150.25.72/29",

    "45.150.25.96/30",

    "89.249.62.152/30",

    "45.150.25.248/30",

    "93.188.85.80/29",

    "93.188.85.164/30",

    "93.188.85.200/29",

    "93.188.85.212/30",

    "213.230.125.44/30",

    "213.230.125.104/29",

    "89.249.63.180/30",

    "213.230.125.160/27",

    "45.150.25.100/30",

    "89.249.63.140/30",

    "185.203.236.32/29",

    "185.203.236.48/28",

    "185.203.236.176/30",

    "185.203.236.40/29",

    "185.203.237.12/30",

    "213.230.125.144/28",

    "89.249.63.40/29",

    "89.249.63.32/30",

    "89.249.63.208/28",

    "89.249.63.36/30",

    "45.150.25.104/29",

    "45.150.25.124/30",

    "93.188.85.208/30",

    "93.188.85.160/30",

    "93.188.85.96/28",

    "185.203.236.248/29",

    "93.188.85.228/30",

    "185.203.236.168/30",

    "185.203.236.104/30",

    "45.150.25.64/30",

    "185.203.236.113/28",

    "185.203.236.128/29",

    "185.203.236.136/29",

    "94.141.85.72/29",

    "93.188.85.192/30",

    "213.230.125.120/29",

    "185.203.236.108/30",

    "89.249.63.100/30",

    "89.249.63.144/28",

    "45.150.25.68/30",

    "45.150.25.200/29",

    "89.249.63.160/28",

    "45.150.25.114/32",

    "45.150.25.115/32",

    "45.150.25.116/32",

    "45.150.25.117/32",

    "45.150.25.118/32",

    "94.141.85.80/28",

    "94.141.85.176/29",

    "89.249.63.18/32",

    "89.249.63.16/28",

    "89.249.63.19/32",

    "89.249.63.20/32",

    "89.249.63.21/32",

    "89.249.63.22/32",

    "89.249.63.24/32",

    "89.249.63.23/32",

    "89.249.63.25/32",

    "89.249.63.26/32",

    "89.249.63.27/32",

    "89.249.63.28/32",

    "94.141.85.98/32",

    "94.141.85.99/32",

    "94.141.85.100/32",

    "94.141.85.102/32",

    "94.141.85.103/32",

    "94.141.85.106/32",

    "94.141.85.149/32",

    "94.141.85.104/32",

    "94.141.85.152/32",

    "94.141.85.154/32",

    "94.141.85.156/32",

    "94.141.85.153/32",

    "94.141.85.147/32",

    "94.141.85.151/32",

    "94.141.85.150/32",

    "94.141.85.148/32",

    "94.141.85.157/32",

    "94.141.85.158/32",

    "94.141.85.146/32",

    "185.203.236.183/32",

    "185.203.236.198/32",

    "185.203.236.181/32",

    "185.203.236.182/32",

    "185.203.237.25/32",

    "185.203.237.26/32",

    "185.203.237.181/32",

    "185.203.237.182/32",

    "89.249.62.129/32",

    "94.141.85.244/32",

    "45.150.25.170/32",

    "213.230.125.129/32",

    "213.230.125.130/32",

    "213.230.125.73/32",

    "213.230.125.74/32",

    "213.230.125.75/32",

    "213.230.125.76/32",

    "213.230.125.77/32",

    "213.230.125.78/32",

    "213.230.125.33/32",

    "213.230.125.34/32",

    "213.230.125.37/32",

    "213.230.125.38/32",

    "185.203.237.17/32",

    "185.203.237.18/32",

    "185.203.237.19/32",

    "185.203.237.20/32",

    "185.203.237.21/32",

    "185.203.237.22/32",

    "45.150.25.171/32",

    "89.249.62.46/32",

    "89.249.62.47/32",
]

# ============================================================================
# P14 — DASHBOARD CONFIGURATION
#
# Added for the per-service web dashboard (ddos_monitor/web.py). All
# constants above are PRESERVED unchanged. The dashboard reads only from
# ClickHouse (the TABLE_* names + CH_* credentials) — never from
# shared_state or database.py.
# ============================================================================
DASHBOARD_REFRESH_SECONDS           = 1     # browser auto-refresh interval
DASHBOARD_TIMESERIES_WINDOW_SECONDS = 300   # 5-min window for slot-detail charts
DASHBOARD_ALERTS_LIMIT              = 100   # max rows on the Alerts tab
DASHBOARD_OVERVIEW_RECENT_SECONDS   = 60    # "recent activity" window on Overview

# Slots whose last heartbeat is older than this are considered
# dormant and excluded from the dashboard's services view.
# Default 60s allows for brief network blips while still hiding
# slots that were retired (e.g., after registry reconfiguration).
DASHBOARD_SLOT_FRESHNESS_SECONDS    = 60

SERVICES_JSON_PATH                  = "/tmp/svc.json"  # live registry for Registry tab

