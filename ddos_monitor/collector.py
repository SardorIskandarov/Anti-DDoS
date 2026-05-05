import socket
import os
import time
from datetime import datetime
from ipaddress import ip_address, ip_network
import config
import database
import shared_state


# ---------------------------------------------------------------------------
# Build a frozenset of target networks once at import time so the per-record
# lookup is a simple "any(addr in net …)" check.
# ---------------------------------------------------------------------------
_TARGET_NETS = frozenset(
    ip_network(prefix, strict=False) for prefix in config.TARGET_PREFIXES
)


def _is_target_ip(ip_str):
    """Return True if *ip_str* falls within any configured target prefix."""
    try:
        addr = ip_address(ip_str)
        return any(addr in net for net in _TARGET_NETS)
    except ValueError:
        return False


# ============================================================================
# CSV SCHEMA  (60 columns total, 58/52-column legacy formats still accepted)
# ============================================================================
#
#  Header (3):
#    0  timestamp_ms
#    1  port
#    2  dst_ip
#
#  Tier 0 raw features (6):
#    3  pps
#    4  bps
#    5  fps
#    6  burst_pps
#    7  burst_bps
#    8  burst_fps
#
#  Tier 1.1 TCP raw features (7):
#    9  tcp_syn_ratio
#   10  tcp_synack_ratio
#   11  tcp_finack_ratio
#   12  tcp_rst_ratio
#   13  tcp_ack_data_ratio
#   14  tcp_pps_ratio
#   15  tcp_bps_ratio
#
#  Tier 1.2 UDP raw features (3):
#   16  udp_bps_ratio
#   17  udp_pps_ratio
#   18  udp_flow_ratio
#
#  Tier 1.3 ICMP raw features (2):
#   19  icmp_echo_ratio
#   20  icmp_pps_ratio
#
#  Tier 1.4 Distribution raw features (2):
#   21  src_ip_ratio
#   22  dst_port_ratio
#
#  Tier 0 EWMA means (6):
#   23  em_pps
#   24  em_bps
#   25  em_fps
#   26  em_burst_pps
#   27  em_burst_bps
#   28  em_burst_fps
#
#  Tier 1.1 EWMA means (7):
#   29  em_tcp_syn_ratio
#   30  em_tcp_synack_ratio
#   31  em_tcp_finack_ratio
#   32  em_tcp_rst_ratio
#   33  em_tcp_ack_data_ratio
#   34  em_tcp_pps_ratio
#   35  em_tcp_bps_ratio
#
#  Tier 1.2 EWMA means (3):
#   36  em_udp_bps_ratio
#   37  em_udp_pps_ratio
#   38  em_udp_flow_ratio
#
#  Tier 1.3 EWMA means (2):
#   39  em_icmp_echo_ratio
#   40  em_icmp_pps_ratio
#
#  Tier 1.4 EWMA means (2):
#   41  em_src_ip_ratio
#   42  em_dst_port_ratio
#
#  Detection fields (15):
#   43  detection_state         (string: WARMUP|NORMAL|SUSPICIOUS|ATTACK|RECOVERING)
#   44  tier0_global_risk       (float, fused Tier-0 continuous risk)
#   45  tier0_risk_pps          (float [0,1])
#   46  tier0_risk_bps          (float [0,1])
#   47  tier0_risk_fps          (float [0,1])
#   48  tier0_risk_burst_pps    (float [0,1])
#   49  tier0_risk_burst_bps    (float [0,1])
#   50  tier0_risk_burst_fps    (float [0,1])
#   51  tier1_tcp_score         (float [0,1])
#   52  tier1_udp_score         (float [0,1])
#   53  tier1_icmp_score        (float [0,1])
#   54  tier1_dist_score        (float [0,1])
#   55  tier1_final_score       (float [0,1], worst-case across sub-tiers)
#   56  tier1_evaluated         (int 0|1)
#   57  warmup_remaining        (int, windows left in warm-up phase)
# 
#  HLL observability fields (2):
#   58  unique_src_ips          (int, HyperLogLog-estimated count)
#   59  unique_dst_ports        (int, HyperLogLog-estimated count)
#
#  Layer-2 profile identity (2, appended):
#   60  profile_name            (string)
#   61  profile_version         (string)

# ----------------------------------------------------------------------------
# Field schema — (name, type) pairs listed in the EXACT order emitted by the
# C snprintf() in ddos_log_and_reset_stats(). Editing either side requires
# editing the other; the column count is enforced below.
# ----------------------------------------------------------------------------
CSV_FIELDS = [
    # ── Header (3) ─────────────────────────────────────────────────────
    ('timestamp_ms',           'ts_ms'),
    ('port',                   'int'),
    ('dst_ip',                 'str'),

    # ── Tier 0 raw (6) ─────────────────────────────────────────────────
    ('pps',                    'float'),
    ('bps',                    'float'),
    ('fps',                    'float'),
    ('burst_pps',              'float'),
    ('burst_bps',              'float'),
    ('burst_fps',              'float'),

    # ── Tier 1.1 TCP raw (7) ───────────────────────────────────────────
    ('tcp_syn_ratio',          'float'),
    ('tcp_synack_ratio',       'float'),
    ('tcp_finack_ratio',       'float'),
    ('tcp_rst_ratio',          'float'),
    ('tcp_ack_data_ratio',     'float'),
    ('tcp_pps_ratio',          'float'),
    ('tcp_bps_ratio',          'float'),

    # ── Tier 1.2 UDP raw (3) ───────────────────────────────────────────
    ('udp_bps_ratio',          'float'),
    ('udp_pps_ratio',          'float'),
    ('udp_flow_ratio',         'float'),

    # ── Tier 1.3 ICMP raw (2) ──────────────────────────────────────────
    ('icmp_echo_ratio',        'float'),
    ('icmp_pps_ratio',         'float'),

    # ── Tier 1.4 Distribution raw (2) ──────────────────────────────────
    ('src_ip_ratio',           'float'),
    ('dst_port_ratio',         'float'),

    # ── Tier 0 EWMA means (6) ──────────────────────────────────────────
    ('em_pps',                 'float'),
    ('em_bps',                 'float'),
    ('em_fps',                 'float'),
    ('em_burst_pps',           'float'),
    ('em_burst_bps',           'float'),
    ('em_burst_fps',           'float'),

    # ── Tier 1.1 TCP EWMA means (7) ────────────────────────────────────
    ('em_tcp_syn_ratio',       'float'),
    ('em_tcp_synack_ratio',    'float'),
    ('em_tcp_finack_ratio',    'float'),
    ('em_tcp_rst_ratio',       'float'),
    ('em_tcp_ack_data_ratio',  'float'),
    ('em_tcp_pps_ratio',       'float'),
    ('em_tcp_bps_ratio',       'float'),

    # ── Tier 1.2 UDP EWMA means (3) ────────────────────────────────────
    ('em_udp_bps_ratio',       'float'),
    ('em_udp_pps_ratio',       'float'),
    ('em_udp_flow_ratio',      'float'),

    # ── Tier 1.3 ICMP EWMA means (2) ───────────────────────────────────
    ('em_icmp_echo_ratio',     'float'),
    ('em_icmp_pps_ratio',      'float'),

    # ── Tier 1.4 Distribution EWMA means (2) ───────────────────────────
    ('em_src_ip_ratio',        'float'),
    ('em_dst_port_ratio',      'float'),

    # ── Detection fields (15) ──────────────────────────────────────────
    ('detection_state',        'str'),
    ('tier0_global_risk',      'float'),
    ('tier0_risk_pps',         'float'),
    ('tier0_risk_bps',         'float'),
    ('tier0_risk_fps',         'float'),
    ('tier0_risk_burst_pps',   'float'),
    ('tier0_risk_burst_bps',   'float'),
    ('tier0_risk_burst_fps',   'float'),
    ('tier1_tcp_score',        'float'),
    ('tier1_udp_score',        'float'),
    ('tier1_icmp_score',       'float'),
    ('tier1_dist_score',       'float'),
    ('tier1_final_score',      'float'),
    ('tier1_evaluated',        'bool'),
    ('warmup_remaining',       'int'),

    # ── HLL observability fields (2) ───────────────────────────────────
    ('unique_src_ips',         'int'),
    ('unique_dst_ports',       'int'),

    # ── Layer-2 profile identity (2) ───────────────────────────────────
    ('profile_name',           'str'),
    ('profile_version',        'str'),
]

EXPECTED_CSV_FIELDS = len(CSV_FIELDS)  # 62
assert EXPECTED_CSV_FIELDS == 62, f"CSV schema drift: {EXPECTED_CSV_FIELDS} fields"

# Accept legacy 60-column lines from a pre-profile C binary so a partial
# upgrade doesn't drop telemetry. Missing profile fields are filled in
# with the "default" identity, which matches the C-side fallback.
LEGACY_CSV_FIELDS = 60


def _coerce(raw, kind):
    if kind == 'ts_ms':
        return datetime.fromtimestamp(int(raw) / 1000.0)
    if kind == 'int':
        return int(raw)
    if kind == 'float':
        return float(raw)
    if kind == 'bool':
        return bool(int(raw))
    return raw  # 'str'


# ============================================================================
# TEMP RECORD PARSER (multi-timescale temporal observability)
# ============================================================================
#
# Locked 79-field comma-separated line emitted by C l2_temporal_update_1s().
# Field 0 is the literal "TEMP" record-type token; fields 1..78 are the
# data columns persisted 1:1 to dst_ip_temporal_stats. Any change to the
# C formatter MUST bump L2_TEMP_SCHEMA_VERSION on the C side AND update
# this parser, _TEMPORAL_INSERT_COLUMNS in database.py, and the CREATE
# TABLE statement in the same commit.
#
# Field index reference (0-based parts[]; matches database.py
# _TEMPORAL_INSERT_COLUMNS in lockstep):
#   parts[0]    "TEMP"
#   parts[1]    schema_ver        (must equal a value in
#                                   config.TEMPORAL_SUPPORTED_SCHEMA_VERS)
#   parts[2]    rollup_ver
#   parts[3]    timestamp_ms      → DB column `timestamp` (DateTime64)
#   parts[4]    port
#   parts[5]    dst_ip
#   parts[6]    window_sec
#   parts[7]    bucket_epoch_ms
#   parts[8]    valid_seconds
#   parts[9]    baseline_ready
#   parts[10]   temporal_state
#   parts[11..28]  volume          (3 metrics × 6: avg, em, ratio, z,
#                                   min, max — ordering pps → bps → fps)
#   parts[29..42]  protocol-share pairs  (7 × 2: cur, baseline)
#   parts[43..52]  TCP-flag pairs        (5 × 2: cur, baseline)
#   parts[53..56]  distribution pairs    (2 × 2: cur, baseline)
#   parts[57..69]  raw counters          (13)
#   parts[70..73]  per-state seconds     (normal, warmup, suspicious,
#                                          attack)
#   parts[74..78]  scores                (volume, protocol_shift,
#                                          persistence, ramp,
#                                          temporal_score)


def parse_temporal_line(line):
    """Parse one TEMP record line.

    Returns a dict whose keys exactly match `database._TEMPORAL_INSERT_COLUMNS`
    on success, or None on any structural / type / version mismatch.
    Errors are logged but never raised — the caller MUST be able to
    drop a malformed TEMP line without breaking either collector thread.
    """
    parts = line.strip().split(',')

    if len(parts) != config.TEMPORAL_EXPECTED_FIELDS:
        print(f"[Collector] Bad TEMP: expected "
              f"{config.TEMPORAL_EXPECTED_FIELDS} fields, got {len(parts)}")
        return None

    if parts[0] != 'TEMP':
        return None

    try:
        schema_ver = int(parts[1])
        if schema_ver not in config.TEMPORAL_SUPPORTED_SCHEMA_VERS:
            print(f"[Collector] TEMP unsupported schema_ver={schema_ver}, "
                  f"dropping")
            return None

        # The dict below is the SOLE source of truth for the row written
        # to dst_ip_temporal_stats. Its keys match _TEMPORAL_INSERT_COLUMNS
        # 1:1 in name and order; no placeholder fields, no fields dropped.
        return {
            # Header (10) — TEMP fields 1..10
            'schema_ver':       schema_ver,
            'rollup_ver':       int(parts[2]),
            'timestamp':        datetime.fromtimestamp(int(parts[3]) / 1000.0),
            'port':             int(parts[4]),
            'dst_ip':           parts[5],
            'window_sec':       int(parts[6]),
            'bucket_epoch_ms':  int(parts[7]),
            'valid_seconds':    int(parts[8]),
            'baseline_ready':   int(parts[9]),
            'temporal_state':   parts[10],

            # Volume (18) — TEMP fields 11..28
            'avg_pps':   float(parts[11]),
            'em_pps':    float(parts[12]),
            'ratio_pps': float(parts[13]),
            'z_pps':     float(parts[14]),
            'min_pps':   float(parts[15]),
            'max_pps':   float(parts[16]),
            'avg_bps':   float(parts[17]),
            'em_bps':    float(parts[18]),
            'ratio_bps': float(parts[19]),
            'z_bps':     float(parts[20]),
            'min_bps':   float(parts[21]),
            'max_bps':   float(parts[22]),
            'avg_fps':   float(parts[23]),
            'em_fps':    float(parts[24]),
            'ratio_fps': float(parts[25]),
            'z_fps':     float(parts[26]),
            'min_fps':   float(parts[27]),
            'max_fps':   float(parts[28]),

            # Protocol-share pairs (14) — TEMP fields 29..42
            'tcp_pps_ratio':      float(parts[29]),
            'em_tcp_pps_ratio':   float(parts[30]),
            'tcp_bps_ratio':      float(parts[31]),
            'em_tcp_bps_ratio':   float(parts[32]),
            'udp_pps_ratio':      float(parts[33]),
            'em_udp_pps_ratio':   float(parts[34]),
            'udp_bps_ratio':      float(parts[35]),
            'em_udp_bps_ratio':   float(parts[36]),
            'udp_flow_ratio':     float(parts[37]),
            'em_udp_flow_ratio':  float(parts[38]),
            'icmp_pps_ratio':     float(parts[39]),
            'em_icmp_pps_ratio':  float(parts[40]),
            'icmp_echo_ratio':    float(parts[41]),
            'em_icmp_echo_ratio': float(parts[42]),

            # TCP-flag pairs (10) — TEMP fields 43..52
            'tcp_syn_ratio':         float(parts[43]),
            'em_tcp_syn_ratio':      float(parts[44]),
            'tcp_synack_ratio':      float(parts[45]),
            'em_tcp_synack_ratio':   float(parts[46]),
            'tcp_finack_ratio':      float(parts[47]),
            'em_tcp_finack_ratio':   float(parts[48]),
            'tcp_rst_ratio':         float(parts[49]),
            'em_tcp_rst_ratio':      float(parts[50]),
            'tcp_ack_data_ratio':    float(parts[51]),
            'em_tcp_ack_data_ratio': float(parts[52]),

            # Distribution pairs (4) — TEMP fields 53..56
            'src_ip_ratio':      float(parts[53]),
            'em_src_ip_ratio':   float(parts[54]),
            'dst_port_ratio':    float(parts[55]),
            'em_dst_port_ratio': float(parts[56]),

            # Raw counters (13) — TEMP fields 57..69
            'total_pkts':     int(parts[57]),
            'total_bytes':    int(parts[58]),
            'tcp_pkts':       int(parts[59]),
            'tcp_bytes':      int(parts[60]),
            'udp_pkts':       int(parts[61]),
            'udp_bytes':      int(parts[62]),
            'icmp_pkts':      int(parts[63]),
            'icmp_echo_pkts': int(parts[64]),
            'syn_pkts':       int(parts[65]),
            'synack_pkts':    int(parts[66]),
            'finack_pkts':    int(parts[67]),
            'rst_pkts':       int(parts[68]),
            'ack_data_pkts':  int(parts[69]),

            # Per-state seconds (4) — TEMP fields 70..73
            'normal_seconds':     int(parts[70]),
            'warmup_seconds':     int(parts[71]),
            'suspicious_seconds': int(parts[72]),
            'attack_seconds':     int(parts[73]),

            # Scores (5) — TEMP fields 74..78
            'volume_score':         float(parts[74]),
            'protocol_shift_score': float(parts[75]),
            'persistence_score':    float(parts[76]),
            'ramp_score':           float(parts[77]),
            'temporal_score':       float(parts[78]),
        }
    except Exception as e:
        print(f"[Collector] TEMP parse error: {e}")
        return None


def parse_csv_line(line):
    """Parse one CSV line emitted by ddos_log_and_reset_stats().

    The mapping of CSV columns to dict keys is driven by CSV_FIELDS so that
    the parser stays in lock-step with the C snprintf format. Any drift in
    column count is rejected up-front to prevent silent index shifting.
    """
    parts = line.strip().split(',')

    if len(parts) == LEGACY_CSV_FIELDS:
        # Legacy pre-profile line: synthesize the two profile-identity
        # fields so downstream code can treat the record uniformly.
        parts = parts + ['default', 'v1']

    if len(parts) != EXPECTED_CSV_FIELDS:
        print(f"[Collector] Bad CSV: expected {EXPECTED_CSV_FIELDS} "
              f"fields, got {len(parts)}")
        return None

    try:
        record = {}
        for (name, kind), raw in zip(CSV_FIELDS, parts):
            if name == 'timestamp_ms':
                record['timestamp'] = _coerce(raw, kind)
            else:
                record[name] = _coerce(raw, kind)
        return record
    except Exception as e:
        print(f"[Collector] Parse error: {e}")
        return None


# ============================================================================
# COLLECTOR THREAD
# ============================================================================

def dpdk_collector_thread():
    """Background thread — receives CSV lines from the DPDK process."""

    try:
        client = database.get_db_client()
        print("[Collector] Database connection established")
    except Exception as e:
        print(f"[Collector] Database connection failed: {e}")
        return

    if os.path.exists(config.SOCK_PATH):
        os.unlink(config.SOCK_PATH)

    server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    server.bind(config.SOCK_PATH)
    server.listen(1)
    print(f"[Collector] Listening on {config.SOCK_PATH} …")

    while True:
        try:
            conn, _ = server.accept()
            print("[Collector] DPDK application connected")

            buf              = ""
            db_batch         = []
            records_received = 0

            while True:
                data = conn.recv(config.BUFFER_SIZE)
                if not data:
                    print("[Collector] DPDK disconnected")
                    if db_batch:
                        database.batch_insert(client, db_batch)
                        db_batch = []
                    break

                buf += data.decode('utf-8', errors='ignore')

                while '\n' in buf:
                    line, buf = buf.split('\n', 1)
                    if not line.strip():
                        continue
                    # This collector is for the 62-field IP CSV stream
                    # ONLY. TEMP records arrive on the separate
                    # TEMPORAL_SOCK_PATH and are handled by
                    # dpdk_temporal_collector_thread(); the C side never
                    # emits TEMP on SOCK_PATH, so any line that reaches
                    # us here is fed straight to the strict 62-field
                    # parse_csv_line() unchanged.
                    try:
                        record = parse_csv_line(line)
                        if not record:
                            continue

                        if not _is_target_ip(record['dst_ip']):
                            continue

                        # Guarantee profile identity is present on every
                        # record reaching RAM / DB, independent of which
                        # CSV-version produced the line. The parser already
                        # fills these in for 62-column and 60-column lines;
                        # setdefault is a cheap insurance policy for any
                        # future ingestion path that bypasses parse_csv_line.
                        record.setdefault('profile_name', 'default')
                        record.setdefault('profile_version', 'v1')

                        state = record['detection_state']
                        if state in ('SUSPICIOUS', 'ATTACK'):
                            t1_ev = record['tier1_evaluated']
                            print(f"[ALERT] {state} | IP={record['dst_ip']} "
                                  f"profile={record['profile_name']}/"
                                  f"{record['profile_version']} "
                                  f"t0_risk={record['tier0_global_risk']:.3f}",
                                  end="")
                            if t1_ev:
                                print(f" tcp={record['tier1_tcp_score']:.3f}"
                                      f" udp={record['tier1_udp_score']:.3f}"
                                      f" icmp={record['tier1_icmp_score']:.3f}"
                                      f" dist={record['tier1_dist_score']:.3f}"
                                      f" final={record['tier1_final_score']:.3f}",
                                      end="")
                            print()

                        with shared_state.data_lock:
                            shared_state.latest_traffic_data.insert(0, record)
                            shared_state.latest_traffic_data = \
                                shared_state.latest_traffic_data[:config.RAM_BUFFER_SIZE]

                        db_batch.append(record)
                        records_received += 1

                        if len(db_batch) >= config.BATCH_SIZE:
                            database.batch_insert(client, db_batch)
                            # print(f"[Collector] Records so far: {records_received}")
                            db_batch = []

                    except Exception as e:
                        print(f"[Collector] Record error: {e}")

            conn.close()
            print("[Collector] Waiting for next connection …")

        except Exception as e:
            print(f"[Collector] Error: {e}")
            time.sleep(1)


# ============================================================================
# TEMPORAL COLLECTOR THREAD
# ============================================================================
#
# Listens on the dedicated TEMPORAL_SOCK_PATH for TEMP records produced
# by C l2_temporal_update_1s(). Mirrors dpdk_collector_thread's
# accept-then-loop structure but only handles the 79-field TEMP schema:
# any non-TEMP line is logged and dropped. Failures here are local —
# the IP path on SOCK_PATH is on a separate thread and a separate fd,
# so a temporal hiccup cannot affect existing 1-second IP records.
def dpdk_temporal_collector_thread():
    """Background thread — receives TEMP records on the dedicated
    temporal Unix socket and persists them to dst_ip_temporal_stats."""

    try:
        client = database.get_db_client()
        print("[Collector/Temporal] Database connection established")
    except Exception as e:
        print(f"[Collector/Temporal] Database connection failed: {e}")
        return

    if os.path.exists(config.TEMPORAL_SOCK_PATH):
        os.unlink(config.TEMPORAL_SOCK_PATH)

    server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    server.bind(config.TEMPORAL_SOCK_PATH)
    server.listen(1)
    print(f"[Collector/Temporal] Listening on {config.TEMPORAL_SOCK_PATH} …")

    while True:
        try:
            conn, _ = server.accept()
            print("[Collector/Temporal] DPDK temporal stream connected")

            buf               = ""
            temporal_db_batch = []
            records_received  = 0

            while True:
                data = conn.recv(config.BUFFER_SIZE)
                if not data:
                    print("[Collector/Temporal] DPDK temporal stream disconnected")
                    if temporal_db_batch:
                        database.batch_insert_temporal(client, temporal_db_batch)
                        temporal_db_batch = []
                    break

                buf += data.decode('utf-8', errors='ignore')

                while '\n' in buf:
                    line, buf = buf.split('\n', 1)
                    if not line.strip():
                        continue

                    # Defensive: anything that does not start with the
                    # locked record-type token is dropped. The temporal
                    # socket should NEVER carry IP CSV lines, so we do
                    # not attempt parse_csv_line() here.
                    if not line.startswith('TEMP,'):
                        print(f"[Collector/Temporal] non-TEMP line dropped "
                              f"(prefix={line[:8]!r})")
                        continue

                    try:
                        record = parse_temporal_line(line)
                        if not record:
                            continue

                        if not _is_target_ip(record['dst_ip']):
                            continue

                        with shared_state.temporal_data_lock:
                            shared_state.latest_temporal_data.insert(0, record)
                            shared_state.latest_temporal_data = \
                                shared_state.latest_temporal_data[:config.TEMPORAL_RAM_BUFFER_SIZE]

                        temporal_db_batch.append(record)
                        records_received += 1

                        if len(temporal_db_batch) >= config.BATCH_SIZE:
                            if not database.batch_insert_temporal(client, temporal_db_batch):
                                # Insert failure: log and drop the batch
                                # rather than retain it indefinitely. IP
                                # path is unaffected — different thread,
                                # different fd, different table.
                                print("[Collector/Temporal] batch insert failed; "
                                      "dropping batch")
                            temporal_db_batch = []

                    except Exception as e:
                        print(f"[Collector/Temporal] Record error: {e}")

            conn.close()
            print("[Collector/Temporal] Waiting for next connection …")

        except Exception as e:
            print(f"[Collector/Temporal] Error: {e}")
            time.sleep(1)
