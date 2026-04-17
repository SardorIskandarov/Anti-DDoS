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
]

EXPECTED_CSV_FIELDS = len(CSV_FIELDS)  # 60
assert EXPECTED_CSV_FIELDS == 60, f"CSV schema drift: {EXPECTED_CSV_FIELDS} fields"


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


def parse_csv_line(line):
    """Parse one CSV line emitted by ddos_log_and_reset_stats().

    The mapping of CSV columns to dict keys is driven by CSV_FIELDS so that
    the parser stays in lock-step with the C snprintf format. Any drift in
    column count is rejected up-front to prevent silent index shifting.
    """
    parts = line.strip().split(',')

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
                    try:
                        record = parse_csv_line(line)
                        if not record:
                            continue

                        if not _is_target_ip(record['dst_ip']):
                            continue

                        state = record['detection_state']
                        if state in ('SUSPICIOUS', 'ATTACK'):
                            t1_ev = record['tier1_evaluated']
                            print(f"[ALERT] {state} | IP={record['dst_ip']} "
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
