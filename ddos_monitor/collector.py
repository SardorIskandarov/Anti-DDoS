import socket
import os
import time
from datetime import datetime
import config
import database
import shared_state


# ============================================================================
# CSV SCHEMA  (52 columns total)
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
#  Detection fields (9):
#   43  detection_state         (string: WARMUP|NORMAL|SUSPICIOUS|ATTACK|RECOVERING)
#   44  tier0_score             (float [0,1])
#   45  tier1_tcp_score         (float [0,1])
#   46  tier1_udp_score         (float [0,1])
#   47  tier1_icmp_score        (float [0,1])
#   48  tier1_dist_score        (float [0,1])
#   49  tier1_final_score       (float [0,1], worst-case across sub-tiers)
#   50  tier1_evaluated         (int 0|1)
#   51  warmup_remaining        (int, windows left in warm-up phase)

EXPECTED_CSV_FIELDS = 52


def parse_csv_line(line):
    """Parse one CSV line emitted by ddos_log_and_reset_stats()."""
    try:
        parts = line.strip().split(',')

        if len(parts) != EXPECTED_CSV_FIELDS:
            print(f"[Collector] Bad CSV: expected {EXPECTED_CSV_FIELDS} fields, "
                  f"got {len(parts)}")
            return None

        return {
            # ── header ──────────────────────────────────────────────────
            'timestamp':              datetime.fromtimestamp(int(parts[0]) / 1000.0),
            'port':                   int(parts[1]),
            'dst_ip':                 parts[2],

            # ── Tier 0 raw ───────────────────────────────────────────────
            'pps':                    float(parts[3]),
            'bps':                    float(parts[4]),
            'fps':                    float(parts[5]),
            'burst_pps':              float(parts[6]),
            'burst_bps':              float(parts[7]),
            'burst_fps':              float(parts[8]),

            # ── Tier 1.1 TCP raw ─────────────────────────────────────────
            'tcp_syn_ratio':          float(parts[9]),
            'tcp_synack_ratio':       float(parts[10]),
            'tcp_finack_ratio':       float(parts[11]),
            'tcp_rst_ratio':          float(parts[12]),
            'tcp_ack_data_ratio':     float(parts[13]),
            'tcp_pps_ratio':          float(parts[14]),
            'tcp_bps_ratio':          float(parts[15]),

            # ── Tier 1.2 UDP raw ─────────────────────────────────────────
            'udp_bps_ratio':          float(parts[16]),
            'udp_pps_ratio':          float(parts[17]),
            'udp_flow_ratio':         float(parts[18]),

            # ── Tier 1.3 ICMP raw ────────────────────────────────────────
            'icmp_echo_ratio':        float(parts[19]),
            'icmp_pps_ratio':         float(parts[20]),

            # ── Tier 1.4 Distribution raw ────────────────────────────────
            'src_ip_ratio':           float(parts[21]),
            'dst_port_ratio':         float(parts[22]),

            # ── Tier 0 EWMA means ────────────────────────────────────────
            'em_pps':                 float(parts[23]),
            'em_bps':                 float(parts[24]),
            'em_fps':                 float(parts[25]),
            'em_burst_pps':           float(parts[26]),
            'em_burst_bps':           float(parts[27]),
            'em_burst_fps':           float(parts[28]),

            # ── Tier 1.1 TCP EWMA means ──────────────────────────────────
            'em_tcp_syn_ratio':       float(parts[29]),
            'em_tcp_synack_ratio':    float(parts[30]),
            'em_tcp_finack_ratio':    float(parts[31]),
            'em_tcp_rst_ratio':       float(parts[32]),
            'em_tcp_ack_data_ratio':  float(parts[33]),
            'em_tcp_pps_ratio':       float(parts[34]),
            'em_tcp_bps_ratio':       float(parts[35]),

            # ── Tier 1.2 UDP EWMA means ──────────────────────────────────
            'em_udp_bps_ratio':       float(parts[36]),
            'em_udp_pps_ratio':       float(parts[37]),
            'em_udp_flow_ratio':      float(parts[38]),

            # ── Tier 1.3 ICMP EWMA means ─────────────────────────────────
            'em_icmp_echo_ratio':     float(parts[39]),
            'em_icmp_pps_ratio':      float(parts[40]),

            # ── Tier 1.4 Distribution EWMA means ─────────────────────────
            'em_src_ip_ratio':        float(parts[41]),
            'em_dst_port_ratio':      float(parts[42]),

            # ── Detection fields ─────────────────────────────────────────
            'detection_state':        parts[43],
            'tier0_score':            float(parts[44]),
            'tier1_tcp_score':        float(parts[45]),
            'tier1_udp_score':        float(parts[46]),
            'tier1_icmp_score':       float(parts[47]),
            'tier1_dist_score':       float(parts[48]),
            'tier1_final_score':      float(parts[49]),
            'tier1_evaluated':        bool(int(parts[50])),
            'warmup_remaining':       int(parts[51]),
        }

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

                        state = record['detection_state']
                        if state in ('SUSPICIOUS', 'ATTACK'):
                            t1_ev = record['tier1_evaluated']
                            print(f"[ALERT] {state} | IP={record['dst_ip']} "
                                  f"t0={record['tier0_score']:.3f}",
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
                            print(f"[Collector] Records so far: {records_received}")
                            db_batch = []

                    except Exception as e:
                        print(f"[Collector] Record error: {e}")

            conn.close()
            print("[Collector] Waiting for next connection …")

        except Exception as e:
            print(f"[Collector] Error: {e}")
            time.sleep(1)