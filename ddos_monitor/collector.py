import socket
import os
import time
from datetime import datetime
import config
import database
import shared_state


# CSV column count after the C-side EWMA/Z-score additions:
#   3 header fields  (timestamp, port, dst_ip)
#  17 raw features
#  17 Z-score fields
EXPECTED_CSV_FIELDS = 37


def parse_csv_line(line):
    """
    Parse a CSV line into a dictionary with all 37 fields.

    Column order (mirrors ddos_log_and_reset_stats in l2fwd_ddos_collector.c):

      0  timestamp
      1  port
      2  dst_ip
      --- raw features ---
      3  pps
      4  bps
      5  fps
      6  burst_factor
      7  inbound_bits
      8  outbound_bits
      9  udp
      10 tcp
      11 icmp
      12 syn_ratio
      13 synack_ratio
      14 finack_ratio
      15 rst_ratio
      16 udp_flows
      17 unique_src_ips
      18 unique_dst_ports
      19 icmp_echo_rate
      --- EWMA Z-scores (same feature order, prefixed z_) ---
      20 z_pps
      21 z_bps
      22 z_fps
      23 z_burst_factor
      24 z_inbound_bits
      25 z_outbound_bits
      26 z_udp
      27 z_tcp
      28 z_icmp
      29 z_syn_ratio
      30 z_synack_ratio
      31 z_finack_ratio
      32 z_rst_ratio
      33 z_udp_flows
      34 z_unique_src_ips
      35 z_unique_dst_ports
      36 z_icmp_echo_rate
    """
    try:
        parts = line.strip().split(',')

        if len(parts) != EXPECTED_CSV_FIELDS:
            print(f"[Collector] Invalid CSV format: expected {EXPECTED_CSV_FIELDS} fields, "
                  f"got {len(parts)}")
            return None

        data = {
            # ── header ────────────────────────────────────────────────────
            'timestamp':         datetime.fromtimestamp(int(parts[0]) / 1000.0),
            'port':              int(parts[1]),
            'dst_ip':            parts[2],

            # ── raw features ───────────────────────────────────────────────
            'pps':               float(parts[3]),
            'bps':               float(parts[4]),
            'fps':               float(parts[5]),
            'burst_factor':      float(parts[6]),
            'inbound_bits':      float(parts[7]),
            'outbound_bits':     float(parts[8]),
            'udp':               float(parts[9]),
            'tcp':               float(parts[10]),
            'icmp':              float(parts[11]),
            'syn_pps':           float(parts[12]),   # stored as syn_ratio in C
            'synack_pps':        float(parts[13]),
            'finack_pps':        float(parts[14]),
            'rst_pps':           float(parts[15]),
            'udp_flows':         int(float(parts[16])),
            'unique_src_ips':    int(float(parts[17])),
            'unique_dst_ports':  int(float(parts[18])),
            'icmp_echo_rate':    float(parts[19]),

            # ── EWMA Z-scores ─────────────────────────────────────────────
            'z_pps':             float(parts[20]),
            'z_bps':             float(parts[21]),
            'z_fps':             float(parts[22]),
            'z_burst_factor':    float(parts[23]),
            'z_inbound_bits':    float(parts[24]),
            'z_outbound_bits':   float(parts[25]),
            'z_udp':             float(parts[26]),
            'z_tcp':             float(parts[27]),
            'z_icmp':            float(parts[28]),
            'z_syn_pps':         float(parts[29]),
            'z_synack_pps':      float(parts[30]),
            'z_finack_pps':      float(parts[31]),
            'z_rst_pps':         float(parts[32]),
            'z_udp_flows':       float(parts[33]),
            'z_unique_src_ips':  float(parts[34]),
            'z_unique_dst_ports':float(parts[35]),
            'z_icmp_echo_rate':  float(parts[36]),
        }

        return data

    except Exception as e:
        print(f"[Collector] Failed to parse CSV line: {e}")
        return None


def dpdk_collector_thread():
    """Background thread to collect stats from Unix Socket."""

    # Initialize DB connection for this thread
    try:
        client = database.get_db_client()
        print("[Collector] Database connection established")
    except Exception as e:
        print(f"[Collector] Database connection failed: {e}")
        return

    # Setup Unix Socket
    if os.path.exists(config.SOCK_PATH):
        os.unlink(config.SOCK_PATH)

    server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    server.bind(config.SOCK_PATH)
    server.listen(1)
    print(f"[Collector] Listening on {config.SOCK_PATH}...")
    print("[Collector] Waiting for DPDK application to connect...")

    while True:
        try:
            conn, _ = server.accept()
            print("[Collector] DPDK application connected!")

            buffer = ""
            db_batch = []
            records_received = 0

            while True:
                data = conn.recv(config.BUFFER_SIZE)
                if not data:
                    print("[Collector] DPDK application disconnected")

                    # Insert remaining batch before closing
                    if db_batch:
                        database.batch_insert(client, db_batch)
                        db_batch = []
                    break

                buffer += data.decode('utf-8', errors='ignore')

                while '\n' in buffer:
                    line, buffer = buffer.split('\n', 1)
                    if not line.strip():
                        continue

                    try:
                        record = parse_csv_line(line)

                        if record:
                            # 1. UPDATE SHARED MEMORY (for real-time dashboard)
                            with shared_state.data_lock:
                                shared_state.latest_traffic_data.insert(0, record)
                                # Keep only last N records in RAM
                                shared_state.latest_traffic_data = \
                                    shared_state.latest_traffic_data[:config.RAM_BUFFER_SIZE]

                            # 2. BATCH FOR DATABASE (for historical analysis)
                            db_batch.append(record)
                            records_received += 1

                            if len(db_batch) >= config.BATCH_SIZE:
                                database.batch_insert(client, db_batch)
                                print(f"[Collector] Total records received: {records_received}")
                                db_batch = []

                    except Exception as e:
                        print(f"[Collector] Parse error: {e}")

            print("[Collector] Connection closed. Waiting for new connection...")
            conn.close()

        except Exception as e:
            print(f"[Collector] Error: {e}")
            time.sleep(1)