import socket
import os
import time
from datetime import datetime
import config
import database
import shared_state


def parse_csv_line(line):
    """Parse CSV line into dictionary with all 20 fields."""
    try:
        parts = line.strip().split(',')
        
        if len(parts) != 20:
            print(f"[Collector] Invalid CSV format, expected 20 fields, got {len(parts)}")
            return None
        
        # Parse all fields according to CSV format:
        # timestamp,port,dst_ip,pps,bps,fps,burst_factor,inbound_bits,outbound_bits,
        # udp,tcp,icmp,syn_pps,synack_pps,finack_pps,rst_pps,udp_flows,
        # unique_src_ips,unique_dst_ports,icmp_echo_rate
        
        data = {
            'timestamp': datetime.fromtimestamp(int(parts[0]) / 1000.0),  # Convert ms to seconds
            'port': int(parts[1]),
            'dst_ip': parts[2],
            'pps': float(parts[3]),
            'bps': float(parts[4]),
            'fps': float(parts[5]),
            'burst_factor': float(parts[6]),
            'inbound_bits': float(parts[7]),
            'outbound_bits': float(parts[8]),
            'udp': float(parts[9]),
            'tcp': float(parts[10]),
            'icmp': float(parts[11]),
            'syn_pps': float(parts[12]),
            'synack_pps': float(parts[13]),
            'finack_pps': float(parts[14]),
            'rst_pps': float(parts[15]),
            'udp_flows': int(parts[16]),
            'unique_src_ips': int(parts[17]),
            'unique_dst_ports': int(parts[18]),
            'icmp_echo_rate': float(parts[19])
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
                        # Parse CSV with all 20 fields
                        record = parse_csv_line(line)
                        
                        if record:
                            # 1. UPDATE SHARED MEMORY (For Real-time Dashboard)
                            with shared_state.data_lock:
                                shared_state.latest_traffic_data.insert(0, record)
                                # Keep only last N records in RAM
                                shared_state.latest_traffic_data = \
                                    shared_state.latest_traffic_data[:config.RAM_BUFFER_SIZE]

                            # 2. BATCH FOR DATABASE (For Historical Analysis)
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