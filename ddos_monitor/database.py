from clickhouse_driver import Client
import config

def get_db_client():
    """Establishes connection to ClickHouse and creates schema if missing."""
    
    # Connect to ClickHouse
    client = Client(
        host=config.CH_HOST,
        port=config.CH_PORT,
        settings={'use_numpy': False}
    )
    
    print(f"[Database] Connected to ClickHouse at {config.CH_HOST}:{config.CH_PORT}")
    
    # Create Database
    client.execute(f'CREATE DATABASE IF NOT EXISTS {config.CH_DB}')
    print(f"[Database] Database '{config.CH_DB}' ready")
    
    # Create Table with full schema (all 20 fields)
    create_table_query = f"""
    CREATE TABLE IF NOT EXISTS {config.CH_DB}.{config.CH_TABLE} (
        timestamp DateTime64(3),
        port UInt16,
        dst_ip String,
        pps Float64,
        bps Float64,
        fps Float64,
        burst_factor Float64,
        inbound_bits Float64,
        outbound_bits Float64,
        udp Float64,
        tcp Float64,
        icmp Float64,
        syn_pps Float64,
        synack_pps Float64,
        finack_pps Float64,
        rst_pps Float64,
        udp_flows UInt64,
        unique_src_ips UInt64,
        unique_dst_ports UInt64,
        icmp_echo_rate Float64
    ) ENGINE = MergeTree()
    PARTITION BY toYYYYMMDD(timestamp)
    ORDER BY (dst_ip, timestamp)
    TTL timestamp + INTERVAL 30 DAY
    SETTINGS index_granularity = 8192
    """
    
    client.execute(create_table_query)
    print(f"[Database] Table '{config.CH_DB}.{config.CH_TABLE}' ready")
    
    return client


def batch_insert(client, batch_data):
    """Insert batch of data into ClickHouse."""
    if not batch_data:
        return True
    
    try:
        query = f"INSERT INTO {config.CH_DB}.{config.CH_TABLE} VALUES"
        client.execute(query, batch_data)
        print(f"[Database] Inserted batch of {len(batch_data)} records")
        return True
    except Exception as e:
        print(f"[Database] Failed to insert batch: {e}")
        return False