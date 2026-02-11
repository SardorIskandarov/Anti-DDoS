from clickhouse_driver import Client
import config


def get_db_client():
    """Establishes connection to ClickHouse and creates schema if missing."""

    client = Client(
        host=config.CH_HOST,
        port=config.CH_PORT,
        settings={'use_numpy': False}
    )

    print(f"[Database] Connected to ClickHouse at {config.CH_HOST}:{config.CH_PORT}")

    # Create Database
    client.execute(f'CREATE DATABASE IF NOT EXISTS {config.CH_DB}')
    print(f"[Database] Database '{config.CH_DB}' ready")

    # -------------------------------------------------------------------------
    # Create Table
    #
    # Schema mirrors the 57-field CSV produced by l2fwd_ddos_collector.c:
    #   - 3  header fields
    #   - 17 raw traffic features
    #   - 17 EWMA mean values      (prefixed em_)
    #   - 17 EWMA Z-score features (prefixed z_)
    #   - 3  detection engine fields
    # -------------------------------------------------------------------------
    create_table_query = f"""
    CREATE TABLE IF NOT EXISTS {config.CH_DB}.{config.CH_TABLE} (
        -- Header
        timestamp           DateTime64(3),
        port                UInt16,
        dst_ip              String,

        -- Raw traffic features
        pps                 Float64,
        bps                 Float64,
        fps                 Float64,
        burst_factor        Float64,
        inbound_bits        Float64,
        outbound_bits       Float64,
        udp                 Float64,
        tcp                 Float64,
        icmp                Float64,
        syn_pps             Float64,
        synack_pps          Float64,
        finack_pps          Float64,
        rst_pps             Float64,
        udp_flows           UInt64,
        unique_src_ips      UInt64,
        unique_dst_ports    UInt64,
        icmp_echo_rate      Float64,

        -- EWMA moving-average baseline for each raw feature (prefixed em_)
        -- These are the smoothed long-run averages used as the baseline model.
        -- Plotting em_X alongside X shows how far current traffic deviates
        -- from its learned normal.
        em_pps              Float64,
        em_bps              Float64,
        em_fps              Float64,
        em_burst_factor     Float64,
        em_inbound_bits     Float64,
        em_outbound_bits    Float64,
        em_udp              Float64,
        em_tcp              Float64,
        em_icmp             Float64,
        em_syn_pps          Float64,
        em_synack_pps       Float64,
        em_finack_pps       Float64,
        em_rst_pps          Float64,
        em_udp_flows        Float64,
        em_unique_src_ips   Float64,
        em_unique_dst_ports Float64,
        em_icmp_echo_rate   Float64,

        -- EWMA Z-scores (same feature order, prefixed z_)
        -- Values near 0 = normal baseline.
        -- |z| > 3 typically indicates a statistically significant anomaly.
        z_pps               Float64,
        z_bps               Float64,
        z_fps               Float64,
        z_burst_factor      Float64,
        z_inbound_bits      Float64,
        z_outbound_bits     Float64,
        z_udp               Float64,
        z_tcp               Float64,
        z_icmp              Float64,
        z_syn_pps           Float64,
        z_synack_pps        Float64,
        z_finack_pps        Float64,
        z_rst_pps           Float64,
        z_udp_flows         Float64,
        z_unique_src_ips    Float64,
        z_unique_dst_ports  Float64,
        z_icmp_echo_rate    Float64,

        -- Detection engine fields
        -- detection_state: WARMUP, NORMAL, SUSPICIOUS, ATTACK, RECOVERING
        -- tier0_distance_norm: Normalized Manhattan distance for Tier-0 features [0, 1]
        -- tier1_distance_norm: Normalized Manhattan distance for Tier-1 features [0, 1]
        detection_state     String,
        tier0_distance_norm Float64,
        tier1_distance_norm Float64
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
    """Insert a batch of records into ClickHouse."""
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