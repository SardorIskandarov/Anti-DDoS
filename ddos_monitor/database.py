from clickhouse_driver import Client
import config


def get_db_client():
    """Connect to ClickHouse and create schema if it does not exist."""

    client = Client(
        host=config.CH_HOST,
        port=config.CH_PORT,
        settings={'use_numpy': False}
    )
    print(f"[Database] Connected to ClickHouse at {config.CH_HOST}:{config.CH_PORT}")

    client.execute(f'CREATE DATABASE IF NOT EXISTS {config.CH_DB}')
    print(f"[Database] Database '{config.CH_DB}' ready")

    # -------------------------------------------------------------------------
    # Schema mirrors the 60-field CSV produced by l2fwd_ddos_collector.c:
    #
    #   3  header fields
    #   6  Tier 0 raw features
    #   7  Tier 1.1 TCP raw features
    #   3  Tier 1.2 UDP raw features
    #   2  Tier 1.3 ICMP raw features
    #   2  Tier 1.4 Distribution raw features
    #   6  Tier 0 EWMA means
    #   7  Tier 1.1 TCP EWMA means
    #   3  Tier 1.2 UDP EWMA means
    #   2  Tier 1.3 ICMP EWMA means
    #   2  Tier 1.4 Distribution EWMA means
    #   15 Detection engine fields
    #   2  HLL observability fields
    # -------------------------------------------------------------------------
    create_table_query = f"""
    CREATE TABLE IF NOT EXISTS {config.CH_DB}.{config.CH_TABLE} (

        -- ── Header ──────────────────────────────────────────────────────
        timestamp               DateTime64(3),
        port                    UInt16,
        dst_ip                  String,

        -- ── Tier 0: Volume features (always active) ─────────────────────
        pps                     Float64,
        bps                     Float64,
        fps                     Float64,
        burst_pps               Float64,
        burst_bps               Float64,
        burst_fps               Float64,

        -- ── Tier 1.1: TCP behavioural features (passive) ────────────────
        tcp_syn_ratio           Float64,
        tcp_synack_ratio        Float64,
        tcp_finack_ratio        Float64,
        tcp_rst_ratio           Float64,
        tcp_ack_data_ratio      Float64,
        tcp_pps_ratio           Float64,
        tcp_bps_ratio           Float64,

        -- ── Tier 1.2: UDP behavioural features (passive) ────────────────
        udp_bps_ratio           Float64,
        udp_pps_ratio           Float64,
        udp_flow_ratio          Float64,

        -- ── Tier 1.3: ICMP behavioural features (passive) ───────────────
        icmp_echo_ratio         Float64,
        icmp_pps_ratio          Float64,

        -- ── Tier 1.4: Distribution features (passive) ───────────────────
        src_ip_ratio            Float64,
        dst_port_ratio          Float64,

        -- ── Tier 0 EWMA means ───────────────────────────────────────────
        em_pps                  Float64,
        em_bps                  Float64,
        em_fps                  Float64,
        em_burst_pps            Float64,
        em_burst_bps            Float64,
        em_burst_fps            Float64,

        -- ── Tier 1.1 TCP EWMA means ─────────────────────────────────────
        em_tcp_syn_ratio        Float64,
        em_tcp_synack_ratio     Float64,
        em_tcp_finack_ratio     Float64,
        em_tcp_rst_ratio        Float64,
        em_tcp_ack_data_ratio   Float64,
        em_tcp_pps_ratio        Float64,
        em_tcp_bps_ratio        Float64,

        -- ── Tier 1.2 UDP EWMA means ─────────────────────────────────────
        em_udp_bps_ratio        Float64,
        em_udp_pps_ratio        Float64,
        em_udp_flow_ratio       Float64,

        -- ── Tier 1.3 ICMP EWMA means ────────────────────────────────────
        em_icmp_echo_ratio      Float64,
        em_icmp_pps_ratio       Float64,

        -- ── Tier 1.4 Distribution EWMA means ────────────────────────────
        em_src_ip_ratio         Float64,
        em_dst_port_ratio       Float64,

        -- ── Detection engine outputs ─────────────────────────────────────
        -- detection_state: WARMUP | NORMAL | SUSPICIOUS | ATTACK | RECOVERING
        detection_state         String,
        -- tier0_global_risk: fused Tier-0 continuous risk
        tier0_global_risk       Float64,
        -- per-feature Tier-0 risks [0,1]
        tier0_risk_pps          Float64,
        tier0_risk_bps          Float64,
        tier0_risk_fps          Float64,
        tier0_risk_burst_pps    Float64,
        tier0_risk_burst_bps    Float64,
        tier0_risk_burst_fps    Float64,
        -- tier1_*_score: per-sub-tier sigmoid scores [0,1]
        tier1_tcp_score         Float64,
        tier1_udp_score         Float64,
        tier1_icmp_score        Float64,
        tier1_dist_score        Float64,
        -- tier1_final_score: worst-case across all Tier-1 sub-tiers
        tier1_final_score       Float64,
        -- tier1_evaluated: 1 if Tier-1 was triggered this window, else 0
        tier1_evaluated         UInt8,
        -- warmup_remaining: windows left before detection becomes active
        warmup_remaining        UInt32,

        -- ── Raw HLL observability counts ────────────────────────────────
        unique_src_ips          UInt64,
        unique_dst_ports        UInt64

    ) ENGINE = MergeTree()
    PARTITION BY toYYYYMMDD(timestamp)
    ORDER BY (dst_ip, timestamp)
    TTL timestamp + INTERVAL 30 DAY
    SETTINGS index_granularity = 8192
    """

    client.execute(create_table_query)

    existing_columns = {
        row[0] for row in client.execute(
            """
            SELECT name
            FROM system.columns
            WHERE database = %(database)s AND table = %(table)s
            """,
            {'database': config.CH_DB, 'table': config.CH_TABLE}
        )
    }
    if 'tier0_score' in existing_columns and 'tier0_global_risk' not in existing_columns:
        client.execute(
            f"ALTER TABLE {config.CH_DB}.{config.CH_TABLE} "
            "RENAME COLUMN tier0_score TO tier0_global_risk"
        )
        print(f"[Database] Renamed legacy Tier-0 risk column on "
              f"'{config.CH_DB}.{config.CH_TABLE}'")

    previous_column = 'tier0_global_risk'
    for column_name in (
        'tier0_risk_pps',
        'tier0_risk_bps',
        'tier0_risk_fps',
        'tier0_risk_burst_pps',
        'tier0_risk_burst_bps',
        'tier0_risk_burst_fps',
    ):
        client.execute(
            f"ALTER TABLE {config.CH_DB}.{config.CH_TABLE} "
            f"ADD COLUMN IF NOT EXISTS {column_name} Float64 AFTER {previous_column}"
        )
        previous_column = column_name

    client.execute(
        f"ALTER TABLE {config.CH_DB}.{config.CH_TABLE} "
        "ADD COLUMN IF NOT EXISTS unique_src_ips UInt64 AFTER warmup_remaining"
    )
    client.execute(
        f"ALTER TABLE {config.CH_DB}.{config.CH_TABLE} "
        "ADD COLUMN IF NOT EXISTS unique_dst_ports UInt64 AFTER unique_src_ips"
    )

    print(f"[Database] Table '{config.CH_DB}.{config.CH_TABLE}' ready")
    return client


def batch_insert(client, batch_data):
    """Insert a batch of records into ClickHouse."""
    if not batch_data:
        return True
    try:
        client.execute(
            f"INSERT INTO {config.CH_DB}.{config.CH_TABLE} VALUES",
            batch_data
        )
        print(f"[Database] Inserted {len(batch_data)} records")
        return True
    except Exception as e:
        print(f"[Database] Insert failed: {e}")
        return False
