from clickhouse_driver import Client
import config


def get_db_client():
    """Connect to ClickHouse and create schema if it does not exist."""

    client = Client(
        host=config.CH_HOST,
        port=config.CH_PORT,
        user=config.CH_USER,
        password=config.CH_PASSWORD,
        settings={'use_numpy': False}
    )
    print(f"[Database] Connected to ClickHouse at {config.CH_HOST}:{config.CH_PORT}")

    client.execute(f'CREATE DATABASE IF NOT EXISTS {config.CH_DB}')
    print(f"[Database] Database '{config.CH_DB}' ready")

    # -------------------------------------------------------------------------
    # Schema mirrors the 62-field CSV produced by l2fwd_ddos_collector.c:
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
    #   2  Layer-2 profile identity (profile_name, profile_version)
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

        -- ── Tier 1.1 V2: TCP behavioral signatures ──────────────────────
        empty_ack_ratio         Float64,
        zero_window_ratio       Float64,
        small_window_ratio      Float64,
        new_flow_ratio          Float64,
        syn_fin_ratio           Float64,
        syn_to_synack_ratio     Float64,
        tcp_pkt_size_cov        Float64,
        tcp_mean_pkt_size       Float64,

        -- ── Tier 1.2: UDP behavioural features (passive) ────────────────
        udp_bps_ratio           Float64,
        udp_pps_ratio           Float64,
        udp_flow_ratio          Float64,

        -- ── Tier 1.2 V2: UDP behavioral signatures ──────────────────────
        udp_pkt_size_cov        Float64,
        udp_mean_pkt_size       Float64,

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

        -- ── Tier 1.1 V2: TCP EWMA means ─────────────────────────────────
        em_empty_ack_ratio      Float64,
        em_zero_window_ratio    Float64,
        em_small_window_ratio   Float64,
        em_new_flow_ratio       Float64,
        em_syn_fin_ratio        Float64,
        em_syn_to_synack_ratio  Float64,
        em_tcp_pkt_size_cov     Float64,
        em_tcp_mean_pkt_size    Float64,

        -- ── Tier 1.2 UDP EWMA means ─────────────────────────────────────
        em_udp_bps_ratio        Float64,
        em_udp_pps_ratio        Float64,
        em_udp_flow_ratio       Float64,

        -- ── Tier 1.2 V2: UDP EWMA means ─────────────────────────────────
        em_udp_pkt_size_cov     Float64,
        em_udp_mean_pkt_size    Float64,

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
        unique_dst_ports        UInt64,

        -- ── Layer-2 profile identity (per dst_ip) ───────────────────────
        profile_name            String DEFAULT 'default',
        profile_version         String DEFAULT 'v1',

        -- ── V3.0 L3-channel raw features ───────────────────────────────
        ttl_stddev        Float64,
        ip_frag_ratio     Float64,
        other_proto_ratio Float64,

        -- ── V3.0 L3-channel derived features ───────────────────────────
        em_ttl_stddev     Float64,
        tier1_l3_score    Float64,
        attack_evidence   Float64,

        -- ── V3.1 L3-channel raw features ───────────────────────────────
        src_port_top1_share Float64,
        src_24_top1_share   Float64,
        src_24_entropy      Float64,

        -- ── V3.1 L3-channel EWMA features ──────────────────────────────
        em_src_port_top1_share Float64,
        em_src_24_top1_share   Float64,
        em_src_24_entropy      Float64,

        -- ── DIRECTIONALITY_EXPERIMENT (TEMPORARY — REMOVE WHEN DONE) ─────
        inbound_pkts  UInt64,
        outbound_pkts UInt64

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

    # Layer-2 profile identity — additive, backward-compatible for
    # existing deployments. Defaults match the C-side default profile.
    client.execute(
        f"ALTER TABLE {config.CH_DB}.{config.CH_TABLE} "
        "ADD COLUMN IF NOT EXISTS profile_name String DEFAULT 'default' "
        "AFTER unique_dst_ports"
    )
    client.execute(
        f"ALTER TABLE {config.CH_DB}.{config.CH_TABLE} "
        "ADD COLUMN IF NOT EXISTS profile_version String DEFAULT 'v1' "
        "AFTER profile_name"
    )

    # ─────────────────────────────────────────────────────────────────
    # V2 columns — additive ALTERs for existing deployments. New
    # deployments pick these up via the CREATE TABLE above. The order
    # below mirrors the CSV column order (TCP raw → UDP raw → TCP EWMA
    # → UDP EWMA) and uses ADD COLUMN IF NOT EXISTS for idempotency.
    # ─────────────────────────────────────────────────────────────────

    # Tier 1.1 V2 raw — anchor after tcp_bps_ratio
    v2_tcp_raw_anchor = 'tcp_bps_ratio'
    for col in (
        'empty_ack_ratio', 'zero_window_ratio', 'small_window_ratio',
        'new_flow_ratio', 'syn_fin_ratio', 'syn_to_synack_ratio',
        'tcp_pkt_size_cov', 'tcp_mean_pkt_size',
    ):
        client.execute(
            f"ALTER TABLE {config.CH_DB}.{config.CH_TABLE} "
            f"ADD COLUMN IF NOT EXISTS {col} Float64 AFTER {v2_tcp_raw_anchor}"
        )
        v2_tcp_raw_anchor = col

    # Tier 1.2 V2 raw — anchor after udp_flow_ratio
    v2_udp_raw_anchor = 'udp_flow_ratio'
    for col in ('udp_pkt_size_cov', 'udp_mean_pkt_size'):
        client.execute(
            f"ALTER TABLE {config.CH_DB}.{config.CH_TABLE} "
            f"ADD COLUMN IF NOT EXISTS {col} Float64 AFTER {v2_udp_raw_anchor}"
        )
        v2_udp_raw_anchor = col

    # Tier 1.1 V2 EWMA means — anchor after em_tcp_bps_ratio
    v2_tcp_em_anchor = 'em_tcp_bps_ratio'
    for col in (
        'em_empty_ack_ratio', 'em_zero_window_ratio', 'em_small_window_ratio',
        'em_new_flow_ratio', 'em_syn_fin_ratio', 'em_syn_to_synack_ratio',
        'em_tcp_pkt_size_cov', 'em_tcp_mean_pkt_size',
    ):
        client.execute(
            f"ALTER TABLE {config.CH_DB}.{config.CH_TABLE} "
            f"ADD COLUMN IF NOT EXISTS {col} Float64 AFTER {v2_tcp_em_anchor}"
        )
        v2_tcp_em_anchor = col

    # Tier 1.2 V2 EWMA means — anchor after em_udp_flow_ratio
    v2_udp_em_anchor = 'em_udp_flow_ratio'
    for col in ('em_udp_pkt_size_cov', 'em_udp_mean_pkt_size'):
        client.execute(
            f"ALTER TABLE {config.CH_DB}.{config.CH_TABLE} "
            f"ADD COLUMN IF NOT EXISTS {col} Float64 AFTER {v2_udp_em_anchor}"
        )
        v2_udp_em_anchor = col

    # ─────────────────────────────────────────────────────────────────
    # V3.0 L3-channel columns — additive ALTERs for existing deployments.
    # All 6 columns appended after profile_version (the v2 trailing
    # column). Order matches CSV column order.
    # ─────────────────────────────────────────────────────────────────
    v3_anchor = 'profile_version'
    for col in (
        'ttl_stddev', 'ip_frag_ratio', 'other_proto_ratio',
        'em_ttl_stddev', 'tier1_l3_score', 'attack_evidence',
    ):
        client.execute(
            f"ALTER TABLE {config.CH_DB}.{config.CH_TABLE} "
            f"ADD COLUMN IF NOT EXISTS {col} Float64 AFTER {v3_anchor}"
        )
        v3_anchor = col

    # ─────────────────────────────────────────────────────────────────
    # V3.1 L3-channel columns — additive ALTERs for existing deployments.
    # Anchored after attack_evidence (v3.0 trailing column).
    # ─────────────────────────────────────────────────────────────────
    v31_anchor = 'attack_evidence'
    for col in (
        'src_port_top1_share', 'src_24_top1_share', 'src_24_entropy',
        'em_src_port_top1_share', 'em_src_24_top1_share', 'em_src_24_entropy',
    ):
        client.execute(
            f"ALTER TABLE {config.CH_DB}.{config.CH_TABLE} "
            f"ADD COLUMN IF NOT EXISTS {col} Float64 AFTER {v31_anchor}"
        )
        v31_anchor = col

    # ─────────────────────────────────────────────────────────────────
    # DIRECTIONALITY_EXPERIMENT — additive ALTERs for existing tables.
    # ─────────────────────────────────────────────────────────────────
    exp_anchor = 'em_src_24_entropy'
    for col in ('inbound_pkts', 'outbound_pkts'):
        client.execute(
            f"ALTER TABLE {config.CH_DB}.{config.CH_TABLE} "
            f"ADD COLUMN IF NOT EXISTS {col} UInt64 AFTER {exp_anchor}"
        )
        exp_anchor = col

    print(f"[Database] Table '{config.CH_DB}.{config.CH_TABLE}' ready")

    # ------------------------------------------------------------------
    # Multi-timescale temporal observability table.
    #
    # Schema is locked at L2_TEMP_SCHEMA_VERSION = 1: exactly 78 columns,
    # one per data field of the 79-field C TEMP line. Field 1 of the
    # TEMP line is the literal "TEMP" record-type token and is NOT
    # stored. Fields 2..79 map 1:1 to the 78 columns below in the same
    # order, so _TEMPORAL_INSERT_COLUMNS and parse_temporal_line()
    # share a single positional contract with the C side.
    #
    # The previous 74-column revision contained seven placeholder
    # detector-evidence columns and a String rollup_version that drifted
    # from the C output. If the table already exists with that older
    # shape (detected via the absence of bucket_epoch_ms) we drop and
    # recreate it before continuing — temporal data accumulated under
    # the drifted schema is throwaway at this stage of development.
    # ------------------------------------------------------------------
    existing_temporal_columns = {
        row[0] for row in client.execute(
            """
            SELECT name
            FROM system.columns
            WHERE database = %(database)s AND table = %(table)s
            """,
            {'database': config.CH_DB, 'table': config.CH_TEMPORAL_TABLE}
        )
    }
    if existing_temporal_columns and 'bucket_epoch_ms' not in existing_temporal_columns:
        print(f"[Database] Migrating {config.CH_TEMPORAL_TABLE}: previous "
              f"schema lacks bucket_epoch_ms — dropping and recreating "
              f"with the locked 78-column schema")
        client.execute(
            f"DROP TABLE {config.CH_DB}.{config.CH_TEMPORAL_TABLE}"
        )

    create_temporal_table_query = f"""
    CREATE TABLE IF NOT EXISTS {config.CH_DB}.{config.CH_TEMPORAL_TABLE} (
        -- Header (TEMP fields 2..11) ----------------------------------
        schema_ver                UInt16,
        rollup_ver                UInt16,
        timestamp                 DateTime64(3),
        port                      UInt16,
        dst_ip                    String,
        window_sec                UInt16,
        bucket_epoch_ms           UInt64,
        valid_seconds             UInt32,
        baseline_ready            UInt8,
        temporal_state            String,

        -- Volume (TEMP 12..29): 3 metrics × (avg, em, ratio, z, min, max)
        avg_pps                   Float64,
        em_pps                    Float64,
        ratio_pps                 Float64,
        z_pps                     Float64,
        min_pps                   Float64,
        max_pps                   Float64,
        avg_bps                   Float64,
        em_bps                    Float64,
        ratio_bps                 Float64,
        z_bps                     Float64,
        min_bps                   Float64,
        max_bps                   Float64,
        avg_fps                   Float64,
        em_fps                    Float64,
        ratio_fps                 Float64,
        z_fps                     Float64,
        min_fps                   Float64,
        max_fps                   Float64,

        -- Protocol-share pairs (TEMP 30..43): cur, baseline ----------
        tcp_pps_ratio             Float64,
        em_tcp_pps_ratio          Float64,
        tcp_bps_ratio             Float64,
        em_tcp_bps_ratio          Float64,
        udp_pps_ratio             Float64,
        em_udp_pps_ratio          Float64,
        udp_bps_ratio             Float64,
        em_udp_bps_ratio          Float64,
        udp_flow_ratio            Float64,
        em_udp_flow_ratio         Float64,
        icmp_pps_ratio            Float64,
        em_icmp_pps_ratio         Float64,
        icmp_echo_ratio           Float64,
        em_icmp_echo_ratio        Float64,

        -- TCP flag pairs (TEMP 44..53): cur, baseline -----------------
        tcp_syn_ratio             Float64,
        em_tcp_syn_ratio          Float64,
        tcp_synack_ratio          Float64,
        em_tcp_synack_ratio       Float64,
        tcp_finack_ratio          Float64,
        em_tcp_finack_ratio       Float64,
        tcp_rst_ratio             Float64,
        em_tcp_rst_ratio          Float64,
        tcp_ack_data_ratio        Float64,
        em_tcp_ack_data_ratio     Float64,

        -- Distribution pairs (TEMP 54..57): cur, baseline -------------
        src_ip_ratio              Float64,
        em_src_ip_ratio           Float64,
        dst_port_ratio            Float64,
        em_dst_port_ratio         Float64,

        -- Raw counters (TEMP 58..70) ----------------------------------
        total_pkts                UInt64,
        total_bytes               UInt64,
        tcp_pkts                  UInt64,
        tcp_bytes                 UInt64,
        udp_pkts                  UInt64,
        udp_bytes                 UInt64,
        icmp_pkts                 UInt64,
        icmp_echo_pkts            UInt64,
        syn_pkts                  UInt64,
        synack_pkts               UInt64,
        finack_pkts               UInt64,
        rst_pkts                  UInt64,
        ack_data_pkts             UInt64,

        -- Per-state seconds (TEMP 71..74) -----------------------------
        normal_seconds            UInt32,
        warmup_seconds            UInt32,
        suspicious_seconds        UInt32,
        attack_seconds            UInt32,

        -- Scores (TEMP 75..79) ----------------------------------------
        volume_score              Float64,
        protocol_shift_score      Float64,
        persistence_score         Float64,
        ramp_score                Float64,
        temporal_score            Float64
    ) ENGINE = MergeTree()
    PARTITION BY toYYYYMMDD(timestamp)
    ORDER BY (dst_ip, window_sec, timestamp)
    TTL timestamp + INTERVAL 30 DAY
    """
    client.execute(create_temporal_table_query)
    print(f"[Database] Table '{config.CH_DB}.{config.CH_TEMPORAL_TABLE}' ready")

    return client


# Locked insert column order for dst_ip_temporal_stats — exactly 78
# entries, one per data field of the 79-field C TEMP line (TEMP token
# not stored). Mirrors the CREATE TABLE schema 1:1 so the dict-based
# INSERT in batch_insert_temporal() never relies on table-default
# column order.
#
# Any reorder / add / remove / rename here MUST be paired in the same
# commit with a matching CREATE / ALTER, an L2_TEMP_SCHEMA_VERSION
# bump on the C side, and a TEMPORAL_EXPECTED_FIELDS / parser update
# in collector.py.
_TEMPORAL_INSERT_COLUMNS = (
    # Header (10)
    'schema_ver', 'rollup_ver',
    'timestamp', 'port', 'dst_ip', 'window_sec',
    'bucket_epoch_ms', 'valid_seconds', 'baseline_ready', 'temporal_state',

    # Volume (18) — avg / em / ratio / z / min / max for pps, bps, fps
    'avg_pps', 'em_pps', 'ratio_pps', 'z_pps', 'min_pps', 'max_pps',
    'avg_bps', 'em_bps', 'ratio_bps', 'z_bps', 'min_bps', 'max_bps',
    'avg_fps', 'em_fps', 'ratio_fps', 'z_fps', 'min_fps', 'max_fps',

    # Protocol-share pairs (14)
    'tcp_pps_ratio',   'em_tcp_pps_ratio',
    'tcp_bps_ratio',   'em_tcp_bps_ratio',
    'udp_pps_ratio',   'em_udp_pps_ratio',
    'udp_bps_ratio',   'em_udp_bps_ratio',
    'udp_flow_ratio',  'em_udp_flow_ratio',
    'icmp_pps_ratio',  'em_icmp_pps_ratio',
    'icmp_echo_ratio', 'em_icmp_echo_ratio',

    # TCP flag pairs (10)
    'tcp_syn_ratio',      'em_tcp_syn_ratio',
    'tcp_synack_ratio',   'em_tcp_synack_ratio',
    'tcp_finack_ratio',   'em_tcp_finack_ratio',
    'tcp_rst_ratio',      'em_tcp_rst_ratio',
    'tcp_ack_data_ratio', 'em_tcp_ack_data_ratio',

    # Distribution pairs (4)
    'src_ip_ratio',   'em_src_ip_ratio',
    'dst_port_ratio', 'em_dst_port_ratio',

    # Raw counters (13)
    'total_pkts',     'total_bytes',
    'tcp_pkts',       'tcp_bytes',
    'udp_pkts',       'udp_bytes',
    'icmp_pkts',      'icmp_echo_pkts',
    'syn_pkts',       'synack_pkts',
    'finack_pkts',    'rst_pkts',       'ack_data_pkts',

    # Per-state seconds (4)
    'normal_seconds',     'warmup_seconds',
    'suspicious_seconds', 'attack_seconds',

    # Scores (5) — temporal_score is the per-scale fused score and
    # lives at the end of the schema, not in the header.
    'volume_score', 'protocol_shift_score',
    'persistence_score', 'ramp_score', 'temporal_score',
)
assert len(_TEMPORAL_INSERT_COLUMNS) == 78, (
    f"Temporal column count drift: {len(_TEMPORAL_INSERT_COLUMNS)}")


def batch_insert(client, batch_data):
    """Insert a batch of records into ClickHouse."""
    if not batch_data:
        return True
    try:
        client.execute(
            f"INSERT INTO {config.CH_DB}.{config.CH_TABLE} VALUES",
            batch_data
        )
        # print(f"[Database] Inserted {len(batch_data)} records")
        return True
    except Exception as e:
        print(f"[Database] Insert failed: {e}")
        return False


def batch_insert_temporal(client, temporal_batch_data):
    """Insert a batch of TEMP records into dst_ip_temporal_stats.

    `temporal_batch_data` is a list of dicts whose keys exactly match
    `_TEMPORAL_INSERT_COLUMNS`. Empty batches return True (no-op) so the
    collector flush logic stays branch-free. Any failure is logged and
    surfaced as False so the collector can decide whether to retain or
    drop the batch — IP record processing is unaffected either way.
    """
    if not temporal_batch_data:
        return True

    cols_sql = ", ".join(_TEMPORAL_INSERT_COLUMNS)
    query = (
        f"INSERT INTO {config.CH_DB}.{config.CH_TEMPORAL_TABLE} "
        f"({cols_sql}) VALUES"
    )
    try:
        client.execute(query, temporal_batch_data)
        return True
    except Exception as e:
        print(f"[Database] Temporal insert failed: {e}")
        return False
