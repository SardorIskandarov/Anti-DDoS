#!/usr/bin/env python3
"""
ClickHouse schema migration for the Anti-DDoS per-service architecture (P11).

Safely transitions the database from the legacy per-IP schema to the new
per-service schema. Old data is PRESERVED by renaming, never dropped.

Usage:
    python3 scripts/migrate_clickhouse_schema.py [--dry-run] [--force]

Behaviour:
    1. Connects to ClickHouse using credentials from ddos_monitor/config.py
       (CH_HOST / CH_PORT / CH_USER / CH_PASSWORD / CH_DB).
    2. Ensures the database exists.
    3. Detects current schema state (legacy / partial / migrated).
    4. Renames  traffic_stats -> traffic_stats_legacy  (if not already done).
    5. Creates the 4 new tables with IF NOT EXISTS (idempotent):
         service_stats
         service_phase_transitions
         service_temporal_aggregates
         service_registry_snapshots
    6. Verifies each new table is queryable.
    7. Prints a summary.

Idempotency: running this twice in a row is harmless. If the schema is
already fully migrated it prints "Already migrated, nothing to do" and
exits 0 (unless --force is given, in which case it re-runs the
IF NOT EXISTS creates anyway — still harmless).

--dry-run prints every SQL statement that WOULD run, executes nothing,
and does not require clickhouse_driver to be installed.

Exit code: 0 on success, non-zero on any failure.
"""

import argparse
import os
import sys
import time

# --- make the flat ddos_monitor modules importable (import config) -------
_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(_REPO_ROOT, "ddos_monitor"))
import config  # noqa: E402

# clickhouse_driver is imported LAZILY inside _connect() so that
# --dry-run works on a bare interpreter without the package installed.

LEGACY_TABLE_NAME = config.CH_TABLE                       # "traffic_stats"
LEGACY_RENAMED_NAME = config.TABLE_TRAFFIC_STATS_LEGACY   # "traffic_stats_legacy"

NEW_TABLES = (
    config.TABLE_SERVICE_STATS,
    config.TABLE_PHASE_TRANSITIONS,
    config.TABLE_TEMPORAL_AGGREGATES,
    config.TABLE_REGISTRY_SNAPSHOTS,
)

# ===========================================================================
# Schema definitions. {db} is filled in with config.CH_DB at execution time.
# ===========================================================================

SCHEMA_SERVICE_STATS = """
CREATE TABLE IF NOT EXISTS {db}.service_stats (
    timestamp_ns       UInt64,
    timestamp_dt       DateTime DEFAULT toDateTime(intDiv(timestamp_ns, 1000000000)),
    slot_id            UInt16,
    sequence_num       UInt64,

    target_ip          UInt32,
    target_ip_str      String DEFAULT IPv4NumToString(target_ip),
    port               UInt16,
    proto_kind         UInt8,
    proto_kind_str     LowCardinality(String) DEFAULT
        multiIf(
            proto_kind = 1, 'TCP',
            proto_kind = 2, 'UDP',
            proto_kind = 3, 'ICMP',
            proto_kind = 4, 'CATCHALL_TCP',
            proto_kind = 5, 'CATCHALL_UDP',
            proto_kind = 6, 'CATCHALL_ICMP',
            proto_kind = 7, 'CATCHALL_OTHER',
            'UNKNOWN'),
    is_catchall        UInt8,
    profile_name       LowCardinality(String),

    phase              UInt8,
    phase_str          LowCardinality(String) DEFAULT
        multiIf(
            phase = 0, 'WARMUP',
            phase = 1, 'NORMAL',
            phase = 2, 'SUSPICIOUS',
            phase = 3, 'ATTACK',
            'UNKNOWN'),
    prev_phase         UInt8,
    warmup_remaining   UInt32,
    consecutive_attack_windows  UInt32,
    baseline_freeze_remaining   UInt32,
    thaw_cooldown_remaining     UInt32,
    windows_seen       UInt32,

    inbound_pkts       UInt64,
    inbound_bytes      UInt64,
    off_proto_pkts     UInt64,
    ip_frag_pkts       UInt64,
    ttl_sum            UInt64,
    ttl_sum_sq         UInt64,
    out_pkts           UInt64,
    out_bytes          UInt64,
    out_tcp_pkts       UInt32,
    out_udp_pkts       UInt32,
    out_icmp_pkts      UInt32,

    tcp_pkts           UInt64,
    tcp_bytes          UInt64,
    syn_pkts           UInt64,
    syn_ack_pkts       UInt64,
    fin_ack_pkts       UInt64,
    rst_pkts           UInt64,
    ack_data_pkts      UInt64,
    empty_ack_pkts     UInt64,
    zero_window_pkts   UInt64,
    udp_pkts           UInt64,
    udp_bytes          UInt64,
    icmp_pkts          UInt64,

    unique_src_ips     Float64,
    unique_flows       Float64,
    src_24_top1_share  Float64,
    src_24_entropy     Float64,
    ttl_mean           Float64,
    ttl_stddev         Float64,
    bw_pps_z_last      Float64,
    bw_bps_z_last      Float64,

    tier0_score          Float64,
    tier1_tcp_score      Float64,
    tier1_udp_score      Float64,
    tier1_icmp_score     Float64,
    tier1_dist_score     Float64,
    tier1_l3_score       Float64,
    tier1_offproto_score Float64,
    tier1_final_score    Float64,

    win_10s_total_pkts       UInt32,
    win_10s_peak_pps         UInt32,
    win_10s_attack_seconds   UInt32,
    win_60s_total_pkts       UInt32,
    win_60s_peak_pps         UInt32,
    win_60s_attack_seconds   UInt32,
    win_300s_total_pkts      UInt32,
    win_300s_peak_pps        UInt32,
    win_300s_attack_seconds  UInt32,

    inserted_at        DateTime DEFAULT now()
)
ENGINE = MergeTree
PARTITION BY toYYYYMMDD(timestamp_dt)
ORDER BY (target_ip, port, proto_kind, timestamp_ns)
TTL timestamp_dt + INTERVAL 30 DAY
SETTINGS index_granularity = 8192
"""

SCHEMA_PHASE_TRANSITIONS = """
CREATE TABLE IF NOT EXISTS {db}.service_phase_transitions (
    timestamp_ns       UInt64,
    timestamp_dt       DateTime DEFAULT toDateTime(intDiv(timestamp_ns, 1000000000)),
    slot_id            UInt16,
    target_ip          UInt32,
    target_ip_str      String DEFAULT IPv4NumToString(target_ip),
    port               UInt16,
    proto_kind         UInt8,
    profile_name       LowCardinality(String),
    from_phase         UInt8,
    from_phase_str     LowCardinality(String),
    to_phase           UInt8,
    to_phase_str       LowCardinality(String),
    tier0_score        Float64,
    tier1_final_score  Float64,
    attack_evidence    Float64,
    consecutive_attack_windows UInt32,
    inserted_at        DateTime DEFAULT now()
)
ENGINE = MergeTree
PARTITION BY toYYYYMMDD(timestamp_dt)
ORDER BY (target_ip, port, proto_kind, timestamp_ns)
TTL timestamp_dt + INTERVAL 90 DAY
"""

SCHEMA_TEMPORAL_AGGREGATES = """
CREATE TABLE IF NOT EXISTS {db}.service_temporal_aggregates (
    timestamp_ns       UInt64,
    timestamp_dt       DateTime DEFAULT toDateTime(intDiv(timestamp_ns, 1000000000)),
    slot_id            UInt16,
    target_ip          UInt32,
    port               UInt16,
    proto_kind         UInt8,
    window_seconds     UInt16,
    total_pkts         UInt64,
    peak_pps           UInt32,
    attack_seconds     UInt32,
    inserted_at        DateTime DEFAULT now()
)
ENGINE = MergeTree
PARTITION BY toYYYYMMDD(timestamp_dt)
ORDER BY (target_ip, port, proto_kind, window_seconds, timestamp_ns)
TTL timestamp_dt + INTERVAL 30 DAY
"""

SCHEMA_REGISTRY_SNAPSHOTS = """
CREATE TABLE IF NOT EXISTS {db}.service_registry_snapshots (
    timestamp_dt       DateTime DEFAULT now(),
    event_type         LowCardinality(String),
    source_path        String,
    n_protected_ips    UInt32,
    n_profiles         UInt32,
    n_services         UInt32,
    n_catchalls        UInt32,
    n_total_slots      UInt32,
    reload_count       UInt64,
    reload_failures    UInt64,
    error_message      String,
    services_json_sha256 FixedString(64)
)
ENGINE = MergeTree
PARTITION BY toYYYYMM(timestamp_dt)
ORDER BY (timestamp_dt, event_type)
TTL timestamp_dt + INTERVAL 1 YEAR
"""

TABLE_SCHEMAS = {
    config.TABLE_SERVICE_STATS:       SCHEMA_SERVICE_STATS,
    config.TABLE_PHASE_TRANSITIONS:   SCHEMA_PHASE_TRANSITIONS,
    config.TABLE_TEMPORAL_AGGREGATES: SCHEMA_TEMPORAL_AGGREGATES,
    config.TABLE_REGISTRY_SNAPSHOTS:  SCHEMA_REGISTRY_SNAPSHOTS,
}


# ===========================================================================
# Helpers
# ===========================================================================


def log(msg):
    """Timestamped, prefixed log line to stdout."""
    ts = time.strftime("%Y-%m-%dT%H:%M:%S")
    print(f"[migrate] {ts} {msg}", flush=True)


def _connect():
    """Open a ClickHouse client (no database= so we can CREATE DATABASE).

    Imported lazily so --dry-run works without clickhouse_driver."""
    from clickhouse_driver import Client
    client = Client(
        host=config.CH_HOST,
        port=config.CH_PORT,
        user=config.CH_USER,
        password=config.CH_PASSWORD,
        settings={"use_numpy": False},
    )
    log(f"connected to ClickHouse at {config.CH_HOST}:{config.CH_PORT}")
    return client


def _existing_tables(client, db):
    """Return the set of table names that exist in the target database."""
    rows = client.execute(
        "SELECT name FROM system.tables WHERE database = %(db)s",
        {"db": db})
    return {r[0] for r in rows}


# ===========================================================================
# Migration
# ===========================================================================


def run_migration(dry_run, force):
    db = config.CH_DB

    create_db_sql = f"CREATE DATABASE IF NOT EXISTS {db}"
    rename_sql = (f"RENAME TABLE {db}.{LEGACY_TABLE_NAME} "
                  f"TO {db}.{LEGACY_RENAMED_NAME}")

    # ---- dry-run: print SQL, touch nothing ----
    if dry_run:
        log("DRY RUN — the following SQL would be executed:")
        print()
        print("-- step 1: ensure database exists")
        print(create_db_sql + ";")
        print()
        print("-- step 2: rename legacy table (only if traffic_stats exists")
        print("--         and traffic_stats_legacy does not)")
        print(rename_sql + ";")
        print()
        step = 3
        for name in NEW_TABLES:
            print(f"-- step {step}: create {name}")
            print(TABLE_SCHEMAS[name].format(db=db).strip() + ";")
            print()
            step += 1
        log("DRY RUN complete — nothing was executed.")
        return 0

    # ---- real run ----
    try:
        client = _connect()
    except ImportError:
        log("ERROR: clickhouse_driver is not installed. Install it "
            "(it ships in ddos_monitor/venv) or run with --dry-run.")
        return 2
    except Exception as exc:  # noqa: BLE001
        log(f"ERROR: could not connect to ClickHouse: {exc}")
        return 2

    try:
        # Step 1: ensure database.
        log(f"ensuring database '{db}' exists")
        client.execute(create_db_sql)

        existing = _existing_tables(client, db)
        legacy_present = LEGACY_TABLE_NAME in existing
        legacy_renamed = LEGACY_RENAMED_NAME in existing
        new_present = {t for t in NEW_TABLES if t in existing}

        log(f"current state: legacy '{LEGACY_TABLE_NAME}'="
            f"{'present' if legacy_present else 'absent'}, "
            f"'{LEGACY_RENAMED_NAME}'="
            f"{'present' if legacy_renamed else 'absent'}, "
            f"new tables present: {sorted(new_present) or 'none'}")

        fully_migrated = (legacy_renamed
                          and len(new_present) == len(NEW_TABLES))
        if fully_migrated and not force:
            log("Already migrated, nothing to do "
                "(pass --force to re-run the idempotent creates).")
            return 0

        # Step 2: rename the legacy table (idempotent).
        if legacy_present and not legacy_renamed:
            log(f"renaming '{LEGACY_TABLE_NAME}' -> '{LEGACY_RENAMED_NAME}' "
                "(forensic data preserved, never dropped)")
            client.execute(rename_sql)
        elif legacy_renamed:
            log(f"'{LEGACY_RENAMED_NAME}' already exists — rename skipped")
        else:
            log(f"no legacy '{LEGACY_TABLE_NAME}' table found — "
                "rename skipped (fresh install)")

        # Step 3..6: create the four new tables (IF NOT EXISTS — idempotent).
        for name in NEW_TABLES:
            if name in new_present and not force:
                log(f"table '{name}' already exists — create skipped")
            else:
                log(f"creating table '{name}'")
                client.execute(TABLE_SCHEMAS[name].format(db=db))

        # Step 7: verify each new table is queryable.
        log("verifying new tables ...")
        for name in NEW_TABLES:
            count = client.execute(
                f"SELECT count() FROM {db}.{name}")[0][0]
            log(f"  verified '{name}' (current row count: {count})")

        log("migration complete — all 4 new tables present and queryable")
        log(f"legacy data preserved in '{db}.{LEGACY_RENAMED_NAME}'")
        return 0

    except Exception as exc:  # noqa: BLE001
        log(f"ERROR: migration failed: {exc}")
        return 1
    finally:
        try:
            client.disconnect()
        except Exception:  # noqa: BLE001
            pass


def main():
    parser = argparse.ArgumentParser(
        description="Migrate ClickHouse to the per-service schema (P11).")
    parser.add_argument("--dry-run", action="store_true",
                        help="print the SQL that would run; execute nothing")
    parser.add_argument("--force", action="store_true",
                        help="re-run the idempotent creates even if the "
                             "schema is already fully migrated")
    args = parser.parse_args()
    return run_migration(args.dry_run, args.force)


if __name__ == "__main__":
    sys.exit(main())
