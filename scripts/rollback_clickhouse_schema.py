#!/usr/bin/env python3
"""
Rollback the per-service ClickHouse schema migration (P11).

DROPS the 4 per-service tables and renames traffic_stats_legacy back to
traffic_stats, restoring the legacy per-IP schema.

Usage:
    python3 scripts/rollback_clickhouse_schema.py --confirm
    python3 scripts/rollback_clickhouse_schema.py --dry-run

Safety: this is DESTRUCTIVE (it DROPs the per-service tables and any
rows they hold), so a real run requires the explicit --confirm flag.
--dry-run prints the SQL and touches nothing (and does not need
clickhouse_driver installed).

The legacy data itself is never at risk: traffic_stats_legacy is only
RENAMEd, never dropped. After rollback the legacy table is back under
its original name traffic_stats.

Exit code: 0 on success, non-zero on any failure or missing --confirm.
"""

import argparse
import os
import sys
import time

# --- make the flat ddos_monitor modules importable (import config) -------
_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(_REPO_ROOT, "ddos_monitor"))
import config  # noqa: E402

# clickhouse_driver is imported lazily inside _connect().

LEGACY_TABLE_NAME = config.CH_TABLE                       # "traffic_stats"
LEGACY_RENAMED_NAME = config.TABLE_TRAFFIC_STATS_LEGACY   # "traffic_stats_legacy"

NEW_TABLES = (
    config.TABLE_SERVICE_STATS,
    config.TABLE_PHASE_TRANSITIONS,
    config.TABLE_TEMPORAL_AGGREGATES,
    config.TABLE_REGISTRY_SNAPSHOTS,
)


def log(msg):
    ts = time.strftime("%Y-%m-%dT%H:%M:%S")
    print(f"[rollback] {ts} {msg}", flush=True)


def _connect():
    """Open a ClickHouse client. Lazy import so --dry-run needs no driver."""
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
    rows = client.execute(
        "SELECT name FROM system.tables WHERE database = %(db)s",
        {"db": db})
    return {r[0] for r in rows}


def run_rollback(dry_run):
    db = config.CH_DB
    drop_sqls = [f"DROP TABLE IF EXISTS {db}.{t}" for t in NEW_TABLES]
    rename_sql = (f"RENAME TABLE {db}.{LEGACY_RENAMED_NAME} "
                  f"TO {db}.{LEGACY_TABLE_NAME}")

    if dry_run:
        log("DRY RUN — the following SQL would be executed:")
        print()
        for i, sql in enumerate(drop_sqls, start=1):
            print(f"-- step {i}: drop per-service table")
            print(sql + ";")
            print()
        print(f"-- step {len(drop_sqls) + 1}: restore legacy table name")
        print(f"--         (only if {LEGACY_RENAMED_NAME} exists and")
        print(f"--          {LEGACY_TABLE_NAME} does not)")
        print(rename_sql + ";")
        print()
        log("DRY RUN complete — nothing was executed.")
        return 0

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
        existing = _existing_tables(client, db)

        # Step 1..4: drop the per-service tables.
        for t in NEW_TABLES:
            if t in existing:
                log(f"dropping table '{t}'")
                client.execute(f"DROP TABLE IF EXISTS {db}.{t}")
            else:
                log(f"table '{t}' not present — drop skipped")

        # Step 5: restore the legacy table name.
        existing = _existing_tables(client, db)
        legacy_present = LEGACY_TABLE_NAME in existing
        legacy_renamed = LEGACY_RENAMED_NAME in existing
        if legacy_renamed and not legacy_present:
            log(f"renaming '{LEGACY_RENAMED_NAME}' -> '{LEGACY_TABLE_NAME}'")
            client.execute(rename_sql)
        elif legacy_present:
            log(f"'{LEGACY_TABLE_NAME}' already exists — rename skipped")
        else:
            log(f"no '{LEGACY_RENAMED_NAME}' table found — rename skipped "
                "(nothing to restore)")

        log("rollback complete — legacy per-IP schema restored")
        return 0

    except Exception as exc:  # noqa: BLE001
        log(f"ERROR: rollback failed: {exc}")
        return 1
    finally:
        try:
            client.disconnect()
        except Exception:  # noqa: BLE001
            pass


def main():
    parser = argparse.ArgumentParser(
        description="Rollback the per-service ClickHouse schema (P11). "
                    "DESTRUCTIVE — drops the 4 per-service tables.")
    parser.add_argument("--confirm", action="store_true",
                        help="required to actually execute the rollback")
    parser.add_argument("--dry-run", action="store_true",
                        help="print the SQL that would run; execute nothing")
    args = parser.parse_args()

    if args.dry_run:
        return run_rollback(dry_run=True)

    if not args.confirm:
        print("ERROR: rollback is destructive (it DROPs the 4 per-service "
              "tables).", file=sys.stderr)
        print("Re-run with --confirm to proceed, or --dry-run to preview "
              "the SQL.", file=sys.stderr)
        return 2

    return run_rollback(dry_run=False)


if __name__ == "__main__":
    sys.exit(main())
