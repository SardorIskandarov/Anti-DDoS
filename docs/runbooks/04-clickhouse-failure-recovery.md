# Runbook 04 — ClickHouse Failure Recovery

What happens when ClickHouse goes down, what recovers on its own, what does
not, and how to bring things back.

---

## Design stance: telemetry is best-effort

The detection path does **not** depend on ClickHouse. The engine keeps
detecting and the collector keeps receiving wire messages whether or not
ClickHouse is reachable. ClickHouse is the *telemetry sink* — losing it
degrades observability, not protection.

This means: **lost batches stay lost.** There is no spool-to-disk, no replay.
Accepting a bounded gap in the historical record during a ClickHouse outage is
an intentional v1.0.0 trade-off.

---

## What auto-recovers

- **Collector** — during a ClickHouse outage it cannot insert. It drops the
  affected batches, logs the errors, and keeps its socket bound. When
  ClickHouse comes back, the collector's next insert succeeds and it resumes
  normally. It may need a manual restart in some failure modes — see below.
- **Dashboard** — `/api/health` returns `status: degraded` and
  `ch_reachable: false` while ClickHouse is unreachable. The dashboard process
  stays up and serves the UI (tabs may show errors or stale data). When
  ClickHouse returns, health flips back to `ok` on the next check with no
  intervention.

## What does NOT auto-recover

- **The data gap.** Rows that would have been inserted during the outage are
  gone. After recovery you will see a hole in `service_stats` /
  `service_phase_transitions` covering the outage window.
- **A wedged collector.** Depending on how ClickHouse failed (hard crash vs
  clean stop), the collector's client connection can end up in a state it
  does not cleanly recover from. If the collector is not inserting again
  within a minute of ClickHouse being back, restart it (below).

---

## Check ClickHouse status

```bash
sudo systemctl status clickhouse-server
journalctl -u clickhouse-server -n 50 --no-pager
```

`clickhouse-server.service` is **not** managed by this project — it is a
separate, independently-installed service. The Anti-DDoS collector and
dashboard only declare `Requires=clickhouse-server.service`; they do not
start, stop, or configure it.

Quick reachability test:

```bash
clickhouse-client --password="$CH_PASSWORD" -q "SELECT 1"
```

(`CH_PASSWORD` comes from `/etc/anti-ddos/env` in production; the dev fallback
still works if the env file is absent.)

---

## Find the outage window

After recovery, identify exactly what was lost:

```sql
-- Most recent data on either side of the gap
SELECT min(timestamp_dt) AS first_seen,
       max(timestamp_dt) AS last_seen
FROM ddos_detection.service_stats
WHERE timestamp_dt > (now() - INTERVAL 1 HOUR);
```

```sql
-- Per-minute row counts — the gap shows up as missing/low minutes
SELECT toStartOfMinute(timestamp_dt) AS minute, count() AS rows
FROM ddos_detection.service_stats
WHERE timestamp_dt > (now() - INTERVAL 1 HOUR)
GROUP BY minute
ORDER BY minute;
```

Record the gap start/end in your incident notes — it is the authoritative
"we were blind from X to Y" statement.

---

## Bring the collector back after ClickHouse recovers

1. Confirm ClickHouse is healthy: `sudo systemctl status clickhouse-server`
   and the `SELECT 1` test above.
2. Check whether the collector resumed on its own:
   ```bash
   journalctl -u anti-ddos-collector -n 30 --no-pager
   ```
   Look for fresh successful-insert / batch-flush lines.
3. If it is still logging insert errors, restart it — it reconnects cleanly:
   ```bash
   sudo systemctl restart anti-ddos-collector
   ```
4. Because restarting the collector drops the engine's socket connection (the
   engine does not auto-reconnect), also restart the engine:
   ```bash
   sudo systemctl restart anti-ddos-engine
   ```
5. Verify end-to-end:
   ```bash
   make smoke
   ```

The dashboard needs no action — its health check re-probes ClickHouse on its
own and flips back to `ok`.

---

## Disk-full scenarios

A full ClickHouse data partition looks like a ClickHouse outage from the
collector's side (inserts fail).

```bash
df -h /var/lib/clickhouse
```

The schema sets TTLs on the per-service tables (retention on the order of
30 / 90 / 365 days depending on the table — see `docs/clickhouse_schema.md`
for the exact per-table values). ClickHouse drops aged partitions
automatically as part of normal merge activity, so steady-state disk use is
bounded. If the disk is full anyway:

- Confirm the TTLs are actually present:
  ```sql
  SELECT table, engine_full
  FROM system.tables
  WHERE database = 'ddos_detection';
  ```
- Check what is consuming space:
  ```sql
  SELECT table, formatReadableSize(sum(bytes_on_disk)) AS size
  FROM system.parts
  WHERE database = 'ddos_detection' AND active = 1
  GROUP BY table
  ORDER BY sum(bytes_on_disk) DESC;
  ```
- Forcing early cleanup of an aged partition is a ClickHouse-admin task
  (`ALTER TABLE ... DROP PARTITION ...`), done deliberately and with the
  retention policy in mind. Backup/restore of ClickHouse data is explicitly
  out of scope for this project — ClickHouse manages its own storage.

Once space is freed and ClickHouse accepts writes again, follow the collector
recovery steps above.
