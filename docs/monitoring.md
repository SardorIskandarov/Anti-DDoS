# Monitoring Playbook

Day-to-day monitoring reference for the Anti-DDoS per-service detection
system: health checks, ClickHouse queries, and how to read the dashboard.

For incident response see the runbooks in `docs/runbooks/`. This document is
about *watching* the system, not fixing it.

---

## A. Daily health checks

A healthy system passes all four of these. They take under a minute.

### 1. All four systemd services active

```bash
make systemd-status
```

Expect `active` for `anti-ddos-dpdk-setup` (shows `active (exited)` — it is a
oneshot), `anti-ddos-collector`, `anti-ddos-engine`, `anti-ddos-dashboard`.
Anything `failed` or `activating (auto-restart)` -> runbook 01.

### 2. Dashboard health endpoint

```bash
curl -s http://localhost:5000/api/health
```

Expect `status: ok` and `ch_reachable: true`. `status: degraded` means data
has gone stale or ClickHouse is unreachable -> runbook 04.

### 3. ClickHouse data freshness

```bash
clickhouse-client --password="$CH_PASSWORD" -q \
  "SELECT now() - max(timestamp_dt) FROM ddos_detection.service_stats"
```

Expect a value **under 30 seconds**. The engine emits per-slot snapshots every
second; anything older than ~30s means the engine or collector is not
delivering.

### 4. Process check — three distinct PIDs

```bash
pgrep -f l2fwd                  # engine
pgrep -f ddos_monitor/main.py   # collector
pgrep -f ddos_monitor/web.py    # dashboard
```

Three commands, three PIDs. The `make smoke` integration test wraps checks
1–4 plus NIC bindings and slot counts — run `make smoke` for the full sweep.

---

## B. ClickHouse reference queries

All queries assume the `ddos_detection` database. Run with
`clickhouse-client --password="$CH_PASSWORD" -q "<sql>"`, or paste into the
ClickHouse client interactively.

### 1. Phase distribution right now

**Answers:** how many service slots are in each detection phase at this moment.
**Run it when:** starting a shift, or to sanity-check after an alert — most
slots should be `NORMAL`.

```sql
SELECT
    phase,
    count() AS slots
FROM (
    SELECT
        slot_id,
        argMax(phase_str, timestamp_ns) AS phase
    FROM ddos_detection.service_stats
    WHERE timestamp_dt >= now() - INTERVAL 60 SECOND
    GROUP BY slot_id
)
GROUP BY phase
ORDER BY slots DESC;
```

### 2. Top 10 slots by Tier-1 score, last 5 minutes

**Answers:** which slots are scoring hottest right now.
**Run it when:** triaging — find the worst offenders before drilling into the
dashboard Slot Detail tab.

```sql
SELECT
    target_ip_str, port, proto_kind_str,
    avg(tier1_final_score) AS avg_score,
    max(tier1_final_score) AS peak_score
FROM ddos_detection.service_stats
WHERE timestamp_dt >= now() - INTERVAL 5 MINUTE
GROUP BY target_ip_str, port, proto_kind_str
ORDER BY peak_score DESC
LIMIT 10;
```

### 3. Phase transitions in the last hour

**Answers:** every phase change, newest first — the raw feed behind the
Alerts tab.
**Run it when:** reconstructing an incident timeline, or checking for flapping.

```sql
SELECT
    timestamp_dt, target_ip_str, port, proto_kind,
    from_phase_str, to_phase_str,
    tier1_final_score
FROM ddos_detection.service_phase_transitions
WHERE timestamp_dt >= now() - INTERVAL 1 HOUR
ORDER BY timestamp_ns DESC;
```

### 4. Collector throughput history (rows/minute)

**Answers:** is the collector inserting at a steady rate.
**Run it when:** you suspect the collector is dropping batches or ClickHouse
is slow — look for dips or gaps.

```sql
SELECT
    toStartOfMinute(inserted_at) AS minute,
    count() AS rows_inserted
FROM ddos_detection.service_stats
WHERE inserted_at >= now() - INTERVAL 1 HOUR
GROUP BY minute
ORDER BY minute;
```

### 5. Data freshness

**Answers:** how many seconds since the last row landed. Should be very low.
**Run it when:** any time — this is the single most useful one-line health
query.

```sql
SELECT
    now() - max(timestamp_dt) AS staleness_seconds
FROM ddos_detection.service_stats;
```

### 6. Disk usage by table

**Answers:** how much disk each table is using.
**Run it when:** checking on retention / TTL behaviour, or investigating a
disk-space warning (runbook 04).

```sql
SELECT
    database, table,
    formatReadableSize(sum(bytes_on_disk)) AS size
FROM system.parts
WHERE database = 'ddos_detection' AND active = 1
GROUP BY database, table
ORDER BY sum(bytes_on_disk) DESC;
```

### 7. Registry snapshot history

**Answers:** when the registry last changed and how many slots it defined.
**Run it when:** verifying a `services.json` reload took effect (runbook 03).

```sql
SELECT snapshot_ts, slot_count, source
FROM ddos_detection.service_registry_snapshots
ORDER BY snapshot_ts DESC
LIMIT 10;
```

---

## Anomaly indicators

What "weird" looks like in the numbers, and what it usually means:

| Signal                                            | Likely meaning                                                        |
|---------------------------------------------------|-----------------------------------------------------------------------|
| Collector `queue_drops` > 0                       | Backpressure — ClickHouse is too slow to keep up; inserts are lagging |
| Collector `parse_errors` > 0                      | Wire-protocol mismatch — C and Python wire constants disagree (runbook 05) |
| Collector `reconnects` climbing over time         | Socket / process instability — the collector keeps losing its connection |
| Many slots in `ATTACK` simultaneously             | A real broad attack — or a global threshold tuned too sensitive (runbook 02) |
| `/api/health` `degraded` for > 5 minutes          | Sustained collector or ClickHouse problem — not a transient blip (runbook 04) |
| Freshness query (B5) climbing past ~30s           | Engine or collector not delivering — check both (runbook 01)          |
| Throughput (B4) drops to zero for a minute+       | Collector stalled or ClickHouse outage during that window             |

The collector logs its counters (`queue_drops`, `parse_errors`, `reconnects`)
periodically to its journal:

```bash
journalctl -u anti-ddos-collector --no-pager | grep -iE 'drop|error|reconnect'
```

A healthy collector reports all three at zero.

---

## C. Dashboard signal reference

The dashboard at `http://<host>:5000` has five tabs. What each one tells you:

### Overview tab
Phase-tile distribution across all slots. **Healthy:** the large majority of
tiles `NORMAL`, an occasional `WARMUP` when a slot is newly seen or just
reloaded. **Signal:** any `ATTACK` tile is a real detection — go look. A wave
of `SUSPICIOUS` tiles appearing together is either a developing broad attack
or a threshold problem.

### Services tab
Every slot as a row, colored by current phase. **Healthy:** mostly the
`NORMAL` color. **Signal:** scan for non-`NORMAL` rows; sort/skim for clusters
(same IP, multiple ports) which often indicate a coordinated attack.

### Slot Detail tab
Per-slot deep view. The **Tier-1 score chart** is the key signal: trending
**up** = a developing attack; a sustained high **plateau** = an ongoing
attack; trending **down** = subsiding (or mitigation working). The component
breakdown on this tab identifies the attack *type* — see runbook 02.

### Registry tab
The live registry as the engine currently sees it (sourced from
`/tmp/svc.json`). **Use it to:** confirm a `services.json` reload took effect
— the tab should reflect your change after a SIGHUP (runbook 03).

### Alerts tab
Phase transitions, newest first — the human-facing view of
`service_phase_transitions`. **Signal:** `-> ATTACK` rows, especially
`NORMAL -> ATTACK` (sharp onset). Repeated `SUSPICIOUS <-> NORMAL` rows on one
slot = flapping, usually a tuning issue not an attack.

There is no acknowledge/silence in v1.0.0 — the Alerts tab is a live feed and
the engine keeps recording transitions regardless of operator action. An alert
"clears" only when the slot transitions back to `NORMAL`, which is itself a
new row.
