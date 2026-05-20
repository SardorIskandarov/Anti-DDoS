# ClickHouse Schema — Per-Service Architecture (P11)

This document describes the ClickHouse schema introduced by the
per-service big-bang refactor. It is created and maintained by
`scripts/migrate_clickhouse_schema.py` and consumed by the per-service
collector (`ddos_monitor/collector.py`).

## Migration overview

The legacy per-IP engine wrote a single wide table, `traffic_stats`,
fed by a CSV/text protocol. The per-service engine emits a locked
416-byte binary wire protocol (one message per service slot per 1 Hz
tick) which the new collector lands into **four** purpose-built tables.

The migration:

1. Renames `traffic_stats` → `traffic_stats_legacy` (PRESERVED — never
   dropped; forensic data stays queryable forever).
2. Creates `service_stats`, `service_phase_transitions`,
   `service_temporal_aggregates`, `service_registry_snapshots`.

Run it with:

```bash
python3 scripts/migrate_clickhouse_schema.py --dry-run   # preview SQL
python3 scripts/migrate_clickhouse_schema.py             # apply
```

It is idempotent — re-running it is harmless. To undo:

```bash
python3 scripts/rollback_clickhouse_schema.py --dry-run
python3 scripts/rollback_clickhouse_schema.py --confirm
```

Rollback DROPs the four new tables and renames `traffic_stats_legacy`
back to `traffic_stats`. The legacy data itself is never at risk.

All tables live in the database named by `config.CH_DB`
(`ddos_detection` by default).

---

## Table: `service_stats`

The hot table. One row per active service slot per 1 Hz engine tick.
At full capacity (~250 slots) that is ~250 rows/sec ≈ 21.6 M rows/day.

### Columns

| Column | Type | Meaning |
|---|---|---|
| `timestamp_ns` | UInt64 | Engine wall-clock at emit, nanoseconds since UNIX epoch. |
| `timestamp_dt` | DateTime (DEFAULT) | `timestamp_ns` truncated to seconds; used for partitioning + TTL. |
| `slot_id` | UInt16 | Index into the engine's stats array (0..327). |
| `sequence_num` | UInt64 | Monotonic per-process counter — gap detection. |
| `target_ip` | UInt32 | Protected destination IP, host byte order. |
| `target_ip_str` | String (DEFAULT) | Dotted-quad form of `target_ip`. |
| `port` | UInt16 | Service port (0 for ICMP / catchall slots). |
| `proto_kind` | UInt8 | 1 TCP, 2 UDP, 3 ICMP, 4-7 CATCHALL_{TCP,UDP,ICMP,OTHER}. |
| `proto_kind_str` | LowCardinality(String) (DEFAULT) | Human-readable `proto_kind`. |
| `is_catchall` | UInt8 | 1 if this is a catchall slot, else 0. |
| `profile_name` | LowCardinality(String) | L2 profile name (first 8 chars on the wire). |
| `phase` | UInt8 | 0 WARMUP, 1 NORMAL, 2 SUSPICIOUS, 3 ATTACK. |
| `phase_str` | LowCardinality(String) (DEFAULT) | Human-readable `phase`. |
| `prev_phase` | UInt8 | Phase before the most recent transition. |
| `warmup_remaining` | UInt32 | Ticks left before the slot leaves WARMUP. |
| `consecutive_attack_windows` | UInt32 | Persistence-filter counter. |
| `baseline_freeze_remaining` | UInt32 | Ticks left of EWMA baseline freeze (>0 mid-ATTACK). |
| `thaw_cooldown_remaining` | UInt32 | Post-attack cautious-window counter. |
| `windows_seen` | UInt32 | Low 32 bits of the slot's lifetime tick count. |
| `inbound_pkts` / `inbound_bytes` | UInt64 | Inbound traffic this 1 s window. |
| `off_proto_pkts` | UInt64 | Packets whose IP-proto didn't match the slot's nominal proto. |
| `ip_frag_pkts` | UInt64 | Fragmented inbound packets. |
| `ttl_sum` / `ttl_sum_sq` | UInt64 | Running sum / sum-of-squares of inbound TTLs (for stddev). |
| `out_pkts` / `out_bytes` | UInt64 | Outbound traffic this window. |
| `out_tcp_pkts` / `out_udp_pkts` / `out_icmp_pkts` | UInt32 | Outbound per-proto packet counts. |
| `tcp_pkts` / `tcp_bytes` | UInt64 | TCP arm counters (0 on non-TCP slots). |
| `syn_pkts` / `syn_ack_pkts` / `fin_ack_pkts` / `rst_pkts` | UInt64 | TCP flag breakdown. |
| `ack_data_pkts` / `empty_ack_pkts` / `zero_window_pkts` | UInt64 | TCP behavioural counters. |
| `udp_pkts` / `udp_bytes` | UInt64 | UDP arm counters. |
| `icmp_pkts` | UInt64 | ICMP arm packet count. |
| `unique_src_ips` | Float64 | HLL cardinality estimate of distinct source IPs. |
| `unique_flows` | Float64 | HLL cardinality estimate of distinct flows. |
| `src_24_top1_share` | Float64 | Fraction of traffic from the single heaviest /24. |
| `src_24_entropy` | Float64 | Shannon entropy (bits) of the /24 source distribution. |
| `ttl_mean` / `ttl_stddev` | Float64 | Inbound TTL mean / Bessel-corrected stddev. |
| `bw_pps_z_last` / `bw_bps_z_last` | Float64 | Last burst-window z-score (pps / bps). |
| `tier0_score` | Float64 | Composite Tier-0 CUSUM risk, [0,1]. |
| `tier1_tcp_score` ... `tier1_offproto_score` | Float64 | Per-channel Tier-1 sub-scores, [0,1]. |
| `tier1_final_score` | Float64 | Combined Tier-1 score (weighted MAX of channels), [0,1]. |
| `tier0_risk_pps` / `tier0_risk_bps` / `tier0_risk_fps` | Float64 | Per-channel Tier-0 volumetric risk this window, [0,1] (wire v2). |
| `tier0_risk_burst_pps` / `tier0_risk_burst_bps` / `tier0_risk_burst_fps` | Float64 | Per-channel Tier-0 burst-window risk, [0,1] (wire v2). |
| `dominant_channel` | UInt8 | Argmax detection channel for this window (wire v2). Enum: 0 NONE, 1 PPS, 2 BPS, 3 FPS, 4 TCP, 5 UDP, 6 ICMP, 7 DIST, 8 L3, 9 OFFPROTO. |
| `dominant_channel_str` | LowCardinality(String) (DEFAULT) | DB-derived name of `dominant_channel` via `multiIf`. Source of truth for the mapping: `service_scoring_dominant_name()` / `enum service_dominant_channel` in `l2fwd_service_scoring.h`. |
| `win_{10s,60s,300s}_total_pkts` | UInt32 | Rolling-window total packets. |
| `win_{10s,60s,300s}_peak_pps` | UInt32 | Rolling-window peak pps. |
| `win_{10s,60s,300s}_attack_seconds` | UInt32 | Seconds spent in ATTACK within the window. |
| `inserted_at` | DateTime (DEFAULT) | Collector insert wall-clock. |

### Engine / partitioning / TTL

```
ENGINE = MergeTree
PARTITION BY toYYYYMMDD(timestamp_dt)        -- one part per day
ORDER BY (target_ip, port, proto_kind, timestamp_ns)
TTL timestamp_dt + INTERVAL 30 DAY            -- 30-day retention
```

The `ORDER BY` is tuned for the dominant query shape: "everything for
this service over a time range". Daily partitions keep `OPTIMIZE` and
`DROP PARTITION` cheap.

---

## Table: `service_phase_transitions`

One row each time a slot's `phase` changes. Far lower volume than
`service_stats` — only written on an actual NORMAL↔SUSPICIOUS↔ATTACK
edge. The collector detects transitions by tracking the previous phase
per `slot_id` in memory.

| Column | Type | Meaning |
|---|---|---|
| `timestamp_ns` / `timestamp_dt` | UInt64 / DateTime | When the transition was observed. |
| `slot_id` | UInt16 | Slot index. |
| `target_ip` / `target_ip_str` | UInt32 / String | Protected IP. |
| `port` / `proto_kind` | UInt16 / UInt8 | Service identity. |
| `profile_name` | LowCardinality(String) | L2 profile. |
| `from_phase` / `from_phase_str` | UInt8 / LowCardinality(String) | Phase before the edge. |
| `to_phase` / `to_phase_str` | UInt8 / LowCardinality(String) | Phase after the edge. |
| `tier0_score` / `tier1_final_score` | Float64 | Scores at the transition tick. |
| `attack_evidence` | Float64 | `max(tier0_score, tier1_final_score)` — the value the phase machine actually keyed off. |
| `consecutive_attack_windows` | UInt32 | Persistence counter at the transition. |
| `inserted_at` | DateTime (DEFAULT) | Collector insert wall-clock. |

```
ENGINE = MergeTree
PARTITION BY toYYYYMMDD(timestamp_dt)
ORDER BY (target_ip, port, proto_kind, timestamp_ns)
TTL timestamp_dt + INTERVAL 90 DAY            -- 90-day retention
```

Transitions are kept three times longer than raw stats — they are the
incident audit trail.

---

## Table: `service_temporal_aggregates`

Three rows per slot per tick — one per rolling window (10 s / 60 s /
300 s). A "long, narrow" companion to the wide `service_stats` table:
easier to chart a single window-size series without unpivoting.

| Column | Type | Meaning |
|---|---|---|
| `timestamp_ns` / `timestamp_dt` | UInt64 / DateTime | Tick time. |
| `slot_id` | UInt16 | Slot index. |
| `target_ip` / `port` / `proto_kind` | UInt32 / UInt16 / UInt8 | Service identity. |
| `window_seconds` | UInt16 | 10, 60, or 300. |
| `total_pkts` | UInt64 | Total packets in the window. |
| `peak_pps` | UInt32 | Peak per-second packet rate in the window. |
| `attack_seconds` | UInt32 | Seconds spent in ATTACK within the window. |
| `inserted_at` | DateTime (DEFAULT) | Collector insert wall-clock. |

```
ENGINE = MergeTree
PARTITION BY toYYYYMMDD(timestamp_dt)
ORDER BY (target_ip, port, proto_kind, window_seconds, timestamp_ns)
TTL timestamp_dt + INTERVAL 30 DAY
```

---

## Table: `service_registry_snapshots`

Audit log of registry lifecycle events — engine startup and SIGHUP
reloads (success and failure). Written by the collector / an admin
tool (P13 wiring); not part of the per-tick hot path.

| Column | Type | Meaning |
|---|---|---|
| `timestamp_dt` | DateTime (DEFAULT) | Event time. |
| `event_type` | LowCardinality(String) | `startup`, `reload_success`, `reload_failure`. |
| `source_path` | String | Path of the `services.json` involved. |
| `n_protected_ips` / `n_profiles` / `n_services` / `n_catchalls` / `n_total_slots` | UInt32 | Registry shape after the event. |
| `reload_count` / `reload_failures` | UInt64 | Cumulative engine reload counters. |
| `error_message` | String | Empty on success; the failure reason otherwise. |
| `services_json_sha256` | FixedString(64) | Hex SHA-256 of the `services.json` content — change detection. |

```
ENGINE = MergeTree
PARTITION BY toYYYYMM(timestamp_dt)           -- monthly (low volume)
ORDER BY (timestamp_dt, event_type)
TTL timestamp_dt + INTERVAL 1 YEAR            -- 1-year retention
```

---

## Partitioning & TTL strategy

| Table | Partition | TTL | Rationale |
|---|---|---|---|
| `service_stats` | daily | 30 days | Highest volume; daily parts keep merges + drops cheap. |
| `service_phase_transitions` | daily | 90 days | Incident audit trail — keep longer than raw stats. |
| `service_temporal_aggregates` | daily | 30 days | Same cadence as `service_stats`. |
| `service_registry_snapshots` | monthly | 1 year | Tiny volume; monthly parts are plenty. |
| `traffic_stats_legacy` | (unchanged) | (unchanged) | Frozen — never written again, never dropped. |

## Sizing estimate

At full capacity (~250 active slots, 1 Hz):

- `service_stats`: ~250 rows/sec × 86 400 s ≈ **21.6 M rows/day**.
  Raw wire bytes ≈ 250 × 416 B × 86 400 ≈ **9 GB/day** before ClickHouse
  compression; expect 5-15× compression on disk (lots of repeated
  identity columns + LowCardinality), so on the order of **0.6-1.8
  GB/day** stored, ~20-55 GB for the 30-day window.
- `service_temporal_aggregates`: 3× the row count but far narrower —
  similar or smaller on-disk footprint.
- `service_phase_transitions`: event-driven, typically << 1 % of the
  stats row count.
- `service_registry_snapshots`: a handful of rows per day.

## Example queries

All examples assume the database is `ddos_detection` (`config.CH_DB`).

### All slots currently in ATTACK phase

```sql
SELECT
    target_ip_str, port, proto_kind_str, profile_name,
    tier0_score, tier1_final_score,
    consecutive_attack_windows, baseline_freeze_remaining,
    timestamp_dt
FROM ddos_detection.service_stats
WHERE timestamp_dt > now() - INTERVAL 30 SECOND
  AND phase = 3                       -- ATTACK
ORDER BY tier1_final_score DESC;
```

### Top 10 protected IPs by inbound packets in the last hour

```sql
SELECT
    target_ip_str,
    sum(inbound_pkts)  AS total_pkts,
    sum(inbound_bytes) AS total_bytes
FROM ddos_detection.service_stats
WHERE timestamp_dt > now() - INTERVAL 1 HOUR
GROUP BY target_ip_str
ORDER BY total_pkts DESC
LIMIT 10;
```

### Phase transition history for one IP over the last 24 h

```sql
SELECT
    timestamp_dt, port, proto_kind,
    from_phase_str, to_phase_str,
    tier0_score, tier1_final_score, attack_evidence
FROM ddos_detection.service_phase_transitions
WHERE target_ip_str = '213.230.125.50'
  AND timestamp_dt > now() - INTERVAL 24 HOUR
ORDER BY timestamp_dt;
```

### Average final Tier-1 score per service, 10-minute buckets

```sql
SELECT
    target_ip_str, port, proto_kind_str,
    toStartOfTenMinutes(timestamp_dt) AS bucket,
    avg(tier1_final_score)            AS avg_t1,
    max(tier1_final_score)            AS max_t1
FROM ddos_detection.service_stats
WHERE timestamp_dt > now() - INTERVAL 6 HOUR
GROUP BY target_ip_str, port, proto_kind_str, bucket
ORDER BY target_ip_str, port, bucket;
```

### 60-second-window peak pps per service over the last hour

```sql
SELECT
    target_ip_str, port,
    max(peak_pps) AS hour_peak_pps
FROM ddos_detection.service_temporal_aggregates
WHERE window_seconds = 60
  AND timestamp_dt > now() - INTERVAL 1 HOUR
GROUP BY target_ip_str, port
ORDER BY hour_peak_pps DESC
LIMIT 20;
```

### Registry reload audit (last 30 days)

```sql
SELECT
    timestamp_dt, event_type, source_path,
    n_total_slots, reload_count, reload_failures, error_message
FROM ddos_detection.service_registry_snapshots
WHERE timestamp_dt > now() - INTERVAL 30 DAY
ORDER BY timestamp_dt DESC;
```

### Forensic: querying the preserved legacy data

The legacy per-IP table is intact under its new name. Its schema is
unchanged from the pre-refactor engine (62-column CSV layout — see the
historical `ddos_monitor/database.py` `CREATE TABLE` for column names):

```sql
-- Confirm the legacy table is present and how far back it goes
SELECT
    count()           AS rows,
    min(timestamp_ms) AS earliest_ms,
    max(timestamp_ms) AS latest_ms
FROM ddos_detection.traffic_stats_legacy;

-- Pull legacy rows for a specific dst_ip around an incident window
SELECT *
FROM ddos_detection.traffic_stats_legacy
WHERE dst_ip = '213.230.125.50'
  AND timestamp_ms BETWEEN 1715000000000 AND 1715003600000
ORDER BY timestamp_ms;
```

`traffic_stats_legacy` receives no new writes after the migration — it
is a frozen forensic archive. Keep it until you are confident the
per-service pipeline is fully trusted in production; it is the
data-side rollback path (the binary backup `l2fwd.pre-service` is the
engine-side rollback path).
