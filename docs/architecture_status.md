# Source File Status — Mid-Refactor Snapshot (end of P6, start of Phase 3)

This document classifies every C / header / Python / config file in the
project by its current role in the per-service big-bang refactor.

## Status Categories

- **ACTIVE-NEW**: Part of the per-service architecture being built. Stays
  in root after cutover.
- **ACTIVE-LEGACY**: Currently driving the production hot path. Will
  retire at P16 cutover; moves to `legacy/`.
- **SUPPORTING**: Build / config / docs / vendored deps. Not subject to
  retirement.
- **SHARED-RUNTIME**: Touched by both new and legacy code paths during
  dual-write. Stays in root; may be modified in later prompts.

## C source files

| File                              | Status         | Notes                                                                   |
|-----------------------------------|----------------|-------------------------------------------------------------------------|
| `main.c`                          | SHARED-RUNTIME | Initializes both legacy collector and new service registry              |
| `l2fwd_ddos_collector.c`          | ACTIVE-LEGACY  | per-IP hot path; retires at P16; cross-validation reference until then  |
| `l2fwd_ddos_collector.h`          | ACTIVE-LEGACY  | per-IP stats struct; retires at P16                                     |
| `l2fwd_detection_engine.c`        | ACTIVE-LEGACY  | per-IP detection; retires at P16                                        |
| `l2fwd_detection_engine.h`        | ACTIVE-LEGACY  | per-IP detection types; retires at P16                                  |
| `l2fwd_temporal.c`                | ACTIVE-LEGACY  | per-IP temporal aggregator; retires at P16                              |
| `l2fwd_temporal.h`                | ACTIVE-LEGACY  | per-IP temporal types; retires at P16                                   |
| `l2fwd_l2_profile.c`              | ACTIVE-LEGACY  | compile-time profile table; replaced by JSON                            |
| `l2fwd_l2_profile.h`              | ACTIVE-LEGACY  | struct l2_profile retained (used by registry); see note below           |
| `l2fwd_service_registry.c`        | ACTIVE-NEW     | JSON loader + service hash table (P1-P3)                                |
| `l2fwd_service_registry.h`        | ACTIVE-NEW     | service_key_t, registry types, enum service_proto_kind                  |
| `l2fwd_service_stats.c`           | ACTIVE-NEW     | Per-service runtime stats data model (P4)                               |
| `l2fwd_service_stats.h`           | ACTIVE-NEW     | service_stats struct + lifecycle API                                    |
| `l2fwd_service_detection.c`       | ACTIVE-NEW     | Per-service detection state (P5)                                        |
| `l2fwd_service_detection.h`       | ACTIVE-NEW     | service_detection_state struct                                          |
| `l2fwd_service_temporal_state.c`  | ACTIVE-NEW     | Per-service temporal state (P5)                                         |
| `l2fwd_service_temporal_state.h`  | ACTIVE-NEW     | service_temporal_state struct                                           |
| `l2fwd_service_reload.c`          | ACTIVE-NEW     | SIGHUP reload subsystem (P6)                                            |
| `l2fwd_service_reload.h`          | ACTIVE-NEW     | reload API                                                              |

**Note on `l2fwd_l2_profile.h`**: this header defines `struct l2_profile`,
which the JSON registry parser (`l2fwd_service_registry.c`) uses to populate
profile objects from `services.json`. The struct itself is shared
infrastructure; the LEGACY part is the compile-time profile assignments
(`l2_profile_assignments[]` and the 11 hand-tuned `l2_profile_*_manual_v1`
instances in `.c`). At P16, the assignments array is deleted from `.c`
but the struct definition in `.h` may persist (decision deferred).

## Test files

| File                                      | Status     | Notes                              |
|-------------------------------------------|------------|------------------------------------|
| `tests/test_service_registry_load.c`      | ACTIVE-NEW | 24 assertions, P2 harness          |
| `tests/test_service_stats.c`              | ACTIVE-NEW | 57 assertions, P4 harness          |
| `tests/test_service_detection_state.c`    | ACTIVE-NEW | 62 assertions, P5 detection harness|
| `tests/test_service_temporal_state.c`     | ACTIVE-NEW | 40 assertions, P5 temporal harness |
| `tests/test_service_reload.c`             | ACTIVE-NEW | 54 assertions, P6 harness          |
| `tests/load_one.c`                        | ACTIVE-NEW | Cross-validator driver (P2)        |

## Python backend (ddos_monitor/)

| File                              | Status         | Notes                                       |
|-----------------------------------|----------------|---------------------------------------------|
| `ddos_monitor/main.py`            | SHARED-RUNTIME | Restructured in P12 to read service streams |
| `ddos_monitor/config.py`          | SHARED-RUNTIME | Schema constants update in P11-P12          |
| `ddos_monitor/collector.py`       | SHARED-RUNTIME | Major rewrite in P12                        |
| `ddos_monitor/database.py`        | SHARED-RUNTIME | Schema migration in P11                     |
| `ddos_monitor/web.py`             | SHARED-RUNTIME | New endpoints in P14                        |
| `ddos_monitor/shared_state.py`    | SHARED-RUNTIME | Composite-key records in P12                |

## Config + tooling

| Path                                            | Status     | Notes                                  |
|-------------------------------------------------|------------|----------------------------------------|
| `config/services.json`                | ACTIVE-NEW | Source of truth for registry           |
| `config/docs/services_schema.md`      | ACTIVE-NEW | JSON schema spec (P0)                  |
| `config/scripts/*.py`                 | ACTIVE-NEW | Generator + validator tooling          |
| `third_party/cjson/*`                           | SUPPORTING | Vendored MIT-licensed JSON parser      |
| `meson.build`, `Makefile`                       | SUPPORTING | Build system                           |
| `CHANGELOG.md`                                  | SUPPORTING | Bumped at P16 cutover                  |
| `legacy/README.md`                              | SUPPORTING | Placeholder docs (P6.5)                |
| `docs/architecture_status.md`                   | SUPPORTING | This file (P6.5)                       |
| `docs/migration_map.md`                         | SUPPORTING | Migration table (P6.5)                 |

## Snapshot timestamp

This snapshot reflects the state at the end of P6 (Phase 2 complete).
Will be regenerated at P15 (pre-cutover) and at P16 (post-cutover) to
reflect the actual moves.

---

## Post-P15 final state (v1.0.0)

P15 was production sign-off — operational hardening and documentation only,
no functional code changes. The per-service architecture (P0–P14) plus the
systemd integration is the shipped system.

### Final runtime architecture

Four systemd units, grouped by `anti-ddos.target`:

- `anti-ddos-dpdk-setup.service` — oneshot; binds the two data-plane NICs
  (`0000:02:02.0`, `0000:02:05.0`) to `vfio-pci` in no-IOMMU mode at boot so
  the stack survives reboots. Never touches the management NIC.
- `anti-ddos-collector.service` — `ddos_monitor/main.py`, runs as `user_1`;
  binds `/tmp/ddos_stats_socket`, parses the binary wire protocol, batch-
  inserts into ClickHouse.
- `anti-ddos-engine.service` — `build/l2fwd`, runs as `root` (DPDK); per-
  service detection hot path; emits the wire protocol.
- `anti-ddos-dashboard.service` — `ddos_monitor/web.py`, runs as `user_1`;
  Flask dashboard on `:5000`, reads ClickHouse only.

ClickHouse (`clickhouse-server.service`) is a separate, independently-managed
service holding the four per-service tables plus the preserved
`traffic_stats_legacy`. The dev workflow (`make run` / `make stop`) is
preserved alongside the systemd workflow; the two are mutually exclusive.

### Credentials hardened

`CH_PASSWORD` is no longer hardcoded in `ddos_monitor/config.py`. It is read
from the environment, supplied in production by
`EnvironmentFile=-/etc/anti-ddos/env` (mode 0640, root:user_1) on the
collector, engine, and dashboard units. `config.py` keeps a loud-warning dev
fallback; `.env.example` documents the file format. `.gitignore` now excludes
`.env`, `__pycache__/`, and `/etc/anti-ddos/`, and the previously-tracked
`__pycache__` files were removed from the git index.

### Operations documentation

- Five runbooks in `docs/runbooks/` — restart procedures, attack-alert
  response, protected-IP management, ClickHouse failure recovery, engine/code
  update procedures.
- `docs/monitoring.md` — daily health checks, ClickHouse reference queries,
  anomaly indicators, dashboard signal reference.
- `docs/SIGN_OFF.md` — one-page production acceptance checklist.

### Final integration smoke test

`scripts/integration_smoke_test.sh` (`make smoke`) — fast end-to-end health
check covering systemd unit state, processes, NIC bindings, dashboard health,
slot count, and ClickHouse data freshness.

### Deprecated modules

`ddos_monitor/database.py` and `ddos_monitor/shared_state.py` belong to the
retired legacy per-IP CSV path. Both carry `DEPRECATED post-P12` headers and
are preserved for git history only — the post-P12 collector and post-P14
dashboard do not use them.

### Tag

The project is sealed at tag `v1.0.0`.
