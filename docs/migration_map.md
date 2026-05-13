# Migration Map — File Movements During the Big Bang

This is the authoritative table of WHEN each file moves and HOW.

## Symbol legend

- `[stay]` = file remains in current location, possibly modified
- `[delete]` = file is removed from the repository (with `git rm`)
- `[move]` = file is moved with `git mv` to preserve history
- `[modify-only]` = file changes content but stays put

## Phase-by-phase movement schedule

### Phase 0 — JSON tooling (P0)
- `service_registry/` directory tree created [new]
- All existing engine files [stay]

### Phase 1 — Engine infrastructure (P1-P3)
- `third_party/cjson/*` [new]
- `l2fwd_service_registry.{c,h}` [new]
- `main.c` [modify-only — CLI flag + load call]
- All other existing files [stay]

### Phase 2 — Data model + reload (P4-P6)
- `l2fwd_service_stats.{c,h}` [new]
- `l2fwd_service_detection.{c,h}` [new]
- `l2fwd_service_temporal_state.{c,h}` [new]
- `l2fwd_service_reload.{c,h}` [new]
- `tests/test_service_*.c` [new]
- `main.c` [modify-only — wire stats + reload]
- ACTIVE-LEGACY files [stay, untouched]

### Phase 2.5 — P6.5 cleanup (THIS PROMPT)
- `legacy/` directory created [new, empty placeholder]
- `docs/` directory ensured
- `docs/architecture_status.md` [new]
- `docs/migration_map.md` [new]
- ACTIVE-LEGACY files [modify-only — header comment added]
- No source code changes anywhere

### Phase 3 — Hot path migration (P7-P10)
- `l2fwd_ddos_collector.c` [modify-only — add dual-write hooks]
- `l2fwd_ddos_collector.h` [modify-only — may add forward decls]
- `main.c` [modify-only]
- ACTIVE-NEW files may also be modified to add detection scoring + feature extraction

### Phase 4 — Output side (P11-P13)
- `ddos_monitor/database.py` [modify-only — add new tables]
- `ddos_monitor/collector.py` [modify-only — accept dual streams]
- `ddos_monitor/config.py` [modify-only]
- `ddos_monitor/shared_state.py` [modify-only]
- `scripts/migrate_clickhouse.py` [new]
- `scripts/rollback_clickhouse.py` [new]

### Phase 5 — Operability + cutover (P14-P16)
- `ddos_monitor/web.py` [modify-only — service endpoints]
- `templates/index.html` [modify-only — new tabs]
- `static/js/*` [modify-only — new chart logic]
- At P16 (the cutover commit):
  - `l2fwd_ddos_collector.c` [move → legacy/l2fwd_ddos_collector.c]
  - `l2fwd_ddos_collector.h` [move → legacy/l2fwd_ddos_collector.h]
  - `l2fwd_detection_engine.c` [move → legacy/l2fwd_detection_engine.c]
  - `l2fwd_detection_engine.h` [move → legacy/l2fwd_detection_engine.h]
  - `l2fwd_temporal.c` [move → legacy/l2fwd_temporal.c]
  - `l2fwd_temporal.h` [move → legacy/l2fwd_temporal.h]
  - `l2fwd_l2_profile.c` [move → legacy/l2fwd_l2_profile.c]
  - `l2fwd_l2_profile.h` [stay or move — decision deferred to P16, depends on whether struct l2_profile is still referenced by service_registry]
  - `main.c` [modify-only — remove legacy init calls; keep service init]
  - `meson.build` [modify-only — remove legacy sources from build]
  - ClickHouse table renames executed: traffic_stats → traffic_stats_legacy

### Phase 6 — Validation + sign-off (P17-P18)
- `docs/runbook_*.md` [new]
- `docs/architecture_status.md` [modify-only — final post-cutover snapshot]

## Files that NEVER move

| File                         | Why                                                |
|------------------------------|----------------------------------------------------|
| `main.c`                     | Always the engine entrypoint                       |
| `l2fwd_service_*.{c,h}`      | The future; stay in root forever                   |
| `tests/*`                    | Test harness layout doesn't change                 |
| `ddos_monitor/*`             | Python backend layout doesn't change               |
| `third_party/cjson/*`        | Vendored dep; only changes on cJSON version bump   |
| `service_registry/*`         | Config source of truth; stays put                  |

## Rollback considerations

The `legacy/` folder exists post-cutover as **immutable forensic
archive**. Files inside are preserved in git history through their
move, so `git log --follow legacy/l2fwd_ddos_collector.c` will show
the full development history before AND after the move.

If a critical bug ships post-cutover, emergency rollback uses:
1. Stop new engine
2. Restore old binary: `mv /usr/local/bin/l2fwd.pre-service /usr/local/bin/l2fwd`
3. Restart with old systemd unit
4. Rename ClickHouse tables back: `RENAME TABLE traffic_stats_legacy TO traffic_stats`

The source files in `legacy/` are NOT used for rollback. The binary
backup is. Source files in `legacy/` are for code review / forensics
only.
