# legacy/ — Files Slated for Retirement at Cutover

This directory exists as a **placeholder during Phase 3-5 of the per-service
refactor (prompts P7-P15)**. It will receive source files at the P16 cutover
commit, NOT before.

## Why this folder exists now

During the dual-write phase (P7-P15), the per-IP source files (`l2fwd_ddos_collector.*`,
`l2fwd_detection_engine.*`, `l2fwd_l2_profile.*`, `l2fwd_temporal.*`) remain
active in the engine. They form the **reference path** that the new per-service
code is being validated against. Cross-validation requires the per-IP path to
produce its CSV output continuously throughout dual-write.

If we moved these files prematurely, we would either:
1. Break the build, or
2. Lose the cross-validation reference that proves the new engine works correctly.

## What goes here, and when

| File                         | Moves here at | Reason                                  |
|------------------------------|---------------|------------------------------------------|
| `l2fwd_ddos_collector.c`     | P16 cutover   | per-IP hot path retired                 |
| `l2fwd_ddos_collector.h`     | P16 cutover   | per-IP types retired                    |
| `l2fwd_detection_engine.c`   | P16 cutover   | per-IP detection retired                |
| `l2fwd_detection_engine.h`   | P16 cutover   | per-IP detection types retired          |
| `l2fwd_l2_profile.c`         | P16 cutover   | compile-time profile table retired      |
| `l2fwd_l2_profile.h`         | P16 cutover   | replaced by JSON registry profiles      |
| `l2fwd_temporal.c`           | P16 cutover   | per-IP temporal aggregator retired      |
| `l2fwd_temporal.h`           | P16 cutover   | per-IP temporal types retired           |

## What does NOT go here

- `main.c` — stays in root; gets modified at cutover to remove legacy init calls
- All `l2fwd_service_*.{c,h}` — these are the new world; stay in root
- `tests/*` — test harnesses stay in their folder
- `ddos_monitor/*` — Python backend; gets restructured separately in P12
- `third_party/cjson/*` — vendored dependency, stays put

## DO NOT manually move files here before P16

The migration script in P16's prompt will do `git mv` for each file
atomically as part of the deprecation switch commit. Premature manual
moves will break the build, dual-write cross-validation, and the
rollback path.

## After P16

Once cutover is complete and the new engine has been running stably,
the contents of this folder are preserved for:

1. **Forensic reference** if a post-cutover bug requires comparing
   old behavior to new behavior.
2. **Emergency rollback** if a critical issue is discovered within
   the first 7-10 days post-cutover. The `l2fwd.pre-service` binary
   backup plus these source files together restore the legacy world.

Files in `legacy/` are NOT compiled into the post-cutover engine. The
old binary (`/usr/local/bin/l2fwd.pre-service`) exists separately.
