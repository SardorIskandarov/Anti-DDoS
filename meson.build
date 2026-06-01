project('l2fwd', 'c',
  version: '0.1.0',
  default_options: [
    'buildtype=release',
    'c_std=c11',
    'warning_level=2',
  ],
)

dpdk_dep = dependency('libdpdk', required: true)

add_project_arguments('-D_GNU_SOURCE', language: 'c')
add_project_arguments('-march=native', '-O3', '-funroll-loops', language: 'c')

# P1: include path for the vendored cJSON parser (third_party/cjson).
# Used by l2fwd_service_registry.c starting in P2.
inc_dirs = include_directories('engine', 'third_party/cjson')

# P1: vendored cJSON compiled as its own static lib so we can relax
# warnings ONLY for that translation unit (upstream code emits a few
# under -Wall -Wextra; suppressing project-wide would defeat the point).
# c_std=c89 matches cJSON's stated baseline.
cjson_lib = static_library('cjson',
  sources: 'third_party/cjson/cJSON.c',
  include_directories: inc_dirs,
  c_args: [
    '-w',          # silence all warnings for the vendored TU only
    '-std=c89',
  ],
  install: false,
)

src = [
  'engine/main.c',
  # P7 cutover: the four legacy per-IP modules (l2fwd_ddos_collector.c,
  # l2fwd_detection_engine.c, l2fwd_l2_profile.c, l2fwd_temporal.c) have
  # been retired and their source moved to legacy/. They are no longer
  # compiled into the engine.
  'engine/l2fwd_service_registry.c',      # P1: skeleton (stubs only); P2 fleshed out
  'engine/l2fwd_service_stats.c',         # P4: runtime per-service stats data model
  'engine/l2fwd_service_reload.c',        # P6: SIGHUP-driven services.json reload
  'engine/l2fwd_service_hotpath.c',       # P7: per-service packet hot path
  'engine/l2fwd_service_features.c',      # HLL/CM sketch primitives (post-cutover)
  # P5 cutover: detection P8/P9 (feature derivation + scoring/phase) moved to the
  # Python brain (ddos_monitor/detection); the frozen C parity oracle lives in
  # legacy/reference/. The socket wire protocol (l2fwd_service_wire.c) is retired
  # to legacy/ — the engine ships RAW telemetry via the snapshot shm instead.
  'engine/l2fwd_service_snapshot.c',      # C->Python raw-telemetry shm producer
  ]

executable('l2fwd',
  sources: src,
  include_directories: inc_dirs,
  link_with: cjson_lib,
  dependencies: [dpdk_dep],
  link_args: ['-lm', '-lrt'],   # -lrt: shm_open for the snapshot producer
  install: true,
)

# P2: standalone test harness for the service registry loader.
# No DPDK linkage — runs from any shell.
#   Build: ninja -C build test_service_registry_load
#   Run:   ./build/test_service_registry_load
test_registry = executable('test_service_registry_load',
  sources: [
    'tests/c/test_service_registry_load.c',
    'engine/l2fwd_service_registry.c',
  ],
  include_directories: inc_dirs,
  link_with: cjson_lib,
  install: false,
)

test('service_registry_load',
  test_registry,
  timeout: 30,
)

# P2: standalone "load one file, return rc" driver. Used by the
# cross-validator equivalence test to feed Python and C the exact
# same JSON.
executable('load_one',
  sources: [
    'tests/c/load_one.c',
    'engine/l2fwd_service_registry.c',
  ],
  include_directories: inc_dirs,
  link_with: cjson_lib,
  install: false,
)

# P4: standalone test harness for the service_stats data model (raw counters +
# sketches). No DPDK linkage.
test_stats = executable('test_service_stats',
  sources: [
    'tests/c/test_service_stats.c',
    'engine/l2fwd_service_stats.c',
    'engine/l2fwd_service_registry.c',
  ],
  include_directories: inc_dirs,
  link_with: cjson_lib,
  install: false,
)

test('service_stats',
  test_stats,
  timeout: 30,
)

# P5 cutover: test_service_detection_state and test_service_temporal_state were
# removed — per-slot detection_state / temporal_state no longer exist in the C
# data model (the Python brain owns detection). The frozen C originals live in
# legacy/reference/ and are exercised by tests/python/test_detector_*.py.

# P6: standalone test harness for the SIGHUP reload subsystem (registry + stats
# + reload). Post-cutover there is no detection/temporal state to wire.
test_reload = executable('test_service_reload',
  sources: [
    'tests/c/test_service_reload.c',
    'engine/l2fwd_service_reload.c',
    'engine/l2fwd_service_stats.c',
    'engine/l2fwd_service_registry.c',
  ],
  include_directories: inc_dirs,
  link_with: cjson_lib,
  install: false,
)

test('service_reload',
  test_reload,
  timeout: 30,
)

# P5 cutover: test_service_features / test_service_scoring / test_service_wire /
# dump_wire_sample were removed — their C modules (P8 feature derivation, P9
# scoring, the socket wire protocol) are no longer built into the engine. The
# frozen P8/P9 parity oracle in legacy/reference/ is exercised by the Python
# tests (tests/python/test_detector_*.py); HLL/CM sketch math is covered by the
# snapshot round-trip there.
