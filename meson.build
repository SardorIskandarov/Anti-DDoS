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
inc_dirs = include_directories('third_party/cjson')

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
  'main.c',
  # P7 cutover: the four legacy per-IP modules (l2fwd_ddos_collector.c,
  # l2fwd_detection_engine.c, l2fwd_l2_profile.c, l2fwd_temporal.c) have
  # been retired and their source moved to legacy/. They are no longer
  # compiled into the engine.
  'l2fwd_service_registry.c',      # P1: skeleton (stubs only); P2 fleshed out
  'l2fwd_service_stats.c',         # P4: runtime per-service stats data model
  'l2fwd_service_detection.c',     # P5: per-service detection state
  'l2fwd_service_temporal_state.c',# P5: per-service temporal state
  'l2fwd_service_reload.c',        # P6: SIGHUP-driven services.json reload
  'l2fwd_service_hotpath.c',       # P7: per-service packet hot path
  'l2fwd_service_features.c',      # P8: feature extraction (HLL/CM/EWMA)
  'l2fwd_service_scoring.c',       # P9: detection scoring + phase machine
  'l2fwd_service_wire.c',          # P10: binary wire protocol v1
  ]

executable('l2fwd',
  sources: src,
  include_directories: inc_dirs,
  link_with: cjson_lib,
  dependencies: [dpdk_dep],
  link_args: ['-lm'],
  install: true,
)

# P2: standalone test harness for the service registry loader.
# No DPDK linkage — runs from any shell.
#   Build: ninja -C build test_service_registry_load
#   Run:   ./build/test_service_registry_load
test_registry = executable('test_service_registry_load',
  sources: [
    'tests/test_service_registry_load.c',
    'l2fwd_service_registry.c',
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
    'tests/load_one.c',
    'l2fwd_service_registry.c',
  ],
  include_directories: inc_dirs,
  link_with: cjson_lib,
  install: false,
)

# P4: standalone test harness for service_stats data model.
# No DPDK linkage.
#   Build: ninja -C build test_service_stats
#   Run:   ./build/test_service_stats
# P5: now also links the two new per-service state modules, because
# l2fwd_service_stats.c references service_detection_state_alloc /
# service_temporal_state_alloc from the wire_* helpers.
test_stats = executable('test_service_stats',
  sources: [
    'tests/test_service_stats.c',
    'l2fwd_service_stats.c',
    'l2fwd_service_registry.c',
    'l2fwd_service_detection.c',
    'l2fwd_service_temporal_state.c',
  ],
  include_directories: inc_dirs,
  link_with: cjson_lib,
  install: false,
)

test('service_stats',
  test_stats,
  timeout: 30,
)

# P5: standalone test harness for per-service detection state.
# Pulls in the service_registry so we can read a real profile from
# services.json for the profile-aware init test.
#   Build: ninja -C build test_service_detection_state
#   Run:   ./build/test_service_detection_state
test_detection = executable('test_service_detection_state',
  sources: [
    'tests/test_service_detection_state.c',
    'l2fwd_service_detection.c',
    'l2fwd_service_registry.c',
  ],
  include_directories: inc_dirs,
  link_with: cjson_lib,
  install: false,
)

test('service_detection_state',
  test_detection,
  timeout: 30,
)

# P5: standalone test harness for per-service temporal state.
# No registry needed — the temporal state is fully self-contained.
#   Build: ninja -C build test_service_temporal_state
#   Run:   ./build/test_service_temporal_state
test_temporal = executable('test_service_temporal_state',
  sources: [
    'tests/test_service_temporal_state.c',
    'l2fwd_service_temporal_state.c',
  ],
  include_directories: inc_dirs,
  install: false,
)

test('service_temporal_state',
  test_temporal,
  timeout: 30,
)

# P6: standalone test harness for SIGHUP reload subsystem. Links the full
# Phase 2 stack — registry, stats, detection, temporal, reload — because
# the reload's perform() touches every layer end-to-end.
#   Build: ninja -C build test_service_reload
#   Run:   ./build/test_service_reload
test_reload = executable('test_service_reload',
  sources: [
    'tests/test_service_reload.c',
    'l2fwd_service_reload.c',
    'l2fwd_service_stats.c',
    'l2fwd_service_registry.c',
    'l2fwd_service_detection.c',
    'l2fwd_service_temporal_state.c',
  ],
  include_directories: inc_dirs,
  link_with: cjson_lib,
  install: false,
)

test('service_reload',
  test_reload,
  timeout: 30,
)

# P8: standalone test harness for the feature extraction primitives.
# Exercises HLL, CM, EWMA, burst window, Welford, compute_one, and the
# temporal ring-buffer push. Pulls in service_stats / service_registry
# only because compute_one walks struct service_stats by value.
#   Build: ninja -C build test_service_features
#   Run:   ./build/test_service_features
test_features = executable('test_service_features',
  sources: [
    'tests/test_service_features.c',
    'l2fwd_service_features.c',
    'l2fwd_service_scoring.c',          # P9: features.c now refs is_frozen
    'l2fwd_service_stats.c',
    'l2fwd_service_detection.c',
    'l2fwd_service_temporal_state.c',
    'l2fwd_service_registry.c',
  ],
  include_directories: inc_dirs,
  link_with: cjson_lib,
  link_args: ['-lm'],   # service_features uses log/sqrt/ldexp
  install: false,
)

test('service_features',
  test_features,
  timeout: 30,
)

# P9: standalone test harness for the detection scoring layer. Exercises
# CUSUM, Tier-1 channels, phase machine, freeze respect, off-protocol
# detector. Pulls in scoring + features + the data-model modules (no
# DPDK; the scoring layer is pure CPU math on stats).
#   Build: ninja -C build test_service_scoring
#   Run:   ./build/test_service_scoring
test_scoring = executable('test_service_scoring',
  sources: [
    'tests/test_service_scoring.c',
    'l2fwd_service_scoring.c',
    'l2fwd_service_features.c',
    'l2fwd_service_stats.c',
    'l2fwd_service_detection.c',
    'l2fwd_service_temporal_state.c',
    'l2fwd_service_registry.c',
  ],
  include_directories: inc_dirs,
  link_with: cjson_lib,
  link_args: ['-lm'],   # scoring + features use math
  install: false,
)

test('service_scoring',
  test_scoring,
  timeout: 30,
)

# P10: standalone test harness for the wire protocol. Exercises CRC32,
# big-endian round-trips, full slot serialize+verify+parse, malformed
# message rejection, and serializes every active slot from the real
# services.json registry.
#   Build: ninja -C build test_service_wire
#   Run:   ./build/test_service_wire
test_wire = executable('test_service_wire',
  sources: [
    'tests/test_service_wire.c',
    'l2fwd_service_wire.c',
    'l2fwd_service_features.c',
    'l2fwd_service_scoring.c',
    'l2fwd_service_stats.c',
    'l2fwd_service_detection.c',
    'l2fwd_service_temporal_state.c',
    'l2fwd_service_registry.c',
  ],
  include_directories: inc_dirs,
  link_with: cjson_lib,
  link_args: ['-lm'],   # features + scoring use math; wire uses ldexp through features
  install: false,
)

test('service_wire',
  test_wire,
  timeout: 30,
)

# Test-only helper: emits ONE canonical v2 wire message (the
# test_full_slot_roundtrip fixture) to stdout as raw bytes, for C->Python
# wire-equivalence checking. Not a test() target and not installed; links the
# same sources as test_service_wire so it stays byte-identical to the engine.
#   Build: ninja -C build dump_wire_sample
#   Use:   ./build/dump_wire_sample > sample.bin   (binary on stdout)
dump_wire_sample = executable('dump_wire_sample',
  sources: [
    'tests/dump_wire_sample.c',
    'l2fwd_service_wire.c',
    'l2fwd_service_features.c',
    'l2fwd_service_scoring.c',
    'l2fwd_service_stats.c',
    'l2fwd_service_detection.c',
    'l2fwd_service_temporal_state.c',
    'l2fwd_service_registry.c',
  ],
  include_directories: inc_dirs,
  link_with: cjson_lib,
  link_args: ['-lm'],
  install: false,
)
