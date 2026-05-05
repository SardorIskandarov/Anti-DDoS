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

src = [
  'main.c',
  'l2fwd_ddos_collector.c',
  'l2fwd_detection_engine.c',
  'l2fwd_l2_profile.c',
  'l2fwd_temporal.c',
  ]

executable('l2fwd',
  sources: src,
  # FIX: Added ssl_dep to the list below
  dependencies: [dpdk_dep], 
  link_args: ['-lm'],
  install: true,
)
