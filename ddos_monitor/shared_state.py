# =============================================================================
# DEPRECATED post-P12.
#
# These in-memory buffers were written by the legacy CSV collector and read
# by the legacy web.py. The post-P12 collector (collector.py) does NOT
# populate these buffers, and the post-P14 dashboard (web.py) does NOT read
# them. Preserved for git history only.
# =============================================================================
# shared_state.py — process-wide thread-safe buffers shared between the
# DPDK collector threads (writers) and the Flask web layer (readers).
#
# Two independent buffers live here:
#
#   1. latest_traffic_data / data_lock
#      Newest-first list of the most recent 1-second IP records produced
#      by the DPDK collector and fed into ClickHouse `traffic_stats`.
#      Bounded by config.RAM_BUFFER_SIZE.
#
#   2. latest_temporal_data / temporal_data_lock
#      Newest-first list of the most recent multi-timescale TEMP records
#      produced by the temporal collector and fed into
#      `dst_ip_temporal_stats`. Bounded by config.TEMPORAL_RAM_BUFFER_SIZE.
#      Independent from the IP buffer so a temporal hiccup cannot
#      perturb the existing 1-second IP path.

import threading


# 1-second IP records — used by /api/stats, /api/live, /api/alerts, etc.
latest_traffic_data = []
data_lock = threading.Lock()

# Multi-timescale temporal records — used by /api/temporal/*.
latest_temporal_data = []
temporal_data_lock = threading.Lock()
