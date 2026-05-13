/**
 * @file   l2fwd_service_temporal_state.c
 * @brief  Per-service temporal state lifecycle — P5 implementation.
 *
 * Pure storage + lifecycle. No window aggregation, no baseline math, no
 * TEMP line emission. Hot-path code does not call any of these functions
 * yet — P8 wires them up.
 */

#include "l2fwd_service_temporal_state.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* -------------------------------------------------------------------------
 * Lifecycle
 * ------------------------------------------------------------------------- */

struct service_temporal_state *service_temporal_state_alloc(void) {
    struct service_temporal_state *tmp =
        calloc(1, sizeof(struct service_temporal_state));
    if (!tmp) {
        fprintf(stderr,
                "[service_temporal] [ERROR] alloc of %zu bytes failed\n",
                sizeof(struct service_temporal_state));
        return NULL;
    }
    return tmp;
}

int service_temporal_state_init(struct service_temporal_state *tmp) {
    if (!tmp) return -1;

    memset(tmp, 0, sizeof(*tmp));

    tmp->windows[SERVICE_TEMPORAL_WINDOW_10S_INDEX].size_seconds  =
        SERVICE_TEMPORAL_WINDOW_10S_SIZE;
    tmp->windows[SERVICE_TEMPORAL_WINDOW_60S_INDEX].size_seconds  =
        SERVICE_TEMPORAL_WINDOW_60S_SIZE;
    tmp->windows[SERVICE_TEMPORAL_WINDOW_300S_INDEX].size_seconds =
        SERVICE_TEMPORAL_WINDOW_300S_SIZE;

    tmp->active = true;
    return 0;
}

void service_temporal_state_reset(struct service_temporal_state *tmp) {
    if (!tmp) return;

    /* Cache the bits we need to preserve. */
    bool was_active = tmp->active;
    uint16_t sz0 = tmp->windows[0].size_seconds;
    uint16_t sz1 = tmp->windows[1].size_seconds;
    uint16_t sz2 = tmp->windows[2].size_seconds;

    /* Zero ring buffer entries. */
    memset(tmp->samples, 0, sizeof(tmp->samples));
    tmp->sample_head  = 0;
    tmp->sample_count = 0;

    /* Zero each window aggregate, then restore size_seconds. */
    memset(tmp->windows, 0, sizeof(tmp->windows));
    tmp->windows[SERVICE_TEMPORAL_WINDOW_10S_INDEX].size_seconds  = sz0;
    tmp->windows[SERVICE_TEMPORAL_WINDOW_60S_INDEX].size_seconds  = sz1;
    tmp->windows[SERVICE_TEMPORAL_WINDOW_300S_INDEX].size_seconds = sz2;

    /* PRESERVED. */
    tmp->active = was_active;

    /* Cleared. */
    tmp->last_update_ns     = 0;
    tmp->total_samples_seen = 0;
}

void service_temporal_state_destroy(struct service_temporal_state *tmp) {
    if (!tmp) return;
    free(tmp);
}

/* -------------------------------------------------------------------------
 * Diagnostics
 * ------------------------------------------------------------------------- */

void service_temporal_state_log(const struct service_temporal_state *tmp) {
    if (!tmp) {
        fprintf(stderr, "[service_temporal] (NULL)\n");
        return;
    }
    fprintf(stderr,
            "[service_temporal] active=%d sample_count=%u total_seen=%llu "
            "windows: 10s_pkts=%llu 60s_pkts=%llu 300s_pkts=%llu\n",
            (int)tmp->active,
            (unsigned)tmp->sample_count,
            (unsigned long long)tmp->total_samples_seen,
            (unsigned long long)tmp->windows[SERVICE_TEMPORAL_WINDOW_10S_INDEX].total_pkts,
            (unsigned long long)tmp->windows[SERVICE_TEMPORAL_WINDOW_60S_INDEX].total_pkts,
            (unsigned long long)tmp->windows[SERVICE_TEMPORAL_WINDOW_300S_INDEX].total_pkts);
}

size_t service_temporal_state_sizeof(void) {
    return sizeof(struct service_temporal_state);
}
