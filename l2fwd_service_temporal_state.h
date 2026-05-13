#ifndef __L2FWD_SERVICE_TEMPORAL_STATE_H__
#define __L2FWD_SERVICE_TEMPORAL_STATE_H__

/**
 * @file   l2fwd_service_temporal_state.h
 * @brief  Per-service temporal aggregation state — P5 of the big-bang refactor.
 *
 * Mirrors the existing per-IP temporal module (l2fwd_temporal.h) in INTENT
 * (10s / 60s / 300s rolling windows) but with a simpler storage shape suited
 * to per-slot allocation:
 *
 *   - A single 1Hz ring buffer of SERVICE_TEMPORAL_MAX_SAMPLES (= 300) entries
 *     instead of the legacy 10s-bucket × 30 ring.
 *   - Three derived per-window aggregate structs (10s/60s/300s).
 *
 * The legacy module stays UNCHANGED in P5. Both modules will coexist through
 * the P7-P16 cutover. The aggregation math (sample insertion, window fold,
 * baseline updates) lands in P8. P5 ships only the data layout + lifecycle.
 *
 * Module name is deliberately `service_temporal_state` (not `service_temporal`)
 * to avoid colliding with l2fwd_temporal.h's `struct l2_temporal_state` in
 * the C tag namespace.
 */

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

/* -------------------------------------------------------------------------
 * Window geometry
 *
 * Window sizes match the locked legacy values from l2fwd_temporal.h
 * (L2_TEMP_SCALE_10S/60S/300S). MAX_SAMPLES = 300 holds the full 300-second
 * scale at 1Hz.
 * ------------------------------------------------------------------------- */
#define SERVICE_TEMPORAL_WINDOW_COUNT       3
#define SERVICE_TEMPORAL_WINDOW_10S_INDEX   0
#define SERVICE_TEMPORAL_WINDOW_60S_INDEX   1
#define SERVICE_TEMPORAL_WINDOW_300S_INDEX  2

#define SERVICE_TEMPORAL_WINDOW_10S_SIZE    10
#define SERVICE_TEMPORAL_WINDOW_60S_SIZE    60
#define SERVICE_TEMPORAL_WINDOW_300S_SIZE   300

/* Per-1Hz sample buffer for ring aggregation. Must be >= 300S_SIZE. */
#define SERVICE_TEMPORAL_MAX_SAMPLES        300

/* -------------------------------------------------------------------------
 * Per-window aggregate (derived from the 1Hz ring on each window close)
 * ------------------------------------------------------------------------- */
struct service_temporal_window {
    uint16_t size_seconds;       /**< 10, 60, or 300                     */
    uint16_t samples_filled;     /**< valid samples backing this window  */

    uint64_t total_pkts;
    uint64_t total_bytes;
    uint64_t total_flows;
    double   mean_pps;
    double   mean_bps;
    double   peak_pps;
    double   peak_bps;

    /* Per-state seconds tally across the window. */
    uint32_t attack_seconds;
    uint32_t suspicious_seconds;
};

/* -------------------------------------------------------------------------
 * Per-service temporal state
 *
 * Allocated on the heap (calloc) and pointed to from service_stats.temporal_state.
 * Plain calloc-backed.
 * ------------------------------------------------------------------------- */
struct service_temporal_state {
    bool active;

    /* 1Hz ring buffer of recent samples. samples[sample_head] is the
     * NEWEST entry; older entries trail behind modulo MAX_SAMPLES.
     *
     * detection_phase is a uint8_t mirror of enum service_detection_phase
     * — kept here so window aggregates can tally seconds-per-phase without
     * cross-pointer chase to the detection_state allocation. */
    struct {
        uint64_t timestamp_ns;
        uint64_t pkts;
        uint64_t bytes;
        uint64_t flows;
        uint8_t  detection_phase;
    } samples[SERVICE_TEMPORAL_MAX_SAMPLES];

    uint32_t sample_head;            /**< index of newest written sample */
    uint32_t sample_count;           /**< valid samples (capped at MAX)  */

    /* Per-window rolling aggregates. */
    struct service_temporal_window windows[SERVICE_TEMPORAL_WINDOW_COUNT];

    /* Bookkeeping. */
    uint64_t last_update_ns;
    uint64_t total_samples_seen;
};

/* -------------------------------------------------------------------------
 * Public API
 * ------------------------------------------------------------------------- */

/** Allocate one temporal state (calloc). Returns NULL on OOM. */
struct service_temporal_state *service_temporal_state_alloc(void);

/**
 * Initialise:
 *   - memset to zero
 *   - windows[0..2].size_seconds = {10, 60, 300}
 *   - active = true
 *
 * Returns 0 on success, negative if tmp is NULL.
 */
int service_temporal_state_init(struct service_temporal_state *tmp);

/**
 * Reset: zero the ring buffer + all per-window aggregates. PRESERVES `active`
 * and windows[].size_seconds. sample_head and sample_count are reset to 0.
 */
void service_temporal_state_reset(struct service_temporal_state *tmp);

/** Destroy: free the heap allocation. Idempotent if tmp is NULL. */
void service_temporal_state_destroy(struct service_temporal_state *tmp);

/** Diagnostic: one-line summary. */
void service_temporal_state_log(const struct service_temporal_state *tmp);

/** Size in bytes of one temporal state (for memory-budget tests). */
size_t service_temporal_state_sizeof(void);

#endif /* __L2FWD_SERVICE_TEMPORAL_STATE_H__ */
