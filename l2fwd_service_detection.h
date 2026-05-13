#ifndef __L2FWD_SERVICE_DETECTION_H__
#define __L2FWD_SERVICE_DETECTION_H__

/**
 * @file   l2fwd_service_detection.h
 * @brief  Per-service detection state — P5 of the big-bang refactor.
 *
 * Mirrors the per-IP `struct detection_engine` from l2fwd_detection_engine.h
 * but at PER-SLOT granularity. P5 owns allocation + lifecycle + the
 * stub-zero-able shape of the state. No CUSUM math, no EWMA updates, no
 * phase transitions — those land in P8/P9.
 *
 * Divergence note vs the legacy per-IP detection_engine:
 *   - The legacy module exposes a typedef'd enum (`detection_state_t`) with
 *     unprefixed values (WARMUP / NORMAL / SUSPICIOUS / ATTACK). To avoid
 *     symbol collision when both modules are linked into the same binary
 *     during the P0-P17 cutover, P5 uses a NEW prefixed enum
 *     `service_detection_phase`. The integer ordinals match so cross-module
 *     comparisons (legacy -> per-service) are byte-equivalent if needed.
 *   - The legacy struct keeps a full `struct detection_result` cache; P5
 *     keeps only the last_* scalar scores actually consumed by the CSV
 *     emitter to keep per-slot footprint tight (~hundreds of bytes vs ~1 KB).
 */

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

/* Forward-declared so the header is decoupled from the profile module. */
struct l2_profile;

/* -------------------------------------------------------------------------
 * Detection state machine
 * ------------------------------------------------------------------------- */

enum service_detection_phase {
    SERVICE_DET_PHASE_WARMUP     = 0,
    SERVICE_DET_PHASE_NORMAL     = 1,
    SERVICE_DET_PHASE_SUSPICIOUS = 2,
    SERVICE_DET_PHASE_ATTACK     = 3,
    SERVICE_DET_PHASE_MAX        = 4,
};

/**
 * Fallback warmup window count used when no profile is supplied (or the
 * supplied profile has warmup_windows = 0). Matches the legacy
 * DETECTION_WARMUP_WINDOWS constant in l2fwd_detection_engine.h.
 */
#define SERVICE_DETECTION_DEFAULT_WARMUP_WINDOWS  400u

/* -------------------------------------------------------------------------
 * Per-channel CUSUM state
 *
 * Distinct from legacy `struct cusum_state {S, variance, alpha_std}` —
 * the legacy struct conflates Tier-0 indexed-array storage with EWMA
 * smoothing. Here we split: per-channel CUSUM lives in its own struct,
 * and EWMA lives in service_common_ewma (l2fwd_service_stats.h).
 * P9 will populate breach_count from the H * std cusum alarm.
 * ------------------------------------------------------------------------- */
struct service_cusum_state {
    double   S_plus;        /**< positive deviation accumulator       */
    double   S_minus;       /**< negative deviation accumulator       */
    double   last_value;    /**< last observed value (delta input)    */
    uint32_t breach_count;  /**< times H was exceeded in this window  */
};

/* -------------------------------------------------------------------------
 * Per-service detection state
 *
 * Allocated on the heap (calloc) and pointed to from service_stats.detection_state.
 * Plain calloc-backed — no DPDK hugepages in P5.
 * ------------------------------------------------------------------------- */
struct service_detection_state {
    /* Phase machine. */
    uint8_t  phase;                          /**< enum service_detection_phase */
    uint8_t  prev_phase;                     /**< for transition logging       */
    bool     active;                         /**< true once init() has been called */

    /* Warmup tracking. */
    uint32_t warmup_windows_completed;
    uint32_t warmup_remaining;

    /* CUSUM state per Tier-0 channel. */
    struct service_cusum_state cusum_pps;
    struct service_cusum_state cusum_bps;
    struct service_cusum_state cusum_fps;
    struct service_cusum_state cusum_burst_pps;
    struct service_cusum_state cusum_burst_bps;
    struct service_cusum_state cusum_burst_fps;

    /* Persistence filter — consecutive windows scoring ATTACK. */
    uint32_t consecutive_attack_windows;

    /* Freeze / thaw counters. */
    uint32_t baseline_freeze_remaining;      /**< >0 means EWMA frozen        */
    uint32_t thaw_cooldown_remaining;        /**< post-attack cautious window */

    /* Cached scores (CSV emit consumes these). Cleared each window. */
    double last_tier0_score;
    double last_tier0_risk_pps;
    double last_tier0_risk_bps;
    double last_tier0_risk_fps;
    double last_tier0_risk_burst_pps;
    double last_tier0_risk_burst_bps;
    double last_tier0_risk_burst_fps;
    double last_tier1_tcp_score;
    double last_tier1_udp_score;
    double last_tier1_icmp_score;
    double last_tier1_dist_score;
    double last_tier1_l3_score;
    double last_tier1_offproto_score;        /**< P9 off-protocol detector */
    double last_tier1_final_score;
    bool   last_tier1_evaluated;
    double last_attack_evidence;

    /* Window bookkeeping (independent of slot->window_count). */
    uint64_t windows_seen;
    uint64_t last_phase_change_window;

    /* Profile pointer (cached at init; not owned). */
    const struct l2_profile *profile;
};

/* -------------------------------------------------------------------------
 * Public API
 * ------------------------------------------------------------------------- */

/**
 * Allocate one detection state struct (calloc). Returns NULL on OOM. The
 * caller owns the allocation and must call service_detection_state_destroy().
 */
struct service_detection_state *service_detection_state_alloc(void);

/**
 * Initialise a detection state from a profile.
 *   - phase = WARMUP, prev_phase = WARMUP
 *   - warmup_remaining = profile->warmup_windows (or
 *     SERVICE_DETECTION_DEFAULT_WARMUP_WINDOWS if profile is NULL or its
 *     warmup_windows is 0)
 *   - all CUSUM state zero, all last_* zero
 *   - active = true
 *
 * Returns 0 on success, negative if `det` is NULL.
 */
int service_detection_state_init(struct service_detection_state *det,
                                  const struct l2_profile *profile);

/**
 * Reset per-window-emit fields. Called between windows. PRESERVES phase,
 * CUSUM accumulators, warmup_remaining, consecutive_attack_windows,
 * baseline_freeze_remaining, thaw_cooldown_remaining. Zeros the last_*
 * cached scores and increments windows_seen.
 */
void service_detection_state_reset_window(struct service_detection_state *det);

/** Destroy: free the heap allocation. Idempotent if det is NULL. */
void service_detection_state_destroy(struct service_detection_state *det);

/** Return a stable string name for a phase enum value. */
const char *service_detection_phase_name(uint8_t phase);

/** Diagnostic: one-line summary to stderr. */
void service_detection_state_log(const struct service_detection_state *det);

/* -------------------------------------------------------------------------
 * Compile-time invariants
 * ------------------------------------------------------------------------- */
_Static_assert(sizeof(struct service_detection_state) > 0,
               "service_detection_state must have non-zero size");

#endif /* __L2FWD_SERVICE_DETECTION_H__ */
