#ifndef __L2FWD_SERVICE_SCORING_H__
#define __L2FWD_SERVICE_SCORING_H__

/**
 * @file   l2fwd_service_scoring.h
 * @brief  Per-service detection scoring — P9 of the big-bang refactor.
 *
 * P7 wired raw counters into per-slot stats. P8 turned those raw counters
 * into ratios + EWMA-tracked baselines. P9 adds the brain on top:
 *
 *   - Tier-0 CUSUM detectors on six volumetric channels
 *     (pps, bps, fps, burst_pps, burst_bps, burst_fps).
 *   - Tier-1 multi-feature scoring per protocol family (TCP / UDP / ICMP),
 *     plus universal Distribution and L3 sub-channels.
 *   - Off-protocol detector (TCP slot receiving UDP, etc).
 *   - Final score combination: weighted MAX of the protocol channel +
 *     universal channels (any one strong signal triggers).
 *   - Phase machine: WARMUP -> NORMAL -> SUSPICIOUS -> ATTACK -> NORMAL,
 *     with persistence filter and post-attack thaw cooldown.
 *   - Baseline freeze: while in ATTACK, the feature-extraction layer
 *     stops feeding EWMA updates so the baseline isn't poisoned.
 *
 * Hot-path coupling: the scoring layer runs on the main-lcore 1Hz tick
 * AFTER service_features_compute_all() and BEFORE the per-window reset.
 * Packets continue to flow through service_hotpath_process_packet()
 * untouched.
 */

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

/* Forward decls — full definitions are in the consumer modules. */
struct service_stats;
struct service_stats_array;
struct service_cusum_state;
struct service_detection_state;
struct l2_profile;

/* -------------------------------------------------------------------------
 * Lifecycle
 * ------------------------------------------------------------------------- */

/** One-time init. Currently emits a log line; reserved for future use
 *  (per-tenant thresholds, model loading). Returns 0 on success. */
int  service_scoring_init(void);

/** Tear down. Idempotent. */
void service_scoring_destroy(void);

/* -------------------------------------------------------------------------
 * Tier-0 CUSUM primitive
 *
 * Normalised one-sided CUSUM:
 *
 *     deviation = (x - mean) / stddev
 *     S_plus    = max(0, S_plus + deviation - k)
 *     breach when S_plus > h
 *
 * Because deviation is already in sigma units, k and h are scalars and
 * not stddev-scaled themselves. Returns true iff S_plus crossed h on
 * this update. When stddev < ε, the CUSUM is disabled (no baseline) and
 * the function returns false without mutating S_plus.
 * ------------------------------------------------------------------------- */
bool service_scoring_cusum_update(struct service_cusum_state *state,
                                   double x, double mean, double stddev,
                                   double k, double h);

void service_scoring_cusum_reset(struct service_cusum_state *state);

/* -------------------------------------------------------------------------
 * Tier-0 evaluate: volumetric ramp detection
 *
 * Runs CUSUM on six channels (pps, bps, fps + their burst-window
 * z-score variants) and returns a composite risk score in [0, 1] derived
 * from breach count and peak S_plus. Side effects: writes the per-channel
 * risk scores into slot->detection_state->last_tier0_risk_*.
 * ------------------------------------------------------------------------- */
double service_scoring_tier0_evaluate(struct service_stats *slot);

/* -------------------------------------------------------------------------
 * Tier-1 per-channel scores in [0, 1]
 *
 * Each channel function returns 0.0 if the slot's traffic volume is too
 * low (the EWMA hasn't seen meaningful samples). Otherwise it averages
 * the sigmoid-mapped z-scores of 3-5 relevant features.
 * ------------------------------------------------------------------------- */
double service_scoring_tier1_tcp         (const struct service_stats *slot);
double service_scoring_tier1_udp         (const struct service_stats *slot);
double service_scoring_tier1_icmp        (const struct service_stats *slot);
double service_scoring_tier1_distribution(const struct service_stats *slot);
double service_scoring_tier1_l3          (const struct service_stats *slot);

/** Off-protocol detector — non-matching IP-proto traffic on a typed slot. */
double service_scoring_offproto          (const struct service_stats *slot);

/* -------------------------------------------------------------------------
 * Combine the per-channel scores into a final Tier-1 score in [0, 1].
 *
 *   - For TCP / UDP / ICMP slots, only the matching protocol channel
 *     contributes (the others are zero because their volume gate
 *     short-circuits).
 *   - For OTHER catchall slots, the protocol-arm channels are max'd.
 *   - Distribution + L3 + offproto are universal.
 *
 * Side effects: caches each sub-score in detection_state->last_tier1_*.
 * ------------------------------------------------------------------------- */
double service_scoring_combine(struct service_stats *slot);

/* -------------------------------------------------------------------------
 * Phase machine
 *
 * Runs Tier-0 + Tier-1 + combine on the slot, then advances
 * detection_state->phase based on the resulting attack_evidence
 * (= max(t0, t1_final)). Counts down warmup_remaining,
 * baseline_freeze_remaining, thaw_cooldown_remaining each tick.
 *
 * Transitions (all configurable via SCORING_DEFAULT_* in the .c):
 *
 *     WARMUP     -> NORMAL       after profile->warmup_windows elapse
 *     NORMAL     -> SUSPICIOUS   when score > SUSPICIOUS_THRESHOLD
 *     SUSPICIOUS -> ATTACK       when score > ATTACK_THRESHOLD for
 *                                PERSISTENCE_WINDOWS consecutive ticks
 *     SUSPICIOUS -> NORMAL       when score < RECOVERY_THRESHOLD for
 *                                RECOVERY_WINDOWS_SUSP consecutive ticks
 *     ATTACK     -> NORMAL       when score < RECOVERY_THRESHOLD for
 *                                RECOVERY_WINDOWS_ATK consecutive ticks
 *                                (sets thaw_cooldown_remaining on exit)
 *
 * Logs every phase transition to stderr. Always increments windows_seen.
 * ------------------------------------------------------------------------- */
void service_scoring_update_phase(struct service_stats *slot);

/* -------------------------------------------------------------------------
 * Main entry — evaluate every active slot. Called once per 1Hz tick.
 * ------------------------------------------------------------------------- */
void service_scoring_evaluate_all(struct service_stats_array *arr);

/* -------------------------------------------------------------------------
 * Helpers
 * ------------------------------------------------------------------------- */

/** True if the slot is currently in baseline-freeze (mid-ATTACK).
 *  Read by service_features_compute_one to skip EWMA updates. */
bool service_scoring_is_frozen(const struct service_stats *slot);

/** Diagnostic: log per-slot summary (phase, all sub-scores) to stderr. */
void service_scoring_log_slot(const struct service_stats *slot);

#endif /* __L2FWD_SERVICE_SCORING_H__ */
