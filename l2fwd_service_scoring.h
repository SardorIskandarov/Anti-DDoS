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
 * Dominant detection channel — which single channel best explains the
 * current attack shape. Computed at the end of service_scoring_combine() as
 * an argmax across the live Tier-0 volumetric risks and Tier-1 behavioral
 * scores for the slot's proto_kind. Carried to Layer-3 on the wire.
 * ------------------------------------------------------------------------- */
enum service_dominant_channel {
    DOMINANT_NONE = 0, DOMINANT_PPS = 1, DOMINANT_BPS = 2, DOMINANT_FPS = 3,
    DOMINANT_TCP = 4, DOMINANT_UDP = 5, DOMINANT_ICMP = 6,
    DOMINANT_DIST = 7, DOMINANT_L3 = 8, DOMINANT_OFFPROTO = 9,
};

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
 * Phase machine — gated sequential cascade with baseline-poisoning hardening.
 *
 * Tier-0 weighted risk R0 is always computed (CUSUM on pps/bps/fps + burst
 * z-scores), honoring the CUSUM freeze.
 *
 * An absolute volumetric floor (profile->absolute_{pps,bps,fps}_threshold,
 * baseline-INDEPENDENT — it reads raw counters, never the EWMA/CUSUM
 * baseline) forces ATTACK immediately, bypassing the gate and Tier-1.
 *
 * Otherwise the tiers run sequentially: a persistence gate must open first
 * (consecutive Tier-0 fires >= SCORING_GATE_PERSISTENCE_WINDOWS); only then
 * does Tier-1 (service_scoring_combine) run, and its combined score decides
 * the phase IMMEDIATELY — T1 >= ATTACK_THRESHOLD -> ATTACK, >=
 * SUSPICIOUS_THRESHOLD -> SUSPICIOUS, else NORMAL (veto). There is no
 * multi-window NORMAL->SUSPICIOUS->ATTACK ladder.
 *
 * learning_mode and warmup compute + cache Tier-1 for the dashboard but
 * never transition the phase.
 *
 * Two distinct freeze scopes guard the baseline:
 *   - EWMA-only freeze (ewma_freeze_remaining): armed the instant Tier-0
 *     fires, it protects the baseline from slow ramp poisoning while CUSUM
 *     stays live (CUSUM is what detects the ramp).
 *   - Full ATTACK-freeze (attack_freeze_active): armed on entering ATTACK
 *     (via Tier-1 OR the absolute floor), it holds BOTH EWMA and CUSUM at
 *     their last clean values. Released only after thaw_cooldown_windows
 *     consecutive NORMAL windows; any non-NORMAL window resets that streak.
 *
 * baseline_freeze_remaining / thaw_cooldown_remaining are DERIVED each
 * window from the authoritative freeze state purely for the wire serializer
 * (their serialized meaning is preserved); they are not independent
 * countdowns.
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

/** "Should EWMA updates be skipped this window?" — TRUE under either the
 *  full ATTACK-freeze OR the EWMA-only freeze (Tier-0 fired). Read by
 *  service_features_compute_one to skip EWMA updates. */
bool service_scoring_is_frozen(const struct service_stats *slot);

/** "Should Tier-0 CUSUM updates be skipped this window?" — TRUE only under
 *  the full ATTACK-freeze. The EWMA-only freeze leaves CUSUM live (CUSUM is
 *  what detects the ramp). Read inside service_scoring_tier0_evaluate. */
bool service_scoring_cusum_is_frozen(const struct service_stats *slot);

/** Stable string name for an enum service_dominant_channel value
 *  ("NONE","PPS","BPS","FPS","TCP","UDP","ICMP","DIST","L3","OFFPROTO").
 *  Mirrors service_detection_phase_name. */
const char *service_scoring_dominant_name(uint8_t dominant);

/** Diagnostic: log per-slot summary (phase, all sub-scores) to stderr. */
void service_scoring_log_slot(const struct service_stats *slot);

#endif /* __L2FWD_SERVICE_SCORING_H__ */
