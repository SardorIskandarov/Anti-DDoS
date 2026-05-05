#ifndef __L2FWD_L2_PROFILE_H__
#define __L2FWD_L2_PROFILE_H__

#include <stdint.h>

/*
 * Layer-2 profile / config container.
 *
 * Holds the Layer-2 hyperparameters that will, in later steps, become
 * tunable per destination IP. The struct definition is introduced here
 * in isolation: nothing in the detector consumes these fields yet, and
 * no existing macro is replaced. A single default profile object whose
 * values mirror the current #defines is provided so later steps can
 * attach a pointer without changing behavior.
 *
 * Explicitly NOT in this struct (must stay global and unchanged):
 *   - HyperLogLog parameters (HLL_PRECISION, HLL_SIZE, HLL_ALPHA_16384)
 *   - Attack-type heuristic thresholds (inline literals in the
 *     detection engine's attack-classification block)
 *   - EWMA structural constants (EWMA_WARMUP_PERIODS, EWMA_EPSILON)
 *   - Burst-window sizes (BURST_LONG_WINDOW_SEC, BURST_WINDOW_MAX_SEC)
 *   - Debug filters (DEBUG_IP), MIN_STD_FLOOR
 */
struct l2_profile {
    /* Identity (surfaced on the dashboard in a later step) */
    const char *name;
    const char *version;

    /* EWMA smoothing factors (one per tier collection) */
    double alpha_tier0;
    double alpha_tier1_tcp;
    double alpha_tier1_udp;
    double alpha_tier1_icmp;
    double alpha_tier1_dist;

    /* Warm-up length (windows) */
    uint32_t warmup_windows;

    /* Tier-0 CUSUM / Z-score parameters */
    double cusum_k_pps;
    double cusum_h_pps;
    double cusum_k_bps;
    double cusum_h_bps;
    double cusum_k_fps;
    double cusum_h_fps;
    double burst_z_threshold;
    double variance_ceiling_factor;

    /* Tier-0 continuous risk fusion */
    double t0_w_pps;
    double t0_w_bps;
    double t0_w_fps;
    double t0_w_burst_pps;
    double t0_w_burst_bps;
    double t0_w_burst_fps;
    double t0_suspicious_risk_threshold;
    double t0_risk_threshold;

    /* Tier-0 absolute volumetric override */
    double absolute_pps_threshold;
    double absolute_bps_threshold;
    double absolute_fps_threshold;

    /* Tier-0 persistence / freeze / thaw counters (windows) */
    uint32_t consecutive_attack_windows;
    uint32_t baseline_freeze_windows;
    uint32_t thaw_cooldown_windows;

    /* Tier-1 sigmoid mapping */
    double sigmoid_k;
    double sigmoid_d0;

    /* Tier-1 decision thresholds */
    double threshold_normal;
    double threshold_suspicious;

    /* Tier-1 weighted fusion */
    double w_tcp;
    double w_udp;
    double w_icmp;
    double w_dist;
};

/*
 * Default profile. Values mirror the current Layer-2 #defines exactly,
 * so any destination IP that resolves to this profile behaves identically
 * to the pre-refactor engine.
 */
extern const struct l2_profile l2_profile_default;

/*
 * Example non-default profile. Demonstrates that alternate profiles
 * compile and can be pointed at; not assigned to any IP by default.
 */
extern const struct l2_profile l2_profile_45_150_25_70_manual_v1;
extern const struct l2_profile l2_profile_213_230_125_66_manual_v1;
extern const struct l2_profile l2_profile_213_230_125_170_manual_v1;
extern const struct l2_profile l2_profile_45_150_25_116_manual_v1;
extern const struct l2_profile l2_profile_89_249_62_131_manual_v1;
extern const struct l2_profile l2_profile_94_141_85_150_manual_v1;

/*
 * Resolve the Layer-2 profile for a given destination IP.
 *
 * dst_ip is in host byte order (the same form used throughout the
 * detector hot path). If dst_ip appears in the static assignment table
 * the corresponding profile is returned; otherwise the default profile
 * is returned.
 *
 * Stateless, thread-safe, O(N) over the assignment table (typically
 * empty or small). Called exactly once per new dst_ip entry creation.
 */
const struct l2_profile *l2_profile_for_ip(uint32_t dst_ip);

#endif /* __L2FWD_L2_PROFILE_H__ */
