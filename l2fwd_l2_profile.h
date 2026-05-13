/*
 * ============================================================================
 *  LEGACY MODULE — PRESERVED DURING DUAL-WRITE (Phase 3 — P7..P15)
 * ============================================================================
 *
 *  Status:      ACTIVE-LEGACY
 *  Retirement:  P16 cutover commit
 *  Destination: legacy/  (preserved as forensic reference)
 *
 *  This file is part of the per-IP detection architecture that is being
 *  replaced by the per-service architecture under l2fwd_service_*.{c,h}.
 *  It REMAINS COMPILED and ACTIVE during P7..P15 because:
 *
 *    1. It is the cross-validation reference that proves the new per-service
 *       hot path produces equivalent aggregate counters.
 *    2. It provides the rollback path until the new engine is signed off
 *       at P18.
 *
 *  DO NOT delete or rename this file before P16. The big-bang cutover
 *  prompt (P16) will move it to legacy/ atomically as part of the
 *  deprecation switch.
 *
 *  See docs/architecture_status.md and docs/migration_map.md for the
 *  full classification of every source file in this project.
 * ============================================================================
 */
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

    /* === V2 FEATURE WEIGHTS ===
     *
     * These weights gate the contribution of new v2 features to Tier-1
     * distance computation. Default 0.0 means feature is computed and
     * logged but does NOT contribute to attack scoring — existing
     * profile behavior is preserved.
     *
     * IMPORTANT CALIBRATION COUPLING:
     * When you set non-zero weights for these features in a profile,
     * you are increasing the dynamic range of the Tier-1 raw distance
     * `d`. This affects how `sigmoid_d0` should be tuned for that
     * profile. Specifically:
     *   - With all weights at 0.0:  d ranges over [0, ~21]
     *     (existing 7 TCP / 3 UDP / 2 ICMP / 2 DIST features)
     *   - With weights summing to W: d ranges over roughly [0, ~21 + 3*W]
     *
     * After adding non-zero weights for an IP, you typically need to
     * RE-TUNE `sigmoid_d0` upward to compensate, otherwise classification
     * thresholds will fire earlier than intended.
     *
     * Practical guidance:
     *   - Start by enabling ONE new feature with weight 0.3
     *   - Re-run profile validation against captured normal data
     *   - Adjust sigmoid_d0 if FP rate or attack-coverage shifts
     *   - Repeat per feature
     *
     * The existing 7 TCP / 3 UDP / 2 ICMP / 2 DIST features keep
     * implicit weight 1.0 (hardcoded in compute_tier1_*_score).
     * Unification into the weight system is deferred to a future
     * refactor. */

    /* TCP behavioral feature weights */
    double w_feat_empty_ack;
    double w_feat_zero_window;
    double w_feat_small_window;
    double w_feat_new_flow;
    double w_feat_syn_fin;
    double w_feat_syn_to_synack;
    double w_feat_tcp_pkt_size_cov;
    double w_feat_tcp_mean_pkt_size;

    /* UDP behavioral feature weights */
    double w_feat_udp_pkt_size_cov;
    double w_feat_udp_mean_pkt_size;

    /* === V3.0 L3-CHANNEL WEIGHTS AND THRESHOLDS ===
     *
     * v3 features form a parallel Tier-1.5 L3 channel that runs
     * alongside Tier-1 TCP/UDP/ICMP/DIST. The L3 score is
     * OR-combined with tier1_final_score via max() in the final
     * decision logic. This means activating an L3 weight does NOT
     * perturb existing TCP/UDP/ICMP/DIST calibrations for an IP.
     *
     * CALIBRATION COUPLING:
     * The L3 channel has its own sigmoid (k_l3, d0_l3). When you
     * activate L3 weights, adjust sigmoid_d0_l3 to compensate for
     * additional raw distance contribution, exactly like v2's
     * calibration coupling for Tier-1 TCP/UDP.
     *
     * Default 0.0 means features are computed and logged but contribute
     * nothing to scoring. Existing profile behavior is preserved.
     */

    /* L3 sub-channel sigmoid (independent from Tier-1 sigmoid) */
    double sigmoid_k_l3;
    double sigmoid_d0_l3;

    /* L3 feature weights (v3.0) */
    double w_feat_ttl_stddev;
    double w_feat_ip_frag;
    double w_feat_other_proto;

    /* V3.1 L3 weights (count-min-sketch based features) */
    double w_feat_src_port_top1;
    double w_feat_src_24_top1;
    double w_feat_src_24_entropy;

    /* Per-profile noise-floor overrides for the threshold-based
     * L3 features. Default 0.0 means "use the macro default from
     * l2fwd_detection_engine.h" (NaN → fall back). Non-zero values
     * let specific IPs (e.g. VPN concentrators that legitimately
     * see ESP traffic) raise their floor. */
    double frag_noise_floor_override;       /* 0.0 = use default */
    double other_proto_noise_floor_override; /* 0.0 = use default */
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
extern const struct l2_profile l2_profile_213_230_125_130_manual_v1;
extern const struct l2_profile l2_profile_213_230_125_50_manual_v1;
extern const struct l2_profile l2_profile_213_230_125_148_manual_v1;
extern const struct l2_profile l2_profile_213_230_125_46_manual_v1;
extern const struct l2_profile l2_profile_89_249_63_215_manual_v1;
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
