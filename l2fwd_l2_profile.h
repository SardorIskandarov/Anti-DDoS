/*
 * ============================================================================
 *  RESIDUAL HEADER — struct definition only; per-IP path retired in P7
 * ============================================================================
 *
 *  Status:      RESIDUAL (post-P7)
 *  Was:         ACTIVE-LEGACY through P6.5
 *  Survives:    struct l2_profile definition only (used by l2fwd_service_registry
 *               to fill profile records parsed out of services.json).
 *
 *  Removed at P7:
 *    - The l2fwd_l2_profile.c file (moved to legacy/).
 *    - The l2_profile_default and l2_profile_*_manual_v1 extern objects
 *      (they lived in the .c, which is gone from the build).
 *    - The l2_profile_for_ip(uint32_t) lookup helper (compile-time
 *      assignment table was the only consumer, also gone).
 *
 *  This header MAY be retired entirely later if the registry is refactored
 *  to define its own profile record type, but that's a P15+ cleanup, not
 *  a P7 concern.
 *
 *  See docs/architecture_status.md and docs/migration_map.md for the full
 *  classification of every source file in this project.
 * ============================================================================
 */
#ifndef __L2FWD_L2_PROFILE_H__
#define __L2FWD_L2_PROFILE_H__

#include <stdint.h>

/*
 * Layer-2 profile / config container.
 *
 * Holds the Layer-2 hyperparameters tuned per (target_ip, port, proto)
 * service. At P7+ these values are populated by the JSON registry parser
 * from services.json. The compile-time profile table that used to live in
 * l2fwd_l2_profile.c is retired (file moved to legacy/).
 *
 * Explicitly NOT in this struct (must stay global and unchanged):
 *   - HyperLogLog parameters (HLL_PRECISION, HLL_SIZE, HLL_ALPHA_16384)
 *   - Attack-type heuristic thresholds (inline literals)
 *   - EWMA structural constants (EWMA_WARMUP_PERIODS, EWMA_EPSILON)
 *   - Burst-window sizes (BURST_LONG_WINDOW_SEC, BURST_WINDOW_MAX_SEC)
 *   - Debug filters (DEBUG_IP), MIN_STD_FLOOR
 */
struct l2_profile {
    /* Identity (surfaced on the dashboard) */
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
     * Gate the contribution of new v2 features to Tier-1 distance
     * computation. Default 0.0 means feature is computed and logged but
     * does NOT contribute to attack scoring.
     *
     * CALIBRATION COUPLING:
     * When you set non-zero weights, you increase the dynamic range of
     * the Tier-1 raw distance `d`. Re-tune `sigmoid_d0` to compensate.
     */

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
     * v3 features form a parallel Tier-1.5 L3 channel that runs alongside
     * Tier-1 TCP/UDP/ICMP/DIST. The L3 score is OR-combined with
     * tier1_final_score via max() in the final decision logic.
     *
     * The L3 channel has its own sigmoid (k_l3, d0_l3). Default 0.0
     * means features are computed and logged but contribute nothing
     * to scoring.
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

    /* Per-profile noise-floor overrides for the threshold-based L3
     * features. Default 0.0 means "use the macro default" (was defined
     * in the legacy detection engine; constants are inlined into the
     * per-service detection code in P9). */
    double frag_noise_floor_override;       /* 0.0 = use default */
    double other_proto_noise_floor_override; /* 0.0 = use default */
};

#endif /* __L2FWD_L2_PROFILE_H__ */
