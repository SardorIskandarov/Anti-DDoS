#include "l2fwd_l2_profile.h"
#include "l2fwd_ddos_collector.h"     /* EWMA_ALPHA_TIER* */
#include "l2fwd_detection_engine.h"   /* Tier-0 / Tier-1 tunables */
#include <stddef.h>                   /* NULL */

/*
 * Each field is initialised from the existing macro of the same purpose.
 * Keeping the mapping macro-for-field makes this change easy to audit:
 * a reviewer can confirm one-to-one that no tunable changed value.
 */
const struct l2_profile l2_profile_default = {
    .name    = "default",
    .version = "v1",

    /* EWMA alphas */
    .alpha_tier0      = EWMA_ALPHA_TIER0,
    .alpha_tier1_tcp  = EWMA_ALPHA_TIER1_1,
    .alpha_tier1_udp  = EWMA_ALPHA_TIER1_2,
    .alpha_tier1_icmp = EWMA_ALPHA_TIER1_3,
    .alpha_tier1_dist = EWMA_ALPHA_TIER1_4,

    /* Warm-up */
    .warmup_windows = DETECTION_WARMUP_WINDOWS,

    /* Tier-0 CUSUM / Z-score */
    .cusum_k_pps             = CUSUM_K_PPS,
    .cusum_h_pps             = CUSUM_H_PPS,
    .cusum_k_bps             = CUSUM_K_BPS,
    .cusum_h_bps             = CUSUM_H_BPS,
    .cusum_k_fps             = CUSUM_K_FPS,
    .cusum_h_fps             = CUSUM_H_FPS,
    .burst_z_threshold       = BURST_Z_THRESHOLD,
    .variance_ceiling_factor = VARIANCE_CEILING_FACTOR,

    /* Tier-0 risk fusion */
    .t0_w_pps                     = T0_W_PPS,
    .t0_w_bps                     = T0_W_BPS,
    .t0_w_fps                     = T0_W_FPS,
    .t0_w_burst_pps               = T0_W_BURST_PPS,
    .t0_w_burst_bps               = T0_W_BURST_BPS,
    .t0_w_burst_fps               = T0_W_BURST_FPS,
    .t0_suspicious_risk_threshold = T0_SUSPICIOUS_RISK_THRESHOLD,
    .t0_risk_threshold            = T0_RISK_THRESHOLD,

    /* Tier-0 absolute overrides */
    .absolute_pps_threshold = ABSOLUTE_PPS_THRESHOLD,
    .absolute_bps_threshold = ABSOLUTE_BPS_THRESHOLD,
    .absolute_fps_threshold = ABSOLUTE_FPS_THRESHOLD,

    /* Persistence / freeze / thaw */
    .consecutive_attack_windows = CONSECUTIVE_ATTACK_WINDOWS,
    .baseline_freeze_windows    = BASELINE_FREEZE_WINDOWS,
    .thaw_cooldown_windows      = THAW_COOLDOWN_WINDOWS,

    /* Tier-1 sigmoid */
    .sigmoid_k  = SIGMOID_K,
    .sigmoid_d0 = SIGMOID_D0,

    /* Tier-1 decision thresholds */
    .threshold_normal     = THRESHOLD_NORMAL,
    .threshold_suspicious = THRESHOLD_SUSPICIOUS,

    /* Tier-1 weighted fusion */
    .w_tcp  = W_TCP,
    .w_udp  = W_UDP,
    .w_icmp = W_ICMP,
    .w_dist = W_DIST,

    /* V2 feature weights — all 0.0 means features are computed but inert */
    .w_feat_empty_ack            = 0.0,
    .w_feat_zero_window          = 0.0,
    .w_feat_small_window         = 0.0,
    .w_feat_new_flow             = 0.0,
    .w_feat_syn_fin              = 0.0,
    .w_feat_syn_to_synack        = 0.0,
    .w_feat_tcp_pkt_size_cov     = 0.0,
    .w_feat_tcp_mean_pkt_size    = 0.0,
    .w_feat_udp_pkt_size_cov     = 0.0,
    .w_feat_udp_mean_pkt_size    = 0.0,

    /* V3.0 L3 channel — all 0.0 means L3 score is computed but inert */
    .sigmoid_k_l3                     = 0.90,  /* matches default Tier-1 */
    .sigmoid_d0_l3                    = 1.40,  /* matches default Tier-1 */
    .w_feat_ttl_stddev                = 0.0,
    .w_feat_ip_frag                   = 0.0,
    .w_feat_other_proto               = 0.0,

    /* V3.1 L3 weights — zero defaults, computed but inert */
    .w_feat_src_port_top1   = 0.0,
    .w_feat_src_24_top1     = 0.0,
    .w_feat_src_24_entropy  = 0.0,

    .frag_noise_floor_override        = 0.0,
    .other_proto_noise_floor_override = 0.0,
};

/*
 * Example non-default profile. Demonstrates a tighter detection stance:
 * faster Tier-0 commit (lower CUSUM H, lower burst Z), lower Tier-0 risk
 * thresholds, fewer persistence windows, and lower Tier-1 decision
 * thresholds. All other fields match the default so behavior elsewhere
 * stays comparable. Not assigned to any IP by default.
 */


// ========================
// IP : 45.150.25.116
// ========================
const struct l2_profile l2_profile_45_150_25_116_manual_v1 = {
    .name    = "45.150.25.116",
    .version = "manual_v1",

    /* EWMA alphas */
    .alpha_tier0      = 0.03,
    .alpha_tier1_tcp  = 0.04,
    .alpha_tier1_udp  = 0.07,
    .alpha_tier1_icmp = 0.03,
    .alpha_tier1_dist = 0.06,

    /* Warm-up */
    .warmup_windows = 450,

    /* Tier-0 CUSUM / Z-score */
    .cusum_k_pps             = 0.12,
    .cusum_h_pps             = 7.5,
    .cusum_k_bps             = 0.12,
    .cusum_h_bps             = 7.5,
    .cusum_k_fps             = 0.90,
    .cusum_h_fps             = 7.0,
    .burst_z_threshold       = 10.0,
    .variance_ceiling_factor = 2.5,

    /* Tier-0 risk fusion */
    .t0_w_pps       = 2.7,
    .t0_w_bps       = 1.7,
    .t0_w_fps       = 0.6,
    .t0_w_burst_pps = 1.0,
    .t0_w_burst_bps = 0.7,
    .t0_w_burst_fps = 0.3,

    .t0_suspicious_risk_threshold = 5.2,
    .t0_risk_threshold            = 6.5,

    /* Absolute volumetric overrides */
    .absolute_pps_threshold = 35000.0,
    .absolute_bps_threshold = 500000000.0,
    .absolute_fps_threshold = 150.0,

    /* Persistence / freeze / thaw */
    .consecutive_attack_windows = 2,
    .baseline_freeze_windows    = 12,
    .thaw_cooldown_windows      = 20,

    /* Tier-1 sigmoid */
    .sigmoid_k  = 1.0,
    .sigmoid_d0 = 1.1,

    /* Tier-1 decision thresholds */
    .threshold_normal     = 0.45,
    .threshold_suspicious = 0.68,

    /* Tier-1 weighted fusion */
    .w_tcp  = 0.05,
    .w_udp  = 0.65,
    .w_icmp = 0.05,
    .w_dist = 0.25,
    .sigmoid_k_l3                     = 0.90,
    .sigmoid_d0_l3                    = 1.40,
};


// ========================
// IP : 89.249.62.131
// ========================
const struct l2_profile l2_profile_89_249_62_131_manual_v1 = {
    .name    = "89.249.62.131",
    .version = "manual_v1",

    /* EWMA alphas */
    .alpha_tier0      = 0.03,
    .alpha_tier1_tcp  = 0.04,
    .alpha_tier1_udp  = 0.05,
    .alpha_tier1_icmp = 0.03,
    .alpha_tier1_dist = 0.05,

    /* Warm-up */
    .warmup_windows = 400,

    /* Tier-0 CUSUM / Z-score */
    .cusum_k_pps             = 0.14,
    .cusum_h_pps             = 8.0,
    .cusum_k_bps             = 0.14,
    .cusum_h_bps             = 8.0,
    .cusum_k_fps             = 1.00,
    .cusum_h_fps             = 8.0,
    .burst_z_threshold       = 10.0,
    .variance_ceiling_factor = 3.0,

    /* Tier-0 risk fusion */
    .t0_w_pps       = 2.8,
    .t0_w_bps       = 2.2,
    .t0_w_fps       = 0.7,
    .t0_w_burst_pps = 0.9,
    .t0_w_burst_bps = 0.7,
    .t0_w_burst_fps = 0.3,

    .t0_suspicious_risk_threshold = 5.8,
    .t0_risk_threshold            = 7.2,

    /* Absolute volumetric overrides */
    .absolute_pps_threshold = 20000.0,
    .absolute_bps_threshold = 220000000.0,
    .absolute_fps_threshold = 150.0,

    /* Persistence / freeze / thaw */
    .consecutive_attack_windows = 3,
    .baseline_freeze_windows    = 12,
    .thaw_cooldown_windows      = 20,

    /* Tier-1 sigmoid */
    .sigmoid_k  = 0.90,
    .sigmoid_d0 = 1.30,

    /* Tier-1 decision thresholds */
    .threshold_normal     = 0.55,
    .threshold_suspicious = 0.82,

    /* Tier-1 weighted fusion */
    .w_tcp  = 0.55,
    .w_udp  = 0.05,
    .w_icmp = 0.05,
    .w_dist = 0.35,
    .sigmoid_k_l3                     = 0.90,
    .sigmoid_d0_l3                    = 1.40,
};



// ========================
// IP : 94.141.85.150
// ========================
const struct l2_profile l2_profile_94_141_85_150_manual_v1 = {
    .name    = "94.141.85.150",
    .version = "manual_v1",

    /* EWMA alphas */
    .alpha_tier0      = 0.03,
    .alpha_tier1_tcp  = 0.06,
    .alpha_tier1_udp  = 0.08,
    .alpha_tier1_icmp = 0.03,
    .alpha_tier1_dist = 0.06,

    /* Warm-up */
    .warmup_windows = 400,

    /* Tier-0 CUSUM / Z-score */
    .cusum_k_pps             = 0.14,
    .cusum_h_pps             = 8.0,
    .cusum_k_bps             = 0.14,
    .cusum_h_bps             = 8.0,
    .cusum_k_fps             = 0.95,
    .cusum_h_fps             = 8.0,
    .burst_z_threshold       = 10.0,
    .variance_ceiling_factor = 3.0,

    /* Tier-0 risk fusion */
    .t0_w_pps       = 2.8,
    .t0_w_bps       = 1.8,
    .t0_w_fps       = 0.6,
    .t0_w_burst_pps = 0.8,
    .t0_w_burst_bps = 0.6,
    .t0_w_burst_fps = 0.2,

    .t0_suspicious_risk_threshold = 5.6,
    .t0_risk_threshold            = 6.4,

    /* Absolute volumetric overrides */
    .absolute_pps_threshold = 20000.0,
    .absolute_bps_threshold = 220000000.0,
    .absolute_fps_threshold = 360.0,

    /* Persistence / freeze / thaw */
    .consecutive_attack_windows = 4,
    .baseline_freeze_windows    = 12,
    .thaw_cooldown_windows      = 20,

    /* Tier-1 sigmoid */
    .sigmoid_k  = 0.90,
    .sigmoid_d0 = 1.30,

    /* Tier-1 decision thresholds */
    .threshold_normal     = 0.55,
    .threshold_suspicious = 0.85,

    /* Tier-1 weighted fusion */
    .w_tcp  = 0.35,
    .w_udp  = 0.30,
    .w_icmp = 0.10,
    .w_dist = 0.25,
    .sigmoid_k_l3                     = 0.90,
    .sigmoid_d0_l3                    = 1.40,
};


// ========================
// IP : 213.230.125.170
// ========================
const struct l2_profile l2_profile_213_230_125_170_manual_v1 = {
    .name    = "213.230.125.170",
    .version = "manual_v1",

    /* EWMA alphas */
    .alpha_tier0      = 0.035,
    .alpha_tier1_tcp  = 0.07,
    .alpha_tier1_udp  = 0.07,
    .alpha_tier1_icmp = 0.03,
    .alpha_tier1_dist = 0.07,

    /* Warm-up */
    .warmup_windows = 700,

    /* Tier-0 CUSUM / Z-score */
    .cusum_k_pps             = 0.15,
    .cusum_h_pps             = 8.5,
    .cusum_k_bps             = 0.15,
    .cusum_h_bps             = 8.5,
    .cusum_k_fps             = 1.00,
    .cusum_h_fps             = 9.0,
    .burst_z_threshold       = 10.0,
    .variance_ceiling_factor = 3.0,

    /* Tier-0 risk fusion */
    .t0_w_pps       = 2.2,
    .t0_w_bps       = 1.4,
    .t0_w_fps       = 0.35,
    .t0_w_burst_pps = 0.6,
    .t0_w_burst_bps = 0.5,
    .t0_w_burst_fps = 0.15,

    .t0_suspicious_risk_threshold = 4.8,
    .t0_risk_threshold            = 5.6,

    /* Absolute volumetric overrides */
    .absolute_pps_threshold = 1300000.0,
    .absolute_bps_threshold = 12000000000.0,
    .absolute_fps_threshold = 25000.0,

    /* Persistence / freeze / thaw */
    .consecutive_attack_windows = 5,
    .baseline_freeze_windows    = 12,
    .thaw_cooldown_windows      = 25,

    /* Tier-1 sigmoid */
    .sigmoid_k  = 0.80,
    .sigmoid_d0 = 1.50,

    /* Tier-1 decision thresholds */
    .threshold_normal     = 0.70,
    .threshold_suspicious = 0.92,

    /* Tier-1 weighted fusion */
    .w_tcp  = 0.40,
    .w_udp  = 0.25,
    .w_icmp = 0.05,
    .w_dist = 0.30,
    .sigmoid_k_l3                     = 0.90,
    .sigmoid_d0_l3                    = 1.40,
};


// ========================
// IP : 213.230.125.66
// ========================
const struct l2_profile l2_profile_213_230_125_66_manual_v1 = {
    .name    = "213.230.125.66",
    .version = "manual_v1",

    /* EWMA alphas */
    .alpha_tier0      = 0.035,
    .alpha_tier1_tcp  = 0.07,
    .alpha_tier1_udp  = 0.07,
    .alpha_tier1_icmp = 0.03,
    .alpha_tier1_dist = 0.07,

    /* Warm-up */
    .warmup_windows = 700,

    /* Tier-0 CUSUM / Z-score */
    .cusum_k_pps             = 0.15,
    .cusum_h_pps             = 8.5,
    .cusum_k_bps             = 0.15,
    .cusum_h_bps             = 8.5,
    .cusum_k_fps             = 1.00,
    .cusum_h_fps             = 9.0,
    .burst_z_threshold       = 10.0,
    .variance_ceiling_factor = 3.0,

    /* Tier-0 risk fusion */
    .t0_w_pps       = 2.2,
    .t0_w_bps       = 1.5,
    .t0_w_fps       = 0.35,
    .t0_w_burst_pps = 0.7,
    .t0_w_burst_bps = 0.55,
    .t0_w_burst_fps = 0.15,

    .t0_suspicious_risk_threshold = 4.7,
    .t0_risk_threshold            = 5.25,

    /* Absolute volumetric overrides */
    .absolute_pps_threshold = 500000.0,
    .absolute_bps_threshold = 4500000000.0,
    .absolute_fps_threshold = 8000.0,

    /* Persistence / freeze / thaw */
    .consecutive_attack_windows = 5,
    .baseline_freeze_windows    = 12,
    .thaw_cooldown_windows      = 25,

    /* Tier-1 sigmoid */
    .sigmoid_k  = 0.80,
    .sigmoid_d0 = 1.50,

    /* Tier-1 decision thresholds */
    .threshold_normal     = 0.75,
    .threshold_suspicious = 0.95,

    /* Tier-1 weighted fusion */
    .w_tcp  = 0.40,
    .w_udp  = 0.25,
    .w_icmp = 0.05,
    .w_dist = 0.30,
    .sigmoid_k_l3                     = 0.90,
    .sigmoid_d0_l3                    = 1.40,
};


// ========================
// IP : 45.150.25.70
// ========================
const struct l2_profile l2_profile_45_150_25_70_manual_v1 = {
    .name    = "45.150.25.70",
    .version = "manual_v1",

    /* EWMA alphas */
    .alpha_tier0      = 0.035,
    .alpha_tier1_tcp  = 0.07,
    .alpha_tier1_udp  = 0.07,
    .alpha_tier1_icmp = 0.03,
    .alpha_tier1_dist = 0.07,

    /* Warm-up */
    .warmup_windows = 700,

    /* Tier-0 CUSUM / Z-score */
    .cusum_k_pps             = 0.15,
    .cusum_h_pps             = 8.5,
    .cusum_k_bps             = 0.15,
    .cusum_h_bps             = 8.5,
    .cusum_k_fps             = 1.00,
    .cusum_h_fps             = 9.0,
    .burst_z_threshold       = 10.0,
    .variance_ceiling_factor = 3.0,

    /* Tier-0 risk fusion */
    .t0_w_pps       = 2.2,
    .t0_w_bps       = 1.5,
    .t0_w_fps       = 0.35,
    .t0_w_burst_pps = 0.7,
    .t0_w_burst_bps = 0.55,
    .t0_w_burst_fps = 0.15,

    .t0_suspicious_risk_threshold = 4.7,
    .t0_risk_threshold            = 5.25,

    /* Absolute volumetric overrides */
    .absolute_pps_threshold = 500000.0,
    .absolute_bps_threshold = 4000000000.0,
    .absolute_fps_threshold = 7500.0,

    /* Persistence / freeze / thaw */
    .consecutive_attack_windows = 5,
    .baseline_freeze_windows    = 12,
    .thaw_cooldown_windows      = 25,

    /* Tier-1 sigmoid */
    .sigmoid_k  = 0.80,
    .sigmoid_d0 = 1.50,

    /* Tier-1 decision thresholds */
    .threshold_normal     = 0.75,
    .threshold_suspicious = 0.95,

    /* Tier-1 weighted fusion */
    .w_tcp  = 0.30,
    .w_udp  = 0.35,
    .w_icmp = 0.05,
    .w_dist = 0.30,
    .sigmoid_k_l3                     = 0.90,
    .sigmoid_d0_l3                    = 1.40,
};

// ========================
// IP : 89.249.63.215
// ========================
const struct l2_profile l2_profile_89_249_63_215_manual_v1 = {
    .name    = "89.249.63.215",
    .version = "manual_v1",

    /* EWMA alphas — slow on volume to ride through diurnal cycle;
     * default cadence on protocol/distribution channels which are
     * already well-tuned for mixed-protocol services. */
    .alpha_tier0      = 0.030,
    .alpha_tier1_tcp  = 0.04,
    .alpha_tier1_udp  = 0.07,
    .alpha_tier1_icmp = 0.03,
    .alpha_tier1_dist = 0.06,

    /* Warm-up — 10 minutes spans both quiet and busy phases. */
    .warmup_windows = 600,

    /* Tier-0 CUSUM / Z-score — h raised over default (6.5 → 9.0)
     * because organic 30-second peaks reach z ≈ 9–12; k stays at
     * 0.15 so genuine ramps still register. variance_ceiling at
     * 2.5× keeps the std growth bounded but realistic. */
    .cusum_k_pps             = 0.15,
    .cusum_h_pps             = 9.0,
    .cusum_k_bps             = 0.15,
    .cusum_h_bps             = 9.0,
    .cusum_k_fps             = 1.00,
    .cusum_h_fps             = 7.5,
    .burst_z_threshold       = 13.0,
    .variance_ceiling_factor = 2.5,

    /* Tier-0 risk fusion — pps weighted highest (most reliable
     * signal); fps weight kept moderate because rare single-window
     * fps spikes (e.g. 1364 outlier) shouldn't dominate fusion. */
    .t0_w_pps       = 2.5,
    .t0_w_bps       = 1.5,
    .t0_w_fps       = 0.50,
    .t0_w_burst_pps = 0.9,
    .t0_w_burst_bps = 0.7,
    .t0_w_burst_fps = 0.30,

    .t0_suspicious_risk_threshold = 4.5,
    .t0_risk_threshold            = 5.5,

    /* Absolute volumetric overrides — sized at ~1.4×–1.5× the 7-day
     * observed max (pps 46.5K → 65K, bps 539M → 800M, fps 1364 → 2K).
     * Verified: zero rows above any of these thresholds in 540K
     * windows. Tight enough to catch realistic floods; loose enough
     * to absorb peak-hour bursts and modest organic growth. */
    .absolute_pps_threshold = 65000.0,
    .absolute_bps_threshold = 800000000.0,
    .absolute_fps_threshold = 2000.0,

    /* Persistence / freeze / thaw — 4 windows of agreement filters
     * single-window transients (which are common on this host)
     * while still committing within 4 seconds for sustained attacks. */
    .consecutive_attack_windows = 4,
    .baseline_freeze_windows    = 12,
    .thaw_cooldown_windows      = 22,

    /* Tier-1 sigmoid — d0 = 1.4 just above the organic raw-distance
     * distribution; k = 0.9 keeps the curve steep enough that real
     * attacks (d > 2) saturate quickly. */
    .sigmoid_k  = 0.90,
    .sigmoid_d0 = 1.40,

    /* Tier-1 decision thresholds — 0.60 NORMAL/SUSPICIOUS boundary
     * suppresses the default-profile 14% FP rate while still
     * catching moderate behavioral anomalies; 0.85 ATTACK threshold
     * matches the pattern used by similar 89.249.62.x peer profile. */
    .threshold_normal     = 0.60,
    .threshold_suspicious = 0.85,

    /* Tier-1 weighted fusion — UDP given the largest share since
     * UDP floods are the most likely attack vector here; TCP weight
     * reduced because the TCP score channel is the noisiest single
     * channel on this host (organic p99 = 0.997); dist retained as
     * a stable secondary signal. */
    .w_tcp  = 0.15,
    .w_udp  = 0.50,
    .w_icmp = 0.05,
    .w_dist = 0.30,
    .sigmoid_k_l3                     = 0.90,
    .sigmoid_d0_l3                    = 1.40,
};

// ========================
// IP : 213.230.125.46
// ========================
const struct l2_profile l2_profile_213_230_125_46_manual_v1 = {
    .name    = "213.230.125.46",
    .version = "manual_v1",

    /* EWMA alphas — tier0 slightly faster than 215's profile because
     * this host ramps from quiet (median ~70 pps at hour 7) to busy
     * (median ~4400 pps at hour 13) over a few hours; default cadence
     * for protocol/distribution channels. */
    .alpha_tier0      = 0.030,
    .alpha_tier1_tcp  = 0.04,
    .alpha_tier1_udp  = 0.07,
    .alpha_tier1_icmp = 0.03,
    .alpha_tier1_dist = 0.06,

    /* Warm-up — 10 minutes spans both quiet and busy phases. */
    .warmup_windows = 600,

    /* Tier-0 CUSUM / Z-score — cusum_h_fps lifted to 8.0 (vs 7.5 on
     * 215) because fps spikes here are much larger (max 3838 vs 1364)
     * and run-lengths at fps>=1500 reach 18 windows organically.
     * burst_z = 14.0 — organic burst factors reach max ~19 with
     * p99.99 around 15-19 raw, but the variance-ceiling-capped
     * z-score stays comfortably below 14 in normal traffic. */
    .cusum_k_pps             = 0.15,
    .cusum_h_pps             = 9.0,
    .cusum_k_bps             = 0.15,
    .cusum_h_bps             = 9.0,
    .cusum_k_fps             = 1.00,
    .cusum_h_fps             = 8.0,
    .burst_z_threshold       = 14.0,
    .variance_ceiling_factor = 2.5,

    /* Tier-0 risk fusion — same shape as 215's profile; pps weighted
     * highest as the most reliable volumetric signal. Total weight
     * sum = 6.4. */
    .t0_w_pps       = 2.5,
    .t0_w_bps       = 1.5,
    .t0_w_fps       = 0.50,
    .t0_w_burst_pps = 0.9,
    .t0_w_burst_bps = 0.7,
    .t0_w_burst_fps = 0.30,

    /* Risk thresholds calibrated against 7-day organic data:
     *   risk_thr=5.0 with consec=4 → ~0.0035% trigger rate
     *   (~3 anomalous windows per day, well below default's 11%
     *    false-positive rate but above the blind-zone of risk_thr=5.5
     *    which gave 0.0006%). Suspicious threshold lowered
     *    proportionally for early dashboard warning. */
    .t0_suspicious_risk_threshold = 4.0,
    .t0_risk_threshold            = 5.0,

    /* Absolute volumetric overrides — sized at ~1.30×–1.41× the
     * 7-day observed max (pps 58.5K → 80K, bps 672M → 950M,
     * fps 3.8K → 5K). Verified zero violations across 540K
     * post-warmup windows. Tighter than the prior pass to avoid
     * blind-spot for a moderate (~1.5× peak) flood while still
     * absorbing all observed legitimate bursts. */
    .absolute_pps_threshold = 80000.0,
    .absolute_bps_threshold = 950000000.0,
    .absolute_fps_threshold = 5000.0,

    /* Persistence / freeze / thaw — pps>=30K runs are at most 3
     * windows organically, so consecutive_attack_windows=4 reliably
     * filters legitimate spikes while still firing within 4 seconds
     * for sustained anomalies. */
    .consecutive_attack_windows = 4,
    .baseline_freeze_windows    = 12,
    .thaw_cooldown_windows      = 22,

    /* Tier-1 sigmoid — d0=1.45 sits between 215's 1.40 and a fully
     * permissive 1.50, absorbing the higher organic raw-distance
     * values seen on this host (TCP raw distance reaches p99=11.4)
     * without blunting attack sensitivity. k=0.90 gives a steep
     * enough curve that real attacks (d > ~2.2) saturate quickly. */
    .sigmoid_k  = 0.90,
    .sigmoid_d0 = 1.45,

    /* Tier-1 decision thresholds — 0.60 NORMAL/SUSPICIOUS boundary
     * matches the 215 profile philosophy. With Tier-0 only tripping
     * ~0.0035% organically, the gating already prevents most FPs;
     * 0.60 lets Tier-1 confirm rather than block real attacks. */
    .threshold_normal     = 0.60,
    .threshold_suspicious = 0.85,

    /* Tier-1 weighted fusion — TCP weight kept moderate (0.20)
     * despite TCP being the dominant protocol on this host (58.6%),
     * because tier1_tcp_score is the noisiest single channel here
     * (organic p99 = 0.997). UDP gets 0.40 since UDP floods remain
     * the most likely real attack vector. ICMP set to a near-floor
     * 0.05 because this host has essentially no ICMP traffic
     * (icmp_echo_ratio median = 0, mean = 0.006). dist retained at
     * 0.35 as the most stable behavioral signal. */
    .w_tcp  = 0.20,
    .w_udp  = 0.40,
    .w_icmp = 0.05,
    .w_dist = 0.35,
    .sigmoid_k_l3                     = 0.90,
    .sigmoid_d0_l3                    = 1.40,
};

// ========================
// IP : 213.230.125.148
// ========================
const struct l2_profile l2_profile_213_230_125_148_manual_v1 = {
    .name    = "213.230.125.148",
    .version = "manual_v1",

    /* EWMA alphas — tier0 slightly slower (0.025) because this host's
     * volume is much more stable than 215/46 (pps std/mean ~0.65 vs
     * 1.65). Less need for fast adaptation; defaults for the
     * protocol-ratio tiers. */
    .alpha_tier0      = 0.025,
    .alpha_tier1_tcp  = 0.04,
    .alpha_tier1_udp  = 0.07,
    .alpha_tier1_icmp = 0.03,
    .alpha_tier1_dist = 0.06,

    /* Warm-up — 10 minutes is enough for this very-stable baseline. */
    .warmup_windows = 600,

    /* Tier-0 CUSUM / Z-score — h_pps/bps lifted modestly from default
     * (6.5 -> 7.5) because pps>=5000 runs reach 180 windows organically;
     * h_fps lifted to 7.0 because the high fps baseline (1084) makes
     * absolute residuals large; burst_z=12 because organic burst
     * factors are MUCH smaller here than on prior IPs (burst_pps
     * p99.99=6.0 vs 15+ on 46/215); variance_ceiling at default 2.0
     * because baseline variance is already low — no need to widen. */
    .cusum_k_pps             = 0.12,
    .cusum_h_pps             = 7.5,
    .cusum_k_bps             = 0.12,
    .cusum_h_bps             = 7.5,
    .cusum_k_fps             = 0.95,
    .cusum_h_fps             = 7.0,
    .burst_z_threshold       = 12.0,
    .variance_ceiling_factor = 2.0,

    /* Tier-0 risk fusion — fps weight reduced to 0.5 (critical for
     * this host) because fps baseline of 1084 means any perturbation
     * produces a large absolute residual; with higher weight, fusion
     * saturates routinely on organic peaks (sim verified: w_fps=0.8
     * -> 13.6% FP rate; w_fps=0.5 -> <0.01%). Total weight sum = 6.2. */
    .t0_w_pps       = 2.5,
    .t0_w_bps       = 1.5,
    .t0_w_fps       = 0.50,
    .t0_w_burst_pps = 0.8,
    .t0_w_burst_bps = 0.6,
    .t0_w_burst_fps = 0.30,

    /* Risk thresholds calibrated against 7-day organic data:
     *   risk_thr=4.8 sits comfortably above the saturation cliff at
     *   ~4.5 (where risk_pps + risk_bps + 0.5*risk_fps land) so it
     *   only fires when burst contributions also show up. Verified
     *   organic trigger rate ~0.003% (16 windows / 7 days). Below 4.8
     *   would push trigger rate to 13%+. */
    .t0_suspicious_risk_threshold = 3.8,
    .t0_risk_threshold            = 4.8,

    /* Absolute volumetric overrides — sized at 1.07×–1.33× the 7-day
     * observed max (pps 82.7K → 90K, bps 938M → 1.0G, fps 3012 → 4K).
     * Verified zero violations across 540K post-warmup windows.
     * Note: the May 5 23:00 outlier event (29 windows of pps 50-82K,
     * bps up to 938M) is treated as legitimate per the "all data
     * normal" tuning policy, so thresholds clear those values. The
     * non-outlier max is much lower (pps 40K, bps 444M), so the
     * effective attack-detection floor is ~2.25× true natural max. */
    .absolute_pps_threshold = 90000.0,
    .absolute_bps_threshold = 1000000000.0,
    .absolute_fps_threshold = 4000.0,

    /* Persistence / freeze / thaw — pps>=40K runs are at most 3
     * windows organically, so consecutive_attack_windows=4 reliably
     * filters legitimate single-burst spikes while still firing
     * within 4 seconds for sustained anomalies. */
    .consecutive_attack_windows = 4,
    .baseline_freeze_windows    = 12,
    .thaw_cooldown_windows      = 22,

    /* Tier-1 sigmoid — d0=1.45 matches 46's final tuning; absorbs
     * the saturated raw distances coming from the rare-protocol
     * problem (TCP raw distance reaches huge values because
     * em_tcp_pps_ratio drifts near zero during UDP-only periods,
     * then any TCP packet produces enormous norm_dist). k=0.90
     * keeps the curve sharp enough to differentiate. */
    .sigmoid_k  = 0.90,
    .sigmoid_d0 = 1.45,

    /* Tier-1 decision thresholds — 0.60 NORMAL/SUSPICIOUS boundary
     * matches the final tunings for 215/46. With Tier-0 only tripping
     * ~0.003% organically, the gating already prevents most FPs;
     * 0.60 lets Tier-1 confirm rather than block real attacks. */
    .threshold_normal     = 0.60,
    .threshold_suspicious = 0.85,

    /* Tier-1 weighted fusion — heavy UDP weighting (0.55) reflects
     * the protocol mix on this host (UDP-dominant 54%, TCP-dominant
     * only 3%). w_tcp pulled to a floor 0.10 because TCP appears
     * occasionally with very small EWMA baselines, producing
     * unreliable (saturated) tcp_score values that would otherwise
     * dominate fusion. ICMP at floor since icmp_pps_ratio mean is
     * 0.0019 — essentially absent. */
    .w_tcp  = 0.10,
    .w_udp  = 0.55,
    .w_icmp = 0.05,
    .w_dist = 0.30,
    .sigmoid_k_l3                     = 0.90,
    .sigmoid_d0_l3                    = 1.40,
};


// ========================
// IP : 213.230.125.50
// ========================
const struct l2_profile l2_profile_213_230_125_50_manual_v1 = {
    .name    = "213.230.125.50",
    .version = "manual_v1",

    /* EWMA alphas — tier0 at 0.030 because diurnal swing is wide
     * (hour-4 median 212 → hour-17 median 661, 3× swing); default
     * cadence on protocol/distribution channels. */
    .alpha_tier0      = 0.030,
    .alpha_tier1_tcp  = 0.04,
    .alpha_tier1_udp  = 0.07,
    .alpha_tier1_icmp = 0.03,
    .alpha_tier1_dist = 0.06,

    /* Warm-up — 10 minutes spans both quiet and busy phases. */
    .warmup_windows = 600,

    /* Tier-0 CUSUM / Z-score — h_pps/bps lifted to 9.0 because
     * pps>=5000 organic runs reach 53 windows during peak hours
     * 17-19 (legitimate burst behavior on this host); h_fps at 7.5
     * because fps tail is genuinely extended (single 4788 outlier,
     * regular 300-600 spikes). burst_z=14.0 since organic burst_pps
     * reaches p99.99=14.6 and burst_bps p99.99=18.6. variance_ceiling
     * at 2.5 absorbs the diurnal swing realistically. */
    .cusum_k_pps             = 0.15,
    .cusum_h_pps             = 9.0,
    .cusum_k_bps             = 0.15,
    .cusum_h_bps             = 9.0,
    .cusum_k_fps             = 1.00,
    .cusum_h_fps             = 7.5,
    .burst_z_threshold       = 14.0,
    .variance_ceiling_factor = 2.5,

    /* Tier-0 risk fusion — same shape as the 215/46/148/46 family;
     * total weight sum = 6.2. fps weight kept at 0.5 because rare
     * single-window outliers (4788 fps on May 6, 14:00 hour
     * regularly hits 600-2000) shouldn't dominate fusion. */
    .t0_w_pps       = 2.5,
    .t0_w_bps       = 1.5,
    .t0_w_fps       = 0.50,
    .t0_w_burst_pps = 0.8,
    .t0_w_burst_bps = 0.6,
    .t0_w_burst_fps = 0.30,

    /* Risk thresholds — calibrated against the FP rate on the
     * confirmed-normal portion of 5+ days of data (excluding the
     * A10-labeled May 6 19-minute attack window):
     *   risk_thr=5.0 + consec=4 → 10 false positives across 463K
     *   confirmed-normal seconds (0.002%, ~2/day). Lowering to 4.5
     *   would push FP to 0.087% (~80/day) for zero additional
     *   coverage of the May 6 attack, since that attack is
     *   sub-baseline volumetrically. */
    .t0_suspicious_risk_threshold = 4.0,
    .t0_risk_threshold            = 5.0,

    /* Absolute volumetric overrides — sized at 1.36-1.42× the 5-day
     * confirmed-normal max (pps 46.8K → 65K, bps 565M → 800M, fps
     * 4788 → 6500). Verified zero violations across 463K
     * confirmed-normal windows. The May 6 attack peaks (6.8K pps,
     * 70M bps, 453 fps) are FAR below these thresholds, so the
     * absolute path will never fire on that attack class — this is
     * by design, not a bug: relaxing these thresholds to catch the
     * ACK flood would require setting them BELOW normal p99 levels,
     * generating thousands of FPs daily on legitimate peak hours. */
    .absolute_pps_threshold = 65000.0,
    .absolute_bps_threshold = 800000000.0,
    .absolute_fps_threshold = 6500.0,

    /* Persistence / freeze / thaw — pps>=20K runs reach max 5
     * windows organically, so consecutive_attack_windows=4 reliably
     * filters legitimate burst spikes. Lowering to 2 (default)
     * would still not catch the ACK flood (Tier-0 risk inside the
     * attack window only crosses 5.0 in 26 of 1147 seconds, all
     * isolated single windows). */
    .consecutive_attack_windows = 4,
    .baseline_freeze_windows    = 12,
    .thaw_cooldown_windows      = 22,

    /* Tier-1 sigmoid — d0=1.45, k=0.90 (matches 46/148/46 family).
     * Mixed-protocol traffic produces moderate organic raw distances
     * on both TCP and UDP channels; d0=1.45 absorbs them while
     * keeping the curve steep enough that real attacks (d > 2.2)
     * saturate quickly. */
    .sigmoid_k  = 0.90,
    .sigmoid_d0 = 1.45,

    /* Tier-1 decision thresholds — 0.60/0.85, same as other tuned
     * profiles. With Tier-0 only tripping ~0.002% organically,
     * Tier-1 acts as behavioral confirmation rather than a primary
     * detector. Note: the May 6 ACK flood DID produce tier1_tcp_score
     * up to 0.89 in 5 windows organically — the limitation isn't
     * Tier-1 sensitivity, it's that Tier-0 doesn't open the gate
     * for Tier-1 to evaluate during the attack (volume too low). */
    .threshold_normal     = 0.60,
    .threshold_suspicious = 0.80,

    /* Tier-1 weighted fusion — slight TCP-leaning (0.35) matching
     * the 38% TCP-dominant / 57% mixed protocol profile of this host
     * (ACK-flood vector goes here when Tier-0 does open the gate).
     * UDP gets substantial 0.30 because UDP reaches 36% organically
     * and remains a viable amplification attack vector. ICMP at
     * floor 0.05 (icmp_pps_ratio mean = 0.001). dist gets 0.30 as
     * the secondary signal for distributed/multi-source attacks. */
    .w_tcp  = 0.35,
    .w_udp  = 0.30,
    .w_icmp = 0.05,
    .w_dist = 0.30,
    .sigmoid_k_l3                     = 0.90,
    .sigmoid_d0_l3                    = 1.40,
};


// ========================
// IP : 213.230.125.130
// ========================
const struct l2_profile l2_profile_213_230_125_130_manual_v1 = {
    .name    = "213.230.125.130",
    .version = "manual_v1",

    /* EWMA alphas — slow tier0 (0.025) because we have no diurnal
     * data; let baselines adapt gradually rather than overfit to the
     * 16-minute snapshot. Default cadence on protocol/distribution
     * channels — they're noisy at this volume but slowing them
     * further would just delay the inevitable readjustment when real
     * traffic arrives. */
    .alpha_tier0      = 0.025,
    .alpha_tier1_tcp  = 0.04,
    .alpha_tier1_udp  = 0.07,
    .alpha_tier1_icmp = 0.03,
    .alpha_tier1_dist = 0.06,

    /* Warm-up — 10 minutes covers a few diurnal phases on a busier
     * host; on this low-volume host it just lets the engine see
     * enough single-packet ratio swings to estimate variance. */
    .warmup_windows = 600,

    /* Tier-0 CUSUM / Z-score — h_pps/bps lifted to 8.0 (between
     * stable-host 7.5 and bursty-host 9.0) because at single-digit
     * pps any small bump produces large relative residuals. h_fps
     * at 7.5 because fps similarly is noise-dominated. burst_z=15
     * because organic burst factors reach 9-10× on this idle
     * baseline (going from 1 pkt to 10 pkts is a normal 10× burst).
     * variance_ceiling=2.5 absorbs the high std/mean ratio from
     * idle-then-bumpy traffic. */
    .cusum_k_pps             = 0.12,
    .cusum_h_pps             = 8.0,
    .cusum_k_bps             = 0.12,
    .cusum_h_bps             = 8.0,
    .cusum_k_fps             = 0.95,
    .cusum_h_fps             = 7.5,
    .burst_z_threshold       = 15.0,
    .variance_ceiling_factor = 2.5,

    /* Tier-0 risk fusion — same shape (sum=6.2) as the small-host
     * 94.141.85.122 profile. fps weight at 0.5 keeps a single fps
     * spike from saturating fusion. */
    .t0_w_pps       = 2.5,
    .t0_w_bps       = 1.5,
    .t0_w_fps       = 0.50,
    .t0_w_burst_pps = 0.8,
    .t0_w_burst_bps = 0.6,
    .t0_w_burst_fps = 0.30,

    /* Risk thresholds — risk_thr=5.0 with consec=4 produces 0
     * triggers on the available 16-minute snapshot. Default profile
     * already produced 1 ATTACK at pps=14 in this dataset, so we
     * know the default is over-sensitive. risk_thr=5.0 keeps us
     * away from that noise floor. */
    .t0_suspicious_risk_threshold = 4.0,
    .t0_risk_threshold            = 5.0,

    /* Absolute volumetric overrides — sized DELIBERATELY WIDE at
     * ~3-7× the observed snapshot max because we have no diurnal
     * data. Observed max: pps 38, bps 46K, fps 10. Profile values:
     * pps 250 (~6.6× headroom), bps 1.5M (~32× headroom), fps 50
     * (~5× headroom). For an idle host these are still small enough
     * that any real volumetric attack (1000+ pps, 10+ Mbps) trips
     * immediately, but loose enough that a normal business-hour
     * spike to 50-100 pps wouldn't cause a false positive.
     *
     * IMPORTANT: these thresholds should be RE-EVALUATED after 24+
     * hours of representative data capture. */
    .absolute_pps_threshold = 250.0,
    .absolute_bps_threshold = 1500000.0,
    .absolute_fps_threshold = 50.0,

    /* Persistence / freeze / thaw — consec=4 reliably filters
     * single-window noise common at this volume scale. */
    .consecutive_attack_windows = 4,
    .baseline_freeze_windows    = 12,
    .thaw_cooldown_windows      = 22,

    /* Tier-1 sigmoid — d0=1.50 (slightly higher than the 1.45 used
     * on busier hosts) because at 3 pps median, single-packet
     * arrival of any TCP-flag type produces saturated raw distances
     * (e.g. 1 SYN out of 1 TCP packet → tcp_syn_ratio=1.0 vs
     * baseline 0.05 produces enormous norm_dist). The wider d0
     * absorbs this single-packet noise. */
    .sigmoid_k  = 0.85,
    .sigmoid_d0 = 1.50,

    /* Tier-1 decision thresholds — 0.62 NORMAL/SUSPICIOUS slightly
     * higher than 0.60 used on busier hosts to compensate for the
     * single-packet ratio saturation problem on low-volume hosts. */
    .threshold_normal     = 0.62,
    .threshold_suspicious = 0.85,

    /* Tier-1 weighted fusion — UDP-leaning (0.45) because the
     * 16-minute snapshot shows UDP-dominant 59%, but capped because
     * the protocol mix is unstable on idle hosts. TCP gets 0.20
     * because it does appear (21% dominant). ICMP at floor 0.05.
     * dist gets 0.30 as a stable signal — this host's natural
     * src_ip_ratio mean is 0.65 (high because few packets per
     * source), so dist_score deviation is the most reliable
     * indicator of distributed attacks here. */
    .w_tcp  = 0.20,
    .w_udp  = 0.45,
    .w_icmp = 0.05,
    .w_dist = 0.30,
    .sigmoid_k_l3                     = 0.90,
    .sigmoid_d0_l3                    = 1.40,
};


/* ------------------------------------------------------------------------- */
/* Static IP → profile assignment table.
 *
 * Empty by default (only a sentinel), so every destination IP resolves to
 * l2_profile_default and behavior is unchanged. To assign a non-default
 * profile to a specific IP, insert a row before the sentinel. Example:
 *
 *   { RTE_IPV4(10, 10, 10, 1), &l2_profile_sensitive },
 *
 * dst_ip values are in host byte order (matching detector hot path).
 * Iteration stops at the first entry whose profile pointer is NULL.
 */
/* ------------------------------------------------------------------------- */

struct l2_profile_assignment {
    uint32_t                  dst_ip;   /* host byte order */
    const struct l2_profile  *profile;  /* NULL terminates the table */
};

static const struct l2_profile_assignment l2_profile_assignments[] = {
    /* Insert per-IP overrides here. */
    { RTE_IPV4(213, 230, 125, 130), &l2_profile_213_230_125_130_manual_v1 },
    { RTE_IPV4(213, 230, 125, 50), &l2_profile_213_230_125_50_manual_v1 },
    { RTE_IPV4(213, 230, 125, 148), &l2_profile_213_230_125_148_manual_v1 },
    { RTE_IPV4(213, 230, 125, 46), &l2_profile_213_230_125_46_manual_v1 },
    { RTE_IPV4(89, 249, 63, 215), &l2_profile_89_249_63_215_manual_v1 },
    { RTE_IPV4(45, 150, 25, 70), &l2_profile_45_150_25_70_manual_v1 },
    { RTE_IPV4(213, 230, 125, 66), &l2_profile_213_230_125_66_manual_v1 },
    { RTE_IPV4(213, 230, 125, 170), &l2_profile_213_230_125_170_manual_v1 },
    { RTE_IPV4(89, 249, 62, 131), &l2_profile_89_249_62_131_manual_v1 },
    { RTE_IPV4(45, 150, 25, 116), &l2_profile_45_150_25_116_manual_v1 },
    { RTE_IPV4(94, 141, 85, 150), &l2_profile_94_141_85_150_manual_v1 },
    { 0, NULL },   /* sentinel — do not remove */
};

const struct l2_profile *l2_profile_for_ip(uint32_t dst_ip) {
    for (const struct l2_profile_assignment *a = l2_profile_assignments;
         a->profile != NULL; a++) {
        if (a->dst_ip == dst_ip) {
            return a->profile;
        }
    }
    return &l2_profile_default;
}

