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

