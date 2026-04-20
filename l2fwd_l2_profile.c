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
const struct l2_profile l2_profile_sensitive = {
    .name    = "sensitive",
    .version = "v1",

    /* EWMA alphas — unchanged from default */
    .alpha_tier0      = 0.25,
    .alpha_tier1_tcp  = 0.12,
    .alpha_tier1_udp  = 0.12,
    .alpha_tier1_icmp = 0.12,
    .alpha_tier1_dist = 0.12,

    /* Warm-up — unchanged */
    .warmup_windows = 200,

    /* Tier-0 CUSUM: same K, tighter H; lower burst Z */
    .cusum_k_pps             = 0.04,
    .cusum_h_pps             = 4.5,
    .cusum_k_bps             = 0.04,
    .cusum_h_bps             = 4.5,
    .cusum_k_fps             = 0.05,
    .cusum_h_fps             = 4.0,
    .burst_z_threshold       = 4.0,
    .variance_ceiling_factor = 3.0,

    /* Tier-0 fusion weights — unchanged */
    .t0_w_pps       = 3,
    .t0_w_bps       = 3,
    .t0_w_fps       = 2,
    .t0_w_burst_pps = 1.5,
    .t0_w_burst_bps = 1.5,
    .t0_w_burst_fps = 1,

    /* Tier-0 risk thresholds — lower so SUSPICIOUS/ATTACK fire earlier */
    .t0_suspicious_risk_threshold = 4.5,
    .t0_risk_threshold            = 6.5,

    /* Tier-0 absolute overrides — unchanged */
    .absolute_pps_threshold = 30000.0,
    .absolute_bps_threshold = 200000000.0,
    .absolute_fps_threshold = 190,

    /* Persistence: shorter commit; freeze/thaw unchanged */
    .consecutive_attack_windows = 3,
    .baseline_freeze_windows    = BASELINE_FREEZE_WINDOWS,
    .thaw_cooldown_windows      = THAW_COOLDOWN_WINDOWS,

    /* Tier-1 sigmoid — unchanged */
    .sigmoid_k  = 0.9,
    .sigmoid_d0 = 1.2,

    /* Tier-1 decision thresholds — tighter */
    .threshold_normal     = 0.40,
    .threshold_suspicious = 0.65,

    /* Tier-1 fusion weights — unchanged */
    .w_tcp  = 0.65,
    .w_udp  = 0.10,
    .w_icmp = 0.05,
    .w_dist = 0.20,
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
    { RTE_IPV4(89, 249, 62, 130), &l2_profile_sensitive },
    { RTE_IPV4(89, 249, 62, 131), &l2_profile_sensitive },
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

