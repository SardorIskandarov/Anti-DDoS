#ifndef __L2FWD_DETECTION_ENGINE_H__
#define __L2FWD_DETECTION_ENGINE_H__

#include <stdint.h>
#include <stdbool.h>
#include "l2fwd_ddos_collector.h"

// ============================================================================
// DETECTION ENGINE CONFIGURATION
// ============================================================================

/**
 * Warm-up: Learn baselines silently before making decisions.
 */
#define DETECTION_WARMUP_WINDOWS 1000

/**
 * CHANGE 1: Z-score threshold for burst features (burst_pps, burst_bps, burst_fps)
 * 
 * Burst features use EWMA + Z-score instead of CUSUM:
 *   z = (x - ewma_mean) / (std + epsilon)
 *   risk = clamp(z / BURST_Z_THRESHOLD, 0, 1)
 */
#define BURST_Z_THRESHOLD 5.0

/**
 * CHANGE 2: Per-feature CUSUM parameters (PPS, BPS, FPS only)
 *
 * Formula:
 *   S_t = max(0, S_{t-1} + (x_t - ewma_mean - k * ewma_std))
 *   Alarm when S_t > H (H = h * ewma_std)
 */
#define CUSUM_K_PPS  0.08
#define CUSUM_H_PPS  4.0

#define CUSUM_K_BPS  0.08
#define CUSUM_H_BPS  4.0

#define CUSUM_K_FPS  0.08
#define CUSUM_H_FPS  4.0

/**
 * CHANGE 3: Tier-0 continuous risk scoring weights
 *
 * global_risk = sum(w_i * risk_i)
 * 
 * Trigger when: global_risk >= T0_RISK_THRESHOLD
 */
#define T0_W_PPS         3.0
#define T0_W_BPS         3.0
#define T0_W_FPS         2.0
#define T0_W_BURST_PPS   1.5
#define T0_W_BURST_BPS   1.5
#define T0_W_BURST_FPS   1.0

#define T0_RISK_THRESHOLD 8.0

/**
 * ABSOLUTE VOLUMETRIC OVERRIDE THRESHOLDS (PRODUCTION SAFETY NET)
 *
 * Instant ATTACK trigger if ANY of these is exceeded in a single window.
 * This bypasses CUSUM + persistence delay for raw volumetric attacks.
 *
 * Recommended starting values for corporate/ISP networks:
 *   PPS  18000 → tiny-packet floods (hping3, SYN, ICMP)
 *   BPS  800M  → bandwidth/amplification/reflection attacks
 *   FPS  50000 → flow-table exhaustion / distributed SYN floods
 *
 * Tune higher if you see false positives on legitimate bursts.
 */
#define ABSOLUTE_PPS_THRESHOLD  50000.0
#define ABSOLUTE_BPS_THRESHOLD  100000000.0
#define ABSOLUTE_FPS_THRESHOLD  30000.0

/**
 * Tier-0 attack confirmation with persistence filter.
 *
 * STEP 1 (Per-window):
 *   if (global_risk >= T0_RISK_THRESHOLD):
 *       consecutive_attack_counter++
 *   else:
 *       consecutive_attack_counter = 0
 *
 * STEP 2 (Confirmation):
 *   if (consecutive_attack_counter >= CONSECUTIVE_ATTACK_WINDOWS):
 *       Tier-0 = ATTACK
 *   else:
 *       Tier-0 = NORMAL
 */
#define CONSECUTIVE_ATTACK_WINDOWS 3  /* 3 consecutive seconds */

/** Tier-1 sigmoid parameters (unchanged) */
#define SIGMOID_K   0.8
#define SIGMOID_D0  1.4

/** Tier-1 decision thresholds */
#define THRESHOLD_NORMAL     0.45
#define THRESHOLD_SUSPICIOUS 0.65

/**
 * IMPROVEMENT 3: Tier-1 weighted fusion weights
 * Replaces "worst wins" with weighted average for balanced decision making
 */
#define W_TCP   0.4
#define W_UDP   0.3
#define W_DIST  0.2
#define W_ICMP  0.1

/**
 * EARLY FREEZE: Freeze as soon as Tier-0 risk exceeds threshold.
 */
#define BASELINE_FREEZE_WINDOWS 10

/**
 * THAW COOLDOWN: Number of consecutive NORMAL windows required before
 * unfreezing baselines after an attack ends.
 */
#define THAW_COOLDOWN_WINDOWS 20

// ============================================================================
// DETECTION STATES
// ============================================================================

typedef enum {
    DETECTION_STATE_WARMUP,      /* Learning baselines */
    DETECTION_STATE_NORMAL,      /* All clear */
    DETECTION_STATE_SUSPICIOUS,  /* Tier-1 says suspicious */
    DETECTION_STATE_ATTACK,      /* Tier-1 confirmed attack */
} detection_state_t;

// ============================================================================
// ATTACK TYPES
// ============================================================================

typedef enum {
    ATTACK_TYPE_NONE,
    ATTACK_TYPE_SYN_FLOOD,
    ATTACK_TYPE_ACK_FLOOD,
    ATTACK_TYPE_RST_FIN_FLOOD,
    ATTACK_TYPE_UDP_FLOOD,
    ATTACK_TYPE_ICMP_FLOOD,
    ATTACK_TYPE_DISTRIBUTED,
    ATTACK_TYPE_AMPLIFICATION,
    ATTACK_TYPE_UNKNOWN
} attack_type_t;

// ============================================================================
// FEATURE VECTORS
// ============================================================================

struct tier0_features {
    double pps;
    double bps;
    double fps;
    double burst_pps;
    double burst_bps;
    double burst_fps;
};
#define TIER0_N 6

struct tier1_tcp_features {
    double syn_ratio;
    double synack_ratio;
    double finack_ratio;
    double rst_ratio;
    double ack_data_ratio;
    double tcp_pps_ratio;
    double tcp_bps_ratio;
};
#define TIER1_TCP_N 7

struct tier1_udp_features {
    double udp_bps_ratio;
    double udp_pps_ratio;
    double udp_flow_ratio;
};
#define TIER1_UDP_N 3

struct tier1_icmp_features {
    double icmp_echo_ratio;
    double icmp_pps_ratio;
};
#define TIER1_ICMP_N 2

struct tier1_dist_features {
    double src_ip_ratio;
    double dst_port_ratio;
};
#define TIER1_DIST_N 2

// ============================================================================
// CUSUM STATE
// ============================================================================

/**
 * Per-feature state for detection.
 *
 * For CUSUM features (pps, bps, fps):
 *   S_t = max(0, S_{t-1} + (r_t - k))
 *
 * For burst features (burst_pps, burst_bps, burst_fps):
 *   z = (x - mean) / std
 *   S is unused
 *
 * variance field is used by BOTH types.
 */
struct cusum_state {
    double S;         /* CUSUM accumulator (unused for burst features) */
    double variance;  /* Variance tracking (used by both CUSUM and Z-score) */
    double alpha_std; /* Variance smoothing factor */
};

// ============================================================================
// TIER BASELINE STATE
// ============================================================================

struct tier_state {
    bool     frozen;
    uint32_t freeze_counter;
};

// ============================================================================
// DETECTION RESULT
// ============================================================================

struct detection_result {
    detection_state_t state;

    /* CHANGE 3: Tier-0 continuous risk scores per feature */
    double tier0_risk_pps;
    double tier0_risk_bps;
    double tier0_risk_fps;
    double tier0_risk_burst_pps;
    double tier0_risk_burst_bps;
    double tier0_risk_burst_fps;
    double tier0_global_risk;

    /* Legacy Tier-0 CUSUM metrics (for monitoring) */
    double tier0_cusum_pps;
    double tier0_cusum_bps;
    double tier0_cusum_fps;
    double tier0_cusum_burst_pps;
    double tier0_cusum_burst_bps;
    double tier0_cusum_burst_fps;
    int    tier0_attack_count;
    double tier0_score;

    /* Tier-1 metrics */
    bool   tier1_evaluated;
    double tier1_tcp_raw_dist;
    double tier1_tcp_score;
    double tier1_udp_raw_dist;
    double tier1_udp_score;
    double tier1_icmp_raw_dist;
    double tier1_icmp_score;
    double tier1_dist_raw_dist;
    double tier1_dist_score;
    double tier1_final_score;

    attack_type_t attack_type;

    uint64_t timestamp;
};

// ============================================================================
// DETECTION ENGINE
// ============================================================================

struct detection_engine {
    detection_state_t state;

    /* Tier baseline freeze tracking */
    struct tier_state tier0_state;
    struct tier_state tier1_tcp_state;
    struct tier_state tier1_udp_state;
    struct tier_state tier1_icmp_state;
    struct tier_state tier1_dist_state;

    /* CUSUM/Z-score accumulators (Tier-0 only) */
    struct cusum_state cusum[TIER0_N];

    /* Warm-up counter */
    uint32_t warmup_counter;

    /* Persistence filter */
    uint32_t consecutive_attack_counter;

    /* Thaw cooldown */
    uint32_t thaw_cooldown_counter;

    /* Attack history */
    uint32_t attack_count;
    uint64_t last_attack_time;

    struct detection_result last_result;
};

// ============================================================================
// PUBLIC API
// ============================================================================

void detection_engine_init(struct detection_engine *engine, uint64_t timestamp);

void extract_tier0_features    (const struct dst_ip_stats *stats,
                                 struct tier0_features *out,
                                 double time_sec);
void extract_tier1_tcp_features(const struct dst_ip_stats *stats,
                                 struct tier1_tcp_features *out,
                                 double time_sec);
void extract_tier1_udp_features(const struct dst_ip_stats *stats,
                                 struct tier1_udp_features *out,
                                 double time_sec);
void extract_tier1_icmp_features(const struct dst_ip_stats *stats,
                                  struct tier1_icmp_features *out,
                                  double time_sec);
void extract_tier1_dist_features(const struct dst_ip_stats *stats,
                                  struct tier1_dist_features *out,
                                  double time_sec);

/**
 * CHANGE 2 & 3: Tier-0 detection with per-feature parameters and continuous risk.
 *
 * Returns: number of features exceeding threshold (for backward compatibility)
 * Populates: result->tier0_risk_* and result->tier0_global_risk
 */
int cusum_update_tier0(struct detection_engine *engine,
                       const struct dst_ip_stats *stats,
                       const struct tier0_features *cur,
                       struct detection_result *result,
                       bool frozen);

double compute_tier1_tcp_score (const struct tier1_tcp_ewma  *ewma,
                                 const struct tier1_tcp_features *cur);
double compute_tier1_udp_score (const struct tier1_udp_ewma  *ewma,
                                 const struct tier1_udp_features *cur);
double compute_tier1_icmp_score(const struct tier1_icmp_ewma *ewma,
                                 const struct tier1_icmp_features *cur);
double compute_tier1_dist_score(const struct tier1_dist_ewma *ewma,
                                 const struct tier1_dist_features *cur);

double sigmoid_score(double distance);

struct detection_result detection_engine_process(
    struct detection_engine *engine,
    struct dst_ip_stats     *stats,
    uint64_t timestamp,
    uint32_t dst_ip);   /* dst_ip in host byte order */   

const char *attack_type_str(attack_type_t type);
const char *detection_state_str(detection_state_t state);

#endif /* __L2FWD_DETECTION_ENGINE_H__ */