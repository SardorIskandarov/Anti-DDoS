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
#define DETECTION_WARMUP_WINDOWS 900

/**
 * CUSUM parameters for Tier-0 volume anomaly detection.
 *
 * AGGRESSIVE settings for rapid DDoS detection:
 *   k = 0.5  (low allowance → high sensitivity)
 *   h = 3.0  (moderate threshold for quick response)
 *
 * Formula:
 *   S_t = max(0, S_{t-1} + (x_t - ewma_mean - k * ewma_std))
 *   Alarm when S_t > H (H = h * ewma_std)
 */
#define CUSUM_K  0.45   /* Allowance factor (low = sensitive) */
#define CUSUM_H  3   /* Threshold factor (moderate = responsive) */

/**
 * Tier-0 attack confirmation with persistence filter.
 *
 * STEP 1 (Per-window):
 *   if (alarm_count >= TIER0_ATTACK_THRESHOLD):
 * 
 * 
 * 
 * 
 * 
 * 
 * 
 * 
 * 
 * 
 * 
 * 
 * 
 * 
 * 
 * 
 * 
 * 
 * 
 * 
 * 
 * 
 *       consecutive_attack_counter++
 *   else:
 *       consecutive_attack_counter = 0
 *
 * STEP 2 (Confirmation):
 *   if (consecutive_attack_counter >= CONSECUTIVE_ATTACK_WINDOWS):
 *       Tier-0 = ATTACK
 *   else:
 *       Tier-0 = NORMAL
 *
 * Early freeze: Freeze when alarm_count >= 1
 */
#define TIER0_ATTACK_THRESHOLD 3      /* 2 out of 6 features */
#define CONSECUTIVE_ATTACK_WINDOWS 3  /* 2 consecutive seconds */

/** Tier-1 sigmoid parameters (unchanged) */
#define SIGMOID_K   1.4
#define SIGMOID_D0  0.9

/** Tier-1 decision thresholds */
#define THRESHOLD_NORMAL     0.4
#define THRESHOLD_SUSPICIOUS 0.6

/**
 * EARLY FREEZE: Freeze as soon as ANY Tier-0 alarm fires.
 *
 * When alarm_count >= 1:
 *   - Freeze Tier-0 FAST EWMA (detection baseline)
 *   - Freeze CUSUM variance (prevent std inflation)
 *   - SLOW EWMA continues learning (long-term reference)
 *
 * When attack ends (alarm_count < 1 for consecutive windows):
 *   - Unfreeze immediately
 *   - No gradual recovery
 */
#define BASELINE_FREEZE_WINDOWS 10

/**
 * THAW COOLDOWN: Number of consecutive NORMAL windows required before
 * unfreezing baselines after an attack ends.
 *
 * Prevents learning:
 *   - Tail-end of attacks as normal traffic
 *   - Pulsing attacks as baseline behavior
 *
 * The system must observe THAW_COOLDOWN_WINDOWS consecutive windows
 * with NO alarms before calling thaw_all_tiers().
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
// CUSUM STATE (residual-based, Tier-0 only)
// ============================================================================

/**
 * Per-feature CUSUM state for residual-based detection.
 *
 * Residual: r_t = EWMA_FAST_t - EWMA_SLOW_t
 *
 * Upper CUSUM (detects positive shifts):
 *   S_t = max(0, S_{t-1} + (r_t - k))
 *
 * Alarm: S_t > H (H is FIXED, no variance scaling)
 *
 * FREEZE BEHAVIOR (when tier_state.frozen == true):
 *   - S_t held constant (no accumulation)
 *   - variance held constant (prevent inflation)
 *   - EWMA_FAST held constant
 *   - EWMA_SLOW continues updating
 */
struct cusum_state {
    double S;         /* CUSUM accumulator */
    double variance;  /* Residual variance (for monitoring only) */
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

    /* Tier-0 CUSUM metrics */
    double tier0_cusum_pps;
    double tier0_cusum_bps;
    double tier0_cusum_fps;
    double tier0_cusum_burst_pps;
    double tier0_cusum_burst_bps;
    double tier0_cusum_burst_fps;
    int    tier0_attack_count;
    double tier0_score;  /* Legacy: normalized alarm count */

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

    /* CUSUM accumulators (Tier-0 only, residual-based) */
    struct cusum_state cusum[TIER0_N];

    /* Warm-up counter */
    uint32_t warmup_counter;

    /* Persistence filter */
    uint32_t consecutive_attack_counter;

    /* Thaw cooldown: tracks consecutive NORMAL windows before unfreezing */
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
 * Tier-0: Residual-based CUSUM detection with early freeze.
 *
 * Computes residual = EWMA_FAST - EWMA_SLOW for each feature.
 * Runs CUSUM on residual (NOT raw value).
 * Returns alarm count (0..TIER0_N).
 *
 * FREEZE BEHAVIOR:
 *   frozen == true → S_t, variance, EWMA_FAST all held constant
 *   frozen == false → normal updates
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
    uint64_t timestamp);

const char *detection_state_str(detection_state_t state);

#endif /* __L2FWD_DETECTION_ENGINE_H__ */