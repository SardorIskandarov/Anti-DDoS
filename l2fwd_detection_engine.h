#ifndef __L2FWD_DETECTION_ENGINE_H__
#define __L2FWD_DETECTION_ENGINE_H__

#include <stdint.h>
#include <stdbool.h>
#include "l2fwd_ddos_collector.h"

// ============================================================================
// DETECTION ENGINE CONFIGURATION
// ============================================================================

/**
 * Warm-up period before detection engine becomes active (in seconds).
 * During warm-up, both tiers learn traffic patterns but do not trigger alerts.
 */
#define DETECTION_WARMUP_SECONDS 300 // 5 minutes

/**
 * Sigmoid normalization parameters for Manhattan distance.
 * distance_normalized = 1 / (1 + exp(-k * (distance - midpoint)))
 * 
 * k controls steepness, midpoint is the inflection point.
 */
#define SIGMOID_K        2.0
#define SIGMOID_MIDPOINT 3.0

/**
 * Detection thresholds for normalized distance [0, 1]:
 *   [0.0, 0.3)  → NORMAL
 *   [0.3, 0.6)  → SUSPICIOUS  
 *   [0.6, 1.0]  → ATTACK
 */
#define THRESHOLD_SUSPICIOUS 0.3
#define THRESHOLD_ATTACK     0.6

/**
 * Baseline freeze duration after attack detection (seconds).
 * After an attack is detected, baseline learning is frozen for this period
 * to prevent baseline poisoning.
 */
#define BASELINE_FREEZE_DURATION 300  // 5 minutes

/**
 * Gradual recovery rate after attack ends.
 * When traffic returns to normal, learning resumes gradually.
 * recovery_weight starts at 0 and increases by this amount per second.
 */
#define RECOVERY_RATE_PER_SECOND 0.01  // Full recovery after 100 seconds

// ============================================================================
// DETECTION STATES
// ============================================================================

typedef enum {
    DETECTION_STATE_WARMUP,      /* Learning initial baseline, no alerts */
    DETECTION_STATE_NORMAL,      /* Normal operation */
    DETECTION_STATE_SUSPICIOUS,  /* Tier-0 detected suspicious pattern */
    DETECTION_STATE_ATTACK,      /* Tier-1 confirmed attack */
    DETECTION_STATE_RECOVERING,  /* Attack ended, gradually resuming learning */
} detection_state_t;

// ============================================================================
// FEATURE VECTORS
// ============================================================================

/**
 * Tier-0 feature vector: fast, coarse-grained traffic characteristics.
 * Used for initial anomaly detection.
 */
#define TIER0_FEATURE_COUNT 7

struct tier0_features {
    double pps;
    double bps;
    double fps;
    double inbound_bits;
    double outbound_bits;
    double udp_ratio;
    double tcp_ratio;
    double icmp_ratio;
};

/**
 * Tier-1 feature vector: detailed behavioral characteristics.
 * Used for attack confirmation and detailed analysis.
 */
#define TIER1_FEATURE_COUNT 8

struct tier1_features {
    double syn_ratio;
    double synack_ratio;
    double finack_ratio;
    double rst_ratio;
    double udp_flow_rate;        /* UDP flows / total UDP packets */
    double unique_src_ip_rate;   /* Unique src IPs / PPS */
    double unique_dst_port_rate; /* Unique dst ports / PPS */
    double icmp_echo_rate;
};

// ============================================================================
// BASELINE MODELS (DoM - Degree of Membership)
// ============================================================================

/**
 * Baseline vector for Tier-0 features.
 * Learned via EWMA, frozen during attacks to prevent poisoning.
 */
struct tier0_baseline {
    struct ewma_state pps;
    struct ewma_state bps;
    struct ewma_state fps;
    struct ewma_state inbound_bits;
    struct ewma_state outbound_bits;
    struct ewma_state udp_ratio;
    struct ewma_state tcp_ratio;
    struct ewma_state icmp_ratio;
    
    /* Baseline is frozen when true (during/after attack) */
    bool frozen;
    
    /* Timestamp when baseline was frozen (TSC cycles) */
    uint64_t freeze_timestamp;
};

/**
 * Baseline vector for Tier-1 features.
 * Learns passively, only activates when Tier-0 triggers.
 */
struct tier1_baseline {
    struct ewma_state syn_ratio;
    struct ewma_state synack_ratio;
    struct ewma_state finack_ratio;
    struct ewma_state rst_ratio;
    struct ewma_state udp_flow_rate;
    struct ewma_state unique_src_ip_rate;
    struct ewma_state unique_dst_port_rate;
    struct ewma_state icmp_echo_rate;
    
    /* Baseline is frozen when true (during/after attack) */
    bool frozen;
    
    /* Timestamp when baseline was frozen (TSC cycles) */
    uint64_t freeze_timestamp;
};

// ============================================================================
// DETECTION RESULT
// ============================================================================

/**
 * Detection result for a single time window.
 */
struct detection_result {
    detection_state_t state;
    
    /* Tier-0 metrics */
    double tier0_distance;           /* Raw Manhattan distance */
    double tier0_distance_normalized;/* Sigmoid-normalized [0, 1] */
    
    /* Tier-1 metrics (only valid if tier-0 triggered) */
    bool tier1_evaluated;
    double tier1_distance;
    double tier1_distance_normalized;
    
    /* Timestamps */
    uint64_t timestamp;              /* TSC cycles */
    
    /* Recovery progress [0.0, 1.0] during RECOVERING state */
    double recovery_weight;
};

// ============================================================================
// PER-DESTINATION DETECTION ENGINE
// ============================================================================

/**
 * Detection engine state for a single destination IP.
 */
struct detection_engine {
    /* Current detection state */
    detection_state_t state;
    
    /* Baseline models */
    struct tier0_baseline tier0;
    struct tier1_baseline tier1;
    
    /* Warm-up tracking */
    uint64_t warmup_start_time;      /* TSC cycles */
    uint32_t warmup_windows;         /* Number of 1s windows elapsed */
    
    /* Recovery tracking */
    uint64_t recovery_start_time;    /* TSC cycles when recovery began */
    double recovery_weight;          /* Current recovery weight [0, 1] */
    
    /* Attack history */
    uint64_t last_attack_time;       /* TSC cycles of last attack */
    uint32_t attack_count;           /* Total number of attacks detected */
    
    /* Latest detection result */
    struct detection_result last_result;
};

// ============================================================================
// PUBLIC API
// ============================================================================

/**
 * Initialize detection engine for a destination IP.
 * Called when a new dst_ip_stats entry is created.
 */
void detection_engine_init(struct detection_engine *engine, uint64_t timestamp);

/**
 * Extract Tier-0 features from current stats window.
 */
void extract_tier0_features(const struct dst_ip_stats *stats,
                             struct tier0_features *features,
                             double time_sec);

/**
 * Extract Tier-1 features from current stats window.
 */
void extract_tier1_features(const struct dst_ip_stats *stats,
                             struct tier1_features *features,
                             double time_sec);

/**
 * Update Tier-0 baseline with new observation.
 * Respects freeze state - no update if baseline is frozen.
 */
void update_tier0_baseline(struct tier0_baseline *baseline,
                            const struct tier0_features *features,
                            uint64_t timestamp,
                            double recovery_weight);

/**
 * Update Tier-1 baseline with new observation (passive learning).
 * Respects freeze state - no update if baseline is frozen.
 */
void update_tier1_baseline(struct tier1_baseline *baseline,
                            const struct tier1_features *features,
                            uint64_t timestamp,
                            double recovery_weight);

/**
 * Compute Manhattan distance between current features and baseline.
 */
double compute_tier0_distance(const struct tier0_baseline *baseline,
                               const struct tier0_features *current);

double compute_tier1_distance(const struct tier1_baseline *baseline,
                               const struct tier1_features *current);

/**
 * Normalize distance using sigmoid function.
 * Maps [0, ∞) → [0, 1]
 */
double sigmoid_normalize(double distance);

/**
 * Main detection logic: processes one time window and returns detection result.
 * 
 * @param engine   Detection engine state
 * @param stats    Current destination IP stats
 * @param timestamp Current timestamp (TSC cycles)
 * @return         Detection result for this window
 */
struct detection_result detection_engine_process(struct detection_engine *engine,
                                                   const struct dst_ip_stats *stats,
                                                   uint64_t timestamp);

/**
 * Check if baseline freeze period has expired and initiate recovery if needed.
 */
void check_and_update_recovery(struct detection_engine *engine, uint64_t timestamp);

/**
 * Get human-readable state string.
 */
const char *detection_state_str(detection_state_t state);

#endif /* __L2FWD_DETECTION_ENGINE_H__ */