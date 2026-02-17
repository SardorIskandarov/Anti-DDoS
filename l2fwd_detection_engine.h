#ifndef __L2FWD_DETECTION_ENGINE_H__
#define __L2FWD_DETECTION_ENGINE_H__

#include <stdint.h>
#include <stdbool.h>
#include "l2fwd_ddos_collector.h"

// ============================================================================
// DETECTION ENGINE CONFIGURATION
// ============================================================================

/**
 * Warm-up: engine learns but does not trigger alerts for this many windows.
 * At 1 s/window that is 30 seconds of silent learning before decisions start.
 */
#define DETECTION_WARMUP_WINDOWS 30

/**
 * Sigmoid normalisation:  score = 1 / (1 + exp(-k * (distance - d0)))
 *
 *   k  = steepness (higher → sharper transition)
 *   d0 = inflection point (the "average normal" distance)
 *
 * Starting values per spec: k = 3, d0 = 0.5
 */
#define SIGMOID_K   3.0
#define SIGMOID_D0  0.5

/**
 * Decision thresholds on the normalised score ∈ [0, 1]:
 *   [0.0 , 0.4)  → NORMAL
 *   [0.4 , 0.6]  → SUSPICIOUS
 *   (0.6 , 1.0]  → ATTACK
 */
#define THRESHOLD_NORMAL     0.4
#define THRESHOLD_SUSPICIOUS 0.6

/**
 * After an attack is detected, freeze baselines for this many windows to
 * prevent baseline poisoning during an ongoing attack.
 */
#define BASELINE_FREEZE_WINDOWS 300   /* 5 minutes at 1 s/window */

/**
 * Gradual recovery: weight rises from 0 → 1 over this many windows.
 * Baseline update during recovery uses: alpha * recovery_weight
 */
#define RECOVERY_WINDOWS 100

// ============================================================================
// DETECTION STATES
// ============================================================================

typedef enum {
    DETECTION_STATE_WARMUP,      /* Silently learning, no decisions yet      */
    DETECTION_STATE_NORMAL,      /* All clear                                 */
    DETECTION_STATE_SUSPICIOUS,  /* Tier-0 triggered; Tier-1 says suspicious */
    DETECTION_STATE_ATTACK,      /* Tier-0 triggered; Tier-1 confirmed attack */
    DETECTION_STATE_RECOVERING,  /* Post-attack gradual baseline recovery     */
} detection_state_t;

// ============================================================================
// FEATURE VECTORS
// ============================================================================

/** Tier 0: 6 volume features (always active) */
struct tier0_features {
    double pps;
    double bps;
    double fps;
    double burst_pps;
    double burst_bps;
    double burst_fps;
};
#define TIER0_N 6

/** Tier 1.1: 7 TCP behavioural features (passive → activated by Tier 0) */
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

/** Tier 1.2: 3 UDP behavioural features */
struct tier1_udp_features {
    double udp_bps_ratio;
    double udp_pps_ratio;
    double udp_flow_ratio;
};
#define TIER1_UDP_N 3

/** Tier 1.3: 2 ICMP behavioural features */
struct tier1_icmp_features {
    double icmp_echo_ratio;
    double icmp_pps_ratio;
};
#define TIER1_ICMP_N 2

/** Tier 1.4: 2 distribution features */
struct tier1_dist_features {
    double src_ip_ratio;
    double dst_port_ratio;
};
#define TIER1_DIST_N 2

// ============================================================================
// TIER BASELINE  (frozen during attacks, thawed during recovery)
// ============================================================================

/**
 * Each tier's detection state and freeze metadata.
 * The actual EWMA means live in dst_ip_stats (ewma_t0, ewma_t1_tcp, …)
 * so that the collector can update them even when the detection engine is
 * not deciding.  The baseline struct here only tracks operational state.
 */
struct tier_state {
    bool     frozen;             /* True while baseline updates are paused   */
    uint32_t freeze_counter;     /* Windows remaining in freeze period        */
};

// ============================================================================
// PER-WINDOW DETECTION RESULT
// ============================================================================

struct detection_result {
    detection_state_t state;

    /* Tier-0 metrics — always computed */
    double tier0_raw_dist;           /* Unnormalised Manhattan distance        */
    double tier0_score;              /* Sigmoid-normalised [0, 1]              */

    /* Tier-1 metrics — computed only when Tier-0 triggers */
    bool   tier1_evaluated;
    double tier1_tcp_raw_dist;
    double tier1_tcp_score;
    double tier1_udp_raw_dist;
    double tier1_udp_score;
    double tier1_icmp_raw_dist;
    double tier1_icmp_score;
    double tier1_dist_raw_dist;
    double tier1_dist_score;

    /* Overall Tier-1 score (worst-case across all Tier-1 sub-tiers) */
    double tier1_final_score;

    uint64_t timestamp;          /* TSC cycles */
};

// ============================================================================
// PER-DESTINATION DETECTION ENGINE
// ============================================================================

struct detection_engine {
    detection_state_t state;

    /* Tier baseline operational state (freeze tracking) */
    struct tier_state tier0_state;
    struct tier_state tier1_tcp_state;
    struct tier_state tier1_udp_state;
    struct tier_state tier1_icmp_state;
    struct tier_state tier1_dist_state;

    /* Warm-up counter */
    uint32_t warmup_counter;     /* Windows elapsed since creation           */

    /* Recovery tracking */
    uint32_t recovery_counter;   /* Windows elapsed since recovery began     */
    double   recovery_weight;    /* 0.0 → 1.0 (alpha multiplier during reco) */

    /* Attack history */
    uint32_t attack_count;
    uint64_t last_attack_time;   /* TSC cycles */

    /* Latest result (cached for CSV export) */
    struct detection_result last_result;
};

// ============================================================================
// PUBLIC API
// ============================================================================

/** Initialise engine for a new destination IP entry. */
void detection_engine_init(struct detection_engine *engine, uint64_t timestamp);

/**
 * Extract per-tier feature vectors from the current stats window.
 * Called once per second for every active dst_ip.
 */
void extract_tier0_features   (const struct dst_ip_stats *stats,
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
 * Compute normalised Manhattan distance between a feature vector and its EWMA
 * baseline means.
 *
 * distance_i = |current_i - mean_i| / (mean_i + EWMA_EPSILON)
 * total_distance = Σ distance_i
 * score = sigmoid(total_distance)
 */
double compute_tier0_score   (const struct tier0_ewma      *ewma,
                               const struct tier0_features   *cur);
double compute_tier1_tcp_score(const struct tier1_tcp_ewma  *ewma,
                                const struct tier1_tcp_features *cur);
double compute_tier1_udp_score(const struct tier1_udp_ewma  *ewma,
                                const struct tier1_udp_features *cur);
double compute_tier1_icmp_score(const struct tier1_icmp_ewma *ewma,
                                 const struct tier1_icmp_features *cur);
double compute_tier1_dist_score(const struct tier1_dist_ewma *ewma,
                                 const struct tier1_dist_features *cur);

/** Sigmoid: maps [0, ∞) → [0, 1] using SIGMOID_K and SIGMOID_D0. */
double sigmoid_score(double distance);

/**
 * Main entry point — call once per second per dst_ip after updating counters.
 * Reads EWMA means from stats->ewma_t* structs; updates them if not frozen;
 * returns a detection_result.
 */
struct detection_result detection_engine_process(
    struct detection_engine *engine,
    struct dst_ip_stats     *stats,   /* non-const: updates EWMA means       */
    uint64_t timestamp);

/** Human-readable state label. */
const char *detection_state_str(detection_state_t state);

#endif /* __L2FWD_DETECTION_ENGINE_H__ */