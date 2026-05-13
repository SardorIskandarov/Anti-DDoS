#ifndef __L2FWD_DETECTION_ENGINE_H__
#define __L2FWD_DETECTION_ENGINE_H__
#include <rte_ip.h>
#include <stdint.h>
#include <stdbool.h>
#include "l2fwd_ddos_collector.h"

/* ====================== DEBUG OUTPUT CONFIG ====================== */
/**
 * DEBUG ONLY: Show lightweight Tier-0 risk output
 * ONLY for this exact IP. Change the value when you switch test IPs.
 */
#define DEBUG_IP RTE_IPV4(10, 10, 10, 1)

/* ================================================================ */

// ============================================================================
// DETECTION ENGINE CONFIGURATION
// ============================================================================

/**
 * Warm-up: Learn baselines silently before making decisions.
 */
#define DETECTION_WARMUP_WINDOWS 400

/**
 * CHANGE 1: Z-score threshold for burst features (burst_pps, burst_bps, burst_fps)
 * 
 * Burst features use EWMA + Z-score instead of CUSUM:
 *   z = (x - ewma_mean) / (std + epsilon)
 *   risk = clamp(z / BURST_Z_THRESHOLD, 0, 1)
 */
#define BURST_Z_THRESHOLD 8.5

/* Window size below which an ACK is considered "small"
 * (state-exhaustion signature). Hardcoded at 1024 bytes for v2;
 * could be made per-profile in a future change. */
#define SMALL_WINDOW_THRESHOLD 1024

/* === Tier-1.5 L3 threshold constants (v3.0) ===
 *
 * Two features (ip_frag_ratio, other_proto_ratio) have near-zero
 * organic baselines on most hosts, so EWMA-based deviation
 * detection produces nonsense (huge norm_dist on first non-zero
 * arrival). Instead, these use soft thresholds:
 *
 *   signal = clamp01((value - NOISE_FLOOR) / (SATURATION - NOISE_FLOOR))
 *
 * value <= NOISE_FLOOR → signal = 0 (inert)
 * value >= SATURATION  → signal = 1 (fully fired)
 * linear interpolation between
 */
#define L3_FRAG_NOISE_FLOOR      0.05  /* < 5% fragments = ignore */
#define L3_FRAG_SATURATION       0.20  /* > 20% fragments = fully fired */
#define L3_OTHER_PROTO_NOISE_FLOOR  0.02  /* < 2% other proto = ignore */
#define L3_OTHER_PROTO_SATURATION   0.10  /* > 10% = fully fired */

/**
 * CHANGE 2: Per-feature CUSUM parameters (PPS, BPS, FPS only)
 *
 * Formula:
 *   S_t = max(0, S_{t-1} + (x_t - ewma_mean - k * ewma_std))
 *   Alarm when S_t > H (H = h * ewma_std)
 */
#define CUSUM_K_PPS  0.10
#define CUSUM_H_PPS  6.5

#define CUSUM_K_BPS  0.10
#define CUSUM_H_BPS  6.5

#define CUSUM_K_FPS  0.85
#define CUSUM_H_FPS  6.0

#define VARIANCE_CEILING_FACTOR 2.0

/**
 * CHANGE 3: Tier-0 continuous risk scoring weights
 *
 * global_risk = sum(w_i * risk_i)
 * 
 * Trigger when: global_risk >= T0_RISK_THRESHOLD
 */
#define T0_W_PPS         3.5
#define T0_W_BPS         2
#define T0_W_FPS         1.2
#define T0_W_BURST_PPS   1.5
#define T0_W_BURST_BPS   1
#define T0_W_BURST_FPS   0.5



#define T0_SUSPICIOUS_RISK_THRESHOLD 4.5
#define T0_RISK_THRESHOLD 6.5

/**
 * ABSOLUTE VOLUMETRIC OVERRIDE THRESHOLDS (PRODUCTION SAFETY NET)
 */

#define ABSOLUTE_PPS_THRESHOLD  30000.0
#define ABSOLUTE_BPS_THRESHOLD  310000000.0
#define ABSOLUTE_FPS_THRESHOLD  300.0


#define CONSECUTIVE_ATTACK_WINDOWS 2

/** Tier-1 sigmoid parameters (unchanged) */
#define SIGMOID_K   1.0
#define SIGMOID_D0  1.1

/** Tier-1 decision thresholds */
#define THRESHOLD_NORMAL     0.42
#define THRESHOLD_SUSPICIOUS 0.62

/**
 * IMPROVEMENT 3: Tier-1 weighted fusion weights
 * Replaces "worst wins" with weighted average for balanced decision making
 */
#define W_TCP   0.10
#define W_UDP   0.60
#define W_DIST  0.25
#define W_ICMP  0.05

/**
 * Protocol-presence gating thresholds for Tier-1 fusion.
 *
 * A protocol category contributes to Tier-1 fusion only if its share
 * of the current-window packet mix meets the threshold below. This
 * prevents a low-volume background protocol (e.g. stray TCP during a
 * UDP flood) from driving a large category score that would otherwise
 * distort the weighted fusion and attack typing.
 *
 * DIST has no protocol family and is always active.
 */
#define MIN_TCP_RATIO_FOR_TCP_SCORING   0.05
#define MIN_UDP_RATIO_FOR_UDP_SCORING   0.20
#define MIN_ICMP_RATIO_FOR_ICMP_SCORING 0.02

/**
 * EARLY FREEZE: Freeze as soon as Tier-0 risk exceeds threshold.
 */
#define BASELINE_FREEZE_WINDOWS 12

/**
 * THAW COOLDOWN: Number of consecutive NORMAL windows required before
 * unfreezing baselines after an attack ends.
 */
#define THAW_COOLDOWN_WINDOWS 15

// ============================================================================
// DETECTION STATES
// ============================================================================

typedef enum {
    DETECTION_STATE_WARMUP,      /* Learning baselines */
    DETECTION_STATE_NORMAL,      /* All clear */
    DETECTION_STATE_SUSPICIOUS,  /* Tier-1 says suspicious */
    DETECTION_STATE_ATTACK,      /* Tier-1 confirmed attack */
} detection_state_t;

typedef enum {
    TIER0_STATE_NORMAL,
    TIER0_STATE_SUSPICIOUS,
    TIER0_STATE_ATTACK,
} tier0_detection_state_t;

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
    ATTACK_TYPE_UNKNOWN,
    ATTACK_TYPE_MIXED
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
    /* V2 features (Tier-1 TCP behavioral) */
    double empty_ack_ratio;
    double zero_window_ratio;
    double small_window_ratio;
    double new_flow_ratio;
    double syn_fin_ratio;
    double syn_to_synack_ratio;
    double tcp_pkt_size_cov;
    double tcp_mean_pkt_size;
};
#define TIER1_TCP_N 15  /* was 7 */

struct tier1_udp_features {
    double udp_bps_ratio;
    double udp_pps_ratio;
    double udp_flow_ratio;
    /* V2 features (Tier-1 UDP behavioral) */
    double udp_pkt_size_cov;
    double udp_mean_pkt_size;
};
#define TIER1_UDP_N 5  /* was 3 */

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

/* ============================================================
 * Tier-1.5 L3 features (v3.0).
 *
 * This channel runs in parallel to Tier-1 TCP/UDP/ICMP/DIST.
 * Its score `tier1_l3_score` is OR-combined with
 * `tier1_final_score` in the final decision logic via max().
 *
 * v3.0 ships 3 features. v3.1 will append 4 more (src_port_top1,
 * src_24_top1, src_24_entropy) — do NOT add those fields yet.
 * ============================================================ */
struct tier1_l3_features {
    /* V3.0 */
    double ttl_stddev;
    double ip_frag_ratio;
    double other_proto_ratio;
    /* V3.1 */
    double src_port_top1_share;
    double src_24_top1_share;
    double src_24_entropy;
};

#define TIER1_L3_N 7   /* was 3 (v3.0); now 7 with v3.1 */

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
    tier0_detection_state_t tier0_state;

    /* CHANGE 3: Tier-0 continuous risk scores per feature */
    double tier0_risk_pps;
    double tier0_risk_bps;
    double tier0_risk_fps;
    double tier0_risk_burst_pps;
    double tier0_risk_burst_bps;
    double tier0_risk_burst_fps;
    double tier0_global_risk;

    /* Tier-0 CUSUM metrics (for monitoring) */
    double tier0_cusum_pps;
    double tier0_cusum_bps;
    double tier0_cusum_fps;
    double tier0_cusum_burst_pps;
    double tier0_cusum_burst_bps;
    double tier0_cusum_burst_fps;

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
    double tier1_l3_score;   /* V3.0: parallel L3 sub-channel score */

    attack_type_t attack_type;

    uint64_t timestamp;
};

// ============================================================================
// DETECTION ENGINE
// ============================================================================

struct detection_engine {
    detection_state_t state;

    /* Layer-2 profile driving all Tier-0 / Tier-1 tunables for this IP.
     * Pointed at l2_profile_default by default; a resolver may later
     * assign a per-IP profile at engine init time. */
    const struct l2_profile *profile;

    /* Tier baseline freeze tracking */
    struct tier_state tier0_state;
    struct tier_state tier1_tcp_state;
    struct tier_state tier1_udp_state;
    struct tier_state tier1_icmp_state;
    struct tier_state tier1_dist_state;

    /* CUSUM/Z-score accumulators (Tier-0 only) */
    struct cusum_state cusum[TIER0_N];
    double tier0_initial_std[TIER0_N];

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

void detection_engine_init(struct detection_engine *engine, uint64_t timestamp,
                           const struct l2_profile *profile);

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
 * Populates: result->tier0_risk_* and result->tier0_global_risk
 */
void cusum_update_tier0(struct detection_engine *engine,
                        const struct dst_ip_stats *stats,
                        const struct tier0_features *cur,
                        struct detection_result *result,
                        bool frozen);

double compute_tier1_tcp_score (const struct tier1_tcp_ewma  *ewma,
                                 const struct tier1_tcp_features *cur,
                                 const struct l2_profile *profile);
double compute_tier1_udp_score (const struct tier1_udp_ewma  *ewma,
                                 const struct tier1_udp_features *cur,
                                 const struct l2_profile *profile);
double compute_tier1_icmp_score(const struct tier1_icmp_ewma *ewma,
                                 const struct tier1_icmp_features *cur,
                                 const struct l2_profile *profile);
double compute_tier1_dist_score(const struct tier1_dist_ewma *ewma,
                                 const struct tier1_dist_features *cur,
                                 const struct l2_profile *profile);

/* V3.0: L3 sub-channel feature extraction + score.
 * Externally visible so the CSV emitter in l2fwd_ddos_collector.c can
 * snapshot/recompute the L3 score for every 1-second window. */
void   extract_tier1_l3_features(const struct dst_ip_stats *stats,
                                  struct tier1_l3_features *out);
double compute_tier1_l3_score   (const struct l2_profile *profile,
                                  const struct tier1_l3_features *cur,
                                  const struct tier1_l3_ewma *ewma);

double sigmoid_score(double distance, double k, double d0);

struct detection_result detection_engine_process(
    struct detection_engine *engine,
    struct dst_ip_stats     *stats,
    uint64_t timestamp,
    uint32_t dst_ip);   /* dst_ip in host byte order */   

const char *attack_type_str(attack_type_t type);
const char *detection_state_str(detection_state_t state);
const char *tier0_detection_state_str(tier0_detection_state_t state);

#endif /* __L2FWD_DETECTION_ENGINE_H__ */
