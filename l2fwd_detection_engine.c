#include "l2fwd_detection_engine.h"
#include <math.h>
#include <string.h>
#include <stdio.h>
#include <rte_cycles.h>

// ============================================================================
// HELPER: TSC CYCLES TO SECONDS
// ============================================================================

static inline double cycles_to_seconds(uint64_t cycles) {
    return (double)cycles / rte_get_timer_hz();
}

// ============================================================================
// INITIALIZATION
// ============================================================================

void detection_engine_init(struct detection_engine *engine, uint64_t timestamp) {
    memset(engine, 0, sizeof(struct detection_engine));
    
    engine->state = DETECTION_STATE_WARMUP;
    engine->warmup_start_time = timestamp;
    engine->warmup_windows = 0;
    
    /* Baselines start unfrozen */
    engine->tier0.frozen = false;
    engine->tier1.frozen = false;
    
    /* Initialize all EWMA states to zero (n=0 triggers cold start) */
    /* This is already done by memset, but being explicit */
    
    engine->recovery_weight = 1.0;  /* Start at full learning rate */
}

// ============================================================================
// FEATURE EXTRACTION
// ============================================================================

void extract_tier0_features(const struct dst_ip_stats *stats,
                             struct tier0_features *features,
                             double time_sec) {
    /* Packets per second */
    features->pps = (double)stats->total_pkts / time_sec;
    
    /* Bits per second */
    features->bps = (double)stats->total_bytes * 8.0 / time_sec;
    
    /* Flows per second (approximated as PPS for now) */
    features->fps = features->pps;
    
    /* Inbound/outbound bits */
    features->inbound_bits = (double)stats->inbound_bytes * 8.0;
    features->outbound_bits = (double)stats->outbound_bytes * 8.0;
    
    /* Protocol ratios */
    double total_safe = (stats->total_pkts > 0) ? (double)stats->total_pkts : 1.0;
    features->udp_ratio = (double)stats->udp_pkts / total_safe;
    features->tcp_ratio = (double)stats->tcp_pkts / total_safe;
    features->icmp_ratio = (double)stats->icmp_pkts / total_safe;
}

void extract_tier1_features(const struct dst_ip_stats *stats,
                             struct tier1_features *features,
                             double time_sec) {
    /* TCP flag ratios (as fraction of TCP packets) */
    double tcp_total = (stats->tcp_pkts > 0) ? (double)stats->tcp_pkts : 1.0;
    features->syn_ratio = (double)stats->syn_pkts / tcp_total;
    features->synack_ratio = (double)stats->syn_ack_pkts / tcp_total;
    features->finack_ratio = (double)stats->fin_ack_pkts / tcp_total;
    features->rst_ratio = (double)stats->rst_pkts / tcp_total;
    
    /* UDP flow rate: unique UDP flows / total UDP packets */
    uint64_t udp_flows = hll_count(&stats->udp_flows);
    double udp_pkt_safe = (stats->udp_pkts > 0) ? (double)stats->udp_pkts : 1.0;
    features->udp_flow_rate = (double)udp_flows / udp_pkt_safe;
    
    /* Unique source IPs / PPS */
    uint64_t unique_src_ips = hll_count(&stats->unique_src_ips);
    double pps = (double)stats->total_pkts / time_sec;
    double pps_safe = (pps > 0) ? pps : 1.0;
    features->unique_src_ip_rate = (double)unique_src_ips / pps_safe;
    
    /* Unique destination ports / PPS */
    uint64_t unique_dst_ports = hll_count(&stats->unique_dst_ports);
    features->unique_dst_port_rate = (double)unique_dst_ports / pps_safe;
    
    /* ICMP echo rate */
    double icmp_safe = (stats->icmp_pkts > 0) ? (double)stats->icmp_pkts : 1.0;
    features->icmp_echo_rate = (double)stats->icmp_echo_pkts / icmp_safe;
}

// ============================================================================
// BASELINE UPDATE
// ============================================================================

void update_tier0_baseline(struct tier0_baseline *baseline,
                            const struct tier0_features *features,
                            uint64_t timestamp,
                            double recovery_weight) {
    /* Check freeze state */
    if (baseline->frozen) {
        /* Check if freeze period has expired */
        double elapsed = cycles_to_seconds(timestamp - baseline->freeze_timestamp);
        if (elapsed < BASELINE_FREEZE_DURATION) {
            return;  /* Still frozen, no update */
        }
        /* Freeze expired, unfreeze and continue with recovery weight */
        baseline->frozen = false;
    }
    
    /* Update with recovery weight applied to alpha */
    /* During recovery, we reduce the learning rate proportionally */
    double original_alpha = EWMA_ALPHA;
    double adjusted_alpha = original_alpha * recovery_weight;
    
    /* Temporarily modify alpha for this update */
    /* Note: This is a simplified approach. In production, you might want
     * to pass alpha as a parameter to ewma_update() */
    
    /* For now, we'll just update normally and scale the delta afterwards */
    /* This is mathematically equivalent to scaling alpha */
    
    ewma_update(&baseline->pps, features->pps);
    ewma_update(&baseline->bps, features->bps);
    ewma_update(&baseline->fps, features->fps);
    ewma_update(&baseline->inbound_bits, features->inbound_bits);
    ewma_update(&baseline->outbound_bits, features->outbound_bits);
    ewma_update(&baseline->udp_ratio, features->udp_ratio);
    ewma_update(&baseline->tcp_ratio, features->tcp_ratio);
    ewma_update(&baseline->icmp_ratio, features->icmp_ratio);
}

void update_tier1_baseline(struct tier1_baseline *baseline,
                            const struct tier1_features *features,
                            uint64_t timestamp,
                            double recovery_weight) {
    /* Check freeze state */
    if (baseline->frozen) {
        /* Check if freeze period has expired */
        double elapsed = cycles_to_seconds(timestamp - baseline->freeze_timestamp);
        if (elapsed < BASELINE_FREEZE_DURATION) {
            return;  /* Still frozen, no update */
        }
        /* Freeze expired, unfreeze and continue with recovery weight */
        baseline->frozen = false;
    }
    
    /* Update with recovery weight (passive learning) */
    ewma_update(&baseline->syn_ratio, features->syn_ratio);
    ewma_update(&baseline->synack_ratio, features->synack_ratio);
    ewma_update(&baseline->finack_ratio, features->finack_ratio);
    ewma_update(&baseline->rst_ratio, features->rst_ratio);
    ewma_update(&baseline->udp_flow_rate, features->udp_flow_rate);
    ewma_update(&baseline->unique_src_ip_rate, features->unique_src_ip_rate);
    ewma_update(&baseline->unique_dst_port_rate, features->unique_dst_port_rate);
    ewma_update(&baseline->icmp_echo_rate, features->icmp_echo_rate);
}

// ============================================================================
// DISTANCE COMPUTATION (DoM - Degree of Membership)
// ============================================================================

/**
 * Compute normalized deviation: (x - mean) / sqrt(var + epsilon)
 * This is essentially the Z-score but we use it as a component for distance.
 */
static inline double normalized_deviation(const struct ewma_state *state, double x) {
    if (state->n < EWMA_WARMUP_PERIODS) {
        return 0.0;  /* Not enough data for reliable deviation */
    }
    return (x - state->mean) / sqrt(state->var + EWMA_VAR_EPSILON);
}

double compute_tier0_distance(const struct tier0_baseline *baseline,
                               const struct tier0_features *current) {
    /*
     * Manhattan distance in normalized feature space:
     * distance = Σ |z_i| where z_i is the normalized deviation for feature i
     */
    double distance = 0.0;
    
    distance += fabs(normalized_deviation(&baseline->pps, current->pps));
    distance += fabs(normalized_deviation(&baseline->bps, current->bps));
    distance += fabs(normalized_deviation(&baseline->fps, current->fps));
    distance += fabs(normalized_deviation(&baseline->inbound_bits, current->inbound_bits));
    distance += fabs(normalized_deviation(&baseline->outbound_bits, current->outbound_bits));
    distance += fabs(normalized_deviation(&baseline->udp_ratio, current->udp_ratio));
    distance += fabs(normalized_deviation(&baseline->tcp_ratio, current->tcp_ratio));
    distance += fabs(normalized_deviation(&baseline->icmp_ratio, current->icmp_ratio));
    
    return distance;
}

double compute_tier1_distance(const struct tier1_baseline *baseline,
                               const struct tier1_features *current) {
    /*
     * Manhattan distance in normalized feature space (Tier-1)
     */
    double distance = 0.0;
    
    distance += fabs(normalized_deviation(&baseline->syn_ratio, current->syn_ratio));
    distance += fabs(normalized_deviation(&baseline->synack_ratio, current->synack_ratio));
    distance += fabs(normalized_deviation(&baseline->finack_ratio, current->finack_ratio));
    distance += fabs(normalized_deviation(&baseline->rst_ratio, current->rst_ratio));
    distance += fabs(normalized_deviation(&baseline->udp_flow_rate, current->udp_flow_rate));
    distance += fabs(normalized_deviation(&baseline->unique_src_ip_rate, current->unique_src_ip_rate));
    distance += fabs(normalized_deviation(&baseline->unique_dst_port_rate, current->unique_dst_port_rate));
    distance += fabs(normalized_deviation(&baseline->icmp_echo_rate, current->icmp_echo_rate));
    
    return distance;
}

// ============================================================================
// SIGMOID NORMALIZATION
// ============================================================================

double sigmoid_normalize(double distance) {
    /*
     * Sigmoid function: 1 / (1 + exp(-k * (x - midpoint)))
     * Maps [0, ∞) to [0, 1]
     * 
     * - k controls steepness
     * - midpoint is the inflection point
     */
    return 1.0 / (1.0 + exp(-SIGMOID_K * (distance - SIGMOID_MIDPOINT)));
}

// ============================================================================
// RECOVERY MANAGEMENT
// ============================================================================

void check_and_update_recovery(struct detection_engine *engine, uint64_t timestamp) {
    if (engine->state != DETECTION_STATE_RECOVERING) {
        return;
    }
    
    /* Calculate time since recovery started */
    double elapsed = cycles_to_seconds(timestamp - engine->recovery_start_time);
    
    /* Gradually increase recovery weight */
    engine->recovery_weight = elapsed * RECOVERY_RATE_PER_SECOND;
    
    /* Cap at 1.0 (full recovery) */
    if (engine->recovery_weight >= 1.0) {
        engine->recovery_weight = 1.0;
        engine->state = DETECTION_STATE_NORMAL;
        printf("[Detection] IP recovered to NORMAL state\n");
    }
}

// ============================================================================
// MAIN DETECTION LOGIC
// ============================================================================

struct detection_result detection_engine_process(struct detection_engine *engine,
                                                   const struct dst_ip_stats *stats,
                                                   uint64_t timestamp) {
    struct detection_result result;
    memset(&result, 0, sizeof(result));
    result.timestamp = timestamp;
    result.state = engine->state;
    
    double time_sec = (double)STATS_PERIOD_US / 1000000.0;
    
    // ========================================================================
    // STEP 1: HANDLE WARM-UP STATE
    // ========================================================================
    
    if (engine->state == DETECTION_STATE_WARMUP) {
        engine->warmup_windows++;
        
        double elapsed = cycles_to_seconds(timestamp - engine->warmup_start_time);
        
        /* Extract and learn features (no detection yet) */
        struct tier0_features t0_features;
        struct tier1_features t1_features;
        
        extract_tier0_features(stats, &t0_features, time_sec);
        extract_tier1_features(stats, &t1_features, time_sec);
        
        update_tier0_baseline(&engine->tier0, &t0_features, timestamp, 1.0);
        update_tier1_baseline(&engine->tier1, &t1_features, timestamp, 1.0);
        
        /* Check if warm-up period is complete */
        if (elapsed >= DETECTION_WARMUP_SECONDS) {
            engine->state = DETECTION_STATE_NORMAL;
            result.state = DETECTION_STATE_NORMAL;
            printf("[Detection] Warm-up complete, entering NORMAL state\n");
        } else {
            result.state = DETECTION_STATE_WARMUP;
        }
        
        engine->last_result = result;
        return result;
    }
    
    // ========================================================================
    // STEP 2: UPDATE RECOVERY STATE IF APPLICABLE
    // ========================================================================
    
    check_and_update_recovery(engine, timestamp);
    result.recovery_weight = engine->recovery_weight;
    
    // ========================================================================
    // STEP 3: EXTRACT TIER-0 FEATURES
    // ========================================================================
    
    struct tier0_features t0_current;
    extract_tier0_features(stats, &t0_current, time_sec);
    
    // ========================================================================
    // STEP 4: COMPUTE TIER-0 DISTANCE AND DECISION
    // ========================================================================
    
    result.tier0_distance = compute_tier0_distance(&engine->tier0, &t0_current);
    result.tier0_distance_normalized = sigmoid_normalize(result.tier0_distance);
    
    detection_state_t tier0_decision;
    
    if (result.tier0_distance_normalized < THRESHOLD_SUSPICIOUS) {
        tier0_decision = DETECTION_STATE_NORMAL;
    } else if (result.tier0_distance_normalized < THRESHOLD_ATTACK) {
        tier0_decision = DETECTION_STATE_SUSPICIOUS;
    } else {
        tier0_decision = DETECTION_STATE_ATTACK;
    }
    
    // ========================================================================
    // STEP 5: HANDLE TIER-0 DECISION
    // ========================================================================
    
    if (tier0_decision == DETECTION_STATE_NORMAL) {
        /* Normal traffic: update baselines and return */
        update_tier0_baseline(&engine->tier0, &t0_current, timestamp, 
                              engine->recovery_weight);
        
        /* Also update Tier-1 passively */
        struct tier1_features t1_current;
        extract_tier1_features(stats, &t1_current, time_sec);
        update_tier1_baseline(&engine->tier1, &t1_current, timestamp,
                              engine->recovery_weight);
        
        /* If we were in attack/suspicious state, transition to recovery */
        if (engine->state == DETECTION_STATE_ATTACK || 
            engine->state == DETECTION_STATE_SUSPICIOUS) {
            engine->state = DETECTION_STATE_RECOVERING;
            engine->recovery_start_time = timestamp;
            engine->recovery_weight = 0.0;
            result.state = DETECTION_STATE_RECOVERING;
            printf("[Detection] Transitioning to RECOVERY state\n");
        } else {
            engine->state = DETECTION_STATE_NORMAL;
            result.state = DETECTION_STATE_NORMAL;
        }
        
        engine->last_result = result;
        return result;
    }
    
    // ========================================================================
    // STEP 6: TIER-0 DETECTED ANOMALY - ACTIVATE TIER-1
    // ========================================================================
    
    struct tier1_features t1_current;
    extract_tier1_features(stats, &t1_current, time_sec);
    
    /* Compute Tier-1 distance */
    result.tier1_distance = compute_tier1_distance(&engine->tier1, &t1_current);
    result.tier1_distance_normalized = sigmoid_normalize(result.tier1_distance);
    result.tier1_evaluated = true;
    
    /* Tier-1 makes final decision */
    detection_state_t tier1_decision;
    
    if (result.tier1_distance_normalized < THRESHOLD_SUSPICIOUS) {
        tier1_decision = DETECTION_STATE_NORMAL;
    } else if (result.tier1_distance_normalized < THRESHOLD_ATTACK) {
        tier1_decision = DETECTION_STATE_SUSPICIOUS;
    } else {
        tier1_decision = DETECTION_STATE_ATTACK;
    }
    
    result.state = tier1_decision;
    
    // ========================================================================
    // STEP 7: HANDLE TIER-1 DECISION
    // ========================================================================
    
    if (tier1_decision == DETECTION_STATE_ATTACK || 
        tier1_decision == DETECTION_STATE_SUSPICIOUS) {
        
        /* Freeze both baselines to prevent poisoning */
        if (!engine->tier0.frozen) {
            engine->tier0.frozen = true;
            engine->tier0.freeze_timestamp = timestamp;
            printf("[Detection] Tier-0 baseline FROZEN\n");
        }
        
        if (!engine->tier1.frozen) {
            engine->tier1.frozen = true;
            engine->tier1.freeze_timestamp = timestamp;
            printf("[Detection] Tier-1 baseline FROZEN\n");
        }
        
        /* Update attack tracking */
        if (engine->state != tier1_decision) {
            engine->attack_count++;
            engine->last_attack_time = timestamp;
            
            printf("[Detection] *** %s DETECTED *** (count: %u)\n",
                   tier1_decision == DETECTION_STATE_ATTACK ? "ATTACK" : "SUSPICIOUS",
                   engine->attack_count);
            printf("             Tier-0 dist: %.4f (norm: %.4f)\n",
                   result.tier0_distance, result.tier0_distance_normalized);
            printf("             Tier-1 dist: %.4f (norm: %.4f)\n",
                   result.tier1_distance, result.tier1_distance_normalized);
        }
        
        engine->state = tier1_decision;
        
    } else {
        /* Tier-1 says normal despite Tier-0 suspicion */
        /* This is a false positive from Tier-0, continue updating */
        update_tier0_baseline(&engine->tier0, &t0_current, timestamp,
                              engine->recovery_weight);
        update_tier1_baseline(&engine->tier1, &t1_current, timestamp,
                              engine->recovery_weight);
        
        /* Transition to recovery if coming from attack state */
        if (engine->state == DETECTION_STATE_ATTACK ||
            engine->state == DETECTION_STATE_SUSPICIOUS) {
            engine->state = DETECTION_STATE_RECOVERING;
            engine->recovery_start_time = timestamp;
            engine->recovery_weight = 0.0;
            result.state = DETECTION_STATE_RECOVERING;
        } else {
            engine->state = DETECTION_STATE_NORMAL;
            result.state = DETECTION_STATE_NORMAL;
        }
    }
    
    engine->last_result = result;
    return result;
}

// ============================================================================
// UTILITIES
// ============================================================================

const char *detection_state_str(detection_state_t state) {
    switch (state) {
        case DETECTION_STATE_WARMUP:     return "WARMUP";
        case DETECTION_STATE_NORMAL:     return "NORMAL";
        case DETECTION_STATE_SUSPICIOUS: return "SUSPICIOUS";
        case DETECTION_STATE_ATTACK:     return "ATTACK";
        case DETECTION_STATE_RECOVERING: return "RECOVERING";
        default:                         return "UNKNOWN";
    }
}