#include "l2fwd_detection_engine.h"
#include <math.h>
#include <string.h>
#include <stdio.h>
#include <rte_cycles.h>
#include <rte_ip.h>
// ============================================================================
// SIGMOID  (used only by Tier 1 — unchanged)
// ============================================================================

double sigmoid_score(double distance) {
    return 1.0 / (1.0 + exp(-SIGMOID_K * (distance - SIGMOID_D0)));
}

// ============================================================================
// INITIALIZATION
// ============================================================================

void detection_engine_init(struct detection_engine *engine, uint64_t timestamp) {
    memset(engine, 0, sizeof(struct detection_engine));
    engine->state            = DETECTION_STATE_WARMUP;
    engine->last_attack_time = timestamp;

    engine->consecutive_attack_counter = 0;
    engine->thaw_cooldown_counter = 0;

    for (int i = 0; i < TIER0_N; i++) {
        engine->cusum[i].S         = 0.0;
        engine->cusum[i].variance  = 0.0;
        engine->cusum[i].alpha_std = EWMA_ALPHA_TIER0;
    }
}

// ============================================================================
// FEATURE EXTRACTION  (unchanged)
// ============================================================================

void extract_tier0_features(const struct dst_ip_stats *stats,
                              struct tier0_features *out,
                              double time_sec) {
    out->pps = (double)stats->total_pkts / time_sec;
    out->bps = (double)stats->total_bytes * 8.0 / time_sec;
    out->fps = (double)hll_count(&stats->unique_flows) / time_sec;

    double avg_pps = burst_window_avg(&stats->bw_pps);
    double avg_bps = burst_window_avg(&stats->bw_bps);
    double avg_fps = burst_window_avg(&stats->bw_fps);

    out->burst_pps = (avg_pps > 0.0) ? out->pps / avg_pps : 1.0;
    out->burst_bps = (avg_bps > 0.0) ? out->bps / avg_bps : 1.0;
    out->burst_fps = (avg_fps > 0.0) ? out->fps / avg_fps : 1.0;
}

void extract_tier1_tcp_features(const struct dst_ip_stats *stats,
                                  struct tier1_tcp_features *out,
                                  double time_sec) {
    (void)time_sec;
    double tcp_safe       = (stats->tcp_pkts   > 0) ? (double)stats->tcp_pkts   : 1.0;
    double tot_safe       = (stats->total_pkts > 0) ? (double)stats->total_pkts : 1.0;
    double tot_bytes_safe = (stats->total_bytes> 0) ? (double)stats->total_bytes: 1.0;

    out->syn_ratio      = (double)stats->syn_pkts      / tcp_safe;
    out->synack_ratio   = (double)stats->syn_ack_pkts  / tcp_safe;
    out->finack_ratio   = (double)stats->fin_ack_pkts  / tcp_safe;
    out->rst_ratio      = (double)stats->rst_pkts      / tcp_safe;
    out->ack_data_ratio = (double)stats->ack_data_pkts / tcp_safe;
    out->tcp_pps_ratio  = (double)stats->tcp_pkts      / tot_safe;
    out->tcp_bps_ratio  = (double)stats->tcp_bytes     / tot_bytes_safe;
}

void extract_tier1_udp_features(const struct dst_ip_stats *stats,
                                  struct tier1_udp_features *out,
                                  double time_sec) {
    (void)time_sec;
    double tot_safe       = (stats->total_pkts  > 0) ? (double)stats->total_pkts  : 1.0;
    double tot_bytes_safe = (stats->total_bytes > 0) ? (double)stats->total_bytes : 1.0;
    double udp_pps_safe   = (stats->udp_pkts    > 0) ? (double)stats->udp_pkts    : 1.0;

    out->udp_bps_ratio  = (double)stats->udp_bytes / tot_bytes_safe;
    out->udp_pps_ratio  = (double)stats->udp_pkts  / tot_safe;
    out->udp_flow_ratio = (double)hll_count(&stats->udp_flows) / udp_pps_safe;
}

void extract_tier1_icmp_features(const struct dst_ip_stats *stats,
                                   struct tier1_icmp_features *out,
                                   double time_sec) {
    (void)time_sec;
    double icmp_safe = (stats->icmp_pkts  > 0) ? (double)stats->icmp_pkts  : 1.0;
    double tot_safe  = (stats->total_pkts > 0) ? (double)stats->total_pkts : 1.0;

    out->icmp_echo_ratio = (double)stats->icmp_echo_pkts / icmp_safe;
    out->icmp_pps_ratio  = (double)stats->icmp_pkts      / tot_safe;
}

void extract_tier1_dist_features(const struct dst_ip_stats *stats,
                                   struct tier1_dist_features *out,
                                   double time_sec) {
    double pps_safe = ((double)stats->total_pkts / time_sec > 0)
                        ? (double)stats->total_pkts / time_sec
                        : 1.0;

    out->src_ip_ratio   = (double)hll_count(&stats->unique_src_ips)   / pps_safe;
    out->dst_port_ratio = (double)hll_count(&stats->unique_dst_ports) / pps_safe;
}

// ============================================================================
// UTILITY: Clamp function
// ============================================================================

static inline double clamp(double value, double min_val, double max_val) {
    if (value < min_val) return min_val;
    if (value > max_val) return max_val;
    return value;
}

static void print_risk_bar(const char *name, double risk) {
    static const char filled_block[] = "\xE2\x96\x88";
    static const char empty_block[] = "\xE2\x96\x91";
    const size_t block_len = sizeof(filled_block) - 1;
    char bar[(10 * (sizeof(filled_block) - 1)) + 1];
    double clamped_risk = clamp(risk, 0.0, 1.0);
    int filled_blocks = (clamped_risk > 0.0)
                      ? (int)ceil(clamped_risk * 10.0 - 1e-9)
                      : 0;
    char *cursor = bar;

    if (filled_blocks > 10) {
        filled_blocks = 10;
    }

    for (int i = 0; i < 10; i++) {
        const char *block = (i < filled_blocks) ? filled_block : empty_block;
        memcpy(cursor, block, block_len);
        cursor += block_len;
    }
    *cursor = '\0';

    printf("%-15s %s %.2f\n", name, bar, clamped_risk);
}

// ============================================================================
// TIER 0 — CUSUM + BURST Z-SCORE DETECTION
// ============================================================================

#define MIN_STD_FLOOR 1.0

static bool cusum_update_one(struct cusum_state *cs,
                              const struct ewma_state *ewma,
                              double initial_std,
                              double x,
                              bool in_warmup,
                              bool frozen,
                              double k_factor,
                              double h_factor,
                              double *out_S,
                              double *out_risk) {
    
    bool is_burst_feature = (k_factor == 0.0 && h_factor == 0.0);
    double residual = x - ewma->mean;
    
    if (in_warmup) {
        cs->variance += cs->alpha_std * (residual * residual - cs->variance);
        *out_S = 0.0;
        *out_risk = 0.0;
        return false;
    }

    double current_std = sqrt(cs->variance);

    if (current_std < MIN_STD_FLOOR)
        current_std = MIN_STD_FLOOR;

    if (initial_std > 0.0) {
        double variance_ceiling = VARIANCE_CEILING_FACTOR * initial_std;
        if (current_std > variance_ceiling) {
            current_std = variance_ceiling;
        }
    }

    bool extreme = (residual > (5.0 * current_std));
    if (!extreme) {
        cs->variance += cs->alpha_std * (residual * residual - cs->variance);
    }

    if (is_burst_feature) {
        double z = residual / current_std; 
        *out_S = 0.0;
        *out_risk = (z > 0) ? clamp(z / BURST_Z_THRESHOLD, 0.0, 1.0) : 0.0;
        return (z > BURST_Z_THRESHOLD);
    } else {
        double k_abs = k_factor * current_std;
        double H_abs = h_factor * current_std;

        double S_new = cs->S + (residual - k_abs);
        if (S_new < 0.0) S_new = 0.0;

        if (frozen && S_new > cs->S) {
            S_new = cs->S; 
        }

        cs->S = S_new;
        *out_S = S_new;
        *out_risk = clamp(S_new / H_abs, 0.0, 1.0);

        return (S_new > H_abs);
    }
}

void cusum_update_tier0(struct detection_engine *engine,
                        const struct dst_ip_stats *stats,
                        const struct tier0_features *cur,
                        struct detection_result *result,
                        bool frozen) {
    bool in_warmup = (engine->state == DETECTION_STATE_WARMUP);
    cusum_update_one(&engine->cusum[0], &stats->ewma_t0.pps,
                     engine->tier0_initial_std[0],
                     cur->pps, in_warmup, frozen,
                     CUSUM_K_PPS, CUSUM_H_PPS,
                     &result->tier0_cusum_pps,
                     &result->tier0_risk_pps);

    cusum_update_one(&engine->cusum[1], &stats->ewma_t0.bps,
                     engine->tier0_initial_std[1],
                     cur->bps, in_warmup, frozen,
                     CUSUM_K_BPS, CUSUM_H_BPS,
                     &result->tier0_cusum_bps,
                     &result->tier0_risk_bps);

    cusum_update_one(&engine->cusum[2], &stats->ewma_t0.fps,
                     engine->tier0_initial_std[2],
                     cur->fps, in_warmup, frozen,
                     CUSUM_K_FPS, CUSUM_H_FPS,
                     &result->tier0_cusum_fps,
                     &result->tier0_risk_fps);

    cusum_update_one(&engine->cusum[3], &stats->ewma_t0.burst_pps,
                     engine->tier0_initial_std[3],
                     cur->burst_pps, in_warmup, frozen,
                     0.0, 0.0,
                     &result->tier0_cusum_burst_pps,
                     &result->tier0_risk_burst_pps);

    cusum_update_one(&engine->cusum[4], &stats->ewma_t0.burst_bps,
                     engine->tier0_initial_std[4],
                     cur->burst_bps, in_warmup, frozen,
                     0.0, 0.0,
                     &result->tier0_cusum_burst_bps,
                     &result->tier0_risk_burst_bps);

    cusum_update_one(&engine->cusum[5], &stats->ewma_t0.burst_fps,
                     engine->tier0_initial_std[5],
                     cur->burst_fps, in_warmup, frozen,
                     0.0, 0.0,
                     &result->tier0_cusum_burst_fps,
                     &result->tier0_risk_burst_fps);

    result->tier0_global_risk = 
        T0_W_PPS       * result->tier0_risk_pps +
        T0_W_BPS       * result->tier0_risk_bps +
        T0_W_FPS       * result->tier0_risk_fps +
        T0_W_BURST_PPS * result->tier0_risk_burst_pps +
        T0_W_BURST_BPS * result->tier0_risk_burst_bps +
        T0_W_BURST_FPS * result->tier0_risk_burst_fps;
}

// ============================================================================
// TIER 1 — DISTANCE COMPUTATION (IMPROVEMENT 2: One-sided detection)
// ============================================================================

static inline double norm_dist(const struct ewma_state *s, double current) {
    if (s->n < EWMA_WARMUP_PERIODS) return 0.0;
    
    // IMPROVEMENT 2: One-sided detection - only penalize upward deviations
    double diff = current - s->mean;
    if (diff <= 0.0) return 0.0;  // Ignore drops (downward deviations)
    
    return diff / (s->mean + EWMA_EPSILON);
}

double compute_tier1_tcp_score(const struct tier1_tcp_ewma *ewma,
                                const struct tier1_tcp_features *cur) {
    double d = 0.0;
    d += norm_dist(&ewma->syn_ratio,      cur->syn_ratio);
    d += norm_dist(&ewma->synack_ratio,   cur->synack_ratio);
    d += norm_dist(&ewma->finack_ratio,   cur->finack_ratio);
    d += norm_dist(&ewma->rst_ratio,      cur->rst_ratio);
    d += norm_dist(&ewma->ack_data_ratio, cur->ack_data_ratio);
    d += norm_dist(&ewma->tcp_pps_ratio,  cur->tcp_pps_ratio);
    d += norm_dist(&ewma->tcp_bps_ratio,  cur->tcp_bps_ratio);
    return sigmoid_score(d);
}

double compute_tier1_udp_score(const struct tier1_udp_ewma *ewma,
                                const struct tier1_udp_features *cur) {
    double d = 0.0;
    // PRODUCTION BOOST: UDP volume gets heavier weight (flow_ratio less critical)
    d += norm_dist(&ewma->udp_bps_ratio,  cur->udp_bps_ratio) * 1.6;
    d += norm_dist(&ewma->udp_pps_ratio,  cur->udp_pps_ratio) * 1.5;
    d += norm_dist(&ewma->udp_flow_ratio, cur->udp_flow_ratio) * 0.6;
    return sigmoid_score(d);
}

double compute_tier1_icmp_score(const struct tier1_icmp_ewma *ewma,
                                 const struct tier1_icmp_features *cur) {
    double d = 0.0;
    d += norm_dist(&ewma->icmp_echo_ratio, cur->icmp_echo_ratio);
    d += norm_dist(&ewma->icmp_pps_ratio,  cur->icmp_pps_ratio);
    return sigmoid_score(d);
}

double compute_tier1_dist_score(const struct tier1_dist_ewma *ewma,
                                 const struct tier1_dist_features *cur) {
    double d = 0.0;
    d += norm_dist(&ewma->src_ip_ratio,   cur->src_ip_ratio);
    d += norm_dist(&ewma->dst_port_ratio, cur->dst_port_ratio);
    return sigmoid_score(d);
}

// ============================================================================
// EWMA BASELINE UPDATE HELPERS
// ============================================================================

static void update_ewma_if_active(struct ewma_state *s, double value,
                                   const struct tier_state *ts) {
    if (ts->frozen) return;
    ewma_update(s, value);
}

static void update_tier0_ewma(struct tier0_ewma *e,
                               const struct tier0_features *f,
                               const struct tier_state *ts) {
    update_ewma_if_active(&e->pps,       f->pps,       ts);
    update_ewma_if_active(&e->bps,       f->bps,       ts);
    update_ewma_if_active(&e->fps,       f->fps,       ts);
    update_ewma_if_active(&e->burst_pps, f->burst_pps, ts);
    update_ewma_if_active(&e->burst_bps, f->burst_bps, ts);
    update_ewma_if_active(&e->burst_fps, f->burst_fps, ts);
}

static void update_tier1_tcp_ewma(struct tier1_tcp_ewma *e,
                                   const struct tier1_tcp_features *f,
                                   const struct tier_state *ts) {
    update_ewma_if_active(&e->syn_ratio,      f->syn_ratio,      ts);
    update_ewma_if_active(&e->synack_ratio,   f->synack_ratio,   ts);
    update_ewma_if_active(&e->finack_ratio,   f->finack_ratio,   ts);
    update_ewma_if_active(&e->rst_ratio,      f->rst_ratio,      ts);
    update_ewma_if_active(&e->ack_data_ratio, f->ack_data_ratio, ts);
    update_ewma_if_active(&e->tcp_pps_ratio,  f->tcp_pps_ratio,  ts);
    update_ewma_if_active(&e->tcp_bps_ratio,  f->tcp_bps_ratio,  ts);
}

static void update_tier1_udp_ewma(struct tier1_udp_ewma *e,
                                   const struct tier1_udp_features *f,
                                   const struct tier_state *ts) {
    update_ewma_if_active(&e->udp_bps_ratio,  f->udp_bps_ratio,  ts);
    update_ewma_if_active(&e->udp_pps_ratio,  f->udp_pps_ratio,  ts);
    update_ewma_if_active(&e->udp_flow_ratio, f->udp_flow_ratio, ts);
}

static void update_tier1_icmp_ewma(struct tier1_icmp_ewma *e,
                                    const struct tier1_icmp_features *f,
                                    const struct tier_state *ts) {
    update_ewma_if_active(&e->icmp_echo_ratio, f->icmp_echo_ratio, ts);
    update_ewma_if_active(&e->icmp_pps_ratio,  f->icmp_pps_ratio,  ts);
}

static void update_tier1_dist_ewma(struct tier1_dist_ewma *e,
                                    const struct tier1_dist_features *f,
                                    const struct tier_state *ts) {
    update_ewma_if_active(&e->src_ip_ratio,   f->src_ip_ratio,   ts);
    update_ewma_if_active(&e->dst_port_ratio, f->dst_port_ratio, ts);
}

// ============================================================================
// FREEZE / THAW HELPERS
// ============================================================================

static void freeze_tier(struct tier_state *ts) {
    if (!ts->frozen) {
        ts->frozen         = true;
        ts->freeze_counter = BASELINE_FREEZE_WINDOWS;
    }
}

static void tick_freeze(struct tier_state *ts) {
    if (!ts->frozen) return;
    if (ts->freeze_counter > 0) ts->freeze_counter--;
    if (ts->freeze_counter == 0) ts->frozen = false;
}

static void reset_tier0_cusum(struct detection_engine *engine) {
    for (int i = 0; i < TIER0_N; i++) {
        engine->cusum[i].S = 0.0;
    }
}

// ============================================================================
// CLASSIFY TIER 1 SCORE → STATE
// ============================================================================

static detection_state_t classify(double score) {
    if (score < THRESHOLD_NORMAL)     return DETECTION_STATE_NORMAL;
    if (score < THRESHOLD_SUSPICIOUS) return DETECTION_STATE_SUSPICIOUS;
    return DETECTION_STATE_ATTACK;
}

static tier0_detection_state_t classify_tier0_state(double global_risk,
                                                    bool absolute_override,
                                                    bool tier0_triggered) {
    if (absolute_override || tier0_triggered) {
        return TIER0_STATE_ATTACK;
    }
    if (global_risk >= T0_SUSPICIOUS_RISK_THRESHOLD) {
        return TIER0_STATE_SUSPICIOUS;
    }
    return TIER0_STATE_NORMAL;
}

// ============================================================================
// MAIN DETECTION LOGIC
// ============================================================================

struct detection_result detection_engine_process(
    struct detection_engine *engine,
    struct dst_ip_stats     *stats,
    uint64_t timestamp,
    uint32_t dst_ip)
{
    struct detection_result result;
    memset(&result, 0, sizeof(result));
    result.timestamp = timestamp;
    result.state     = engine->state;

    double time_sec = (double)STATS_PERIOD_US / 1000000.0;

    struct tier0_features       t0;
    struct tier1_tcp_features   t1_tcp;
    struct tier1_udp_features   t1_udp;
    struct tier1_icmp_features  t1_icmp;
    struct tier1_dist_features  t1_dist;

    extract_tier0_features     (stats, &t0,     time_sec);
    extract_tier1_tcp_features (stats, &t1_tcp,  time_sec);
    extract_tier1_udp_features (stats, &t1_udp,  time_sec);
    extract_tier1_icmp_features(stats, &t1_icmp, time_sec);
    extract_tier1_dist_features(stats, &t1_dist, time_sec);

    bool absolute_override =
        (t0.pps > ABSOLUTE_PPS_THRESHOLD ||
         t0.bps > ABSOLUTE_BPS_THRESHOLD ||
         t0.fps > ABSOLUTE_FPS_THRESHOLD);

    if (engine->state == DETECTION_STATE_WARMUP) {
        update_tier0_ewma     (&stats->ewma_t0,      &t0,     &engine->tier0_state);
        update_tier1_tcp_ewma (&stats->ewma_t1_tcp,  &t1_tcp,  &engine->tier1_tcp_state);
        update_tier1_udp_ewma (&stats->ewma_t1_udp,  &t1_udp,  &engine->tier1_udp_state);
        update_tier1_icmp_ewma(&stats->ewma_t1_icmp, &t1_icmp, &engine->tier1_icmp_state);
        update_tier1_dist_ewma(&stats->ewma_t1_dist, &t1_dist, &engine->tier1_dist_state);

        cusum_update_tier0(engine, stats, &t0, &result, false);
        result.tier0_state = classify_tier0_state(result.tier0_global_risk,
                                                  absolute_override,
                                                  false);

        engine->warmup_counter++;
        if (engine->warmup_counter >= DETECTION_WARMUP_WINDOWS) {
            for (int i = 0; i < TIER0_N; i++) {
                engine->tier0_initial_std[i] = sqrt(engine->cusum[i].variance);
            }
            engine->state = DETECTION_STATE_NORMAL;
        }

        result.state = DETECTION_STATE_WARMUP;
        engine->last_result = result;
        return result;
    }

    tick_freeze(&engine->tier0_state);
    tick_freeze(&engine->tier1_tcp_state);
    tick_freeze(&engine->tier1_udp_state);
    tick_freeze(&engine->tier1_icmp_state);
    tick_freeze(&engine->tier1_dist_state);

    bool tier0_frozen = engine->tier0_state.frozen;
    cusum_update_tier0(engine, stats, &t0, &result, tier0_frozen);

    /* ==================================================================
     * CLEANED-UP: ABSOLUTE OVERRIDE + PERSISTENCE IN ONE BLOCK
     * ================================================================== */
    bool tier0_triggered;

    if (absolute_override) {
        // Force trigger + set counter high so thaw requires full cooldown
        engine->consecutive_attack_counter = CONSECUTIVE_ATTACK_WINDOWS;
        result.tier0_global_risk = 9.9;
        tier0_triggered = true;
    } else {
        // Normal risk-based persistence (only runs if no absolute override)
        if (result.tier0_global_risk >= T0_RISK_THRESHOLD) {
            engine->consecutive_attack_counter++;
        } else {
            engine->consecutive_attack_counter = 0;
        }

        tier0_triggered = (engine->consecutive_attack_counter >= CONSECUTIVE_ATTACK_WINDOWS);
    }

    result.tier0_state = classify_tier0_state(result.tier0_global_risk,
                                              absolute_override,
                                              tier0_triggered);

    if (dst_ip == DEBUG_IP) {
        printf("[Detection] Tier-0=%s global=%.2f trigger=%s counter=%u/%u override=%s\n",
               tier0_detection_state_str(result.tier0_state),
               result.tier0_global_risk,
               tier0_triggered ? "yes" : "no",
               engine->consecutive_attack_counter,
               CONSECUTIVE_ATTACK_WINDOWS,
               absolute_override ? "yes" : "no");
        print_risk_bar("PPS risk",   result.tier0_risk_pps);
        print_risk_bar("BPS risk",   result.tier0_risk_bps);
        print_risk_bar("FPS risk",   result.tier0_risk_fps);
        print_risk_bar("Burst PPS",  result.tier0_risk_burst_pps);
        print_risk_bar("Burst BPS",  result.tier0_risk_burst_bps);
        print_risk_bar("Burst FPS",  result.tier0_risk_burst_fps);
    }

    if (tier0_triggered) {
        freeze_tier(&engine->tier0_state);
        freeze_tier(&engine->tier1_tcp_state);
        freeze_tier(&engine->tier1_udp_state);
        freeze_tier(&engine->tier1_icmp_state);
        freeze_tier(&engine->tier1_dist_state);
        
        engine->thaw_cooldown_counter = 0;
    }

    detection_state_t final_state;

    if (!tier0_triggered) {
        final_state = DETECTION_STATE_NORMAL;
    } else {
        result.tier1_evaluated = true;

        result.tier1_tcp_score  = compute_tier1_tcp_score (&stats->ewma_t1_tcp,  &t1_tcp);
        result.tier1_udp_score  = compute_tier1_udp_score (&stats->ewma_t1_udp,  &t1_udp);
        result.tier1_icmp_score = compute_tier1_icmp_score(&stats->ewma_t1_icmp, &t1_icmp);
        result.tier1_dist_score = compute_tier1_dist_score(&stats->ewma_t1_dist, &t1_dist);

        // IMPROVEMENT 3: Hybrid fusion (weighted avg + dominant protocol boost)
        double weighted_score = W_TCP  * result.tier1_tcp_score +
                                W_UDP  * result.tier1_udp_score +
                                W_ICMP * result.tier1_icmp_score +
                                W_DIST * result.tier1_dist_score;

        // Find highest individual score (for single-protocol attacks like UDP/SYN floods)
        double max_individual = result.tier1_tcp_score;
        if (result.tier1_udp_score  > max_individual) max_individual = result.tier1_udp_score;
        if (result.tier1_icmp_score > max_individual) max_individual = result.tier1_icmp_score;
        if (result.tier1_dist_score > max_individual) max_individual = result.tier1_dist_score;

        // Use whichever is higher: weighted fusion (balanced attacks) or max individual (single-protocol)
        result.tier1_final_score = (weighted_score > max_individual) ? weighted_score : max_individual;

        // Classify based on weighted final score
        final_state = classify(result.tier1_final_score);

        // Improved attack classification - more flexible for test tools and real attacks
               result.attack_type = ATTACK_TYPE_NONE;

        if (final_state == DETECTION_STATE_ATTACK || final_state == DETECTION_STATE_SUSPICIOUS) {
            double total_pps_approx = stats->tcp_pkts + stats->udp_pkts + stats->icmp_pkts;
            if (total_pps_approx == 0) total_pps_approx = 1.0;

            double tcp_pps_frac = (double)stats->tcp_pkts / total_pps_approx;
            double udp_pps_frac = (double)stats->udp_pkts / total_pps_approx;
            double icmp_pps_frac = (double)stats->icmp_pkts / total_pps_approx;

            // Use the new absolute_override for all volumetric rules
            bool extreme_volume = absolute_override;

            bool tcp_volumetric =
                ((tcp_pps_frac > 0.50 && result.tier1_tcp_score > 0.65) ||
                 (tcp_pps_frac > 0.70 && extreme_volume));

            bool match_udp_flood =
                ((udp_pps_frac > 0.85 && result.tier1_udp_score > 0.42) ||
                 (udp_pps_frac > 0.95 && extreme_volume));
            bool match_syn_flood = tcp_volumetric && (t1_tcp.syn_ratio > 0.65);
            bool match_ack_flood = tcp_volumetric && (t1_tcp.ack_data_ratio > 0.60);
            bool match_rst_fin_flood =
                (tcp_pps_frac > 0.40 &&
                 (t1_tcp.rst_ratio > 0.50 || t1_tcp.finack_ratio > 0.50) &&
                 result.tier1_tcp_score > 0.55);
            bool match_icmp_flood =
                ((icmp_pps_frac > 0.80 && result.tier1_icmp_score > 0.65) ||
                 (icmp_pps_frac > 0.90 && extreme_volume));
            bool match_distributed =
                (result.tier1_dist_score > 0.70 && t1_dist.src_ip_ratio > 1.2);
            bool match_amplification =
                (result.tier1_udp_score > 0.75 && t1_udp.udp_bps_ratio > 0.85);

            /* Distinguish a single matching rule from a hybrid/multi-vector match. */
            int match_count = 0;
            if (match_udp_flood)     match_count++;
            if (match_syn_flood)     match_count++;
            if (match_ack_flood)     match_count++;
            if (match_rst_fin_flood) match_count++;
            if (match_icmp_flood)    match_count++;
            if (match_distributed)   match_count++;
            if (match_amplification) match_count++;

            if (match_count == 0) {
                result.attack_type = ATTACK_TYPE_UNKNOWN;
            } else if (match_count > 1) {
                result.attack_type = ATTACK_TYPE_MIXED;
            } else if (match_udp_flood) {
                result.attack_type = ATTACK_TYPE_UDP_FLOOD;
            } else if (match_syn_flood) {
                result.attack_type = ATTACK_TYPE_SYN_FLOOD;
            } else if (match_ack_flood) {
                result.attack_type = ATTACK_TYPE_ACK_FLOOD;
            } else if (match_rst_fin_flood) {
                result.attack_type = ATTACK_TYPE_RST_FIN_FLOOD;
            } else if (match_icmp_flood) {
                result.attack_type = ATTACK_TYPE_ICMP_FLOOD;
            } else if (match_distributed) {
                result.attack_type = ATTACK_TYPE_DISTRIBUTED;
            } else {
                result.attack_type = ATTACK_TYPE_AMPLIFICATION;
            }
        }

        if (final_state == DETECTION_STATE_ATTACK ||
            final_state == DETECTION_STATE_SUSPICIOUS) {
            freeze_tier(&engine->tier0_state);
            freeze_tier(&engine->tier1_tcp_state);
            freeze_tier(&engine->tier1_udp_state);
            freeze_tier(&engine->tier1_icmp_state);
            freeze_tier(&engine->tier1_dist_state);

            if (engine->state != final_state) {
                engine->attack_count++;
                engine->last_attack_time = timestamp;
            }
        } else {
            reset_tier0_cusum(engine);          
            engine->consecutive_attack_counter = 0;
            engine->thaw_cooldown_counter = THAW_COOLDOWN_WINDOWS;
        }
    }

    if (final_state == DETECTION_STATE_NORMAL && result.tier0_global_risk < T0_RISK_THRESHOLD) {
        engine->thaw_cooldown_counter++;

        if (engine->thaw_cooldown_counter >= THAW_COOLDOWN_WINDOWS) {
            reset_tier0_cusum(engine);
            engine->consecutive_attack_counter = 0;

            engine->tier0_state.frozen = false;
            engine->tier0_state.freeze_counter = 0;
            engine->tier1_tcp_state.frozen = false;
            engine->tier1_tcp_state.freeze_counter = 0;
            engine->tier1_udp_state.frozen = false;
            engine->tier1_udp_state.freeze_counter = 0;
            engine->tier1_icmp_state.frozen = false;
            engine->tier1_icmp_state.freeze_counter = 0;
            engine->tier1_dist_state.frozen = false;
            engine->tier1_dist_state.freeze_counter = 0;
        }

        update_tier0_ewma     (&stats->ewma_t0,      &t0,     &engine->tier0_state);
        update_tier1_tcp_ewma (&stats->ewma_t1_tcp,  &t1_tcp,  &engine->tier1_tcp_state);
        update_tier1_udp_ewma (&stats->ewma_t1_udp,  &t1_udp,  &engine->tier1_udp_state);
        update_tier1_icmp_ewma(&stats->ewma_t1_icmp, &t1_icmp, &engine->tier1_icmp_state);
        update_tier1_dist_ewma(&stats->ewma_t1_dist, &t1_dist, &engine->tier1_dist_state);
    }

    if (dst_ip == DEBUG_IP) {
        printf("[Detection] Final=%s tier1=%s attack_type=%s\n",
               detection_state_str(final_state),
               result.tier1_evaluated ? "yes" : "no",
               attack_type_str(result.attack_type));
    }

    result.state = final_state;
    engine->state = final_state;
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
        default:                         return "UNKNOWN";
    }
}

const char *tier0_detection_state_str(tier0_detection_state_t state) {
    switch (state) {
        case TIER0_STATE_NORMAL:     return "NORMAL";
        case TIER0_STATE_SUSPICIOUS: return "SUSPICIOUS";
        case TIER0_STATE_ATTACK:     return "ATTACK";
        default:                     return "UNKNOWN";
    }
}

// ============================================================================
// ATTACK CLASSIFICATION
// ============================================================================

const char *attack_type_str(attack_type_t type) {
    switch (type) {
        case ATTACK_TYPE_NONE:           return "NONE";
        case ATTACK_TYPE_SYN_FLOOD:      return "SYN_FLOOD";
        case ATTACK_TYPE_ACK_FLOOD:      return "ACK_FLOOD";
        case ATTACK_TYPE_RST_FIN_FLOOD:  return "RST_FIN_FLOOD";
        case ATTACK_TYPE_UDP_FLOOD:      return "UDP_FLOOD";
        case ATTACK_TYPE_ICMP_FLOOD:     return "ICMP_FLOOD";
        case ATTACK_TYPE_DISTRIBUTED:    return "DISTRIBUTED";
        case ATTACK_TYPE_AMPLIFICATION:  return "AMPLIFICATION";
        case ATTACK_TYPE_UNKNOWN:        return "UNKNOWN";
        case ATTACK_TYPE_MIXED:          return "MIXED";
        default:                         return "UNDEFINED";
    }
}
