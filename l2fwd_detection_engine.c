#include "l2fwd_detection_engine.h"
#include <math.h>
#include <string.h>
#include <stdio.h>
#include <time.h>
#include <rte_cycles.h>

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

// ============================================================================
// TIER 0 — CUSUM + BURST Z-SCORE DETECTION
// ============================================================================

#define MIN_STD_FLOOR 1.0

static bool cusum_update_one(struct cusum_state *cs,
                              const struct ewma_state *ewma,
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
    if (current_std < EWMA_EPSILON) current_std = EWMA_EPSILON;

    if (current_std < MIN_STD_FLOOR)
        current_std = MIN_STD_FLOOR;

    double variance_cap = ewma->mean * 0.5;
    if (current_std > variance_cap && variance_cap > EWMA_EPSILON) {
        current_std = variance_cap;
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

int cusum_update_tier0(struct detection_engine *engine,
                        const struct dst_ip_stats *stats,
                        const struct tier0_features *cur,
                        struct detection_result *result,
                        bool frozen) {
    bool in_warmup = (engine->state == DETECTION_STATE_WARMUP);
    int  alarm_count = 0;
    bool alarm;

    alarm = cusum_update_one(&engine->cusum[0], &stats->ewma_t0.pps,
                              cur->pps, in_warmup, frozen,
                              CUSUM_K_PPS, CUSUM_H_PPS,
                              &result->tier0_cusum_pps,
                              &result->tier0_risk_pps);
    if (alarm) alarm_count++;

    alarm = cusum_update_one(&engine->cusum[1], &stats->ewma_t0.bps,
                              cur->bps, in_warmup, frozen,
                              CUSUM_K_BPS, CUSUM_H_BPS,
                              &result->tier0_cusum_bps,
                              &result->tier0_risk_bps);
    if (alarm) alarm_count++;

    alarm = cusum_update_one(&engine->cusum[2], &stats->ewma_t0.fps,
                              cur->fps, in_warmup, frozen,
                              CUSUM_K_FPS, CUSUM_H_FPS,
                              &result->tier0_cusum_fps,
                              &result->tier0_risk_fps);
    if (alarm) alarm_count++;

    alarm = cusum_update_one(&engine->cusum[3], &stats->ewma_t0.burst_pps,
                              cur->burst_pps, in_warmup, frozen,
                              0.0, 0.0,
                              &result->tier0_cusum_burst_pps,
                              &result->tier0_risk_burst_pps);
    if (alarm) alarm_count++;

    alarm = cusum_update_one(&engine->cusum[4], &stats->ewma_t0.burst_bps,
                              cur->burst_bps, in_warmup, frozen,
                              0.0, 0.0,
                              &result->tier0_cusum_burst_bps,
                              &result->tier0_risk_burst_bps);
    if (alarm) alarm_count++;

    alarm = cusum_update_one(&engine->cusum[5], &stats->ewma_t0.burst_fps,
                              cur->burst_fps, in_warmup, frozen,
                              0.0, 0.0,
                              &result->tier0_cusum_burst_fps,
                              &result->tier0_risk_burst_fps);
    if (alarm) alarm_count++;

    result->tier0_global_risk = 
        T0_W_PPS       * result->tier0_risk_pps +
        T0_W_BPS       * result->tier0_risk_bps +
        T0_W_FPS       * result->tier0_risk_fps +
        T0_W_BURST_PPS * result->tier0_risk_burst_pps +
        T0_W_BURST_BPS * result->tier0_risk_burst_bps +
        T0_W_BURST_FPS * result->tier0_risk_burst_fps;

    result->tier0_attack_count = alarm_count;
    result->tier0_score = (double)alarm_count / (double)TIER0_N;

    return alarm_count;
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

// ============================================================================
// MAIN DETECTION LOGIC WITH COMPREHENSIVE DEBUGGING
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

    if (engine->state == DETECTION_STATE_WARMUP) {
        update_tier0_ewma     (&stats->ewma_t0,      &t0,     &engine->tier0_state);
        update_tier1_tcp_ewma (&stats->ewma_t1_tcp,  &t1_tcp,  &engine->tier1_tcp_state);
        update_tier1_udp_ewma (&stats->ewma_t1_udp,  &t1_udp,  &engine->tier1_udp_state);
        update_tier1_icmp_ewma(&stats->ewma_t1_icmp, &t1_icmp, &engine->tier1_icmp_state);
        update_tier1_dist_ewma(&stats->ewma_t1_dist, &t1_dist, &engine->tier1_dist_state);

        cusum_update_tier0(engine, stats, &t0, &result, false);

        engine->warmup_counter++;
        if (engine->warmup_counter >= DETECTION_WARMUP_WINDOWS) {
            engine->state = DETECTION_STATE_NORMAL;
            if (dst_ip == 0x5DBCD5EA) {
                printf("[Detection] Warm-up complete (%u windows), entering NORMAL\n",
                       engine->warmup_counter);
            }
        }

        result.state = DETECTION_STATE_WARMUP;
        engine->last_result = result;
        return result;
    }

    time_t now = time(NULL);
    struct tm *tm_info = localtime(&now);
    char time_str[32];
    strftime(time_str, sizeof(time_str), "%H:%M:%S", tm_info);
    
    if (dst_ip == 0x5DBCD5EA) {
        printf("\n");
        printf("╔═══════════════════════════════════════════════════════════════════════════╗\n");
        printf("║ DETECTION WINDOW: %s                                                  ║\n", time_str);
        printf("╠═══════════════════════════════════════════════════════════════════════════╣\n");
    }

    tick_freeze(&engine->tier0_state);
    tick_freeze(&engine->tier1_tcp_state);
    tick_freeze(&engine->tier1_udp_state);
    tick_freeze(&engine->tier1_icmp_state);
    tick_freeze(&engine->tier1_dist_state);

    if (dst_ip == 0x5DBCD5EA) {
        printf("║ FREEZE STATE:                                                              ║\n");
        printf("║   Tier0: %6s | T1-TCP: %6s | T1-UDP: %6s | T1-ICMP: %6s | T1-DIST: %6s ║\n",
               engine->tier0_state.frozen ? "FROZEN" : "ACTIVE",
               engine->tier1_tcp_state.frozen ? "FROZEN" : "ACTIVE",
               engine->tier1_udp_state.frozen ? "FROZEN" : "ACTIVE",
               engine->tier1_icmp_state.frozen ? "FROZEN" : "ACTIVE",
               engine->tier1_dist_state.frozen ? "FROZEN" : "ACTIVE");
        printf("╠═══════════════════════════════════════════════════════════════════════════╣\n");

        printf("║ TIER-0 RAW FEATURES:                                                       ║\n");
        printf("║   PPS: %10.0f | BPS: %12.0f | FPS: %8.0f                           ║\n",
               t0.pps, t0.bps, t0.fps);
        printf("║   Burst_PPS: %6.4f | Burst_BPS: %6.4f | Burst_FPS: %6.4f             ║\n",
               t0.burst_pps, t0.burst_bps, t0.burst_fps);
        printf("╠═══════════════════════════════════════════════════════════════════════════╣\n");

        printf("║ TIER-0 EWMA BASELINES:                                                     ║\n");
        printf("║   PPS: %10.0f (n=%4u) | BPS: %12.0f (n=%4u)                       ║\n",
               stats->ewma_t0.pps.mean, stats->ewma_t0.pps.n,
               stats->ewma_t0.bps.mean, stats->ewma_t0.bps.n);
        printf("║   FPS: %10.0f (n=%4u)                                                 ║\n",
               stats->ewma_t0.fps.mean, stats->ewma_t0.fps.n);
        printf("║   Burst_PPS: %6.4f | Burst_BPS: %6.4f | Burst_FPS: %6.4f             ║\n",
               stats->ewma_t0.burst_pps.mean,
               stats->ewma_t0.burst_bps.mean,
               stats->ewma_t0.burst_fps.mean);
        printf("╠═══════════════════════════════════════════════════════════════════════════╣\n");
    }

       bool tier0_frozen = engine->tier0_state.frozen;
    int alarm_count = cusum_update_tier0(engine, stats, &t0, &result, tier0_frozen);

    /* ==================================================================
     * PRODUCTION SAFETY NET – ABSOLUTE VOLUMETRIC OVERRIDE
     * Covers packet floods, bandwidth floods, and flow-table exhaustion.
     * Uses configurable thresholds from the header file.
     * ================================================================== */
    bool absolute_override = 
        (t0.pps > ABSOLUTE_PPS_THRESHOLD ||      /* tiny-packet floods */
         t0.bps > ABSOLUTE_BPS_THRESHOLD ||      /* bandwidth / amplification */
         t0.fps > ABSOLUTE_FPS_THRESHOLD);       /* SYN/distributed flow floods */

    bool tier0_triggered = false;   // ← single declaration here

    if (absolute_override) {
        if (dst_ip == 0x5DBCD5EA) {
            printf("║ 🔥 ABSOLUTE VOLUMETRIC OVERRIDE (PPS=%.0f | BPS=%.0f | FPS=%.0f) → FORCE ATTACK ║\n",
                   t0.pps, t0.bps, t0.fps);
        }
        engine->consecutive_attack_counter = CONSECUTIVE_ATTACK_WINDOWS;
        result.tier0_global_risk = 9.9;
        tier0_triggered = true;
    }

    if (result.tier0_global_risk >= T0_RISK_THRESHOLD) {
        engine->consecutive_attack_counter++;
        if (dst_ip == 0x5DBCD5EA) {
            printf("║ PERSISTENCE: Consecutive attack counter = %u/%u                            ║\n",
                   engine->consecutive_attack_counter, CONSECUTIVE_ATTACK_WINDOWS);
        }
    } else {
        engine->consecutive_attack_counter = 0;
        if (dst_ip == 0x5DBCD5EA) {
            printf("║ PERSISTENCE: Counter reset to 0 (risk below threshold)                     ║\n");
        }
    }
    
    if (dst_ip == 0x5DBCD5EA) {
        printf("╠═══════════════════════════════════════════════════════════════════════════╣\n");
    }

    /* If the absolute override didn't already trigger it, check persistence */
    if (!tier0_triggered) {
        tier0_triggered = (engine->consecutive_attack_counter >= CONSECUTIVE_ATTACK_WINDOWS);
    }
    
    if (dst_ip == 0x5DBCD5EA) {
        printf("╠═══════════════════════════════════════════════════════════════════════════╣\n");
    }

    if (dst_ip == 0x5DBCD5EA) {
        printf("║ TIER-0 CUSUM INTERNAL STATE:                                               ║\n");
        printf("║   [PPS]  S=%8.2f Var=%10.2f Std=%8.2f Risk=%5.3f (k=%.2f h=%.2f)    ║\n",
               engine->cusum[0].S,
               engine->cusum[0].variance,
               sqrt(engine->cusum[0].variance),
               result.tier0_risk_pps,
               CUSUM_K_PPS, CUSUM_H_PPS);
        printf("║   [BPS]  S=%8.2f Var=%10.2f Std=%8.2f Risk=%5.3f (k=%.2f h=%.2f)    ║\n",
               engine->cusum[1].S,
               engine->cusum[1].variance,
               sqrt(engine->cusum[1].variance),
               result.tier0_risk_bps,
               CUSUM_K_BPS, CUSUM_H_BPS);
        printf("║   [FPS]  S=%8.2f Var=%10.2f Std=%8.2f Risk=%5.3f (k=%.2f h=%.2f)    ║\n",
               engine->cusum[2].S,
               engine->cusum[2].variance,
               sqrt(engine->cusum[2].variance),
               result.tier0_risk_fps,
               CUSUM_K_FPS, CUSUM_H_FPS);
        printf("╠═══════════════════════════════════════════════════════════════════════════╣\n");

        printf("║ TIER-0 BURST Z-SCORE STATE:                                                ║\n");
        double z_burst_pps = (t0.burst_pps - stats->ewma_t0.burst_pps.mean) / 
                             (sqrt(engine->cusum[3].variance) + EWMA_EPSILON);
        double z_burst_bps = (t0.burst_bps - stats->ewma_t0.burst_bps.mean) / 
                             (sqrt(engine->cusum[4].variance) + EWMA_EPSILON);
        double z_burst_fps = (t0.burst_fps - stats->ewma_t0.burst_fps.mean) / 
                             (sqrt(engine->cusum[5].variance) + EWMA_EPSILON);
        printf("║   [Burst_PPS] Z=%6.2f Var=%8.4f Risk=%5.3f (threshold=%.1f)           ║\n",
               z_burst_pps, engine->cusum[3].variance, result.tier0_risk_burst_pps, BURST_Z_THRESHOLD);
        printf("║   [Burst_BPS] Z=%6.2f Var=%8.4f Risk=%5.3f (threshold=%.1f)           ║\n",
               z_burst_bps, engine->cusum[4].variance, result.tier0_risk_burst_bps, BURST_Z_THRESHOLD);
        printf("║   [Burst_FPS] Z=%6.2f Var=%8.4f Risk=%5.3f (threshold=%.1f)           ║\n",
               z_burst_fps, engine->cusum[5].variance, result.tier0_risk_burst_fps, BURST_Z_THRESHOLD);
        printf("╠═══════════════════════════════════════════════════════════════════════════╣\n");

        printf("║ TIER-0 GLOBAL RISK COMPUTATION:                                            ║\n");
        double r_pps = T0_W_PPS * result.tier0_risk_pps;
        double r_bps = T0_W_BPS * result.tier0_risk_bps;
        double r_fps = T0_W_FPS * result.tier0_risk_fps;
        double r_bpps = T0_W_BURST_PPS * result.tier0_risk_burst_pps;
        double r_bbps = T0_W_BURST_BPS * result.tier0_risk_burst_bps;
        double r_bfps = T0_W_BURST_FPS * result.tier0_risk_burst_fps;
        printf("║   PPS:       %.1f × %.3f = %.3f                                            ║\n",
               T0_W_PPS, result.tier0_risk_pps, r_pps);
        printf("║   BPS:       %.1f × %.3f = %.3f                                            ║\n",
               T0_W_BPS, result.tier0_risk_bps, r_bps);
        printf("║   FPS:       %.1f × %.3f = %.3f                                            ║\n",
               T0_W_FPS, result.tier0_risk_fps, r_fps);
        printf("║   Burst_PPS: %.1f × %.3f = %.3f                                            ║\n",
               T0_W_BURST_PPS, result.tier0_risk_burst_pps, r_bpps);
        printf("║   Burst_BPS: %.1f × %.3f = %.3f                                            ║\n",
               T0_W_BURST_BPS, result.tier0_risk_burst_bps, r_bbps);
        printf("║   Burst_FPS: %.1f × %.3f = %.3f                                            ║\n",
               T0_W_BURST_FPS, result.tier0_risk_burst_fps, r_bfps);
        printf("║   ─────────────────────────────────────────────────────────────────────   ║\n");
        printf("║   TOTAL:     %.3f (threshold=%.1f) → %s                                ║\n",
               result.tier0_global_risk, T0_RISK_THRESHOLD,
               result.tier0_global_risk >= T0_RISK_THRESHOLD ? "TRIGGER" : "NORMAL");
        printf("╠═══════════════════════════════════════════════════════════════════════════╣\n");
    }

    if (result.tier0_global_risk >= T0_RISK_THRESHOLD) {
        engine->consecutive_attack_counter++;
        if (dst_ip == 0x5DBCD5EA) {
            printf("║ PERSISTENCE: Consecutive attack counter = %u/%u                            ║\n",
                   engine->consecutive_attack_counter, CONSECUTIVE_ATTACK_WINDOWS);
        }
    } else {
        engine->consecutive_attack_counter = 0;
        if (dst_ip == 0x5DBCD5EA) {
            printf("║ PERSISTENCE: Counter reset to 0 (risk below threshold)                     ║\n");
        }
    }
    
    if (dst_ip == 0x5DBCD5EA) {
        printf("╠═══════════════════════════════════════════════════════════════════════════╣\n");
    }

    if (tier0_triggered) {
        if (dst_ip == 0x5DBCD5EA) {
            printf("║ ACTION: Freezing all tiers (persistence confirmed)                         ║\n");
        }
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
        
        if (dst_ip == 0x5DBCD5EA) {
            printf("║ TIER-0 DECISION: NORMAL (persistence not met)                              ║\n");
            printf("║ Thaw cooldown: %u/%u windows                                              ║\n",
                   engine->thaw_cooldown_counter, THAW_COOLDOWN_WINDOWS);
            printf("╚═══════════════════════════════════════════════════════════════════════════╝\n");
        }
        
    } else {
        if (dst_ip == 0x5DBCD5EA) {
            printf("║ TIER-0 DECISION: ATTACK CONFIRMED (persistence met)                        ║\n");
            printf("╠═══════════════════════════════════════════════════════════════════════════╣\n");
            printf("║ TIER-1 EVALUATION TRIGGERED                                                ║\n");
            printf("╠═══════════════════════════════════════════════════════════════════════════╣\n");
        }
        
        result.tier1_evaluated = true;

        if (dst_ip == 0x5DBCD5EA) {
            printf("║ TIER-1 RAW FEATURES:                                                       ║\n");
            printf("║   [TCP]  SYN=%.3f SA=%.3f FA=%.3f RST=%.3f ACK=%.3f                     ║\n",
                   t1_tcp.syn_ratio, t1_tcp.synack_ratio, t1_tcp.finack_ratio,
                   t1_tcp.rst_ratio, t1_tcp.ack_data_ratio);
            printf("║          PPS_ratio=%.3f BPS_ratio=%.3f                                   ║\n",
                   t1_tcp.tcp_pps_ratio, t1_tcp.tcp_bps_ratio);
            printf("║   [UDP]  BPS_ratio=%.3f PPS_ratio=%.3f Flow_ratio=%.3f                  ║\n",
                   t1_udp.udp_bps_ratio, t1_udp.udp_pps_ratio, t1_udp.udp_flow_ratio);
            printf("║   [ICMP] Echo_ratio=%.3f PPS_ratio=%.3f                                  ║\n",
                   t1_icmp.icmp_echo_ratio, t1_icmp.icmp_pps_ratio);
            printf("║   [DIST] SrcIP_ratio=%.3f DstPort_ratio=%.3f                             ║\n",
                   t1_dist.src_ip_ratio, t1_dist.dst_port_ratio);
            printf("╠═══════════════════════════════════════════════════════════════════════════╣\n");

            printf("║ TIER-1 EWMA BASELINES:                                                     ║\n");
            printf("║   [TCP]  SYN=%.3f SA=%.3f FA=%.3f RST=%.3f ACK=%.3f                     ║\n",
                   stats->ewma_t1_tcp.syn_ratio.mean,
                   stats->ewma_t1_tcp.synack_ratio.mean,
                   stats->ewma_t1_tcp.finack_ratio.mean,
                   stats->ewma_t1_tcp.rst_ratio.mean,
                   stats->ewma_t1_tcp.ack_data_ratio.mean);
            printf("║   [UDP]  BPS=%.3f PPS=%.3f Flow=%.3f                                     ║\n",
                   stats->ewma_t1_udp.udp_bps_ratio.mean,
                   stats->ewma_t1_udp.udp_pps_ratio.mean,
                   stats->ewma_t1_udp.udp_flow_ratio.mean);
            printf("║   [ICMP] Echo=%.3f PPS=%.3f                                               ║\n",
                   stats->ewma_t1_icmp.icmp_echo_ratio.mean,
                   stats->ewma_t1_icmp.icmp_pps_ratio.mean);
            printf("║   [DIST] SrcIP=%.3f DstPort=%.3f                                          ║\n",
                   stats->ewma_t1_dist.src_ip_ratio.mean,
                   stats->ewma_t1_dist.dst_port_ratio.mean);
            printf("╠═══════════════════════════════════════════════════════════════════════════╣\n");
        }

        result.tier1_tcp_score  = compute_tier1_tcp_score (&stats->ewma_t1_tcp,  &t1_tcp);
        result.tier1_udp_score  = compute_tier1_udp_score (&stats->ewma_t1_udp,  &t1_udp);
        result.tier1_icmp_score = compute_tier1_icmp_score(&stats->ewma_t1_icmp, &t1_icmp);
        result.tier1_dist_score = compute_tier1_dist_score(&stats->ewma_t1_dist, &t1_dist);

        if (dst_ip == 0x5DBCD5EA) {
            printf("║ TIER-1 COMPUTED SCORES:                                                    ║\n");
            printf("║   TCP:  %.3f  (norm=%.2f susp=%.2f)                                      ║\n",
                   result.tier1_tcp_score, THRESHOLD_NORMAL, THRESHOLD_SUSPICIOUS);
            printf("║   UDP:  %.3f                                                              ║\n",
                   result.tier1_udp_score);
            printf("║   ICMP: %.3f                                                              ║\n",
                   result.tier1_icmp_score);
            printf("║   DIST: %.3f                                                              ║\n",
                   result.tier1_dist_score);
            printf("╠═══════════════════════════════════════════════════════════════════════════╣\n");
        }

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

        detection_state_t tcp_st  = classify(result.tier1_tcp_score);
        detection_state_t udp_st  = classify(result.tier1_udp_score);
        detection_state_t icmp_st = classify(result.tier1_icmp_score);
        detection_state_t dist_st = classify(result.tier1_dist_score);

        if (dst_ip == 0x5DBCD5EA) {
            printf("║ TIER-1 CLASSIFICATIONS:                                                    ║\n");
            printf("║   TCP:  %-12s                                                          ║\n",
                   detection_state_str(tcp_st));
            printf("║   UDP:  %-12s                                                          ║\n",
                   detection_state_str(udp_st));
            printf("║   ICMP: %-12s                                                          ║\n",
                   detection_state_str(icmp_st));
            printf("║   DIST: %-12s                                                          ║\n",
                   detection_state_str(dist_st));
            printf("╠═══════════════════════════════════════════════════════════════════════════╣\n");
            
            // IMPROVEMENT 3: Show weighted fusion breakdown
            printf("║ TIER-1 WEIGHTED FUSION (IMPROVEMENT 3 - HYBRID):                           ║\n");
            printf("║   TCP:  %.1f × %.3f = %.3f                                                ║\n",
                W_TCP, result.tier1_tcp_score, W_TCP * result.tier1_tcp_score);
            printf("║   UDP:  %.1f × %.3f = %.3f                                                ║\n",
                W_UDP, result.tier1_udp_score, W_UDP * result.tier1_udp_score);
            printf("║   ICMP: %.1f × %.3f = %.3f                                                ║\n",
                W_ICMP, result.tier1_icmp_score, W_ICMP * result.tier1_icmp_score);
            printf("║   DIST: %.1f × %.3f = %.3f                                                ║\n",
                W_DIST, result.tier1_dist_score, W_DIST * result.tier1_dist_score);
            printf("║   ─────────────────────────────────────────────────────────────────────   ║\n");
            printf("║   WEIGHTED AVG:       %.3f                                                 ║\n",
                weighted_score);
            printf("║   MAX INDIVIDUAL:     %.3f                                                 ║\n",
                max_individual);
            printf("║   FINAL (HYBRID MAX): %.3f                                                 ║\n",
                result.tier1_final_score);
            printf("╠═══════════════════════════════════════════════════════════════════════════╣\n");
        }

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

            // Rule 1: UDP flood
            if ((udp_pps_frac > 0.85 && result.tier1_udp_score > 0.42) || 
                (udp_pps_frac > 0.95 && extreme_volume)) {
                result.attack_type = ATTACK_TYPE_UDP_FLOOD;
            }
            // Rule 2: SYN flood
            else if ((tcp_pps_frac > 0.50 && result.tier1_tcp_score > 0.65) || 
                     (tcp_pps_frac > 0.70 && extreme_volume)) {
                result.attack_type = ATTACK_TYPE_SYN_FLOOD;
            }
            // Rule 3: ACK flood
            else if ((tcp_pps_frac > 0.50 && result.tier1_tcp_score > 0.65) || 
                     (tcp_pps_frac > 0.70 && extreme_volume)) {
                result.attack_type = ATTACK_TYPE_ACK_FLOOD;
            }
            // Rule 4: RST/FIN flood
            else if ((tcp_pps_frac > 0.40 && result.tier1_tcp_score > 0.55) || 
                     (tcp_pps_frac > 0.60 && extreme_volume)) {
                result.attack_type = ATTACK_TYPE_RST_FIN_FLOOD;
            }
            // Rule 5: ICMP flood
            else if ((icmp_pps_frac > 0.80 && result.tier1_icmp_score > 0.65) || 
                     (icmp_pps_frac > 0.90 && extreme_volume)) {
                result.attack_type = ATTACK_TYPE_ICMP_FLOOD;
            }
            // Rule 6: Distributed
            else if (result.tier1_dist_score > 0.70 && t1_dist.src_ip_ratio > 1.2) {
                result.attack_type = ATTACK_TYPE_DISTRIBUTED;
            }
            // Rule 7: Amplification
            else if (result.tier1_udp_score > 0.75 && t1_udp.udp_bps_ratio > 0.85) {
                result.attack_type = ATTACK_TYPE_AMPLIFICATION;
            }
            else {
                result.attack_type = ATTACK_TYPE_UNKNOWN;
            }
        }

        if (dst_ip == 0x5DBCD5EA) {
            printf("║ TIER-1 FINAL CLASSIFICATION: %-12s                                     ║\n",
                   detection_state_str(final_state));
            printf("║ Attack Type: %-20s                                                   ║\n",
                   attack_type_str(result.attack_type));
            printf("╠═══════════════════════════════════════════════════════════════════════════╣\n");
        }

        if (final_state == DETECTION_STATE_ATTACK ||
            final_state == DETECTION_STATE_SUSPICIOUS) {
            
            if (dst_ip == 0x5DBCD5EA) {
                printf("║ ACTION: Maintaining freeze on all tiers (attack/suspicious confirmed)      ║\n");
            }
            
            freeze_tier(&engine->tier0_state);
            freeze_tier(&engine->tier1_tcp_state);
            freeze_tier(&engine->tier1_udp_state);
            freeze_tier(&engine->tier1_icmp_state);
            freeze_tier(&engine->tier1_dist_state);

            if (engine->state != final_state) {
                engine->attack_count++;
                engine->last_attack_time = timestamp;
                if (dst_ip == 0x5DBCD5EA) {
                    printf("║ ALERT: State transition to %-12s (total attacks: %u)                ║\n",
                           detection_state_str(final_state), engine->attack_count);
                }
            }
        } else {
            if (dst_ip == 0x5DBCD5EA) {
                printf("║ ACTION: Tier-1 cleared false alarm                                         ║\n");
                printf("║ RECOVERY: Tier-1 veto → Resetting Tier-0 CUSUM (fast recovery after attack)║\n");
            }
            
            reset_tier0_cusum(engine);          
            engine->consecutive_attack_counter = 0;
            engine->thaw_cooldown_counter = THAW_COOLDOWN_WINDOWS;
        }
        
        if (dst_ip == 0x5DBCD5EA) {
            printf("╚═══════════════════════════════════════════════════════════════════════════╝\n");
        }
    }

    if (final_state == DETECTION_STATE_NORMAL && result.tier0_global_risk < T0_RISK_THRESHOLD) {
        engine->thaw_cooldown_counter++;

        if (engine->thaw_cooldown_counter >= THAW_COOLDOWN_WINDOWS) {
            if (engine->tier0_state.frozen) {
                if (dst_ip == 0x5DBCD5EA) {
                    printf("\n╔═══════════════════════════════════════════════════════════════════════════╗\n");
                    printf("║ THAW COMPLETE: %u consecutive clean windows                               ║\n",
                           engine->thaw_cooldown_counter);
                    printf("║ ACTION: Unfreezing all tiers, resetting CUSUM, resuming baseline learning ║\n");
                    printf("╚═══════════════════════════════════════════════════════════════════════════╝\n");
                }
            }

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
    } else {
        if (dst_ip == 0x5DBCD5EA) {
            if (final_state != DETECTION_STATE_NORMAL) {
                printf("\n║ GATEKEEPER: Blocking baseline updates (state=%s)                          ║\n",
                       detection_state_str(final_state));
            } else if (result.tier0_global_risk >= T0_RISK_THRESHOLD) {
                printf("\n║ GATEKEEPER: Blocking baseline updates (risk=%.2f >= %.1f)                  ║\n",
                       result.tier0_global_risk, T0_RISK_THRESHOLD);
            }
        }
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
        default:                         return "UNDEFINED";
    }
}