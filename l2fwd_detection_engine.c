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

/**
 * CHANGE 1 & 2: Unified detection function for CUSUM and Z-score
 *
 * For CUSUM features (pps, bps, fps):
 *   - Uses k_factor and h_factor parameters
 *   - Accumulates S_t
 *   - risk = clamp(S_t / H_abs, 0, 1)
 *
 * For burst features (burst_pps, burst_bps, burst_fps):
 *   - k_factor and h_factor are 0 (unused)
 *   - Does NOT accumulate S_t
 *   - Computes z = residual / std
 *   - risk = clamp(z / BURST_Z_THRESHOLD, 0, 1)
 *
 * @param cs         State (S, variance, alpha_std)
 * @param ewma       EWMA baseline
 * @param x          Current value
 * @param in_warmup  Skip accumulation during warmup
 * @param frozen     Hold S and variance constant
 * @param k_factor   CUSUM_K_* or 0 for burst features
 * @param h_factor   CUSUM_H_* or 0 for burst features
 * @param out_S      Output S value (0 for burst features)
 * @param out_risk   Output continuous risk [0, 1]
 * @return           true if exceeds threshold
 */
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

    /* CRITICAL FREEZE for CUSUM features */
    if (frozen && !is_burst_feature) {
        double residual = x - ewma->mean;
        double ewma_std = sqrt(cs->variance);
        if (ewma_std < EWMA_EPSILON)
            ewma_std = EWMA_EPSILON;

        double variance_cap = ewma->mean * 0.5;
        if (ewma_std > variance_cap)
            ewma_std = variance_cap;

        double k_abs = k_factor * ewma_std;
        double H_abs = h_factor * ewma_std;

        double S_new = cs->S + (residual - k_abs);
        if (S_new < 0.0)
            S_new = 0.0;

        if (S_new > cs->S)
            S_new = cs->S;

        cs->S = S_new;
        *out_S = S_new;
        *out_risk = clamp(S_new / H_abs, 0.0, 1.0);

        return (S_new > H_abs);
    }

    /* Compute residual */
    double residual = x - ewma->mean;

    /* =========================================================
       WARMUP PHASE
       ========================================================= */
    if (in_warmup) {
        cs->variance += cs->alpha_std * (residual * residual - cs->variance);
        *out_S = 0.0;
        *out_risk = 0.0;
        return false;
    }

    /* =========================================================
       POST-WARMUP PHASE
       ========================================================= */

    /* Compute current std BEFORE variance update */
    double current_std = sqrt(cs->variance);
    if (current_std < EWMA_EPSILON)
        current_std = EWMA_EPSILON;

    /* Protected variance update (anti-poison) */
    bool extreme = fabs(residual) > (5.0 * current_std);

    if (!extreme && !frozen) {
        cs->variance += cs->alpha_std * (residual * residual - cs->variance);
    }

    double ewma_std = sqrt(cs->variance);

    if (ewma_std < EWMA_EPSILON) {
        if (!is_burst_feature) {
            cs->S = 0.0;
        }
        *out_S = 0.0;
        *out_risk = 0.0;
        return false;
    }

    /* Variance capping */
    double variance_cap = ewma->mean * 0.5;
    if (ewma_std > variance_cap) {
        ewma_std = variance_cap;
    }

    /* =========================================================
       CHANGE 1: BURST FEATURES — Z-SCORE PATH
       ========================================================= */
    if (is_burst_feature) {
        double z = residual / ewma_std;
        *out_S = 0.0;  /* S unused for burst features */
        *out_risk = clamp(fabs(z) / BURST_Z_THRESHOLD, 0.0, 1.0);
        return (fabs(z) > BURST_Z_THRESHOLD);
    }

    /* =========================================================
       CUSUM PATH (pps, bps, fps)
       ========================================================= */
    double k_abs = k_factor * ewma_std;
    double H_abs = h_factor * ewma_std;

    double S_new = cs->S + (residual - k_abs);
    if (S_new < 0.0) S_new = 0.0;

    cs->S  = S_new;
    *out_S = S_new;
    *out_risk = clamp(S_new / H_abs, 0.0, 1.0);

    return (S_new > H_abs);
}

/**
 * CHANGE 2 & 3: Tier-0 detection with per-feature K/H and continuous risk
 *
 * For each feature:
 *   - PPS: uses CUSUM_K_PPS, CUSUM_H_PPS
 *   - BPS: uses CUSUM_K_BPS, CUSUM_H_BPS
 *   - FPS: uses CUSUM_K_FPS, CUSUM_H_FPS
 *   - Burst features: k=0, h=0 (Z-score mode)
 *
 * Computes:
 *   global_risk = sum(weight_i * risk_i)
 *
 * Returns: alarm_count (for backward compatibility)
 */
int cusum_update_tier0(struct detection_engine *engine,
                        const struct dst_ip_stats *stats,
                        const struct tier0_features *cur,
                        struct detection_result *result,
                        bool frozen) {
    bool in_warmup = (engine->state == DETECTION_STATE_WARMUP);
    int  alarm_count = 0;
    bool alarm;
    double risk;

    /* PPS - CUSUM with K_PPS, H_PPS */
    alarm = cusum_update_one(&engine->cusum[0], &stats->ewma_t0.pps,
                              cur->pps, in_warmup, frozen,
                              CUSUM_K_PPS, CUSUM_H_PPS,
                              &result->tier0_cusum_pps,
                              &result->tier0_risk_pps);
    if (alarm) alarm_count++;

    /* BPS - CUSUM with K_BPS, H_BPS */
    alarm = cusum_update_one(&engine->cusum[1], &stats->ewma_t0.bps,
                              cur->bps, in_warmup, frozen,
                              CUSUM_K_BPS, CUSUM_H_BPS,
                              &result->tier0_cusum_bps,
                              &result->tier0_risk_bps);
    if (alarm) alarm_count++;

    /* FPS - CUSUM with K_FPS, H_FPS */
    alarm = cusum_update_one(&engine->cusum[2], &stats->ewma_t0.fps,
                              cur->fps, in_warmup, frozen,
                              CUSUM_K_FPS, CUSUM_H_FPS,
                              &result->tier0_cusum_fps,
                              &result->tier0_risk_fps);
    if (alarm) alarm_count++;

    /* BURST_PPS - Z-score (k=0, h=0) */
    alarm = cusum_update_one(&engine->cusum[3], &stats->ewma_t0.burst_pps,
                              cur->burst_pps, in_warmup, frozen,
                              0.0, 0.0,
                              &result->tier0_cusum_burst_pps,
                              &result->tier0_risk_burst_pps);
    if (alarm) alarm_count++;

    /* BURST_BPS - Z-score (k=0, h=0) */
    alarm = cusum_update_one(&engine->cusum[4], &stats->ewma_t0.burst_bps,
                              cur->burst_bps, in_warmup, frozen,
                              0.0, 0.0,
                              &result->tier0_cusum_burst_bps,
                              &result->tier0_risk_burst_bps);
    if (alarm) alarm_count++;

    /* BURST_FPS - Z-score (k=0, h=0) */
    alarm = cusum_update_one(&engine->cusum[5], &stats->ewma_t0.burst_fps,
                              cur->burst_fps, in_warmup, frozen,
                              0.0, 0.0,
                              &result->tier0_cusum_burst_fps,
                              &result->tier0_risk_burst_fps);
    if (alarm) alarm_count++;

    /* CHANGE 3: Compute weighted global risk */
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
// TIER 1 — DISTANCE COMPUTATION  (unchanged)
// ============================================================================

static inline double norm_dist(const struct ewma_state *s, double current) {
    if (s->n < EWMA_WARMUP_PERIODS) return 0.0;
    return fabs(current - s->mean) / (s->mean + EWMA_EPSILON);
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
    d += norm_dist(&ewma->udp_bps_ratio,  cur->udp_bps_ratio);
    d += norm_dist(&ewma->udp_pps_ratio,  cur->udp_pps_ratio);
    d += norm_dist(&ewma->udp_flow_ratio, cur->udp_flow_ratio);
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
// EWMA BASELINE UPDATE HELPERS  (unchanged)
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
// FREEZE / THAW HELPERS  (unchanged)
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
// HORIZONTAL CONSOLE OUTPUT  (unchanged)
// ============================================================================

static void print_detection_horizontal(
    struct detection_engine *engine,
    const struct dst_ip_stats *stats,
    const struct tier0_features *t0,
    const struct tier1_tcp_features *t1_tcp,
    const struct tier1_udp_features *t1_udp,
    const struct tier1_icmp_features *t1_icmp,
    const struct tier1_dist_features *t1_dist,
    const char *tier0_decision,
    const char *final_decision,
    int alarm_count)
{
    time_t now = time(NULL);
    struct tm *tm_info = localtime(&now);
    char time_str[32];
    strftime(time_str, sizeof(time_str), "%H:%M:%S", tm_info);

    printf("[%s] ", time_str);
    
    printf("T0 PPS:%.0f(avg:%.0f±%.0f) BPS:%.0f(avg:%.0f±%.0f) FPS:%.0f(avg:%.0f±%.0f) | ",
           t0->pps, stats->ewma_t0.pps.mean, sqrt(engine->cusum[0].variance),
           t0->bps, stats->ewma_t0.bps.mean, sqrt(engine->cusum[1].variance),
           t0->fps, stats->ewma_t0.fps.mean, sqrt(engine->cusum[2].variance));
    
    printf("TCP(S:%.2f SA:%.2f R:%.2f) UDP(B:%.2f P:%.2f) ICMP(E:%.2f) | ",
           t1_tcp->syn_ratio, t1_tcp->synack_ratio, t1_tcp->rst_ratio,
           t1_udp->udp_bps_ratio, t1_udp->udp_pps_ratio,
           t1_icmp->icmp_echo_ratio);

    printf("T0=%s[%d/6] -> FINAL=%s\n",
           tier0_decision, alarm_count, final_decision);
}

// ============================================================================
// CLASSIFY TIER 1 SCORE → STATE  (unchanged)
// ============================================================================

static detection_state_t classify(double score) {
    if (score < THRESHOLD_NORMAL)     return DETECTION_STATE_NORMAL;
    if (score < THRESHOLD_SUSPICIOUS) return DETECTION_STATE_SUSPICIOUS;
    return DETECTION_STATE_ATTACK;
}

// ============================================================================
// MAIN DETECTION LOGIC  (CHANGE 3: use global_risk for trigger)
// ============================================================================

struct detection_result detection_engine_process(
    struct detection_engine *engine,
    struct dst_ip_stats     *stats,
    uint64_t timestamp)
{
    struct detection_result result;
    memset(&result, 0, sizeof(result));
    result.timestamp = timestamp;
    result.state     = engine->state;

    double time_sec = (double)STATS_PERIOD_US / 1000000.0;

    /* Feature extraction */
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

    /* WARMUP PATH */
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
            printf("[Detection] Warm-up complete (%u windows), entering NORMAL\n",
                   engine->warmup_counter);
        }

        result.state = DETECTION_STATE_WARMUP;
        engine->last_result = result;
        return result;
    }

    /* POST-WARMUP PATH */
    
    tick_freeze(&engine->tier0_state);
    tick_freeze(&engine->tier1_tcp_state);
    tick_freeze(&engine->tier1_udp_state);
    tick_freeze(&engine->tier1_icmp_state);
    tick_freeze(&engine->tier1_dist_state);

    bool tier0_frozen = engine->tier0_state.frozen;
    int alarm_count = cusum_update_tier0(engine, stats, &t0, &result, tier0_frozen);

    /* CHANGE 3: Use global_risk instead of alarm_count for freeze trigger */
    if (result.tier0_global_risk >= T0_RISK_THRESHOLD) {
        freeze_tier(&engine->tier0_state);
        freeze_tier(&engine->tier1_tcp_state);
        freeze_tier(&engine->tier1_udp_state);
        freeze_tier(&engine->tier1_icmp_state);
        freeze_tier(&engine->tier1_dist_state);
        
        engine->thaw_cooldown_counter = 0;
    }

    /* CHANGE 3: Persistence filter uses global_risk */
    if (result.tier0_global_risk >= T0_RISK_THRESHOLD) {
        engine->consecutive_attack_counter++;
    } else {
        engine->consecutive_attack_counter = 0;
    }

    bool tier0_triggered = (engine->consecutive_attack_counter >= CONSECUTIVE_ATTACK_WINDOWS);

    detection_state_t final_state;

    if (!tier0_triggered) {
        final_state = DETECTION_STATE_NORMAL;
        
        print_detection_horizontal(engine, stats, &t0, &t1_tcp, &t1_udp, &t1_icmp, &t1_dist,
                                   "NORMAL", "NORMAL", alarm_count);
    } else {
        result.tier1_evaluated = true;

        result.tier1_tcp_score  = compute_tier1_tcp_score (&stats->ewma_t1_tcp,  &t1_tcp);
        result.tier1_udp_score  = compute_tier1_udp_score (&stats->ewma_t1_udp,  &t1_udp);
        result.tier1_icmp_score = compute_tier1_icmp_score(&stats->ewma_t1_icmp, &t1_icmp);
        result.tier1_dist_score = compute_tier1_dist_score(&stats->ewma_t1_dist, &t1_dist);

        double worst = result.tier1_tcp_score;
        if (result.tier1_udp_score  > worst) worst = result.tier1_udp_score;
        if (result.tier1_icmp_score > worst) worst = result.tier1_icmp_score;
        if (result.tier1_dist_score > worst) worst = result.tier1_dist_score;
        result.tier1_final_score = worst;

        detection_state_t tcp_st  = classify(result.tier1_tcp_score);
        detection_state_t udp_st  = classify(result.tier1_udp_score);
        detection_state_t icmp_st = classify(result.tier1_icmp_score);
        detection_state_t dist_st = classify(result.tier1_dist_score);

        if (tcp_st  == DETECTION_STATE_ATTACK ||
            udp_st  == DETECTION_STATE_ATTACK ||
            icmp_st == DETECTION_STATE_ATTACK ||
            dist_st == DETECTION_STATE_ATTACK) {
            final_state = DETECTION_STATE_ATTACK;
        } else if (tcp_st  == DETECTION_STATE_SUSPICIOUS ||
                   udp_st  == DETECTION_STATE_SUSPICIOUS ||
                   icmp_st == DETECTION_STATE_SUSPICIOUS ||
                   dist_st == DETECTION_STATE_SUSPICIOUS) {
            final_state = DETECTION_STATE_SUSPICIOUS;
        } else {
            final_state = DETECTION_STATE_NORMAL;
        }

        if (final_state == DETECTION_STATE_ATTACK ||
            final_state == DETECTION_STATE_SUSPICIOUS) {
            
            freeze_tier(&engine->tier0_state);
            freeze_tier(&engine->tier1_tcp_state);
            freeze_tier(&engine->tier1_udp_state);
            freeze_tier(&engine->tier1_icmp_state);
            freeze_tier(&engine->tier1_dist_state);

            print_detection_horizontal(engine, stats, &t0, &t1_tcp, &t1_udp, &t1_icmp, &t1_dist,
                                       "ATTACK", detection_state_str(final_state),
                                       alarm_count);

            if (engine->state != final_state) {
                engine->attack_count++;
                engine->last_attack_time = timestamp;
                printf("[Detection] *** %s *** global_risk=%.2f (threshold=%.1f) "
                       "tcp=%.3f udp=%.3f icmp=%.3f dist=%.3f\n",
                       detection_state_str(final_state),
                       result.tier0_global_risk, T0_RISK_THRESHOLD,
                       result.tier1_tcp_score, result.tier1_udp_score,
                       result.tier1_icmp_score, result.tier1_dist_score);
            }
        } else {
            print_detection_horizontal(engine, stats, &t0, &t1_tcp, &t1_udp, &t1_icmp, &t1_dist,
                                       "ATTACK", "NORMAL", alarm_count);
        }
    }

    /* GATEKEEPER PATTERN - EWMA updates only for clean windows */
    if (final_state == DETECTION_STATE_NORMAL && result.tier0_global_risk < T0_RISK_THRESHOLD) {
        engine->thaw_cooldown_counter++;

        if (engine->thaw_cooldown_counter >= THAW_COOLDOWN_WINDOWS) {
            if (engine->tier0_state.frozen) {
                printf("[Detection] Thaw cooldown complete (%u windows) - recovery confirmed, resetting CUSUM\n",
                       engine->thaw_cooldown_counter);
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