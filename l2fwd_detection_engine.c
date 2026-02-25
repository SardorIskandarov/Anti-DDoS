#include "l2fwd_detection_engine.h"
#include <math.h>
#include <string.h>
#include <stdio.h>
#include <rte_cycles.h>

// ============================================================================
// SIGMOID  (used only by Tier 1 — unchanged)
// ============================================================================

/**
 * sigmoid_score — maps a non-negative Manhattan distance to [0, 1].
 *
 *   score = 1 / (1 + exp(-k * (distance - d0)))
 *
 * Parameters: k = SIGMOID_K, d0 = SIGMOID_D0
 */
double sigmoid_score(double distance) {
    return 1.0 / (1.0 + exp(-SIGMOID_K * (distance - SIGMOID_D0)));
}

// ============================================================================
// INITIALIZATION
// ============================================================================

/*
 * ewma_update / ewma_mean / burst_window_push / burst_window_avg are defined
 * once in l2fwd_ddos_collector.c and declared in the shared header.
 * They must NOT be defined here — doing so causes "multiple definition" linker
 * errors when both translation units are linked together.
 *
 * The init_tier*_alpha helpers live only in l2fwd_ddos_collector.c (called
 * from dst_ip_table_get_or_create).  They are not needed here.
 */

void detection_engine_init(struct detection_engine *engine, uint64_t timestamp) {
    memset(engine, 0, sizeof(struct detection_engine));
    engine->state            = DETECTION_STATE_WARMUP;
    engine->last_attack_time = timestamp;

    /* Initialize persistence filter counter */
    engine->consecutive_attack_counter = 0;

    /* Initialize thaw cooldown counter */
    engine->thaw_cooldown_counter = 0;

    /*
     * Initialize CUSUM per-feature states.
     * alpha_std tracks variance for adaptive thresholding.
     */
    for (int i = 0; i < TIER0_N; i++) {
        engine->cusum[i].S         = 0.0;
        engine->cusum[i].variance  = 0.0;
        engine->cusum[i].alpha_std = EWMA_ALPHA_TIER0;
    }
}

// ============================================================================
// FEATURE EXTRACTION  (unchanged from original)
// ============================================================================

void extract_tier0_features(const struct dst_ip_stats *stats,
                              struct tier0_features *out,
                              double time_sec) {
    out->pps = (double)stats->total_pkts / time_sec;
    out->bps = (double)stats->total_bytes * 8.0 / time_sec;

    /* FPS = HLL estimate of unique five-tuples per second */
    out->fps = (double)hll_count(&stats->unique_flows) / time_sec;

    /* Burst factors: ratio of current 1-s value to long-window average */
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
    (void)time_sec;  /* Unused - ratios don't need time normalization */
    
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
    (void)time_sec;  /* Unused - ratios don't need time normalization */
    
    double tot_safe       = (stats->total_pkts  > 0) ? (double)stats->total_pkts  : 1.0;
    double tot_bytes_safe = (stats->total_bytes > 0) ? (double)stats->total_bytes : 1.0;
    double udp_pps_safe   = (stats->udp_pkts    > 0) ? (double)stats->udp_pkts    : 1.0;

    out->udp_bps_ratio  = (double)stats->udp_bytes / tot_bytes_safe;
    out->udp_pps_ratio  = (double)stats->udp_pkts  / tot_safe;

    double udp_flows    = (double)hll_count(&stats->udp_flows);
    out->udp_flow_ratio = udp_flows / udp_pps_safe;
}

void extract_tier1_icmp_features(const struct dst_ip_stats *stats,
                                   struct tier1_icmp_features *out,
                                   double time_sec) {
    (void)time_sec;  /* Unused - ratios don't need time normalization */
    
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
// TIER 0 — CUSUM DETECTION WITH VARIANCE FREEZE
// ============================================================================

/**
 * cusum_update_one — variance-scaled CUSUM for single EWMA baseline.
 *
 * Formula:
 *   residual = x - ewma_mean
 *   k_abs = CUSUM_K * ewma_std
 *   H_abs = CUSUM_H * ewma_std
 *   S_t = max(0, S_{t-1} + (residual - k_abs))
 *   Alarm if S_t > H_abs
 *
 * FREEZE BEHAVIOR:
 *   frozen == true → S_t AND variance held constant
 *   frozen == false → normal updates
 *
 * @param cs         CUSUM state (S, variance, alpha_std)
 * @param ewma       EWMA baseline (mean, n, alpha)
 * @param x          Current observed value
 * @param in_warmup  Skip accumulation during warmup
 * @param frozen     Hold S_t and variance constant
 * @param out_S      Output S_t value
 * @return           true if alarm (S_t > H_abs)
 */
static bool cusum_update_one(struct cusum_state *cs,
                              const struct ewma_state *ewma,
                              double x,
                              bool in_warmup,
                              bool frozen,
                              double *out_S) {
    /* CRITICAL FREEZE: Hold S_t AND variance constant */
    if (frozen) {

    /* Compute residual */
    double residual = x - ewma->mean;

    /* Use existing variance (do NOT update it) */
    double ewma_std = sqrt(cs->variance);
    if (ewma_std < EWMA_EPSILON)
        ewma_std = EWMA_EPSILON;

    /* Apply same variance cap */
    double variance_cap = ewma->mean * 0.5;
    if (ewma_std > variance_cap)
        ewma_std = variance_cap;

    double k_abs = CUSUM_K * ewma_std;
    double H_abs = CUSUM_H * ewma_std;

    /* ✅ Allow decay */
    double S_new = cs->S + (residual - k_abs);

    if (S_new < 0.0)
        S_new = 0.0;

    /* ❌ Prevent upward growth while frozen */
    if (S_new > cs->S)
        S_new = cs->S;

    cs->S = S_new;
    *out_S = S_new;

    return (S_new > H_abs);
    }

    /* Compute residual */
    double residual = x - ewma->mean;

    /* =========================================================
       WARMUP PHASE
       - Use OLD variance update (no extreme guard)
       - Do NOT accumulate CUSUM
       ========================================================= */
    if (in_warmup) {
        cs->variance += cs->alpha_std *
                        (residual * residual - cs->variance);

        *out_S = 0.0;
        return false;
    }

    /* =========================================================
       POST-WARMUP PHASE
       - Use protected variance update (ANTI-POISON)
       ========================================================= */

    /* Compute current std BEFORE variance update */
    double current_std = sqrt(cs->variance);
    if (current_std < EWMA_EPSILON)
        current_std = EWMA_EPSILON;

    /* Skip variance update if residual is extreme */
    bool extreme = fabs(residual) > (5.0 * current_std);

    if (!extreme) {
        cs->variance += cs->alpha_std *
                        (residual * residual - cs->variance);
    }

    double ewma_std = sqrt(cs->variance);

    /* Guard: if std near zero, signal is stable → no alarm */
    if (ewma_std < EWMA_EPSILON) {
        cs->S  = 0.0;
        *out_S = 0.0;
        return false;
    }

    /* ---- Everything below this stays EXACTLY as you had it ---- */

    /*
     * VARIANCE CAPPING: Limit ewma_std to 50% of the EWMA mean.
     *
     * Prevents threshold explosion during bursty traffic.
     */
    double variance_cap = ewma->mean * 0.5;
    if (ewma_std > variance_cap) {
        ewma_std = variance_cap;
    }

    double k_abs = CUSUM_K * ewma_std;
    double H_abs = CUSUM_H * ewma_std;

    /* Upper CUSUM: detects positive (upward) shifts */
    double S_new = cs->S + (residual - k_abs);
    if (S_new < 0.0) S_new = 0.0;

    cs->S  = S_new;
    *out_S = S_new;

    return (S_new > H_abs);
}
/**
 * cusum_update_tier0 — run CUSUM for all 6 Tier-0 features.
 *
 * Uses variance-scaled threshold with single EWMA baseline.
 *
 * Returns count of features that fired an alarm (0..TIER0_N).
 */
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
                              &result->tier0_cusum_pps);
    if (alarm) alarm_count++;

    alarm = cusum_update_one(&engine->cusum[1], &stats->ewma_t0.bps,
                              cur->bps, in_warmup, frozen,
                              &result->tier0_cusum_bps);
    if (alarm) alarm_count++;

    alarm = cusum_update_one(&engine->cusum[2], &stats->ewma_t0.fps,
                              cur->fps, in_warmup, frozen,
                              &result->tier0_cusum_fps);
    if (alarm) alarm_count++;

    alarm = cusum_update_one(&engine->cusum[3], &stats->ewma_t0.burst_pps,
                              cur->burst_pps, in_warmup, frozen,
                              &result->tier0_cusum_burst_pps);
    if (alarm) alarm_count++;

    alarm = cusum_update_one(&engine->cusum[4], &stats->ewma_t0.burst_bps,
                              cur->burst_bps, in_warmup, frozen,
                              &result->tier0_cusum_burst_bps);
    if (alarm) alarm_count++;

    alarm = cusum_update_one(&engine->cusum[5], &stats->ewma_t0.burst_fps,
                              cur->burst_fps, in_warmup, frozen,
                              &result->tier0_cusum_burst_fps);
    if (alarm) alarm_count++;

    result->tier0_attack_count = alarm_count;
    result->tier0_score = (double)alarm_count / (double)TIER0_N;

    return alarm_count;
}

// ============================================================================
// TIER 1 — DISTANCE COMPUTATION  (unchanged)
// ============================================================================

/**
 * Normalised Manhattan distance for a single feature component:
 *
 *   d_i = |current_i - baseline_mean_i| / (baseline_mean_i + epsilon)
 *
 * During warm-up (n < EWMA_WARMUP_PERIODS) the component contributes 0
 * so it doesn't pollute the distance until the baseline is stable.
 */
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
// EWMA BASELINE UPDATE HELPERS — all tiers learn continuously
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
/* Reset Tier-0 CUSUM accumulators after confirmed recovery */
static void reset_tier0_cusum(struct detection_engine *engine)
{
    for (int i = 0; i < TIER0_N; i++) {
        engine->cusum[i].S = 0.0;
    }
}

// ============================================================================
// HORIZONTAL CONSOLE OUTPUT (from document 3)
// ============================================================================

#include <time.h>

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
    
    /* NEW: Tier-0 features with Mean (avg) and StdDev (±) */
    printf("T0 PPS:%.0f(avg:%.0f±%.0f) BPS:%.0f(avg:%.0f±%.0f) FPS:%.0f(avg:%.0f±%.0f) | ",
           t0->pps, stats->ewma_t0.pps.mean, sqrt(engine->cusum[0].variance),
           t0->bps, stats->ewma_t0.bps.mean, sqrt(engine->cusum[1].variance),
           t0->fps, stats->ewma_t0.fps.mean, sqrt(engine->cusum[2].variance));
    
    /* ORIGINAL: Tier-1 features */
    printf("TCP(S:%.2f SA:%.2f R:%.2f) UDP(B:%.2f P:%.2f) ICMP(E:%.2f) | ",
           t1_tcp->syn_ratio, t1_tcp->synack_ratio, t1_tcp->rst_ratio,
           t1_udp->udp_bps_ratio, t1_udp->udp_pps_ratio,
           t1_icmp->icmp_echo_ratio);

    /* Decisions */
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
// MAIN DETECTION LOGIC — SIMPLIFIED (NO RECOVERY STATE)
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

    /* ═══════════════════════════════════════════════════════════════════════
     * PHASE 1: FEATURE EXTRACTION (unchanged - always first)
     * ═══════════════════════════════════════════════════════════════════════ */
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

    /* ═══════════════════════════════════════════════════════════════════════
     * WARMUP PATH: Learn everything, make no decisions
     * ═══════════════════════════════════════════════════════════════════════ */
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

    /* ═══════════════════════════════════════════════════════════════════════
     * PHASE 2: EVALUATION ONLY (no updates yet)
     * ═══════════════════════════════════════════════════════════════════════ */
    
    /* Tick freeze counters */
    tick_freeze(&engine->tier0_state);
    tick_freeze(&engine->tier1_tcp_state);
    tick_freeze(&engine->tier1_udp_state);
    tick_freeze(&engine->tier1_icmp_state);
    tick_freeze(&engine->tier1_dist_state);

    /* TIER 0 CUSUM evaluation */
    bool tier0_frozen = engine->tier0_state.frozen;
    int alarm_count = cusum_update_tier0(engine, stats, &t0, &result, tier0_frozen);

    /* IMMEDIATE FREEZE on ANY alarm (prevents learning during confirmation) */
    if (alarm_count >= 1) {
        freeze_tier(&engine->tier0_state);
        freeze_tier(&engine->tier1_tcp_state);
        freeze_tier(&engine->tier1_udp_state);
        freeze_tier(&engine->tier1_icmp_state);
        freeze_tier(&engine->tier1_dist_state);
        
        /* Reset cooldown - not a clean window */
        engine->thaw_cooldown_counter = 0;
    }

    /* Persistence filter */
    if (alarm_count >= TIER0_ATTACK_THRESHOLD) {
        engine->consecutive_attack_counter++;
    } else {
        engine->consecutive_attack_counter = 0;
    }

    bool tier0_triggered = (engine->consecutive_attack_counter >= CONSECUTIVE_ATTACK_WINDOWS);

    /* Determine final_state through Tier-1 evaluation if needed */
    detection_state_t final_state;

    if (!tier0_triggered) {
        /* Tier-0 says NORMAL */
        final_state = DETECTION_STATE_NORMAL;
        
        /* Print console output */
        print_detection_horizontal(engine, stats, &t0, &t1_tcp, &t1_udp, &t1_icmp, &t1_dist,
                                   "NORMAL", "NORMAL", alarm_count);
    } else {
        /* Tier-0 triggered - evaluate Tier-1 */
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

        /* Freeze on ATTACK/SUSPICIOUS confirmation */
        if (final_state == DETECTION_STATE_ATTACK ||
            final_state == DETECTION_STATE_SUSPICIOUS) {
            
            freeze_tier(&engine->tier0_state);
            freeze_tier(&engine->tier1_tcp_state);
            freeze_tier(&engine->tier1_udp_state);
            freeze_tier(&engine->tier1_icmp_state);
            freeze_tier(&engine->tier1_dist_state);

            /* Print console output */
            print_detection_horizontal(engine, stats, &t0, &t1_tcp, &t1_udp, &t1_icmp, &t1_dist,
                                       "ATTACK", detection_state_str(final_state),
                                       alarm_count);

            if (engine->state != final_state) {
                engine->attack_count++;
                engine->last_attack_time = timestamp;
                printf("[Detection] *** %s *** cusum_alarms=%d/%d (persisted: %u windows) "
                       "tcp=%.3f udp=%.3f icmp=%.3f dist=%.3f\n",
                       detection_state_str(final_state),
                       alarm_count, TIER0_N,
                       engine->consecutive_attack_counter,
                       result.tier1_tcp_score, result.tier1_udp_score,
                       result.tier1_icmp_score, result.tier1_dist_score);
            }
        } else {
            /* Tier-1 cleared it */
            print_detection_horizontal(engine, stats, &t0, &t1_tcp, &t1_udp, &t1_icmp, &t1_dist,
                                       "ATTACK", "NORMAL", alarm_count);
        }
    }

    /* ═══════════════════════════════════════════════════════════════════════
     * PHASE 3: GATEKEEPER PATTERN - EWMA UPDATES ONLY FOR CLEAN WINDOWS
     * 
     * CRITICAL: Baselines updated ONLY when:
     *   1. final_state == NORMAL (Tier-1 confirmed clean)
     *   2. alarm_count == 0 (no Tier-0 alarms at all)
     * 
     * This prevents:
     *   - First-window poisoning (Tier-1 evaluates before learning)
     *   - Confirmation-phase poisoning (frozen during alarm_count >= 1)
     *   - Tail-end poisoning (thaw cooldown requirement)
     * ═══════════════════════════════════════════════════════════════════════ */
    
    if (final_state == DETECTION_STATE_NORMAL && alarm_count == 0) {
        /* CLEAN WINDOW: Increment cooldown and potentially thaw */
        engine->thaw_cooldown_counter++;

        if (engine->thaw_cooldown_counter >= THAW_COOLDOWN_WINDOWS) {

            if (engine->tier0_state.frozen) {
                printf("[Detection] Thaw cooldown complete (%u windows) - recovery confirmed, resetting CUSUM\n",
                    engine->thaw_cooldown_counter);
                }

                    /* 🔥 CRITICAL: Clear attack memory */
                    reset_tier0_cusum(engine);

            engine->consecutive_attack_counter = 0;

                    /* Unfreeze all tiers */
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

        /* UPDATE ALL BASELINES (only if tiers are unfrozen) */
        update_tier0_ewma     (&stats->ewma_t0,      &t0,     &engine->tier0_state);
        update_tier1_tcp_ewma (&stats->ewma_t1_tcp,  &t1_tcp,  &engine->tier1_tcp_state);
        update_tier1_udp_ewma (&stats->ewma_t1_udp,  &t1_udp,  &engine->tier1_udp_state);
        update_tier1_icmp_ewma(&stats->ewma_t1_icmp, &t1_icmp, &engine->tier1_icmp_state);
        update_tier1_dist_ewma(&stats->ewma_t1_dist, &t1_dist, &engine->tier1_dist_state);
    }
    /* else: NOT a clean window - NO baseline updates */

    /* Update engine state */
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