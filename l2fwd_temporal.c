/*
 * ============================================================================
 *  LEGACY MODULE — PRESERVED DURING DUAL-WRITE (Phase 3 — P7..P15)
 * ============================================================================
 *
 *  Status:      ACTIVE-LEGACY
 *  Retirement:  P16 cutover commit
 *  Destination: legacy/  (preserved as forensic reference)
 *
 *  This file is part of the per-IP detection architecture that is being
 *  replaced by the per-service architecture under l2fwd_service_*.{c,h}.
 *  It REMAINS COMPILED and ACTIVE during P7..P15 because:
 *
 *    1. It is the cross-validation reference that proves the new per-service
 *       hot path produces equivalent aggregate counters.
 *    2. It provides the rollback path until the new engine is signed off
 *       at P18.
 *
 *  DO NOT delete or rename this file before P16. The big-bang cutover
 *  prompt (P16) will move it to legacy/ atomically as part of the
 *  deprecation switch.
 *
 *  See docs/architecture_status.md and docs/migration_map.md for the
 *  full classification of every source file in this project.
 * ============================================================================
 */
/* l2fwd_ddos_collector.h must come first: it provides struct ewma_state
 * (referenced by value inside struct l2_temporal_baselines) and itself
 * pulls in l2fwd_temporal.h between its struct ewma_state and struct
 * dst_ip_stats definitions. The redundant explicit include below is
 * therefore a guarded no-op kept for documentation. See the include-
 * order precondition note in l2fwd_temporal.h. */
#include "l2fwd_ddos_collector.h"
#include "l2fwd_temporal.h"

/* l2fwd_detection_engine.h is included after the two headers above so
 * struct ewma_state, struct l2_temporal_state, and struct dst_ip_stats
 * are all visible by the time the detection-engine declarations are
 * parsed. It supplies the full definitions of struct tier0_features,
 * the four tier1_*_features structs, and struct detection_result that
 * l2_temporal_update_1s reads through pointers. */
#include "l2fwd_detection_engine.h"

#include <assert.h>
#include <float.h>
#include <math.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>

/* Optional debug instrumentation. Compile-time toggled so production
 * builds carry no runtime cost. Currently used only for invariant
 * assertions inside compute_window_stats(). */
#ifndef L2_TEMP_DEBUG
#define L2_TEMP_DEBUG 0
#endif

/* ============================================================================
 * Layer-2 multi-timescale temporal observability — init / reset / labels
 * + the once-per-second update path. Bucket folding, ring promotion, and
 * window-stats finalisation live here. Baseline updates, scoring, and
 * TEMP line emission are still intentionally absent — they land in a
 * subsequent commit so the wiring is reviewable in isolation. Nothing in
 * this file modifies any other module's state.
 * ========================================================================== */

/* Returns 0.0 when the denominator is non-positive, otherwise num/denom.
 * Used everywhere a ratio could otherwise blow up with a divide-by-zero
 * during a quiet window. */
static inline double safe_div(double num, double denom)
{
    return (denom > 0.0) ? (num / denom) : 0.0;
}

static inline double clip01(double x)
{
    if (x < 0.0) return 0.0;
    if (x > 1.0) return 1.0;
    return x;
}

static inline double max_double(double a, double b)
{
    return (a > b) ? a : b;
}

/* ----------------------------------------------------------------------------
 * Per-scale baseline view.
 *
 * struct l2_temporal_baselines lays the per-feature ewma_state instances
 * out as flat fields named with a `_<scale>` suffix. Scoring and update
 * code instead need a per-scale "view" — one set of pointers into the
 * baselines struct that corresponds to a particular l2_temp_scale_t. The
 * view is filled by resolve_scale_baselines() in a single switch-statement
 * dispatch and then consumed uniformly by the rest of the file.
 * -------------------------------------------------------------------------- */
struct scale_baselines {
    struct ewma_state *pps;
    struct ewma_state *bps;
    struct ewma_state *fps;

    struct ewma_state *tcp_pps_ratio;
    struct ewma_state *tcp_bps_ratio;
    struct ewma_state *udp_pps_ratio;
    struct ewma_state *udp_bps_ratio;
    struct ewma_state *udp_flow_ratio;
    struct ewma_state *icmp_pps_ratio;
    struct ewma_state *icmp_echo_ratio;

    struct ewma_state *tcp_syn_ratio;
    struct ewma_state *tcp_synack_ratio;
    struct ewma_state *tcp_finack_ratio;
    struct ewma_state *tcp_rst_ratio;
    struct ewma_state *tcp_ack_data_ratio;

    struct ewma_state *src_ip_ratio;
    struct ewma_state *dst_port_ratio;
};

static void resolve_scale_baselines(struct scale_baselines *sb,
                                     struct l2_temporal_baselines *b,
                                     l2_temp_scale_t scale)
{
    switch (scale) {
    case L2_TEMP_SCALE_10S:
        sb->pps                 = &b->pps_10s;
        sb->bps                 = &b->bps_10s;
        sb->fps                 = &b->fps_10s;
        sb->tcp_pps_ratio       = &b->tcp_pps_ratio_10s;
        sb->tcp_bps_ratio       = &b->tcp_bps_ratio_10s;
        sb->udp_pps_ratio       = &b->udp_pps_ratio_10s;
        sb->udp_bps_ratio       = &b->udp_bps_ratio_10s;
        sb->udp_flow_ratio      = &b->udp_flow_ratio_10s;
        sb->icmp_pps_ratio      = &b->icmp_pps_ratio_10s;
        sb->icmp_echo_ratio     = &b->icmp_echo_ratio_10s;
        sb->tcp_syn_ratio       = &b->tcp_syn_ratio_10s;
        sb->tcp_synack_ratio    = &b->tcp_synack_ratio_10s;
        sb->tcp_finack_ratio    = &b->tcp_finack_ratio_10s;
        sb->tcp_rst_ratio       = &b->tcp_rst_ratio_10s;
        sb->tcp_ack_data_ratio  = &b->tcp_ack_data_ratio_10s;
        sb->src_ip_ratio        = &b->src_ip_ratio_10s;
        sb->dst_port_ratio      = &b->dst_port_ratio_10s;
        break;
    case L2_TEMP_SCALE_60S:
        sb->pps                 = &b->pps_60s;
        sb->bps                 = &b->bps_60s;
        sb->fps                 = &b->fps_60s;
        sb->tcp_pps_ratio       = &b->tcp_pps_ratio_60s;
        sb->tcp_bps_ratio       = &b->tcp_bps_ratio_60s;
        sb->udp_pps_ratio       = &b->udp_pps_ratio_60s;
        sb->udp_bps_ratio       = &b->udp_bps_ratio_60s;
        sb->udp_flow_ratio      = &b->udp_flow_ratio_60s;
        sb->icmp_pps_ratio      = &b->icmp_pps_ratio_60s;
        sb->icmp_echo_ratio     = &b->icmp_echo_ratio_60s;
        sb->tcp_syn_ratio       = &b->tcp_syn_ratio_60s;
        sb->tcp_synack_ratio    = &b->tcp_synack_ratio_60s;
        sb->tcp_finack_ratio    = &b->tcp_finack_ratio_60s;
        sb->tcp_rst_ratio       = &b->tcp_rst_ratio_60s;
        sb->tcp_ack_data_ratio  = &b->tcp_ack_data_ratio_60s;
        sb->src_ip_ratio        = &b->src_ip_ratio_60s;
        sb->dst_port_ratio      = &b->dst_port_ratio_60s;
        break;
    case L2_TEMP_SCALE_300S:
        sb->pps                 = &b->pps_300s;
        sb->bps                 = &b->bps_300s;
        sb->fps                 = &b->fps_300s;
        sb->tcp_pps_ratio       = &b->tcp_pps_ratio_300s;
        sb->tcp_bps_ratio       = &b->tcp_bps_ratio_300s;
        sb->udp_pps_ratio       = &b->udp_pps_ratio_300s;
        sb->udp_bps_ratio       = &b->udp_bps_ratio_300s;
        sb->udp_flow_ratio      = &b->udp_flow_ratio_300s;
        sb->icmp_pps_ratio      = &b->icmp_pps_ratio_300s;
        sb->icmp_echo_ratio     = &b->icmp_echo_ratio_300s;
        sb->tcp_syn_ratio       = &b->tcp_syn_ratio_300s;
        sb->tcp_synack_ratio    = &b->tcp_synack_ratio_300s;
        sb->tcp_finack_ratio    = &b->tcp_finack_ratio_300s;
        sb->tcp_rst_ratio       = &b->tcp_rst_ratio_300s;
        sb->tcp_ack_data_ratio  = &b->tcp_ack_data_ratio_300s;
        sb->src_ip_ratio        = &b->src_ip_ratio_300s;
        sb->dst_port_ratio      = &b->dst_port_ratio_300s;
        break;
    case L2_TEMP_SCALE_COUNT:
    default:
        /* Defensive: caller passed an invalid scale. Zero the view so a
         * subsequent NULL-deref crashes loud and early in tests rather
         * than silently writing through a stale pointer. */
        memset(sb, 0, sizeof(*sb));
        break;
    }
}

/* Stamp the per-scale alpha onto every ewma_state in a scale group. */
static void init_scale_alphas(struct l2_temporal_baselines *b,
                               l2_temp_scale_t scale,
                               double alpha)
{
    struct scale_baselines sb;
    resolve_scale_baselines(&sb, b, scale);

    sb.pps->alpha                = alpha;
    sb.bps->alpha                = alpha;
    sb.fps->alpha                = alpha;
    sb.tcp_pps_ratio->alpha      = alpha;
    sb.tcp_bps_ratio->alpha      = alpha;
    sb.udp_pps_ratio->alpha      = alpha;
    sb.udp_bps_ratio->alpha      = alpha;
    sb.udp_flow_ratio->alpha     = alpha;
    sb.icmp_pps_ratio->alpha     = alpha;
    sb.icmp_echo_ratio->alpha    = alpha;
    sb.tcp_syn_ratio->alpha      = alpha;
    sb.tcp_synack_ratio->alpha   = alpha;
    sb.tcp_finack_ratio->alpha   = alpha;
    sb.tcp_rst_ratio->alpha      = alpha;
    sb.tcp_ack_data_ratio->alpha = alpha;
    sb.src_ip_ratio->alpha       = alpha;
    sb.dst_port_ratio->alpha     = alpha;
}

/* Per-scale valid_seconds floor. Returns UINT32_MAX for an invalid scale
 * so the gate fails closed. */
static uint32_t valid_seconds_floor(l2_temp_scale_t scale)
{
    switch (scale) {
    case L2_TEMP_SCALE_10S:  return L2_TEMP_VALID_10S_MIN;
    case L2_TEMP_SCALE_60S:  return L2_TEMP_VALID_60S_MIN;
    case L2_TEMP_SCALE_300S: return L2_TEMP_VALID_300S_MIN;
    case L2_TEMP_SCALE_COUNT:
    default:                 return UINT32_MAX;
    }
}

/* Push the current window_stats into every baseline of the given scale.
 * Called from the bucket-close path under the strict
 * (temporal NORMAL && 1s NORMAL) gate, and from the bootstrap path
 * during temporal warmup under (1s NORMAL) only. */
static void update_scale_baselines(const struct scale_baselines *sb,
                                    const struct l2_temporal_window_stats *ws)
{
    ewma_update(sb->pps,                ws->avg_pps);
    ewma_update(sb->bps,                ws->avg_bps);
    ewma_update(sb->fps,                ws->avg_fps);
    ewma_update(sb->tcp_pps_ratio,      ws->tcp_pps_ratio);
    ewma_update(sb->tcp_bps_ratio,      ws->tcp_bps_ratio);
    ewma_update(sb->udp_pps_ratio,      ws->udp_pps_ratio);
    ewma_update(sb->udp_bps_ratio,      ws->udp_bps_ratio);
    ewma_update(sb->udp_flow_ratio,     ws->udp_flow_ratio);
    ewma_update(sb->icmp_pps_ratio,     ws->icmp_pps_ratio);
    ewma_update(sb->icmp_echo_ratio,    ws->icmp_echo_ratio);
    ewma_update(sb->tcp_syn_ratio,      ws->tcp_syn_ratio);
    ewma_update(sb->tcp_synack_ratio,   ws->tcp_synack_ratio);
    ewma_update(sb->tcp_finack_ratio,   ws->tcp_finack_ratio);
    ewma_update(sb->tcp_rst_ratio,      ws->tcp_rst_ratio);
    ewma_update(sb->tcp_ack_data_ratio, ws->tcp_ack_data_ratio);
    ewma_update(sb->src_ip_ratio,       ws->src_ip_ratio);
    ewma_update(sb->dst_port_ratio,     ws->dst_port_ratio);
}

void l2_temporal_bucket_reset(struct l2_temporal_bucket_10s *b)
{
    if (b == NULL)
        return;

    memset(b, 0, sizeof(*b));

    /* min_* are initialised to a sentinel "no observation yet" value so
     * that the first folded 1-second window always wins the comparison.
     * max_* stay at 0 because per-second feature values are non-negative. */
    b->min_pps = DBL_MAX;
    b->min_bps = DBL_MAX;
    b->min_fps = DBL_MAX;
}

void l2_temporal_init(struct l2_temporal_state *st)
{
    if (st == NULL)
        return;

    /* Zero the entire structure first, then re-prime the per-bucket
     * min sentinels and stamp the per-scale EWMA alphas onto every
     * baseline. */
    memset(st, 0, sizeof(*st));

    l2_temporal_bucket_reset(&st->current_10s);
    for (size_t i = 0; i < L2_TEMP_RING_BUCKETS; i++)
        l2_temporal_bucket_reset(&st->ring_10s[i]);

    st->ring_index               = 0;
    st->ring_filled              = 0;
    st->seconds_into_current_10s = 0;

    /* Per-scale half-life-based smoothing factors. All ewma_state
     * instances inside a given scale group share the same alpha; see
     * the L2_TEMP_ALPHA_* tunables in l2fwd_temporal.h. */
    init_scale_alphas(&st->baselines, L2_TEMP_SCALE_10S,  L2_TEMP_ALPHA_10S);
    init_scale_alphas(&st->baselines, L2_TEMP_SCALE_60S,  L2_TEMP_ALPHA_60S);
    init_scale_alphas(&st->baselines, L2_TEMP_SCALE_300S, L2_TEMP_ALPHA_300S);

    /* L2_TEMPORAL_WARMUP == 0 so the memset above already covers this,
     * but the explicit loop documents intent and survives any future
     * renumbering of the enum. */
    for (size_t s = 0; s < L2_TEMP_SCALE_COUNT; s++)
        st->last_result.state[s] = L2_TEMPORAL_WARMUP;
}

const char *l2_temporal_state_str(l2_temporal_state_t state)
{
    switch (state) {
    case L2_TEMPORAL_WARMUP:     return "WARMUP";
    case L2_TEMPORAL_NORMAL:     return "NORMAL";
    case L2_TEMPORAL_WATCH:      return "WATCH";
    case L2_TEMPORAL_SUSPICIOUS: return "SUSPICIOUS";
    case L2_TEMPORAL_STRONG:     return "STRONG";
    }
    return "UNKNOWN";
}

/* ============================================================================
 * Internal helpers for the once-per-second update path.
 * ========================================================================== */

/* Fold one 1-second observation into the currently-filling bucket.
 * Caller must have already verified `cur->filled_seconds < L2_TEMP_BUCKET_SECONDS`.
 *
 * - Raw counters are summed (per-window aggregates).
 * - Volume features (pps/bps/fps) accumulate sum and track min/max.
 * - HLL-derived ratios accumulate sum only; window-finalisation divides
 *   by valid_seconds to produce a per-second-averaged ratio.
 * - Detector evidence: tier0_global_risk accumulates both sum (for an
 *   average at finalize) and max; tier1 sub-scores track max only.
 * - Per-state count is incremented based on `det->state` so the invariant
 *   `normal+warmup+suspicious+attack == filled_seconds` holds. */
static void fold_second_into_current(struct l2_temporal_bucket_10s *cur,
                                      const struct dst_ip_stats *stats,
                                      const struct tier0_features *t0,
                                      const struct tier1_udp_features *t1_udp,
                                      const struct tier1_dist_features *t1_dist,
                                      const struct detection_result *det)
{
    cur->filled_seconds++;

    cur->total_pkts      += stats->total_pkts;
    cur->total_bytes     += stats->total_bytes;
    cur->tcp_pkts        += stats->tcp_pkts;
    cur->tcp_bytes       += stats->tcp_bytes;
    cur->udp_pkts        += stats->udp_pkts;
    cur->udp_bytes       += stats->udp_bytes;
    cur->icmp_pkts       += stats->icmp_pkts;
    cur->icmp_echo_pkts  += stats->icmp_echo_pkts;
    cur->syn_pkts        += stats->syn_pkts;
    cur->synack_pkts     += stats->syn_ack_pkts;
    cur->finack_pkts     += stats->fin_ack_pkts;
    cur->rst_pkts        += stats->rst_pkts;
    cur->ack_data_pkts   += stats->ack_data_pkts;

    cur->sum_pps += t0->pps;
    if (t0->pps < cur->min_pps) cur->min_pps = t0->pps;
    if (t0->pps > cur->max_pps) cur->max_pps = t0->pps;

    cur->sum_bps += t0->bps;
    if (t0->bps < cur->min_bps) cur->min_bps = t0->bps;
    if (t0->bps > cur->max_bps) cur->max_bps = t0->bps;

    cur->sum_fps += t0->fps;
    if (t0->fps < cur->min_fps) cur->min_fps = t0->fps;
    if (t0->fps > cur->max_fps) cur->max_fps = t0->fps;

    cur->sum_udp_flow_ratio += t1_udp->udp_flow_ratio;
    cur->sum_src_ip_ratio   += t1_dist->src_ip_ratio;
    cur->sum_dst_port_ratio += t1_dist->dst_port_ratio;

    cur->sum_tier0_global_risk += det->tier0_global_risk;
    if (det->tier0_global_risk > cur->max_tier0_global_risk)
        cur->max_tier0_global_risk = det->tier0_global_risk;
    if (det->tier1_tcp_score   > cur->max_tier1_tcp_score)
        cur->max_tier1_tcp_score   = det->tier1_tcp_score;
    if (det->tier1_udp_score   > cur->max_tier1_udp_score)
        cur->max_tier1_udp_score   = det->tier1_udp_score;
    if (det->tier1_icmp_score  > cur->max_tier1_icmp_score)
        cur->max_tier1_icmp_score  = det->tier1_icmp_score;
    if (det->tier1_dist_score  > cur->max_tier1_dist_score)
        cur->max_tier1_dist_score  = det->tier1_dist_score;
    if (det->tier1_final_score > cur->max_tier1_final_score)
        cur->max_tier1_final_score = det->tier1_final_score;

    switch (det->state) {
    case DETECTION_STATE_NORMAL:     cur->normal_count++;     break;
    case DETECTION_STATE_WARMUP:     cur->warmup_count++;     break;
    case DETECTION_STATE_SUSPICIOUS: cur->suspicious_count++; break;
    case DETECTION_STATE_ATTACK:     cur->attack_count++;     break;
    }
}

/* Aggregate `n_buckets` closed buckets (pointed to by `buckets[]`) into a
 * fully-derived window_stats object. The output is overwritten — callers
 * do NOT need to pre-initialise `out`. NULL bucket pointers are skipped
 * defensively. */
static void compute_window_stats(struct l2_temporal_window_stats *out,
                                  uint16_t window_sec,
                                  const struct l2_temporal_bucket_10s *const *buckets,
                                  size_t n_buckets)
{
    memset(out, 0, sizeof(*out));
    out->window_sec = window_sec;

    double sum_pps = 0.0, min_pps = DBL_MAX, max_pps = 0.0;
    double sum_bps = 0.0, min_bps = DBL_MAX, max_bps = 0.0;
    double sum_fps = 0.0, min_fps = DBL_MAX, max_fps = 0.0;
    double sum_udp_flow_ratio    = 0.0;
    double sum_src_ip_ratio      = 0.0;
    double sum_dst_port_ratio    = 0.0;
    double sum_tier0_global_risk = 0.0;

    for (size_t i = 0; i < n_buckets; i++) {
        const struct l2_temporal_bucket_10s *b = buckets[i];
        if (b == NULL)
            continue;

        out->valid_seconds   += b->filled_seconds;

        out->total_pkts      += b->total_pkts;
        out->total_bytes     += b->total_bytes;
        out->tcp_pkts        += b->tcp_pkts;
        out->tcp_bytes       += b->tcp_bytes;
        out->udp_pkts        += b->udp_pkts;
        out->udp_bytes       += b->udp_bytes;
        out->icmp_pkts       += b->icmp_pkts;
        out->icmp_echo_pkts  += b->icmp_echo_pkts;
        out->syn_pkts        += b->syn_pkts;
        out->synack_pkts     += b->synack_pkts;
        out->finack_pkts     += b->finack_pkts;
        out->rst_pkts        += b->rst_pkts;
        out->ack_data_pkts   += b->ack_data_pkts;

        sum_pps += b->sum_pps;
        sum_bps += b->sum_bps;
        sum_fps += b->sum_fps;

        /* Only consult min / max if the bucket actually saw data, so the
         * DBL_MAX sentinel from an empty bucket can never leak through. */
        if (b->filled_seconds > 0) {
            if (b->min_pps < min_pps) min_pps = b->min_pps;
            if (b->max_pps > max_pps) max_pps = b->max_pps;
            if (b->min_bps < min_bps) min_bps = b->min_bps;
            if (b->max_bps > max_bps) max_bps = b->max_bps;
            if (b->min_fps < min_fps) min_fps = b->min_fps;
            if (b->max_fps > max_fps) max_fps = b->max_fps;
        }

        sum_udp_flow_ratio += b->sum_udp_flow_ratio;
        sum_src_ip_ratio   += b->sum_src_ip_ratio;
        sum_dst_port_ratio += b->sum_dst_port_ratio;

        sum_tier0_global_risk += b->sum_tier0_global_risk;
        if (b->max_tier0_global_risk > out->max_tier0_global_risk)
            out->max_tier0_global_risk = b->max_tier0_global_risk;
        if (b->max_tier1_tcp_score   > out->max_tier1_tcp_score)
            out->max_tier1_tcp_score   = b->max_tier1_tcp_score;
        if (b->max_tier1_udp_score   > out->max_tier1_udp_score)
            out->max_tier1_udp_score   = b->max_tier1_udp_score;
        if (b->max_tier1_icmp_score  > out->max_tier1_icmp_score)
            out->max_tier1_icmp_score  = b->max_tier1_icmp_score;
        if (b->max_tier1_dist_score  > out->max_tier1_dist_score)
            out->max_tier1_dist_score  = b->max_tier1_dist_score;
        if (b->max_tier1_final_score > out->max_tier1_final_score)
            out->max_tier1_final_score = b->max_tier1_final_score;

        /* uint8_t bucket counts are widened to uint32_t in window_stats
         * because 30 closed buckets × 10 seconds == 300 > UINT8_MAX. */
        out->normal_count     += b->normal_count;
        out->warmup_count     += b->warmup_count;
        out->suspicious_count += b->suspicious_count;
        out->attack_count     += b->attack_count;
    }

    const double vs = (double)out->valid_seconds;

    out->avg_pps = safe_div(sum_pps, vs);
    out->avg_bps = safe_div(sum_bps, vs);
    out->avg_fps = safe_div(sum_fps, vs);

    if (out->valid_seconds == 0) {
        /* Empty window — emit zeros rather than the DBL_MAX sentinel. */
        out->min_pps = 0.0; out->max_pps = 0.0;
        out->min_bps = 0.0; out->max_bps = 0.0;
        out->min_fps = 0.0; out->max_fps = 0.0;
    } else {
        out->min_pps = min_pps; out->max_pps = max_pps;
        out->min_bps = min_bps; out->max_bps = max_bps;
        out->min_fps = min_fps; out->max_fps = max_fps;
    }

    /* HLL-derived ratios — per-second averages over the contributing
     * seconds. NOT a full-window unique-count ratio; see the schema
     * comment in l2fwd_temporal.h. */
    out->udp_flow_ratio = safe_div(sum_udp_flow_ratio, vs);
    out->src_ip_ratio   = safe_div(sum_src_ip_ratio,   vs);
    out->dst_port_ratio = safe_div(sum_dst_port_ratio, vs);

    out->avg_tier0_global_risk = safe_div(sum_tier0_global_risk, vs);

    /* Exact protocol shares from the summed raw counters. */
    out->tcp_pps_ratio   = safe_div((double)out->tcp_pkts,       (double)out->total_pkts);
    out->tcp_bps_ratio   = safe_div((double)out->tcp_bytes,      (double)out->total_bytes);
    out->udp_pps_ratio   = safe_div((double)out->udp_pkts,       (double)out->total_pkts);
    out->udp_bps_ratio   = safe_div((double)out->udp_bytes,      (double)out->total_bytes);
    out->icmp_pps_ratio  = safe_div((double)out->icmp_pkts,      (double)out->total_pkts);
    out->icmp_echo_ratio = safe_div((double)out->icmp_echo_pkts, (double)out->icmp_pkts);

    /* Exact TCP flag ratios from the summed raw counters. */
    out->tcp_syn_ratio      = safe_div((double)out->syn_pkts,      (double)out->tcp_pkts);
    out->tcp_synack_ratio   = safe_div((double)out->synack_pkts,   (double)out->tcp_pkts);
    out->tcp_finack_ratio   = safe_div((double)out->finack_pkts,   (double)out->tcp_pkts);
    out->tcp_rst_ratio      = safe_div((double)out->rst_pkts,      (double)out->tcp_pkts);
    out->tcp_ack_data_ratio = safe_div((double)out->ack_data_pkts, (double)out->tcp_pkts);

#if L2_TEMP_DEBUG
    /* Identity invariant: the per-state counts must partition the valid
     * seconds exactly. Any drift here means fold_second_into_current()
     * lost or double-counted a per-second observation. */
    assert(out->normal_count + out->warmup_count
         + out->suspicious_count + out->attack_count
         == out->valid_seconds);
#endif
}

/* Populate `out_ptrs` with the most recent `n_requested` closed buckets
 * in chronological (oldest-to-newest) order, capped at `ring_filled`.
 * Returns the number actually populated so the caller can pass it
 * straight into compute_window_stats. `out_ptrs` must have room for at
 * least `n_requested` entries.
 *
 * Order semantics — LOCKED:
 *   out_ptrs[0]            : oldest bucket in the returned range
 *   out_ptrs[available-1]  : newest bucket (most recently closed)
 *
 * compute_window_stats() itself is order-insensitive (sums / mins /
 * maxes), but the upcoming ramp-score calculation in a later commit
 * compares the head of the window (older) against the tail (newer).
 * Reversing the order here would silently invert the ramp direction.
 * Do not change the ordering without auditing every caller and updating
 * the ramp_score logic at the same time.
 *
 * (A symmetric newest-first walk previously lived here; it had no
 * remaining caller after the switch to chronological iteration and was
 * removed. Reintroduce only with a clearly distinct name such as
 * collect_recent_buckets_newest_first() and only when a concrete debug
 * or non-ramp consumer needs it.) */
static size_t collect_recent_buckets_chronological(
    const struct l2_temporal_state *st,
    size_t n_requested,
    const struct l2_temporal_bucket_10s **out_ptrs)
{
    const size_t available =
        (n_requested > st->ring_filled) ? st->ring_filled : n_requested;

    /* ring_index points at the NEXT slot to overwrite, so the newest
     * bucket lives at (ring_index - 1) and the oldest of the last
     * `available` buckets lives at (ring_index - available), both
     * modulo ring size. Walking k forward from there yields oldest
     * first, newest last. */
    for (size_t k = 0; k < available; k++) {
        const size_t idx = (st->ring_index + L2_TEMP_RING_BUCKETS - available + k)
                           % L2_TEMP_RING_BUCKETS;
        out_ptrs[k] = &st->ring_10s[idx];
    }

#if L2_TEMP_DEBUG
    /* Sanity: out_ptrs[available - 1] must reference the newest bucket
     * (the slot immediately preceding ring_index). Any drift here means
     * the chronological invariant assumed by ramp scoring has broken. */
    if (available > 0) {
        const size_t newest_idx =
            (st->ring_index + L2_TEMP_RING_BUCKETS - 1) % L2_TEMP_RING_BUCKETS;
        assert(out_ptrs[available - 1] == &st->ring_10s[newest_idx]);
    }
#endif

    return available;
}

/* ----------------------------------------------------------------------------
 * Score one window against its same-scale baselines and, conditionally,
 * push the window's stats back into those baselines.
 *
 * Inputs:
 *   st         - per-IP temporal state (mutated: last_result and possibly
 *                baselines)
 *   scale      - which 10s/60s/300s slot we are scoring
 *   ws         - finalised stats for this window (read-only)
 *   ptrs / n_ptrs - the contributing closed buckets in chronological
 *                   (oldest-to-newest) order; consumed by the 60s ramp
 *                   path. The 10s and 300s paths ignore them.
 *   det_state  - the existing 1-second detector's verdict for THIS tick,
 *                used as the second half of the baseline-update gate.
 *
 * Behavioural rules (all locked):
 *   1. Set evaluated[scale] = true. The slot in last_result is fully
 *      reset before any computation so a stale value cannot leak across
 *      bucket closes.
 *   2. baseline_ready[scale] := (baseline.pps.n >= EWMA_WARMUP_PERIODS).
 *      If false, the temporal phase is forced to L2_TEMPORAL_WARMUP and
 *      no score is computed.
 *   3. valid_seconds floor (per scale): if ws->valid_seconds is below
 *      the floor, also force WARMUP and skip scoring.
 *   4. Otherwise compute the per-scale score using the locked weight
 *      matrix (10s: vol/proto/persistence; 60s: vol/proto/ramp/persistence;
 *      300s: vol/proto/persistence) and classify against the locked
 *      thresholds.
 *   5. Baseline update gate (mandatory anti-poisoning):
 *      - During temporal warmup (baseline not yet ready), update
 *        baselines whenever the existing 1-second detector reports
 *        DETECTION_STATE_NORMAL. This bootstraps the per-scale baseline
 *        without relying on its own scoring (which is not available
 *        until the baseline is itself ready).
 *      - Otherwise, update only when state[scale] == L2_TEMPORAL_NORMAL
 *        AND det_state == DETECTION_STATE_NORMAL. Any deviation from
 *        either gate skips the update entirely so a slow-ramp attack
 *        cannot drag the baseline upward.
 *
 * Shadow-mode invariant: this function NEVER writes to anything outside
 * st->last_result and st->baselines. It must not influence the existing
 * 1-second detection_result, the 62-column CSV, the policy module, or
 * the L3 bridge. Temporal scoring is observability-only.
 * -------------------------------------------------------------------------- */
static void score_window_and_maybe_update(
    struct l2_temporal_state *st,
    l2_temp_scale_t scale,
    const struct l2_temporal_window_stats *ws,
    const struct l2_temporal_bucket_10s *const *ptrs,
    size_t n_ptrs,
    detection_state_t det_state)
{
    /* Reset this scale's slot so a previous window's values cannot leak
     * through if we bail out early below. */
    st->last_result.evaluated[scale]            = true;
    st->last_result.score[scale]                = 0.0;
    st->last_result.volume_score[scale]         = 0.0;
    st->last_result.protocol_shift_score[scale] = 0.0;
    st->last_result.persistence_score[scale]    = 0.0;
    st->last_result.ramp_score[scale]           = 0.0;
    st->last_result.ratio_pps[scale]            = 0.0;
    st->last_result.ratio_bps[scale]            = 0.0;
    st->last_result.ratio_fps[scale]            = 0.0;
    st->last_result.z_pps[scale]                = 0.0;
    st->last_result.z_bps[scale]                = 0.0;
    st->last_result.z_fps[scale]                = 0.0;

    struct scale_baselines sb;
    resolve_scale_baselines(&sb, &st->baselines, scale);

    const bool det_normal      = (det_state == DETECTION_STATE_NORMAL);
    const bool baseline_ready  = (sb.pps->n >= EWMA_WARMUP_PERIODS);
    const uint32_t valid_floor = valid_seconds_floor(scale);
    const bool valid_enough    = (ws->valid_seconds >= valid_floor);

    st->last_result.baseline_ready[scale] = baseline_ready;

    /* Bootstrap path: baseline not yet ready. Force WARMUP, skip
     * scoring. We still update baselines if the 1-second detector
     * reports NORMAL — without this, the baseline's `n` would never
     * reach EWMA_WARMUP_PERIODS and the temporal phase would be stuck
     * in WARMUP forever. The 1s NORMAL gate alone is sufficient to
     * prevent poisoning during the bootstrap window. */
    if (!baseline_ready) {
        st->last_result.state[scale] = L2_TEMPORAL_WARMUP;
        if (det_normal)
            update_scale_baselines(&sb, ws);
        return;
    }

    /* Insufficient data path: baseline is mature but the closed window
     * doesn't carry enough seconds to trust either the score or the
     * sample. Force WARMUP and skip both scoring and any baseline
     * update so a sparse window cannot drift the baseline. */
    if (!valid_enough) {
        st->last_result.state[scale] = L2_TEMPORAL_WARMUP;
        return;
    }

    /* ----------------- volumetric ratios + z-scores ---------------- */
    const double pps_mean = sb.pps->mean;
    const double bps_mean = sb.bps->mean;
    const double fps_mean = sb.fps->mean;

    const double pps_ratio = safe_div(ws->avg_pps, pps_mean);
    const double bps_ratio = safe_div(ws->avg_bps, bps_mean);
    const double fps_ratio = safe_div(ws->avg_fps, fps_mean);

    /* User-spec floor: divide by max(std, 1.0). Keeps z-scores bounded
     * for very low-traffic baselines and matches the existing 1s
     * detector's defensive style. */
    const double pps_std = max_double(sqrt(sb.pps->variance), 1.0);
    const double bps_std = max_double(sqrt(sb.bps->variance), 1.0);
    const double fps_std = max_double(sqrt(sb.fps->variance), 1.0);

    const double pps_z = (ws->avg_pps - pps_mean) / pps_std;
    const double bps_z = (ws->avg_bps - bps_mean) / bps_std;
    const double fps_z = (ws->avg_fps - fps_mean) / fps_std;

    st->last_result.ratio_pps[scale] = pps_ratio;
    st->last_result.ratio_bps[scale] = bps_ratio;
    st->last_result.ratio_fps[scale] = fps_ratio;
    st->last_result.z_pps[scale]     = pps_z;
    st->last_result.z_bps[scale]     = bps_z;
    st->last_result.z_fps[scale]     = fps_z;

    /* Volume sub-score: max of normalised ratio and z components. */
    const double ratio_scale = (L2_TEMP_VOLUME_RATIO_FULL - 1.0);
    const double vol_components[6] = {
        clip01((pps_ratio - 1.0) / ratio_scale),
        clip01((bps_ratio - 1.0) / ratio_scale),
        clip01((fps_ratio - 1.0) / ratio_scale),
        clip01(pps_z / L2_TEMP_VOLUME_Z_FULL),
        clip01(bps_z / L2_TEMP_VOLUME_Z_FULL),
        clip01(fps_z / L2_TEMP_VOLUME_Z_FULL),
    };
    double volume_score = 0.0;
    for (size_t i = 0; i < 6; i++)
        if (vol_components[i] > volume_score)
            volume_score = vol_components[i];

    /* ----------------- protocol-shift sub-score -------------------- */
    /* Each shift is current_ratio - baseline_ratio, floored at 0 so a
     * drop in a protocol's share never registers as anomaly here. */
    const double shifts[8] = {
        max_double(0.0, ws->tcp_pps_ratio      - sb.tcp_pps_ratio->mean),
        max_double(0.0, ws->udp_pps_ratio      - sb.udp_pps_ratio->mean),
        max_double(0.0, ws->icmp_pps_ratio     - sb.icmp_pps_ratio->mean),
        max_double(0.0, ws->tcp_syn_ratio      - sb.tcp_syn_ratio->mean),
        max_double(0.0, ws->tcp_synack_ratio   - sb.tcp_synack_ratio->mean),
        max_double(0.0, ws->tcp_finack_ratio   - sb.tcp_finack_ratio->mean),
        max_double(0.0, ws->tcp_rst_ratio      - sb.tcp_rst_ratio->mean),
        max_double(0.0, ws->tcp_ack_data_ratio - sb.tcp_ack_data_ratio->mean),
    };
    double max_shift = 0.0;
    for (size_t i = 0; i < 8; i++)
        if (shifts[i] > max_shift)
            max_shift = shifts[i];
    const double protocol_shift_score = clip01(max_shift / L2_TEMP_PROTO_SHIFT_FULL);

    /* ----------------- persistence sub-score ----------------------- */
    /* Already in [0, 1] by construction (numerator is bounded above by
     * the denominator under the locked invariant
     * normal+warmup+suspicious+attack == valid_seconds). */
    const double persistence_score = safe_div(
        (double)(ws->suspicious_count + ws->attack_count),
        (double)ws->valid_seconds);

    /* ----------------- ramp sub-score (60s only) ------------------- */
    /* Compares the most recent 10s bucket (ptrs[n-1]) against the
     * average of the earlier buckets (ptrs[0..n-2]). Requires the
     * chronological ordering guaranteed by
     * collect_recent_buckets_chronological(). */
    double ramp_score = 0.0;
    if (scale == L2_TEMP_SCALE_60S && n_ptrs >= 2 && ptrs != NULL) {
        const struct l2_temporal_bucket_10s *latest = ptrs[n_ptrs - 1];
        const double latest_secs = (double)latest->filled_seconds;
        const double latest_pps  = safe_div(latest->sum_pps, latest_secs);
        const double latest_bps  = safe_div(latest->sum_bps, latest_secs);
        const double latest_fps  = safe_div(latest->sum_fps, latest_secs);

        double prev_sum_pps = 0.0, prev_sum_bps = 0.0, prev_sum_fps = 0.0;
        double prev_secs    = 0.0;
        for (size_t k = 0; k + 1 < n_ptrs; k++) {
            const struct l2_temporal_bucket_10s *p = ptrs[k];
            if (p == NULL) continue;
            prev_sum_pps += p->sum_pps;
            prev_sum_bps += p->sum_bps;
            prev_sum_fps += p->sum_fps;
            prev_secs    += (double)p->filled_seconds;
        }
        const double prev_pps = safe_div(prev_sum_pps, prev_secs);
        const double prev_bps = safe_div(prev_sum_bps, prev_secs);
        const double prev_fps = safe_div(prev_sum_fps, prev_secs);

        const double ramp_pps = safe_div(latest_pps, prev_pps);
        const double ramp_bps = safe_div(latest_bps, prev_bps);
        const double ramp_fps = safe_div(latest_fps, prev_fps);

        const double ramp_scale_full = (L2_TEMP_RAMP_FULL - 1.0);
        const double ramps[3] = {
            clip01((ramp_pps - 1.0) / ramp_scale_full),
            clip01((ramp_bps - 1.0) / ramp_scale_full),
            clip01((ramp_fps - 1.0) / ramp_scale_full),
        };
        for (size_t i = 0; i < 3; i++)
            if (ramps[i] > ramp_score)
                ramp_score = ramps[i];
    }

    /* ----------------- score fusion (per locked weights) ----------- */
    double score = 0.0;
    switch (scale) {
    case L2_TEMP_SCALE_10S:
        score = L2_TEMP_W10_VOLUME      * volume_score
              + L2_TEMP_W10_PROTOCOL    * protocol_shift_score
              + L2_TEMP_W10_PERSISTENCE * persistence_score;
        break;
    case L2_TEMP_SCALE_60S:
        score = L2_TEMP_W60_VOLUME      * volume_score
              + L2_TEMP_W60_PROTOCOL    * protocol_shift_score
              + L2_TEMP_W60_RAMP        * ramp_score
              + L2_TEMP_W60_PERSISTENCE * persistence_score;
        break;
    case L2_TEMP_SCALE_300S:
        score = L2_TEMP_W300_VOLUME      * volume_score
              + L2_TEMP_W300_PROTOCOL    * protocol_shift_score
              + L2_TEMP_W300_PERSISTENCE * persistence_score;
        break;
    case L2_TEMP_SCALE_COUNT:
    default:
        break;
    }
    score = clip01(score);

    /* ----------------- phase classification ------------------------ */
    l2_temporal_state_t phase;
    if (score < L2_TEMP_SCORE_NORMAL_MAX)            phase = L2_TEMPORAL_NORMAL;
    else if (score < L2_TEMP_SCORE_WATCH_MAX)        phase = L2_TEMPORAL_WATCH;
    else if (score < L2_TEMP_SCORE_SUSPICIOUS_MAX)   phase = L2_TEMPORAL_SUSPICIOUS;
    else                                             phase = L2_TEMPORAL_STRONG;

    st->last_result.volume_score[scale]         = volume_score;
    st->last_result.protocol_shift_score[scale] = protocol_shift_score;
    st->last_result.persistence_score[scale]    = persistence_score;
    st->last_result.ramp_score[scale]           = ramp_score;
    st->last_result.score[scale]                = score;
    st->last_result.state[scale]                = phase;

    /* Mandatory anti-poisoning gate: only update baselines when BOTH
     * the temporal phase for this scale AND the existing 1-second
     * detector verdict say the current window is benign. Slow-ramp
     * attacks rely on the baseline absorbing their traffic; this gate
     * keeps the baseline frozen the moment either detector flags
     * anomaly. */
    if (phase == L2_TEMPORAL_NORMAL && det_normal)
        update_scale_baselines(&sb, ws);
}

/* ----------------------------------------------------------------------------
 * TEMP record emission — locked 79-field schema (schema_ver = 1).
 *
 * Format: a single line ending in '\n', exactly 79 comma-separated fields
 * starting with the literal token "TEMP". Emitted on the dedicated
 * temporal Unix-domain socket only — never on the existing IP socket.
 *
 * Field index (1-based, locked; matches the Python parser added in a
 * later commit and the dst_ip_temporal_stats ClickHouse insert order):
 *
 *    1  TEMP                              record-type token
 *    2  schema_ver                        L2_TEMP_SCHEMA_VERSION
 *    3  rollup_ver                        L2_TEMP_ROLLUP_VERSION
 *    4  timestamp_ms                      end of just-closed second
 *    5  port                              DPDK port id
 *    6  dst_ip                            dotted-quad string
 *    7  window_sec                        10 / 60 / 300
 *    8  bucket_epoch_ms                   start of window (ts - vs*1000)
 *    9  valid_seconds                     contributing 1s slots
 *   10  baseline_ready                    0 / 1
 *   11  temporal_state                    WARMUP|NORMAL|WATCH|SUSPICIOUS|STRONG
 *
 *   Volume (3 metrics × 6 cols = 18):
 *   12-17  avg_pps, em_pps, ratio_pps, z_pps, min_pps, max_pps
 *   18-23  avg_bps, em_bps, ratio_bps, z_bps, min_bps, max_bps
 *   24-29  avg_fps, em_fps, ratio_fps, z_fps, min_fps, max_fps
 *
 *   Protocol-share pairs (7 pairs × 2 = 14):
 *   30-31  tcp_pps_ratio,    em_tcp_pps_ratio
 *   32-33  tcp_bps_ratio,    em_tcp_bps_ratio
 *   34-35  udp_pps_ratio,    em_udp_pps_ratio
 *   36-37  udp_bps_ratio,    em_udp_bps_ratio
 *   38-39  udp_flow_ratio,   em_udp_flow_ratio
 *   40-41  icmp_pps_ratio,   em_icmp_pps_ratio
 *   42-43  icmp_echo_ratio,  em_icmp_echo_ratio
 *
 *   TCP-flag pairs (5 pairs × 2 = 10):
 *   44-45  tcp_syn_ratio,       em_tcp_syn_ratio
 *   46-47  tcp_synack_ratio,    em_tcp_synack_ratio
 *   48-49  tcp_finack_ratio,    em_tcp_finack_ratio
 *   50-51  tcp_rst_ratio,       em_tcp_rst_ratio
 *   52-53  tcp_ack_data_ratio,  em_tcp_ack_data_ratio
 *
 *   Distribution pairs (2 pairs × 2 = 4):
 *   54-55  src_ip_ratio,    em_src_ip_ratio
 *   56-57  dst_port_ratio,  em_dst_port_ratio
 *
 *   Raw counters (13):
 *   58-59  total_pkts, total_bytes
 *   60-61  tcp_pkts, tcp_bytes
 *   62-63  udp_pkts, udp_bytes
 *   64-65  icmp_pkts, icmp_echo_pkts
 *   66-70  syn_pkts, synack_pkts, finack_pkts, rst_pkts, ack_data_pkts
 *
 *   Per-second detection-state tallies (4):
 *   71  normal_seconds
 *   72  warmup_seconds
 *   73  suspicious_seconds
 *   74  attack_seconds
 *
 *   Scores (5):
 *   75  volume_score
 *   76  protocol_shift_score
 *   77  persistence_score
 *   78  ramp_score                         (0.0 for window_sec ∈ {10,300})
 *   79  temporal_score                     fused score for this scale
 *
 * Sum: 11 + 18 + 14 + 10 + 4 + 13 + 4 + 5 = 79 fields.
 *
 * Discipline: do NOT reorder, add, remove, or rename a column without
 * updating the Python parser, the ClickHouse insert order, and bumping
 * L2_TEMP_SCHEMA_VERSION in the same commit (per the schema-locking
 * note in l2fwd_temporal.h).
 *
 * Best-effort send: any send() failure is swallowed and never affects
 * the existing IP record stream. The 8192-byte buffer is sized
 * comfortably above the ~1.3 KB the line actually consumes; a snprintf
 * truncation guard drops the line if anything ever overflows.
 * -------------------------------------------------------------------------- */
static void send_temporal_record(int temporal_sock_fd,
                                  uint64_t timestamp_ms,
                                  uint16_t port,
                                  const char *dst_ip_str,
                                  l2_temp_scale_t scale,
                                  const struct l2_temporal_window_stats *ws,
                                  const struct scale_baselines *sb,
                                  const struct l2_temporal_result *last_result)
{
    if (temporal_sock_fd < 0 || dst_ip_str == NULL || ws == NULL ||
        sb == NULL || last_result == NULL)
        return;

    /* bucket_epoch_ms = start of the contributing window. timestamp_ms
     * is the moment the most recent 1-second slot finished; subtracting
     * valid_seconds*1000 yields the start of the slot range that
     * actually fed this window. For 10s windows that is ts - 10000;
     * for 60s it's ts - 60000; for 300s it's ts - 300000. */
    const uint64_t bucket_epoch_ms =
        timestamp_ms - (uint64_t)ws->valid_seconds * 1000ULL;

    char buffer[8192];
    int len = snprintf(buffer, sizeof(buffer),
        /* Header (fields 1-11) */
        "TEMP,"            /*  1 record type   */
        "%u,%u,"           /*  2 schema_ver, 3 rollup_ver */
        "%llu,%u,%s,"      /*  4 ts_ms, 5 port, 6 dst_ip */
        "%u,%llu,"         /*  7 window_sec, 8 bucket_epoch_ms */
        "%u,%d,%s,"        /*  9 valid_seconds, 10 baseline_ready, 11 state */
        /* Volume (12-29): 3 metrics × (avg, em, ratio, z, min, max) */
        "%.4f,%.4f,%.4f,%.4f,%.4f,%.4f,"
        "%.4f,%.4f,%.4f,%.4f,%.4f,%.4f,"
        "%.4f,%.4f,%.4f,%.4f,%.4f,%.4f,"
        /* Protocol-share pairs (30-43) */
        "%.4f,%.4f,%.4f,%.4f,%.4f,%.4f,%.4f,%.4f,"
        "%.4f,%.4f,%.4f,%.4f,%.4f,%.4f,"
        /* TCP-flag pairs (44-53) */
        "%.4f,%.4f,%.4f,%.4f,%.4f,%.4f,%.4f,%.4f,%.4f,%.4f,"
        /* Distribution pairs (54-57) */
        "%.4f,%.4f,%.4f,%.4f,"
        /* Raw counters (58-70) */
        "%llu,%llu,%llu,%llu,%llu,%llu,%llu,%llu,"
        "%llu,%llu,%llu,%llu,%llu,"
        /* Per-state seconds (71-74) */
        "%u,%u,%u,%u,"
        /* Scores (75-79) */
        "%.4f,%.4f,%.4f,%.4f,%.4f\n",

        /* Header */
        (unsigned)L2_TEMP_SCHEMA_VERSION,
        (unsigned)L2_TEMP_ROLLUP_VERSION,
        (unsigned long long)timestamp_ms,
        (unsigned)port,
        dst_ip_str,
        (unsigned)ws->window_sec,
        (unsigned long long)bucket_epoch_ms,
        (unsigned)ws->valid_seconds,
        last_result->baseline_ready[scale] ? 1 : 0,
        l2_temporal_state_str(last_result->state[scale]),

        /* Volume — pps */
        ws->avg_pps,
        sb->pps->mean,
        last_result->ratio_pps[scale],
        last_result->z_pps[scale],
        ws->min_pps,
        ws->max_pps,
        /* Volume — bps */
        ws->avg_bps,
        sb->bps->mean,
        last_result->ratio_bps[scale],
        last_result->z_bps[scale],
        ws->min_bps,
        ws->max_bps,
        /* Volume — fps */
        ws->avg_fps,
        sb->fps->mean,
        last_result->ratio_fps[scale],
        last_result->z_fps[scale],
        ws->min_fps,
        ws->max_fps,

        /* Protocol shares (current, baseline) pairs */
        ws->tcp_pps_ratio,    sb->tcp_pps_ratio->mean,
        ws->tcp_bps_ratio,    sb->tcp_bps_ratio->mean,
        ws->udp_pps_ratio,    sb->udp_pps_ratio->mean,
        ws->udp_bps_ratio,    sb->udp_bps_ratio->mean,
        ws->udp_flow_ratio,   sb->udp_flow_ratio->mean,
        ws->icmp_pps_ratio,   sb->icmp_pps_ratio->mean,
        ws->icmp_echo_ratio,  sb->icmp_echo_ratio->mean,

        /* TCP flag pairs */
        ws->tcp_syn_ratio,       sb->tcp_syn_ratio->mean,
        ws->tcp_synack_ratio,    sb->tcp_synack_ratio->mean,
        ws->tcp_finack_ratio,    sb->tcp_finack_ratio->mean,
        ws->tcp_rst_ratio,       sb->tcp_rst_ratio->mean,
        ws->tcp_ack_data_ratio,  sb->tcp_ack_data_ratio->mean,

        /* Distribution pairs */
        ws->src_ip_ratio,    sb->src_ip_ratio->mean,
        ws->dst_port_ratio,  sb->dst_port_ratio->mean,

        /* Raw counters */
        (unsigned long long)ws->total_pkts,
        (unsigned long long)ws->total_bytes,
        (unsigned long long)ws->tcp_pkts,
        (unsigned long long)ws->tcp_bytes,
        (unsigned long long)ws->udp_pkts,
        (unsigned long long)ws->udp_bytes,
        (unsigned long long)ws->icmp_pkts,
        (unsigned long long)ws->icmp_echo_pkts,
        (unsigned long long)ws->syn_pkts,
        (unsigned long long)ws->synack_pkts,
        (unsigned long long)ws->finack_pkts,
        (unsigned long long)ws->rst_pkts,
        (unsigned long long)ws->ack_data_pkts,

        /* Per-state seconds */
        (unsigned)ws->normal_count,
        (unsigned)ws->warmup_count,
        (unsigned)ws->suspicious_count,
        (unsigned)ws->attack_count,

        /* Scores: volume / proto_shift / persistence / ramp / fused */
        last_result->volume_score[scale],
        last_result->protocol_shift_score[scale],
        last_result->persistence_score[scale],
        last_result->ramp_score[scale],
        last_result->score[scale]
    );

    /* snprintf returns the number of bytes that would have been written
     * (excluding the terminator) if the buffer were large enough. Anything
     * non-positive or >= buffer-size means the line is malformed and must
     * be dropped rather than partially emitted. */
    if (len <= 0 || (size_t)len >= sizeof(buffer))
        return;

    /* Best-effort send on the dedicated temporal stream. MSG_NOSIGNAL
     * prevents SIGPIPE if the receiver has gone away. The collector
     * owns temporal_sock_fd's lifecycle (its next tick reopens the
     * socket on failure), so we deliberately do NOT close it here.
     * Errors are swallowed: a temporal hiccup must never cascade into
     * IP-record loss on the *separate* IP socket. */
    (void)send(temporal_sock_fd, buffer, (size_t)len, MSG_NOSIGNAL);
}

/* Compose-and-emit wrapper used by l2_temporal_update_1s for each scale
 * that just finalised. Performs the score+baseline update first (writes
 * into st->last_result), then emits a TEMP line on a best-effort basis
 * over the dedicated temporal socket. Failure of either step has no
 * externally observable effect beyond the temporal state itself, and a
 * dropped TEMP record can never affect the existing IP path because
 * `temporal_sock_fd` is independent of the IP `sock_fd`. */
static void finalize_window(struct l2_temporal_state *st,
                             l2_temp_scale_t scale,
                             const struct l2_temporal_window_stats *ws,
                             const struct l2_temporal_bucket_10s *const *ptrs,
                             size_t n_ptrs,
                             detection_state_t det_state,
                             int temporal_sock_fd,
                             uint64_t timestamp_ms,
                             uint16_t port,
                             const char *dst_ip_str)
{
    score_window_and_maybe_update(st, scale, ws, ptrs, n_ptrs, det_state);

    /* temporal_sock_fd < 0 short-circuits inside send_temporal_record();
     * the outer guard simply avoids resolving baselines when we know we
     * won't emit, since that's the only work this branch does outside
     * the export call itself. Never falls back to the IP socket. */
    if (temporal_sock_fd < 0)
        return;

    struct scale_baselines sb_view;
    resolve_scale_baselines(&sb_view, &st->baselines, scale);
    send_temporal_record(temporal_sock_fd, timestamp_ms, port, dst_ip_str,
                          scale, ws, &sb_view, &st->last_result);
}

/* ============================================================================
 * Public API additions
 * ========================================================================== */

bool l2_temporal_update_1s(struct l2_temporal_state *st,
                           const struct dst_ip_stats *stats,
                           uint16_t port,
                           const char *dst_ip_str,
                           const struct tier0_features *t0,
                           const struct tier1_tcp_features *t1_tcp,
                           const struct tier1_udp_features *t1_udp,
                           const struct tier1_icmp_features *t1_icmp,
                           const struct tier1_dist_features *t1_dist,
                           const struct detection_result *det_result,
                           uint64_t timestamp_ms,
                           int temporal_sock_fd)
{
    /* Defensive null checks — keep the runtime contract robust against
     * partial wiring as the temporal pipeline is filled in commit-by-
     * commit. Returning false on any null means callers can ignore the
     * return value safely; nothing observable changes. dst_ip_str is
     * required because the export path needs it; if it ever goes missing
     * we drop the call completely rather than emit a malformed line. */
    if (st == NULL || stats == NULL || dst_ip_str == NULL ||
        t0 == NULL ||
        t1_tcp == NULL || t1_udp == NULL || t1_icmp == NULL ||
        t1_dist == NULL || det_result == NULL)
        return false;

    /* Parameters not yet consumed by the fold/score/export path — silence
     * -Wunused-parameter without changing the published signature. */
    (void)t1_tcp;
    (void)t1_icmp;

    /* Defensive: l2_temporal_bucket_reset() always runs after a close, so
     * a full bucket should never be observable on entry; treat it as a
     * no-op rather than risk a uint8_t overflow. */
    if (st->current_10s.filled_seconds >= L2_TEMP_BUCKET_SECONDS)
        return false;

    fold_second_into_current(&st->current_10s, stats, t0, t1_udp, t1_dist, det_result);
    st->seconds_into_current_10s++;

    if (st->current_10s.filled_seconds < L2_TEMP_BUCKET_SECONDS)
        return false;

    /* ----------------------- Bucket close path ---------------------- */

    /* Snapshot the just-closed bucket, push it onto the ring, then reset
     * the in-progress bucket so the next fold starts clean. */
    const struct l2_temporal_bucket_10s closed = st->current_10s;
    st->ring_10s[st->ring_index] = closed;
    st->ring_index = (uint8_t)((st->ring_index + 1) % L2_TEMP_RING_BUCKETS);
    if (st->ring_filled < L2_TEMP_RING_BUCKETS)
        st->ring_filled++;

    l2_temporal_bucket_reset(&st->current_10s);
    st->seconds_into_current_10s = 0;

    /* The window_stats objects below are stack-local on purpose — they
     * feed finalize_window(), which scores the window into st->last_result
     * and best-effort emits a TEMP line on `temporal_sock_fd`, then discards the
     * stats block. No window_stats copy lives on in the per-IP state.
     *
     * Scoring is shadow-only — it touches s->temporal.last_result and
     * s->temporal.baselines, nothing else. The existing 1-second
     * detection_state stays the sole input to enforcement. */

    /* 10-second scale — single just-closed bucket. */
    {
        const struct l2_temporal_bucket_10s *single[1] = { &closed };
        struct l2_temporal_window_stats w10;
        compute_window_stats(&w10, 10, single, 1);
        finalize_window(st, L2_TEMP_SCALE_10S, &w10, single, 1,
                         det_result->state, temporal_sock_fd,
                         timestamp_ms, port, dst_ip_str);
    }

    /* 60-second scale — last 6 closed buckets, in chronological
     * (oldest-to-newest) order. The order is required by the ramp
     * sub-score and locked at the helper level: do not switch to a
     * newest-first walk without simultaneously updating ramp_score in
     * score_window_and_maybe_update(). */
    if (st->ring_filled >= 6) {
        const struct l2_temporal_bucket_10s *ptrs[6];
        const size_t n = collect_recent_buckets_chronological(st, 6, ptrs);
        struct l2_temporal_window_stats w60;
        compute_window_stats(&w60, 60, ptrs, n);
        finalize_window(st, L2_TEMP_SCALE_60S, &w60, ptrs, n,
                         det_result->state, temporal_sock_fd,
                         timestamp_ms, port, dst_ip_str);
    }

    /* 300-second scale — full ring, in chronological (oldest-to-newest)
     * order. Same ordering contract as the 60s case above. ramp is not
     * a fusion component for the 300s scale per the locked weight
     * matrix, but the ordering is kept consistent so any future
     * ramp-like signal at this scale can rely on it without an audit. */
    if (st->ring_filled >= L2_TEMP_RING_BUCKETS) {
        const struct l2_temporal_bucket_10s *ptrs[L2_TEMP_RING_BUCKETS];
        const size_t n = collect_recent_buckets_chronological(
            st, L2_TEMP_RING_BUCKETS, ptrs);
        struct l2_temporal_window_stats w300;
        compute_window_stats(&w300, 300, ptrs, n);
        finalize_window(st, L2_TEMP_SCALE_300S, &w300, ptrs, n,
                         det_result->state, temporal_sock_fd,
                         timestamp_ms, port, dst_ip_str);
    }

    return true;
}
