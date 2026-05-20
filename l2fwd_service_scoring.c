/**
 * @file   l2fwd_service_scoring.c
 * @brief  Per-service detection scoring — P9 implementation.
 *
 * See l2fwd_service_scoring.h for the public-API contract. P9 ships the
 * full Tier-0 / Tier-1 / Off-proto stack + phase machine + baseline-
 * freeze coordination with the feature-extraction layer.
 *
 * Concurrency: all functions are called from the main lcore inside the
 * 1Hz tick. Read/writes to detection_state fields are single-writer; no
 * atomics needed at this layer.
 */

#include "l2fwd_service_scoring.h"
#include "l2fwd_service_stats.h"
#include "l2fwd_service_detection.h"
#include "l2fwd_service_features.h"
#include "l2fwd_service_registry.h"   /* learning_mode flag (phase suppression) */
#include "l2fwd_l2_profile.h"

#include <math.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

/* -------------------------------------------------------------------------
 * Default tuning constants.
 *
 * P9 hardcodes these. A future P9.1 or post-cutover prompt can move them
 * onto struct l2_profile so each services.json entry can override them.
 * The numbers here mirror the legacy l2fwd_detection_engine.c defaults
 * (T0_RISK_THRESHOLD, CONSECUTIVE_ATTACK_WINDOWS, BASELINE_FREEZE_WINDOWS,
 * THAW_COOLDOWN_WINDOWS), translated to the new normalised score system.
 * ------------------------------------------------------------------------- */

#define SCORING_DEFAULT_TIER0_K                 0.5  /* CUSUM slack (σ units)  */
#define SCORING_DEFAULT_TIER0_H                 4.0  /* CUSUM threshold (σ)    */
#define SCORING_DEFAULT_SUSPICIOUS_THRESHOLD    0.5
#define SCORING_DEFAULT_ATTACK_THRESHOLD        0.7
#define SCORING_DEFAULT_RECOVERY_THRESHOLD      0.3
#define SCORING_DEFAULT_PERSISTENCE_WINDOWS     3    /* SUSP→ATTACK count       */
#define SCORING_DEFAULT_RECOVERY_WINDOWS_SUSP   3    /* SUSP→NORMAL low-windows */
#define SCORING_DEFAULT_RECOVERY_WINDOWS_ATK    5    /* ATTACK→NORMAL low-wins  */
#define SCORING_DEFAULT_FREEZE_WINDOWS          60   /* baseline freeze ticks   */
#define SCORING_DEFAULT_THAW_WINDOWS            30   /* post-attack cautious    */

/* Tier-0 gate: burst channels scored by EWMA z-score (change 2). */
#define SCORING_BURST_Z_THRESHOLD          15.0

/* Tier-0 weighted-risk fusion weights (change 1). */
#define SCORING_T0_W_PPS                    2.5
#define SCORING_T0_W_BPS                    1.5
#define SCORING_T0_W_FPS                    0.5
#define SCORING_T0_W_BURST_PPS              0.8
#define SCORING_T0_W_BURST_BPS              0.6
#define SCORING_T0_W_BURST_FPS              0.3

/* R0 >= this opens the gate (Tier-0 Suspicious-or-Attack). Max
 * achievable R0 with the weights above is 6.2, so keep this below
 * that. The attack-level label is observability only in a gated
 * design — Tier-1 decides severity. */
#define SCORING_T0_GATE_RISK_THRESHOLD      5.0
#define SCORING_T0_ATTACK_RISK_THRESHOLD    6.0

/* Change 4: N consecutive Tier-0 gate-opens before Tier-1 runs. */
#define SCORING_GATE_PERSISTENCE_WINDOWS    3u

/* Dominant-channel argmax: below this, no channel is meaningful -> NONE. */
#define SCORING_DOMINANT_FLOOR              0.15

/* Volume gate: don't score a slot until we've seen at least this many
 * inbound packets in the current window. Prevents single-packet false
 * positives on quiet services. */
#define SCORING_TCP_MIN_PKTS                    10
#define SCORING_UDP_MIN_PKTS                    10
#define SCORING_ICMP_MIN_PKTS                   10
#define SCORING_DIST_MIN_PKTS                   10
#define SCORING_L3_MIN_PKTS                     10
#define SCORING_OFFPROTO_MIN_PKTS               10

#define EPS 1e-9

/* -------------------------------------------------------------------------
 * Lifecycle
 * ------------------------------------------------------------------------- */

int service_scoring_init(void) {
    fprintf(stderr, "[scoring] initialized "
                    "(tier0 k=%.2f h=%.2f, susp=%.2f attack=%.2f recover=%.2f, "
                    "persistence=%u freeze=%u thaw=%u)\n",
            SCORING_DEFAULT_TIER0_K,
            SCORING_DEFAULT_TIER0_H,
            SCORING_DEFAULT_SUSPICIOUS_THRESHOLD,
            SCORING_DEFAULT_ATTACK_THRESHOLD,
            SCORING_DEFAULT_RECOVERY_THRESHOLD,
            (unsigned)SCORING_DEFAULT_PERSISTENCE_WINDOWS,
            (unsigned)SCORING_DEFAULT_FREEZE_WINDOWS,
            (unsigned)SCORING_DEFAULT_THAW_WINDOWS);
    return 0;
}

void service_scoring_destroy(void) {
    /* No file-static state to release. Reserved for future use. */
}

/* -------------------------------------------------------------------------
 * Helpers
 * ------------------------------------------------------------------------- */

/* Map a z-score to a [0,1] risk via a sigmoid centred at |z|=3.
 *
 *   |z| = 0   -> ~0.05
 *   |z| = 3   -> 0.50
 *   |z| = 6   -> ~0.95
 *
 * Uses absolute value: both very low and very high z's are "anomalous"
 * from the baseline perspective. Most features in this codebase are
 * one-sided in practice (attacks push values up), but this is more
 * robust to features where either direction is anomalous (e.g.,
 * entropy collapse vs explosion).
 */
static inline double z_to_score(double z) {
    double abs_z = fabs(z);
    return 1.0 - 1.0 / (1.0 + exp(abs_z - 3.0));
}

/* Safe stddev from EWMA variance. Returns 0 for negative or NaN values. */
static inline double stddev_of(const struct service_ewma_state *e) {
    if (!e || !e->initialized) return 0.0;
    if (e->variance <= 0.0)    return 0.0;
    return sqrt(e->variance);
}

/* Return the slot's detection_state, casted from the void* in the slot.
 * Caller has already ensured it's non-NULL when needed. */
static inline struct service_detection_state *det_of(struct service_stats *slot) {
    return (struct service_detection_state *)slot->detection_state;
}

static inline const struct service_detection_state *
det_of_const(const struct service_stats *slot) {
    return (const struct service_detection_state *)slot->detection_state;
}

/* -------------------------------------------------------------------------
 * CUSUM primitive
 * ------------------------------------------------------------------------- */

bool service_scoring_cusum_update(struct service_cusum_state *state,
                                   double x, double mean, double stddev,
                                   double k, double h)
{
    if (!state) return false;
    state->last_value = x;

    /* No usable baseline -> CUSUM disabled. */
    if (stddev < EPS) return false;

    double deviation = (x - mean) / stddev;
    state->S_plus = fmax(0.0, state->S_plus + deviation - k);

    /* Breach: S_plus is elevated AND the current tick contributed
     * positive deviation. The `deviation > 0` gate keeps CUSUM from
     * shouting "breach!" during the long tail of recovery, when S_plus
     * is still draining from a past attack but the process has already
     * returned to (or fallen below) the baseline mean. Without this
     * gate the Tier-0 composite score would stay sticky for ~h/k ticks
     * after every attack, blocking the phase machine's NORMAL recovery
     * path. */
    if (state->S_plus > h && deviation > 0.0) {
        state->breach_count++;
        return true;
    }
    return false;
}

void service_scoring_cusum_reset(struct service_cusum_state *state) {
    if (!state) return;
    memset(state, 0, sizeof(*state));
}

/* -------------------------------------------------------------------------
 * Tier-0: volumetric ramp detection across 6 channels
 * ------------------------------------------------------------------------- */

/* CHANGE 2: burst risk via EWMA z-score, NOT CUSUM. */
static double burst_z_risk(const struct service_ewma_state *ewma_burst,
                           double z_last)
{
    double z = service_ewma_z_score(ewma_burst, z_last);
    double r = fabs(z) / SCORING_BURST_Z_THRESHOLD;
    return (r > 1.0) ? 1.0 : r;
}

double service_scoring_tier0_evaluate(struct service_stats *slot)
{
    if (!slot || !slot->detection_state) return 0.0;
    struct service_detection_state *det = det_of(slot);

    const double k = SCORING_DEFAULT_TIER0_K;
    const double h = SCORING_DEFAULT_TIER0_H;

    /* CHANGE 4: under the full ATTACK-freeze the CUSUM accumulators are
     * HELD — we do not call service_scoring_cusum_update, so S_plus/S_minus/
     * last_value are left exactly as they were and resume on thaw. R0 is
     * recomputed from the frozen S_plus (no accumulator mutation). The
     * EWMA-only freeze does NOT freeze CUSUM: CUSUM is what detects the
     * ramp, so it must stay live there. */
    const bool cusum_frozen = service_scoring_cusum_is_frozen(slot);

    /* --- CHANGE 1: CUSUM only on pps, bps, fps --- */
    double r_pps = 0.0, r_bps = 0.0, r_fps = 0.0;
    {
        if (!cusum_frozen) {
            double x      = (double)slot->common.inbound_pkts;
            double mean   = slot->common_ewma.pps.mean;
            double stddev = stddev_of(&slot->common_ewma.pps);
            if (service_scoring_cusum_update(&det->cusum_pps, x, mean, stddev, k, h))
                r_pps = fmin(1.0, det->cusum_pps.S_plus / h);
        } else {
            r_pps = fmin(1.0, det->cusum_pps.S_plus / h);   /* held value */
        }
        det->last_tier0_risk_pps = r_pps;
    }
    {
        if (!cusum_frozen) {
            double x      = (double)slot->common.inbound_bytes * 8.0;
            double mean   = slot->common_ewma.bps.mean;
            double stddev = stddev_of(&slot->common_ewma.bps);
            if (service_scoring_cusum_update(&det->cusum_bps, x, mean, stddev, k, h))
                r_bps = fmin(1.0, det->cusum_bps.S_plus / h);
        } else {
            r_bps = fmin(1.0, det->cusum_bps.S_plus / h);   /* held value */
        }
        det->last_tier0_risk_bps = r_bps;
    }
    {
        if (!cusum_frozen) {
            double x      = service_hll_estimate(&slot->common.unique_flows);
            double mean   = slot->common_ewma.fps.mean;
            double stddev = stddev_of(&slot->common_ewma.fps);
            if (service_scoring_cusum_update(&det->cusum_fps, x, mean, stddev, k, h))
                r_fps = fmin(1.0, det->cusum_fps.S_plus / h);
        } else {
            r_fps = fmin(1.0, det->cusum_fps.S_plus / h);   /* held value */
        }
        det->last_tier0_risk_fps = r_fps;
    }

    /* --- CHANGE 2: burst channels by z-score (NO CUSUM) --- */
    double r_bpps = burst_z_risk(&slot->common_ewma.burst_pps,
                                 slot->common.bw_pps.z_last);
    double r_bbps = burst_z_risk(&slot->common_ewma.burst_bps,
                                 slot->common.bw_bps.z_last);
    double r_bfps = burst_z_risk(&slot->common_ewma.burst_fps,
                                 slot->common.bw_fps.z_last);
    det->last_tier0_risk_burst_pps = r_bpps;
    det->last_tier0_risk_burst_bps = r_bbps;
    det->last_tier0_risk_burst_fps = r_bfps;

    /* --- Weighted composite risk (restores the per-IP design) --- */
    double R0 = SCORING_T0_W_PPS       * r_pps
              + SCORING_T0_W_BPS       * r_bps
              + SCORING_T0_W_FPS       * r_fps
              + SCORING_T0_W_BURST_PPS * r_bpps
              + SCORING_T0_W_BURST_BPS * r_bbps
              + SCORING_T0_W_BURST_FPS * r_bfps;

    det->last_tier0_score = R0;
    return R0;
}

/* -------------------------------------------------------------------------
 * Tier-1 sub-channel scores
 * ------------------------------------------------------------------------- */

double service_scoring_tier1_tcp(const struct service_stats *slot)
{
    if (!slot) return 0.0;

    const struct service_tcp_ewma  *e = NULL;
    const struct service_tcp_stats *t = NULL;

    switch (slot->proto_kind) {
    case SERVICE_PROTO_TCP:
    case SERVICE_PROTO_CATCHALL_TCP:
        e = &slot->proto.tcp.ewma;
        t = &slot->proto.tcp.stats;
        break;
    case SERVICE_PROTO_CATCHALL_OTHER:
        e = &slot->proto.other_catchall.tcp_ewma;
        t = &slot->proto.other_catchall.tcp_stats;
        break;
    default:
        return 0.0;
    }
    if (t->tcp_pkts < SCORING_TCP_MIN_PKTS) return 0.0;

    double dn          = (double)t->tcp_pkts;
    double syn_r       = (double)t->syn_pkts          / dn;
    double empty_ack_r = (double)t->empty_ack_pkts    / dn;
    double zero_win_r  = (double)t->zero_window_pkts  / dn;
    double syn_to_sa   = (t->syn_ack_pkts > 0)
        ? (double)t->syn_pkts / (double)t->syn_ack_pkts
        : (double)t->syn_pkts;

    /* Packet-size CoV from raw sums (matches what features.c feeds the
     * EWMA each tick, but computed fresh here to score the current
     * window value against the EWMA baseline). */
    double pkt_mean = dn > 0.0 ? (double)t->tcp_pkt_size_sum / dn : 0.0;
    double pkt_var  = (t->tcp_pkts > 1)
        ? ((double)t->tcp_pkt_size_sum_sq / dn - pkt_mean * pkt_mean)
        : 0.0;
    if (pkt_var < 0.0) pkt_var = 0.0;
    double pkt_cov  = (pkt_mean > 0.0) ? sqrt(pkt_var) / pkt_mean : 0.0;

    double z1 = service_ewma_z_score(&e->syn_ratio,           syn_r);
    double z2 = service_ewma_z_score(&e->empty_ack_ratio,     empty_ack_r);
    double z3 = service_ewma_z_score(&e->zero_window_ratio,   zero_win_r);
    double z4 = service_ewma_z_score(&e->syn_to_synack_ratio, syn_to_sa);
    double z5 = service_ewma_z_score(&e->tcp_pkt_size_cov,    pkt_cov);

    double s = (z_to_score(z1) + z_to_score(z2) + z_to_score(z3)
              + z_to_score(z4) + z_to_score(z5)) / 5.0;
    return fmin(1.0, s);
}

double service_scoring_tier1_udp(const struct service_stats *slot)
{
    if (!slot) return 0.0;

    const struct service_udp_ewma  *e = NULL;
    const struct service_udp_stats *u = NULL;

    switch (slot->proto_kind) {
    case SERVICE_PROTO_UDP:
    case SERVICE_PROTO_CATCHALL_UDP:
        e = &slot->proto.udp.ewma;
        u = &slot->proto.udp.stats;
        break;
    case SERVICE_PROTO_CATCHALL_OTHER:
        e = &slot->proto.other_catchall.udp_ewma;
        u = &slot->proto.other_catchall.udp_stats;
        break;
    default:
        return 0.0;
    }
    if (u->udp_pkts < SCORING_UDP_MIN_PKTS) return 0.0;

    double dn        = (double)u->udp_pkts;
    double pkt_mean  = (double)u->udp_pkt_size_sum / dn;
    double pkt_var   = (u->udp_pkts > 1)
        ? ((double)u->udp_pkt_size_sum_sq / dn - pkt_mean * pkt_mean)
        : 0.0;
    if (pkt_var < 0.0) pkt_var = 0.0;
    double pkt_cov   = (pkt_mean > 0.0) ? sqrt(pkt_var) / pkt_mean : 0.0;
    double flows_est = service_hll_estimate(&u->udp_flows);
    double flow_r    = flows_est / dn;

    double z1 = service_ewma_z_score(&e->udp_pps_ratio,     dn);
    double z2 = service_ewma_z_score(&e->udp_flow_ratio,    flow_r);
    double z3 = service_ewma_z_score(&e->udp_pkt_size_cov,  pkt_cov);
    double z4 = service_ewma_z_score(&e->udp_mean_pkt_size, pkt_mean);

    double s = (z_to_score(z1) + z_to_score(z2) + z_to_score(z3)
              + z_to_score(z4)) / 4.0;
    return fmin(1.0, s);
}

double service_scoring_tier1_icmp(const struct service_stats *slot)
{
    if (!slot) return 0.0;

    const struct service_icmp_ewma  *e = NULL;
    const struct service_icmp_stats *ic = NULL;

    switch (slot->proto_kind) {
    case SERVICE_PROTO_ICMP:
    case SERVICE_PROTO_CATCHALL_ICMP:
        e  = &slot->proto.icmp.ewma;
        ic = &slot->proto.icmp.stats;
        break;
    case SERVICE_PROTO_CATCHALL_OTHER:
        e  = &slot->proto.other_catchall.icmp_ewma;
        ic = &slot->proto.other_catchall.icmp_stats;
        break;
    default:
        return 0.0;
    }
    if (ic->icmp_pkts < SCORING_ICMP_MIN_PKTS) return 0.0;

    double dn     = (double)ic->icmp_pkts;
    double echo_r = (double)ic->icmp_echo_pkts / dn;

    double z1 = service_ewma_z_score(&e->icmp_pps_ratio,  dn);
    double z2 = service_ewma_z_score(&e->icmp_echo_ratio, echo_r);

    double s = (z_to_score(z1) + z_to_score(z2)) / 2.0;
    return fmin(1.0, s);
}

double service_scoring_tier1_distribution(const struct service_stats *slot)
{
    if (!slot) return 0.0;
    if (slot->common.inbound_pkts < SCORING_DIST_MIN_PKTS) return 0.0;

    /* 1. src_ip_ratio (unique src IPs / inbound pkts).
     * 2. src_24_top1_share (heavy /24 concentration → high).
     * 3. src_24_entropy (drop in entropy → high; sign-flip the z). */
    double unique = service_hll_estimate(&slot->common.unique_src_ips);
    double sir    = (slot->common.inbound_pkts > 0)
                  ? unique / (double)slot->common.inbound_pkts : 0.0;
    double z_sir  = service_ewma_z_score(&slot->common_ewma.src_ip_ratio, sir);

    double top1   = service_cm_top1_share(
                       (uint64_t)slot->common.cm_src_24.top_count,
                       slot->common.cm_src_24.total);
    double z_top1 = service_ewma_z_score(
                       &slot->common_ewma.src_24_top1_share, top1);

    double ent    = service_cm_src_24_entropy(&slot->common.cm_src_24);
    double z_ent  = -service_ewma_z_score(
                       &slot->common_ewma.src_24_entropy, ent);

    double s = (z_to_score(z_sir) + z_to_score(z_top1) + z_to_score(z_ent)) / 3.0;
    return fmin(1.0, s);
}

double service_scoring_tier1_l3(const struct service_stats *slot)
{
    if (!slot) return 0.0;
    if (slot->common.inbound_pkts < SCORING_L3_MIN_PKTS) return 0.0;

    /* TTL stddev (anomalous when high — multi-source flooding). */
    double pkts = (double)slot->common.inbound_pkts;
    double ttl_mean   = (pkts > 0.0) ? (double)slot->common.ttl_sum / pkts : 0.0;
    double ttl_var    = (slot->common.inbound_pkts > 1)
        ? ((double)slot->common.ttl_sum_sq / pkts - ttl_mean * ttl_mean)
        : 0.0;
    if (ttl_var < 0.0) ttl_var = 0.0;
    double ttl_stddev = sqrt(ttl_var);
    double z_ttl      = service_ewma_z_score(
                          &slot->common_ewma.ttl_stddev, ttl_stddev);

    /* Fragment ratio (fragments are unusual; large value → suspicious). */
    double frag_r = (pkts > 0.0)
                    ? (double)slot->common.ip_frag_pkts / pkts : 0.0;
    /* We don't track a dedicated frag-ratio EWMA in P8; reuse
     * off_proto_pkts_ratio EWMA as a proxy. Acceptable: frag spikes
     * tend to co-occur with off-proto traffic, and we'll separate them
     * cleanly once an ip_frag EWMA lands. */
    double z_frag = z_to_score(frag_r * 20.0);   /* coarse linear ramp */

    /* off_proto_pkts_ratio z. */
    double off_r = (pkts > 0.0)
                  ? (double)slot->common.off_proto_pkts / pkts : 0.0;
    double z_off = service_ewma_z_score(
                     &slot->common_ewma.off_proto_pkts_ratio, off_r);

    double s = (z_to_score(z_ttl) + z_frag + z_to_score(z_off)) / 3.0;
    return fmin(1.0, s);
}

double service_scoring_offproto(const struct service_stats *slot)
{
    if (!slot) return 0.0;
    if (slot->common.inbound_pkts < SCORING_OFFPROTO_MIN_PKTS) return 0.0;
    double r = (double)slot->common.off_proto_pkts /
               (double)slot->common.inbound_pkts;
    double z = service_ewma_z_score(
                  &slot->common_ewma.off_proto_pkts_ratio, r);
    return z_to_score(z);
}

/* -------------------------------------------------------------------------
 * Dominant-channel argmax
 *
 * Picks the single channel that best explains the current attack shape, as an
 * argmax across BOTH tiers but ONLY over channels live for this proto_kind.
 * Each Tier-0 burst channel folds into its base (burst_pps competes as PPS,
 * etc.) via max(). Below SCORING_DOMINANT_FLOOR -> DOMINANT_NONE. Ties prefer
 * the lower enum value (Tier-0 volumetric before Tier-1 behavioral): we scan
 * ascending and only replace on a strictly-greater value.
 *
 * Must be called after the last_tier0_risk_* and last_tier1_* caches are set.
 * ------------------------------------------------------------------------- */
static uint8_t scoring_compute_dominant(const struct service_detection_state *det,
                                        uint8_t proto_kind)
{
    /* Candidate value per channel, indexed by enum service_dominant_channel.
     * -1.0 marks a channel that is NOT live for this slot. */
    double cand[DOMINANT_OFFPROTO + 1];
    for (int i = 0; i <= DOMINANT_OFFPROTO; i++) cand[i] = -1.0;

    /* Tier-0 volumetric — always live for every proto_kind; fold in burst. */
    cand[DOMINANT_PPS] = fmax(det->last_tier0_risk_pps, det->last_tier0_risk_burst_pps);
    cand[DOMINANT_BPS] = fmax(det->last_tier0_risk_bps, det->last_tier0_risk_burst_bps);
    cand[DOMINANT_FPS] = fmax(det->last_tier0_risk_fps, det->last_tier0_risk_burst_fps);

    /* Universal Tier-1 — live for every proto_kind. */
    cand[DOMINANT_DIST]     = det->last_tier1_dist_score;
    cand[DOMINANT_L3]       = det->last_tier1_l3_score;
    cand[DOMINANT_OFFPROTO] = det->last_tier1_offproto_score;

    /* Proto-family Tier-1 — only the arm(s) live for this slot. A TCP slot
     * must NEVER report a UDP/ICMP dominant, so non-matching arms stay -1. */
    switch (proto_kind) {
    case SERVICE_PROTO_TCP:
    case SERVICE_PROTO_CATCHALL_TCP:
        cand[DOMINANT_TCP] = det->last_tier1_tcp_score;
        break;
    case SERVICE_PROTO_UDP:
    case SERVICE_PROTO_CATCHALL_UDP:
        cand[DOMINANT_UDP] = det->last_tier1_udp_score;
        break;
    case SERVICE_PROTO_ICMP:
    case SERVICE_PROTO_CATCHALL_ICMP:
        cand[DOMINANT_ICMP] = det->last_tier1_icmp_score;
        break;
    case SERVICE_PROTO_CATCHALL_OTHER:
        cand[DOMINANT_TCP]  = det->last_tier1_tcp_score;
        cand[DOMINANT_UDP]  = det->last_tier1_udp_score;
        cand[DOMINANT_ICMP] = det->last_tier1_icmp_score;
        break;
    default:
        break;
    }

    /* Argmax, ascending scan with strict-greater -> low-enum tie-break. */
    uint8_t best_ch = DOMINANT_NONE;
    double  best_v  = 0.0;
    for (int i = DOMINANT_PPS; i <= DOMINANT_OFFPROTO; i++) {
        if (cand[i] > best_v) {
            best_v  = cand[i];
            best_ch = (uint8_t)i;
        }
    }

    return (best_v < SCORING_DOMINANT_FLOOR) ? DOMINANT_NONE : best_ch;
}

/* -------------------------------------------------------------------------
 * Combine sub-scores into the final Tier-1 score
 * ------------------------------------------------------------------------- */

double service_scoring_combine(struct service_stats *slot)
{
    if (!slot || !slot->detection_state) return 0.0;
    struct service_detection_state *det = det_of(slot);

    det->last_tier1_tcp_score      = service_scoring_tier1_tcp(slot);
    det->last_tier1_udp_score      = service_scoring_tier1_udp(slot);
    det->last_tier1_icmp_score     = service_scoring_tier1_icmp(slot);
    det->last_tier1_dist_score     = service_scoring_tier1_distribution(slot);
    det->last_tier1_l3_score       = service_scoring_tier1_l3(slot);
    det->last_tier1_offproto_score = service_scoring_offproto(slot);

    /* Pick the proto-channel score that matches the slot's kind. */
    double proto_score = 0.0;
    switch (slot->proto_kind) {
    case SERVICE_PROTO_TCP:
    case SERVICE_PROTO_CATCHALL_TCP:
        proto_score = det->last_tier1_tcp_score;
        break;
    case SERVICE_PROTO_UDP:
    case SERVICE_PROTO_CATCHALL_UDP:
        proto_score = det->last_tier1_udp_score;
        break;
    case SERVICE_PROTO_ICMP:
    case SERVICE_PROTO_CATCHALL_ICMP:
        proto_score = det->last_tier1_icmp_score;
        break;
    case SERVICE_PROTO_CATCHALL_OTHER:
        proto_score = fmax(fmax(det->last_tier1_tcp_score,
                                 det->last_tier1_udp_score),
                            det->last_tier1_icmp_score);
        break;
    default:
        break;
    }

    /* Weighted MAX — any one strong channel triggers. */
    double final_score = fmax(proto_score,
                          fmax(det->last_tier1_dist_score,
                          fmax(det->last_tier1_l3_score,
                               det->last_tier1_offproto_score)));

    det->last_tier1_final_score = final_score;
    det->last_tier1_evaluated   = true;

    /* Dominant channel: argmax across both tiers over this slot's live
     * channels (after all caches above are populated). */
    det->last_dominant_channel = scoring_compute_dominant(det, slot->proto_kind);

    return final_score;
}

const char *service_scoring_dominant_name(uint8_t dominant)
{
    switch (dominant) {
    case DOMINANT_NONE:     return "NONE";
    case DOMINANT_PPS:      return "PPS";
    case DOMINANT_BPS:      return "BPS";
    case DOMINANT_FPS:      return "FPS";
    case DOMINANT_TCP:      return "TCP";
    case DOMINANT_UDP:      return "UDP";
    case DOMINANT_ICMP:     return "ICMP";
    case DOMINANT_DIST:     return "DIST";
    case DOMINANT_L3:       return "L3";
    case DOMINANT_OFFPROTO: return "OFFPROTO";
    default:                return "UNKNOWN";
    }
}

/* -------------------------------------------------------------------------
 * Phase-machine helpers
 * ------------------------------------------------------------------------- */

/* EWMA-only-freeze duration (Change 2). Profile-driven; falls back to the
 * legacy freeze-window default when the profile is missing or unset. */
static uint32_t pick_ewma_freeze_windows(const struct l2_profile *p) {
    if (p && p->baseline_freeze_windows > 0) return p->baseline_freeze_windows;
    return SCORING_DEFAULT_FREEZE_WINDOWS;
}

/* Number of consecutive NORMAL windows required to release the full
 * ATTACK-freeze (Change 4). Profile-driven with the same fallback rule. */
static uint32_t pick_thaw_windows(const struct l2_profile *p) {
    if (p && p->thaw_cooldown_windows > 0) return p->thaw_cooldown_windows;
    return SCORING_DEFAULT_THAW_WINDOWS;
}

/* CHANGE 1: absolute volumetric floor. Reads the SAME raw window inputs as
 * Tier-0 — never the EWMA/CUSUM baseline — so it fires even when the
 * baseline is cold or poisoned. A profile threshold of 0.0 disables that
 * channel (0 is "off", not a real floor). Breach if ANY enabled channel
 * meets-or-exceeds its threshold. */
static bool tier0_absolute_breach(const struct service_stats *slot,
                                  const struct l2_profile *p)
{
    if (!slot || !p) return false;

    double pps = (double)slot->common.inbound_pkts;
    double bps = (double)slot->common.inbound_bytes * 8.0;
    double fps = service_hll_estimate(&slot->common.unique_flows);

    if (p->absolute_pps_threshold > 0.0 && pps >= p->absolute_pps_threshold)
        return true;
    if (p->absolute_bps_threshold > 0.0 && bps >= p->absolute_bps_threshold)
        return true;
    if (p->absolute_fps_threshold > 0.0 && fps >= p->absolute_fps_threshold)
        return true;
    return false;
}

/* -------------------------------------------------------------------------
 * Phase machine
 * ------------------------------------------------------------------------- */

void service_scoring_update_phase(struct service_stats *slot)
{
    if (!slot || !slot->detection_state) return;
    struct service_detection_state *det = det_of(slot);
    const struct l2_profile *prof = det->profile;

    /* 1. Tier-0 weighted risk. Honors the CUSUM freeze internally. */
    double R0 = service_scoring_tier0_evaluate(slot);

    /* 2. Absolute volumetric floor (Change 1). Provenance flag is written
     *    every window so it is visible in learning/warmup modes too. */
    bool abs_breach = tier0_absolute_breach(slot, prof);
    det->last_absolute_floor_fired = abs_breach;

    /* 3. Tier-0 3-level state + gate-fire signal (gate opens on Suspicious
     *    OR Attack risk). */
    int t0_state;
    if      (R0 >= SCORING_T0_ATTACK_RISK_THRESHOLD) t0_state = SERVICE_DET_PHASE_ATTACK;
    else if (R0 >= SCORING_T0_GATE_RISK_THRESHOLD)   t0_state = SERVICE_DET_PHASE_SUSPICIOUS;
    else                                             t0_state = SERVICE_DET_PHASE_NORMAL;
    bool t0_fired = (t0_state != SERVICE_DET_PHASE_NORMAL);

    /* 4. Learning mode: compute + cache Tier-1 for the dashboard, but never
     *    transition (flag from step 2 is already set). */
    const struct service_registry *reg = service_registry_get_global();
    if (reg && reg->learning_mode) {
        (void)service_scoring_combine(slot);
        det->last_attack_evidence = R0;
        det->windows_seen++;
        return;
    }

    uint8_t old_phase = det->phase;

    /* 5. Tick the freeze countdown. ewma_freeze_remaining is the authoritative
     *    EWMA-only countdown; the wire-facing baseline_freeze_remaining /
     *    thaw_cooldown_remaining are DERIVED at the end of this window. */
    if (det->ewma_freeze_remaining > 0) det->ewma_freeze_remaining--;

    /* 6. Warmup: hold phase, keep Tier-1 scores live for the dashboard. */
    if (det->warmup_remaining > 0) {
        det->warmup_remaining--;
        det->warmup_windows_completed++;
        (void)service_scoring_combine(slot);
        det->last_attack_evidence = R0;
        if (det->warmup_remaining == 0 && det->phase == SERVICE_DET_PHASE_WARMUP)
            det->phase = SERVICE_DET_PHASE_NORMAL;
        goto wire_and_log;
    }

    /* Default to the prior phase: if any future code path reaches a reader
     * without assigning, the slot safely holds its phase (a no-op) rather
     * than reading an indeterminate value. */
    uint8_t new_phase = old_phase;

    if (abs_breach) {
        /* 7. CHANGE 1: absolute floor forces ATTACK now — bypass the
         *    persistence gate and the Tier-1 decision entirely. Still call
         *    combine() so the per-channel sub-scores populate for the
         *    dashboard, but the phase is ATTACK regardless of T1. */
        (void)service_scoring_combine(slot);
        /* Evidence stays the honest Tier-0 number even though the phase is forced
         * ATTACK. On a poisoned/cold baseline R0 may read low while the absolute
         * floor fires — that is expected; provenance is last_absolute_floor_fired,
         * surfaced first-class on the dashboard in a later change. */
        det->last_attack_evidence = R0;
        new_phase = SERVICE_DET_PHASE_ATTACK;
        /* Absolute-breach windows intentionally seed the Tier-1 gate streak: if
         * this attack later decays below the absolute floor but stays elevated,
         * the normal persistence gate is already warm and Tier-1 takes over
         * seamlessly instead of restarting the streak from zero. */
        if (det->consecutive_attack_windows < 0xFFFFFFFFu)
            det->consecutive_attack_windows++;
    } else {
        /* 8. Persistence gate BETWEEN the tiers, then the Tier-1 cascade. */
        if (t0_fired) {
            if (det->consecutive_attack_windows < 0xFFFFFFFFu)
                det->consecutive_attack_windows++;
        } else {
            det->consecutive_attack_windows = 0;
        }
        bool gate_open =
            (det->consecutive_attack_windows >= SCORING_GATE_PERSISTENCE_WINDOWS);

        if (!gate_open) {
            new_phase = SERVICE_DET_PHASE_NORMAL;
            det->last_tier1_evaluated = false;
            det->last_attack_evidence = R0;
        } else {
            double T1 = service_scoring_combine(slot);
            det->last_attack_evidence = T1;
            if      (T1 >= SCORING_DEFAULT_ATTACK_THRESHOLD)     new_phase = SERVICE_DET_PHASE_ATTACK;
            else if (T1 >= SCORING_DEFAULT_SUSPICIOUS_THRESHOLD) new_phase = SERVICE_DET_PHASE_SUSPICIOUS;
            else                                                 new_phase = SERVICE_DET_PHASE_NORMAL; /* veto */
        }

        /* CHANGE 2: the instant Tier-0 fires, arm the EWMA-only freeze —
         *  protect the baseline from ramp poisoning before Tier-1 confirms. */
        if (t0_fired) {
            uint32_t fw = pick_ewma_freeze_windows(prof);
            if (det->ewma_freeze_remaining < fw)
                det->ewma_freeze_remaining = fw;
        }
    }

    det->phase = new_phase;

    /* 9. CHANGE 4: full-freeze (EWMA+CUSUM) arm/release bookkeeping.
     *    Entering/holding ATTACK (via Tier-1 OR the absolute floor) arms the
     *    full freeze and resets the recovery streak. The freeze releases
     *    ONLY after thaw_count consecutive NORMAL windows; any non-NORMAL
     *    window resets the streak (sustained calm required). */
    if (new_phase == SERVICE_DET_PHASE_ATTACK) {
        det->attack_freeze_active       = true;
        det->consecutive_normal_windows = 0;
    } else if (det->attack_freeze_active) {
        if (new_phase == SERVICE_DET_PHASE_NORMAL) {
            det->consecutive_normal_windows++;
            if (det->consecutive_normal_windows >= pick_thaw_windows(prof)) {
                det->attack_freeze_active       = false;
                det->consecutive_normal_windows = 0;
            }
        } else {
            det->consecutive_normal_windows = 0;   /* SUSPICIOUS resets recovery */
        }
    }

wire_and_log:
    /* Derive the serialized freeze fields (wire serializer untouched).
     *  baseline_freeze_remaining: >0 means "baseline currently protected" —
     *  the EWMA-freeze countdown, or a sentinel while the full freeze holds
     *  with the countdown already drained. thaw_cooldown_remaining: clean
     *  windows still needed to release the full freeze (0 when not freezing). */
    det->baseline_freeze_remaining = service_scoring_is_frozen(slot)
        ? (det->ewma_freeze_remaining > 0 ? det->ewma_freeze_remaining : 1u)
        : 0u;
    if (det->attack_freeze_active) {
        uint32_t thaw = pick_thaw_windows(prof);
        det->thaw_cooldown_remaining =
            (thaw > det->consecutive_normal_windows)
                ? (thaw - det->consecutive_normal_windows) : 0u;
    } else {
        det->thaw_cooldown_remaining = 0u;
    }

    /* 10. Transition logging. */
    if (det->phase != old_phase) {
        det->prev_phase = old_phase;
        det->last_phase_change_window = det->windows_seen;
        fprintf(stderr,
            "[scoring] slot ip=%u port=%u proto=%u phase: %s -> %s "
            "(R0=%.3f gate_streak=%u/%u t1=%.3f abs_floor=%d freeze=%c/%c)\n",
            (unsigned)slot->key.target_ip,
            (unsigned)slot->key.port,
            (unsigned)slot->proto_kind,
            service_detection_phase_name(old_phase),
            service_detection_phase_name(det->phase),
            det->last_tier0_score,
            (unsigned)det->consecutive_attack_windows,
            (unsigned)SCORING_GATE_PERSISTENCE_WINDOWS,
            det->last_tier1_final_score,
            (int)det->last_absolute_floor_fired,
            det->attack_freeze_active   ? 'A' : '-',
            det->ewma_freeze_remaining  ? 'E' : '-');
    }
    det->windows_seen++;
}

bool service_scoring_is_frozen(const struct service_stats *slot)
{
    if (!slot || !slot->detection_state) return false;
    const struct service_detection_state *det = det_of_const(slot);
    /* EWMA updates skipped under EITHER freeze scope. */
    return det->attack_freeze_active || det->ewma_freeze_remaining > 0;
}

bool service_scoring_cusum_is_frozen(const struct service_stats *slot)
{
    if (!slot || !slot->detection_state) return false;
    const struct service_detection_state *det = det_of_const(slot);
    /* CUSUM held only under the full ATTACK-freeze. */
    return det->attack_freeze_active;
}

/* -------------------------------------------------------------------------
 * Array-level entry
 * ------------------------------------------------------------------------- */

void service_scoring_evaluate_all(struct service_stats_array *arr)
{
    if (!arr || !arr->slots) return;
    for (size_t i = 0; i < arr->capacity; i++) {
        struct service_stats *s = &arr->slots[i];
        if (!s->active)          continue;
        if (!s->detection_state) continue;
        service_scoring_update_phase(s);
    }
}

/* -------------------------------------------------------------------------
 * Diagnostics
 * ------------------------------------------------------------------------- */

void service_scoring_log_slot(const struct service_stats *slot)
{
    if (!slot || !slot->detection_state) return;
    const struct service_detection_state *det = det_of_const(slot);
    fprintf(stderr,
        "[scoring] ip=%u port=%u proto=%u phase=%s warmup_rem=%u "
        "consec=%u freeze=%u thaw=%u t0=%.3f t1_final=%.3f "
        "tcp=%.3f udp=%.3f icmp=%.3f dist=%.3f l3=%.3f offproto=%.3f\n",
        (unsigned)slot->key.target_ip,
        (unsigned)slot->key.port,
        (unsigned)slot->proto_kind,
        service_detection_phase_name(det->phase),
        (unsigned)det->warmup_remaining,
        (unsigned)det->consecutive_attack_windows,
        (unsigned)det->baseline_freeze_remaining,
        (unsigned)det->thaw_cooldown_remaining,
        det->last_tier0_score,
        det->last_tier1_final_score,
        det->last_tier1_tcp_score,
        det->last_tier1_udp_score,
        det->last_tier1_icmp_score,
        det->last_tier1_dist_score,
        det->last_tier1_l3_score,
        det->last_tier1_offproto_score);
}
