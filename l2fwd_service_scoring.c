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

double service_scoring_tier0_evaluate(struct service_stats *slot)
{
    if (!slot || !slot->detection_state) return 0.0;
    struct service_detection_state *det = det_of(slot);

    const double k = SCORING_DEFAULT_TIER0_K;
    const double h = SCORING_DEFAULT_TIER0_H;

    int    breaches = 0;
    double max_S    = 0.0;

    /* --- pps --- */
    {
        double x      = (double)slot->common.inbound_pkts;
        double mean   = slot->common_ewma.pps.mean;
        double stddev = stddev_of(&slot->common_ewma.pps);
        if (service_scoring_cusum_update(&det->cusum_pps, x, mean, stddev, k, h))
            breaches++;
        if (det->cusum_pps.S_plus > max_S) max_S = det->cusum_pps.S_plus;
        det->last_tier0_risk_pps = fmin(1.0, det->cusum_pps.S_plus / h);
    }
    /* --- bps --- */
    {
        double x      = (double)slot->common.inbound_bytes * 8.0;
        double mean   = slot->common_ewma.bps.mean;
        double stddev = stddev_of(&slot->common_ewma.bps);
        if (service_scoring_cusum_update(&det->cusum_bps, x, mean, stddev, k, h))
            breaches++;
        if (det->cusum_bps.S_plus > max_S) max_S = det->cusum_bps.S_plus;
        det->last_tier0_risk_bps = fmin(1.0, det->cusum_bps.S_plus / h);
    }
    /* --- fps (flows per second; estimated from the HLL) --- */
    {
        double x      = service_hll_estimate(&slot->common.unique_flows);
        double mean   = slot->common_ewma.fps.mean;
        double stddev = stddev_of(&slot->common_ewma.fps);
        if (service_scoring_cusum_update(&det->cusum_fps, x, mean, stddev, k, h))
            breaches++;
        if (det->cusum_fps.S_plus > max_S) max_S = det->cusum_fps.S_plus;
        det->last_tier0_risk_fps = fmin(1.0, det->cusum_fps.S_plus / h);
    }
    /* --- burst variants: z_last is already standardised; mean=0, std=1 --- */
    {
        double x = slot->common.bw_pps.z_last;
        if (service_scoring_cusum_update(&det->cusum_burst_pps, x, 0.0, 1.0, k, h))
            breaches++;
        det->last_tier0_risk_burst_pps =
            fmin(1.0, det->cusum_burst_pps.S_plus / h);
    }
    {
        double x = slot->common.bw_bps.z_last;
        if (service_scoring_cusum_update(&det->cusum_burst_bps, x, 0.0, 1.0, k, h))
            breaches++;
        det->last_tier0_risk_burst_bps =
            fmin(1.0, det->cusum_burst_bps.S_plus / h);
    }
    {
        double x = slot->common.bw_fps.z_last;
        if (service_scoring_cusum_update(&det->cusum_burst_fps, x, 0.0, 1.0, k, h))
            breaches++;
        det->last_tier0_risk_burst_fps =
            fmin(1.0, det->cusum_burst_fps.S_plus / h);
    }

    /* Composite Tier-0 score: how many channels breached, scaled by the
     * worst S_plus / h ratio. Capped at 1.0. */
    double score = ((double)breaches / 6.0) * fmin(1.0, max_S / h);
    return fmin(1.0, score);
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
    return final_score;
}

/* -------------------------------------------------------------------------
 * Phase machine
 * ------------------------------------------------------------------------- */

void service_scoring_update_phase(struct service_stats *slot)
{
    if (!slot || !slot->detection_state) return;
    struct service_detection_state *det = det_of(slot);

    /* Always evaluate both tiers so the dashboard has consistent scores.
     * Tier-0 is a no-op when the EWMA hasn't built a baseline yet
     * (stddev < ε); same for Tier-1's z-score-based channels. */
    double t0 = service_scoring_tier0_evaluate(slot);
    double t1 = service_scoring_combine(slot);
    det->last_tier0_score     = t0;
    det->last_attack_evidence = fmax(t0, t1);

    uint8_t old_phase = det->phase;

    /* Decrement countdowns regardless of phase (the freeze/thaw counters
     * are independent of the phase machine — they can outlast a single
     * NORMAL→ATTACK→NORMAL cycle for protective effect). */
    if (det->baseline_freeze_remaining > 0) det->baseline_freeze_remaining--;
    if (det->thaw_cooldown_remaining   > 0) det->thaw_cooldown_remaining--;

    if (det->warmup_remaining > 0) {
        det->warmup_remaining--;
        det->warmup_windows_completed++;
        if (det->warmup_remaining == 0 &&
            det->phase == SERVICE_DET_PHASE_WARMUP) {
            det->phase = SERVICE_DET_PHASE_NORMAL;
        }
    } else {
        double score = det->last_attack_evidence;

        switch (det->phase) {
        case SERVICE_DET_PHASE_WARMUP:
            /* Belt-and-braces — warmup_remaining hit 0 above without us
             * flipping the phase. Same transition happens here. */
            det->phase = SERVICE_DET_PHASE_NORMAL;
            break;

        case SERVICE_DET_PHASE_NORMAL:
            if (score > SCORING_DEFAULT_SUSPICIOUS_THRESHOLD) {
                det->phase                     = SERVICE_DET_PHASE_SUSPICIOUS;
                det->consecutive_attack_windows = 1;
            }
            break;

        case SERVICE_DET_PHASE_SUSPICIOUS:
            if (score > SCORING_DEFAULT_ATTACK_THRESHOLD) {
                det->consecutive_attack_windows++;
                if (det->consecutive_attack_windows >=
                    SCORING_DEFAULT_PERSISTENCE_WINDOWS) {
                    det->phase                     = SERVICE_DET_PHASE_ATTACK;
                    det->baseline_freeze_remaining = SCORING_DEFAULT_FREEZE_WINDOWS;
                    /* Reset the counter so ATTACK→NORMAL recovery has a
                     * deterministic countdown starting from the
                     * RECOVERY_WINDOWS_ATK value seeded below. */
                    det->consecutive_attack_windows =
                        SCORING_DEFAULT_RECOVERY_WINDOWS_ATK;
                }
            } else if (score < SCORING_DEFAULT_RECOVERY_THRESHOLD) {
                if (det->consecutive_attack_windows > 0)
                    det->consecutive_attack_windows--;
                if (det->consecutive_attack_windows == 0)
                    det->phase = SERVICE_DET_PHASE_NORMAL;
            }
            /* score in middle band (recovery..suspicious) → hold steady. */
            break;

        case SERVICE_DET_PHASE_ATTACK:
            if (score < SCORING_DEFAULT_RECOVERY_THRESHOLD) {
                if (det->consecutive_attack_windows > 0)
                    det->consecutive_attack_windows--;
                if (det->consecutive_attack_windows == 0) {
                    det->phase = SERVICE_DET_PHASE_NORMAL;
                    det->thaw_cooldown_remaining = SCORING_DEFAULT_THAW_WINDOWS;
                }
            } else {
                /* Still attacked. Re-seed the recovery counter — every
                 * elevated window resets the path back to NORMAL. */
                det->consecutive_attack_windows =
                    SCORING_DEFAULT_RECOVERY_WINDOWS_ATK;
            }
            break;

        default:
            break;
        }
    }

    /* Log phase transitions. Both warmup completion and steady-state
     * transitions feed through here. */
    if (det->phase != old_phase) {
        det->prev_phase = old_phase;
        det->last_phase_change_window = det->windows_seen;
        fprintf(stderr,
            "[scoring] slot ip=%u port=%u proto=%u phase: %s -> %s "
            "(t0=%.3f t1=%.3f evidence=%.3f)\n",
            (unsigned)slot->key.target_ip,
            (unsigned)slot->key.port,
            (unsigned)slot->proto_kind,
            service_detection_phase_name(old_phase),
            service_detection_phase_name(det->phase),
            det->last_tier0_score,
            det->last_tier1_final_score,
            det->last_attack_evidence);
    }

    det->windows_seen++;
}

bool service_scoring_is_frozen(const struct service_stats *slot)
{
    if (!slot || !slot->detection_state) return false;
    const struct service_detection_state *det = det_of_const(slot);
    return det->baseline_freeze_remaining > 0;
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
