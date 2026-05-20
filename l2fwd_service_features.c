/**
 * @file   l2fwd_service_features.c
 * @brief  Per-service feature extraction — P8 implementation.
 *
 * See the header for the public-API contract. P8 is pure math: it
 * never modifies the registry, the stats array layout, or the
 * detection / temporal state pointers wired in P5.
 */

#include "l2fwd_service_features.h"
#include "l2fwd_service_stats.h"
#include "l2fwd_service_temporal_state.h"
#include "l2fwd_service_scoring.h"     /* P9: service_scoring_is_frozen() */
#include "l2fwd_l2_profile.h"

#include <math.h>
#include <stdbool.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

/* -------------------------------------------------------------------------
 * Constants
 * ------------------------------------------------------------------------- */

/* Default EWMA smoothing factor when slot->profile is NULL or doesn't
 * carry a usable alpha. Matches the legacy l2fwd_detection_engine.c
 * default (~0.05). P9 may dispatch by tier to use profile->alpha_tier0
 * vs alpha_tier1_tcp etc. — for P8 a single value keeps the math
 * inspectable. */
#define SERVICE_FEATURES_DEFAULT_ALPHA 0.05

/* Change 3: EWMA robustness tunables.
 *  - VARIANCE_CEILING: winsorize each diff to +/- C*stddev (profile-driven;
 *    this is the fallback when the profile is missing or unset).
 *  - MIN_STDDEV_REL/ABS: scale-free min-stddev floor so z-scores can't go
 *    numb. pps/bps/fps live on wildly different scales, so the floor is a
 *    fraction of |mean|, with a tiny absolute backstop for mean ~= 0.
 *  - WINSOR_MIN_SAMPLES: below this sample count there is no usable baseline
 *    to clamp against, so winsorization is skipped. */
#define SERVICE_FEATURES_DEFAULT_VARIANCE_CEILING  3.0
#define EWMA_MIN_STDDEV_REL                        0.01   /* stddev >= 1% of |mean| */
#define EWMA_MIN_STDDEV_ABS                        1e-6   /* mean~=0 backstop        */
#define EWMA_WINSOR_MIN_SAMPLES                    8u     /* skip winsor below this  */

/* The detection_phase enum values that the temporal aggregator counts
 * as ATTACK / SUSPICIOUS seconds. Defined in l2fwd_service_detection.h;
 * mirrored here as literals to keep this TU decoupled from the
 * detection module (the values are part of the stable enum contract). */
#define FEATURES_PHASE_SUSPICIOUS  2
#define FEATURES_PHASE_ATTACK      3

/* -------------------------------------------------------------------------
 * 1.1 HyperLogLog
 *
 * NOTE on register encoding: the standard HLL definition stores ρ(w) —
 * the position of the leftmost 1-bit in the (W-b)-bit value w, counted
 * from the MSB and 1-indexed. With W=32, b=10 we have 22 bits in w.
 *
 * For w with the highest of those 22 bits set, ρ = 1.
 * For w with only the lowest bit set, ρ = 22.
 * For w = 0, ρ is conventionally ≥ 23 (no 1-bit in the window).
 *
 * Converting from __builtin_clz on a 32-bit int: the int has 10 leading
 * zero bits before the 22-bit window even begins, so
 *
 *   ρ = clz(w) - 10 + 1 = clz(w) - 9
 *
 * (Note: the original P8 spec showed `clz(w | 0x1) - 9 + 1`, which
 * stores ρ+1. That biases the cardinality estimator upward by ~2x.
 * The line below uses the correct ρ formula; the `w | 0x1` guard
 * keeps clz bounded for the w=0 case, yielding ρ=22 there.)
 * ------------------------------------------------------------------------- */

void service_hll_insert(struct service_hll *hll, uint32_t hash) {
    if (!hll) return;
    uint32_t idx = hash & 0x3FFu;            /* 10 low bits → register index */
    uint32_t w   = hash >> 10;               /* upper 22 bits used for ρ     */
    uint8_t  rho = (uint8_t)(__builtin_clz(w | 0x1u) - 9);
    if (rho > hll->registers[idx]) {
        hll->registers[idx] = rho;
    }
}

double service_hll_estimate(const struct service_hll *hll) {
    if (!hll) return 0.0;
    const int    m       = 1024;
    /* α_m bias-correction constant from Flajolet et al. */
    const double alpha_m = 0.7213 / (1.0 + 1.079 / (double)m);

    double sum        = 0.0;
    int    zero_count = 0;
    for (int i = 0; i < m; i++) {
        uint8_t r = hll->registers[i];
        sum += ldexp(1.0, -(int)r);          /* 2^{-r} without integer overflow */
        if (r == 0) zero_count++;
    }

    double estimate = alpha_m * (double)m * (double)m / sum;

    /* Small-range correction (linear counting) when many empty buckets. */
    if (estimate <= 2.5 * (double)m && zero_count > 0) {
        estimate = (double)m * log((double)m / (double)zero_count);
    }
    /* Large-range correction omitted — meaningful only above ~2^32 / 30. */
    return estimate;
}

void service_hll_reset(struct service_hll *hll) {
    if (!hll) return;
    memset(hll->registers, 0, sizeof(hll->registers));
}

/* -------------------------------------------------------------------------
 * 1.2 Count-Min sketch
 *
 * Four independent hash functions per CM, seeded with distinct constants.
 * The hash is a 64-bit multiply-shift in the SplitMix family — fast and
 * adequate decorrelation for sketch use (we do NOT need cryptographic
 * strength here).
 * ------------------------------------------------------------------------- */

static const uint32_t k_cm_seeds[4] = {
    0xA5A5A5A5u, 0x5A5A5A5Au, 0xCAFEBABEu, 0xDEADBEEFu
};

static uint32_t cm_hash(uint32_t key, uint32_t seed) {
    uint64_t h = (uint64_t)key * 0x9E3779B97F4A7C15ULL;
    h ^= seed;
    h ^= h >> 33;
    return (uint32_t)h;
}

void service_cm_src_port_insert(struct service_cm_src_port *cm, uint16_t port) {
    if (!cm) return;
    uint32_t counts[4];
    for (int i = 0; i < 4; i++) {
        uint32_t idx = cm_hash((uint32_t)port, k_cm_seeds[i]) % 256u;
        cm->table[i][idx]++;
        counts[i] = cm->table[i][idx];
    }
    cm->total++;
    /* Estimated count for this key = min across rows (CM "min trick"). */
    uint32_t est = counts[0];
    for (int i = 1; i < 4; i++) if (counts[i] < est) est = counts[i];
    if (est > cm->top_count) {
        cm->top_port  = port;
        cm->top_count = est;
    }
}

void service_cm_src_24_insert(struct service_cm_src_24 *cm, uint32_t src_ip) {
    if (!cm) return;
    uint32_t net24 = src_ip & 0xFFFFFF00u;   /* zero the host byte */
    uint32_t counts[4];
    for (int i = 0; i < 4; i++) {
        uint32_t idx = cm_hash(net24, k_cm_seeds[i]) % 512u;
        cm->table[i][idx]++;
        counts[i] = cm->table[i][idx];
    }
    cm->total++;
    uint32_t est = counts[0];
    for (int i = 1; i < 4; i++) if (counts[i] < est) est = counts[i];
    if (est > cm->top_count) {
        cm->top_net24 = net24;
        cm->top_count = est;
    }
}

double service_cm_top1_share(uint64_t top_count, uint64_t total) {
    if (total == 0) return 0.0;
    return (double)top_count / (double)total;
}

double service_cm_src_24_entropy(const struct service_cm_src_24 *cm) {
    if (!cm || cm->total == 0) return 0.0;
    /* Approximate Shannon entropy from row-0 column counts.
     * Using a single row is a low-cost surrogate for the true CM
     * top-K distribution. */
    double entropy = 0.0;
    double total   = (double)cm->total;
    for (int i = 0; i < 512; i++) {
        if (cm->table[0][i] == 0) continue;
        double p = (double)cm->table[0][i] / total;
        entropy -= p * (log(p) / log(2.0));
    }
    return entropy;
}

void service_cm_src_port_reset(struct service_cm_src_port *cm) {
    if (!cm) return;
    memset(cm->table, 0, sizeof(cm->table));
    cm->total     = 0;
    cm->top_port  = 0;
    cm->top_count = 0;
}

void service_cm_src_24_reset(struct service_cm_src_24 *cm) {
    if (!cm) return;
    memset(cm->table, 0, sizeof(cm->table));
    cm->total     = 0;
    cm->top_net24 = 0;
    cm->top_count = 0;
}

/* -------------------------------------------------------------------------
 * 1.3 EWMA
 * ------------------------------------------------------------------------- */

void service_ewma_update(struct service_ewma_state *state,
                          double x, double alpha,
                          double variance_ceiling_factor)
{
    if (!state) return;
    if (!state->initialized) {
        state->mean        = x;
        state->variance    = 0.0;
        state->initialized = true;
    } else {
        double diff = x - state->mean;

        /* Change 3: winsorize the diff to +/- C*stddev, but only once a
         * usable baseline exists (enough samples AND a positive stddev) —
         * before that there is nothing to clamp against. The SAME clamped
         * diff feeds BOTH the mean and the variance term, so a lone spike
         * can neither yank the mean nor inflate variance via the diff^2
         * term. C <= 0 disables winsorization. */
        double stddev = (state->variance > 0.0) ? sqrt(state->variance) : 0.0;
        if (state->sample_count >= EWMA_WINSOR_MIN_SAMPLES &&
            variance_ceiling_factor > 0.0 && stddev > 0.0) {
            double clamp = variance_ceiling_factor * stddev;
            if      (diff >  clamp) diff =  clamp;
            else if (diff < -clamp) diff = -clamp;
        }

        state->mean    += alpha * diff;
        state->variance = (1.0 - alpha) *
                          (state->variance + alpha * diff * diff);

        /* Change 3: scale-free min-stddev floor so z-scores can't collapse
         * to numbness — a relative fraction of |mean| with a tiny absolute
         * backstop for mean ~= 0. */
        double floor = EWMA_MIN_STDDEV_REL * fabs(state->mean);
        if (floor < EWMA_MIN_STDDEV_ABS) floor = EWMA_MIN_STDDEV_ABS;
        if (state->variance < floor * floor) state->variance = floor * floor;
    }
    state->sample_count++;
}

double service_ewma_z_score(const struct service_ewma_state *state, double x) {
    if (!state || !state->initialized) return 0.0;
    if (state->variance < 1e-12)       return 0.0;
    return (x - state->mean) / sqrt(state->variance);
}

/* -------------------------------------------------------------------------
 * 1.4 Burst window (rolling 3-sample buffer)
 * ------------------------------------------------------------------------- */

void service_burst_window_push(struct service_burst_window *bw, double sample) {
    if (!bw) return;
    if (bw->filled < 3) {
        bw->samples[bw->filled++] = sample;
    } else {
        bw->samples[0] = bw->samples[1];
        bw->samples[1] = bw->samples[2];
        bw->samples[2] = sample;
    }

    double sum = 0.0;
    for (int i = 0; i < bw->filled; i++) sum += bw->samples[i];
    bw->mean = sum / (double)bw->filled;

    if (bw->filled >= 2) {
        double ss = 0.0;
        for (int i = 0; i < bw->filled; i++) {
            double d = bw->samples[i] - bw->mean;
            ss += d * d;
        }
        /* Bessel-corrected sample stddev. */
        bw->stddev = sqrt(ss / (double)(bw->filled - 1));
        bw->z_last = (bw->stddev > 1e-9)
                      ? (sample - bw->mean) / bw->stddev
                      : 0.0;
    } else {
        bw->stddev = 0.0;
        bw->z_last = 0.0;
    }
}

void service_burst_window_reset(struct service_burst_window *bw) {
    if (!bw) return;
    memset(bw, 0, sizeof(*bw));
}

/* -------------------------------------------------------------------------
 * 1.5 Welford from running sums (Bessel-corrected)
 * ------------------------------------------------------------------------- */

void service_compute_mean_stddev(uint64_t sum,
                                  uint64_t sum_sq,
                                  uint64_t n,
                                  double *out_mean,
                                  double *out_stddev)
{
    if (out_mean)   *out_mean   = 0.0;
    if (out_stddev) *out_stddev = 0.0;
    if (n == 0) return;

    double dN   = (double)n;
    double dSum = (double)sum;
    double mean = dSum / dN;
    if (out_mean) *out_mean = mean;

    if (n < 2 || !out_stddev) return;

    /* Bessel: variance = (sum_sq - sum² / n) / (n - 1). */
    double num = (double)sum_sq - (dSum * dSum) / dN;
    if (num < 0.0) num = 0.0;     /* float-rounding floor */
    *out_stddev = sqrt(num / (dN - 1.0));
}

/* -------------------------------------------------------------------------
 * 1.6 Per-slot orchestrator
 *
 * Each branch computes the proto-specific ratios + EWMA updates that
 * the union arm holds. The OTHER catchall variant updates the broad
 * other_proto_ratio + dst_port_ratio in common_ewma so the dashboard
 * has a single place to read those without dispatching on proto_kind.
 * ------------------------------------------------------------------------- */

/* Returns the effective alpha for this slot. Defaults to
 * SERVICE_FEATURES_DEFAULT_ALPHA when the profile is missing or its
 * alpha_tier0 is non-positive (services.json files written before P8
 * tuning may leave alpha at 0). */
static double pick_alpha(const struct service_stats *slot) {
    if (slot && slot->profile && slot->profile->alpha_tier0 > 0.0) {
        return slot->profile->alpha_tier0;
    }
    return SERVICE_FEATURES_DEFAULT_ALPHA;
}

/* Returns the EWMA winsorization clamp factor (C) for this slot, mirroring
 * pick_alpha. Defaults to SERVICE_FEATURES_DEFAULT_VARIANCE_CEILING when the
 * profile is missing or its variance_ceiling_factor is non-positive. */
static double pick_variance_ceiling(const struct service_stats *slot) {
    if (slot && slot->profile && slot->profile->variance_ceiling_factor > 0.0) {
        return slot->profile->variance_ceiling_factor;
    }
    return SERVICE_FEATURES_DEFAULT_VARIANCE_CEILING;
}

/* Estimate the proto-specific "flow cardinality" used for the fps
 * derived feature. Returns 0.0 when the slot kind has no flow HLL. */
static double estimate_flows_for_kind(const struct service_stats *slot) {
    switch (slot->proto_kind) {
    case SERVICE_PROTO_TCP:
    case SERVICE_PROTO_CATCHALL_TCP:
        return service_hll_estimate(&slot->proto.tcp.stats.unique_new_flows);
    case SERVICE_PROTO_UDP:
    case SERVICE_PROTO_CATCHALL_UDP:
        return service_hll_estimate(&slot->proto.udp.stats.udp_flows);
    case SERVICE_PROTO_CATCHALL_OTHER:
        /* OTHER catchall: union TCP + UDP arm HLLs (approximate). */
        return service_hll_estimate(&slot->proto.other_catchall.tcp_stats.unique_new_flows)
             + service_hll_estimate(&slot->proto.other_catchall.udp_stats.udp_flows);
    default:
        return 0.0;
    }
}

/* P9: function-scoped macro that gates every EWMA update on the freeze
 * flag captured at the top of service_features_compute_one. Calls into the
 * underlying primitive `service_ewma_update`. When `frozen` is true the
 * macro is a no-op — the slot's EWMA baselines stay unchanged across the
 * attack so they don't get poisoned by attack-elevated traffic.
 *
 * The macro must be #undef'd at the end of the function so it doesn't
 * leak into any other TU that includes this file (it doesn't, but
 * defensive hygiene). */
#define MAYBE_EWMA(state, x) do { \
    if (!frozen) service_ewma_update((state), (x), alpha, vcf); \
} while (0)

void service_features_compute_one(struct service_stats *slot) {
    if (!slot || !slot->active) return;

    /* P9: while in ATTACK with active baseline-freeze, every EWMA update
     * below is skipped. Raw counter reads + burst-window pushes + Welford
     * mean/stddev computations continue normally — they don't mutate
     * persistent baseline state. */
    const bool   frozen = service_scoring_is_frozen(slot);
    const double alpha  = pick_alpha(slot);
    const double vcf    = pick_variance_ceiling(slot);   /* Change 3 clamp factor */

    uint64_t inbound_pkts  = slot->common.inbound_pkts;
    uint64_t inbound_bytes = slot->common.inbound_bytes;

    /* --- Common volumetric features ---------------------------- */
    double pps = (double)inbound_pkts;
    double bps = (double)inbound_bytes * 8.0;       /* convert to bits/sec */
    double fps = estimate_flows_for_kind(slot);

    MAYBE_EWMA(&slot->common_ewma.pps, pps);
    MAYBE_EWMA(&slot->common_ewma.bps, bps);
    MAYBE_EWMA(&slot->common_ewma.fps, fps);

    /* --- Burst windows: push current value, then feed z-scores -- */
    service_burst_window_push(&slot->common.bw_pps, pps);
    service_burst_window_push(&slot->common.bw_bps, bps);
    service_burst_window_push(&slot->common.bw_fps, fps);
    MAYBE_EWMA(&slot->common_ewma.burst_pps, slot->common.bw_pps.z_last);
    MAYBE_EWMA(&slot->common_ewma.burst_bps, slot->common.bw_bps.z_last);
    MAYBE_EWMA(&slot->common_ewma.burst_fps, slot->common.bw_fps.z_last);

    /* --- L3 / TTL features ------------------------------------- */
    double ttl_mean = 0.0, ttl_stddev = 0.0;
    service_compute_mean_stddev(slot->common.ttl_sum,
                                 slot->common.ttl_sum_sq,
                                 inbound_pkts,
                                 &ttl_mean, &ttl_stddev);
    MAYBE_EWMA(&slot->common_ewma.ttl_stddev, ttl_stddev);

    /* src_ip_ratio = unique_src_ips / inbound_pkts. */
    double src_ip_ratio = 0.0;
    if (inbound_pkts > 0) {
        double unique_src = service_hll_estimate(&slot->common.unique_src_ips);
        src_ip_ratio = unique_src / (double)inbound_pkts;
    }
    MAYBE_EWMA(&slot->common_ewma.src_ip_ratio, src_ip_ratio);

    /* off_proto_pkts_ratio = off_proto_pkts / inbound_pkts. */
    double off_proto_ratio = 0.0;
    if (inbound_pkts > 0) {
        off_proto_ratio = (double)slot->common.off_proto_pkts /
                          (double)inbound_pkts;
    }
    MAYBE_EWMA(&slot->common_ewma.off_proto_pkts_ratio, off_proto_ratio);

    /* /24 distribution features. */
    double src24_top1 = service_cm_top1_share(
        (uint64_t)slot->common.cm_src_24.top_count,
        slot->common.cm_src_24.total);
    double src24_ent  = service_cm_src_24_entropy(&slot->common.cm_src_24);
    MAYBE_EWMA(&slot->common_ewma.src_24_top1_share, src24_top1);
    MAYBE_EWMA(&slot->common_ewma.src_24_entropy,    src24_ent);

    /* --- Protocol-specific dispatch ---------------------------- */
    switch (slot->proto_kind) {
    case SERVICE_PROTO_TCP:
    case SERVICE_PROTO_CATCHALL_TCP: {
        struct service_tcp_stats *t = &slot->proto.tcp.stats;
        struct service_tcp_ewma  *e = &slot->proto.tcp.ewma;
        if (t->tcp_pkts > 0) {
            double dn = (double)t->tcp_pkts;

            MAYBE_EWMA(&e->syn_ratio,          (double)t->syn_pkts          / dn);
            MAYBE_EWMA(&e->synack_ratio,       (double)t->syn_ack_pkts      / dn);
            MAYBE_EWMA(&e->finack_ratio,       (double)t->fin_ack_pkts      / dn);
            MAYBE_EWMA(&e->rst_ratio,          (double)t->rst_pkts          / dn);
            MAYBE_EWMA(&e->ack_data_ratio,     (double)t->ack_data_pkts     / dn);
            MAYBE_EWMA(&e->empty_ack_ratio,    (double)t->empty_ack_pkts    / dn);
            MAYBE_EWMA(&e->zero_window_ratio,  (double)t->zero_window_pkts  / dn);
            MAYBE_EWMA(&e->small_window_ratio, (double)t->small_window_pkts / dn);

            /* SYN ratio guards — when denominator is 0, return the
             * numerator as a sentinel ("pure SYN flood, no replies"). */
            double syn_to_synack = (t->syn_ack_pkts > 0)
                ? (double)t->syn_pkts / (double)t->syn_ack_pkts
                : (double)t->syn_pkts;
            MAYBE_EWMA(&e->syn_to_synack_ratio, syn_to_synack);

            double syn_fin = (t->fin_ack_pkts > 0)
                ? (double)t->syn_pkts / (double)t->fin_ack_pkts
                : (double)t->syn_pkts;
            MAYBE_EWMA(&e->syn_fin_ratio, syn_fin);

            /* Packet-size mean + coefficient of variation. */
            double sz_mean = 0.0, sz_stddev = 0.0;
            service_compute_mean_stddev(t->tcp_pkt_size_sum,
                                         t->tcp_pkt_size_sum_sq,
                                         t->tcp_pkts,
                                         &sz_mean, &sz_stddev);
            double sz_cov = (sz_mean > 0.0) ? sz_stddev / sz_mean : 0.0;
            MAYBE_EWMA(&e->tcp_mean_pkt_size, sz_mean);
            MAYBE_EWMA(&e->tcp_pkt_size_cov,  sz_cov);

            double uflows     = service_hll_estimate(&t->unique_new_flows);
            double new_flow_r = uflows / dn;
            MAYBE_EWMA(&e->new_flow_ratio, new_flow_r);

            MAYBE_EWMA(&e->tcp_pps_ratio, dn);
            MAYBE_EWMA(&e->tcp_bps_ratio, (double)t->tcp_bytes * 8.0);
        }
        break;
    }

    case SERVICE_PROTO_UDP:
    case SERVICE_PROTO_CATCHALL_UDP: {
        struct service_udp_stats *u = &slot->proto.udp.stats;
        struct service_udp_ewma  *e = &slot->proto.udp.ewma;
        if (u->udp_pkts > 0) {
            double dn = (double)u->udp_pkts;

            double sz_mean = 0.0, sz_stddev = 0.0;
            service_compute_mean_stddev(u->udp_pkt_size_sum,
                                         u->udp_pkt_size_sum_sq,
                                         u->udp_pkts,
                                         &sz_mean, &sz_stddev);
            double sz_cov = (sz_mean > 0.0) ? sz_stddev / sz_mean : 0.0;
            MAYBE_EWMA(&e->udp_mean_pkt_size, sz_mean);
            MAYBE_EWMA(&e->udp_pkt_size_cov,  sz_cov);

            double uflows = service_hll_estimate(&u->udp_flows);
            MAYBE_EWMA(&e->udp_flow_ratio, uflows / dn);
            MAYBE_EWMA(&e->udp_pps_ratio,  dn);
            MAYBE_EWMA(&e->udp_bps_ratio,  (double)u->udp_bytes * 8.0);
        }
        break;
    }

    case SERVICE_PROTO_ICMP:
    case SERVICE_PROTO_CATCHALL_ICMP: {
        struct service_icmp_stats *ic = &slot->proto.icmp.stats;
        struct service_icmp_ewma  *e  = &slot->proto.icmp.ewma;
        if (ic->icmp_pkts > 0) {
            double dn = (double)ic->icmp_pkts;
            double echo_r = (double)ic->icmp_echo_pkts / dn;
            MAYBE_EWMA(&e->icmp_echo_ratio, echo_r);
            MAYBE_EWMA(&e->icmp_pps_ratio,  dn);
        }
        break;
    }

    case SERVICE_PROTO_CATCHALL_OTHER: {
        uint64_t tcp_p  = slot->proto.other_catchall.tcp_stats.tcp_pkts;
        uint64_t udp_p  = slot->proto.other_catchall.udp_stats.udp_pkts;
        uint64_t icmp_p = slot->proto.other_catchall.icmp_stats.icmp_pkts;
        uint64_t oth_p  = slot->proto.other_catchall.other_stats.other_pkts;
        uint64_t total  = tcp_p + udp_p + icmp_p + oth_p;

        double other_ratio = (total > 0)
            ? (double)oth_p / (double)total : 0.0;
        MAYBE_EWMA(&slot->common_ewma.other_proto_ratio, other_ratio);

        /* dst_port_ratio is only meaningful for OTHER catchall (per the
         * data-model docs in l2fwd_service_stats.h). */
        double udp_ports = service_hll_estimate(
            &slot->proto.other_catchall.unique_dst_ports);
        double dst_port_r = (total > 0)
            ? udp_ports / (double)total : 0.0;
        MAYBE_EWMA(&slot->common_ewma.dst_port_ratio, dst_port_r);
        break;
    }

    default:
        break;
    }
}
#undef MAYBE_EWMA

void service_features_compute_all(struct service_stats_array *arr) {
    if (!arr || !arr->slots) return;
    for (size_t i = 0; i < arr->capacity; i++) {
        if (arr->slots[i].active) {
            service_features_compute_one(&arr->slots[i]);
        }
    }
}

/* -------------------------------------------------------------------------
 * 1.7 Temporal ring buffer
 * ------------------------------------------------------------------------- */

void service_temporal_push_sample(struct service_temporal_state *tmp,
                                   uint64_t now_ns,
                                   uint64_t pkts,
                                   uint64_t bytes,
                                   uint64_t flows,
                                   uint8_t  phase)
{
    if (!tmp) return;
    uint32_t idx = tmp->sample_head;
    tmp->samples[idx].timestamp_ns    = now_ns;
    tmp->samples[idx].pkts            = pkts;
    tmp->samples[idx].bytes           = bytes;
    tmp->samples[idx].flows           = flows;
    tmp->samples[idx].detection_phase = phase;

    tmp->sample_head = (tmp->sample_head + 1u) % SERVICE_TEMPORAL_MAX_SAMPLES;
    if (tmp->sample_count < SERVICE_TEMPORAL_MAX_SAMPLES) {
        tmp->sample_count++;
    }
    tmp->total_samples_seen++;
    tmp->last_update_ns = now_ns;

    service_temporal_recompute_windows(tmp);
}

void service_temporal_recompute_windows(struct service_temporal_state *tmp) {
    if (!tmp) return;
    for (int w = 0; w < SERVICE_TEMPORAL_WINDOW_COUNT; w++) {
        struct service_temporal_window *win = &tmp->windows[w];
        uint16_t want = win->size_seconds;
        uint32_t have = (tmp->sample_count < want)
                        ? tmp->sample_count
                        : (uint32_t)want;
        win->samples_filled = (uint16_t)have;

        uint64_t total_p = 0, total_b = 0, total_f = 0;
        uint64_t peak_p  = 0, peak_b  = 0;
        uint32_t attack_secs = 0, susp_secs = 0;

        /* Walk backward from the most recent sample. sample_head points
         * to the NEXT slot to write, so (head - 1) is the newest valid
         * sample. */
        for (uint32_t k = 0; k < have; k++) {
            uint32_t i = (tmp->sample_head +
                          SERVICE_TEMPORAL_MAX_SAMPLES - 1u - k)
                          % SERVICE_TEMPORAL_MAX_SAMPLES;
            total_p += tmp->samples[i].pkts;
            total_b += tmp->samples[i].bytes;
            total_f += tmp->samples[i].flows;
            if (tmp->samples[i].pkts  > peak_p) peak_p = tmp->samples[i].pkts;
            if (tmp->samples[i].bytes > peak_b) peak_b = tmp->samples[i].bytes;
            if (tmp->samples[i].detection_phase == FEATURES_PHASE_ATTACK)
                attack_secs++;
            if (tmp->samples[i].detection_phase == FEATURES_PHASE_SUSPICIOUS)
                susp_secs++;
        }

        win->total_pkts         = total_p;
        win->total_bytes        = total_b;
        win->total_flows        = total_f;
        win->peak_pps           = (double)peak_p;
        win->peak_bps           = (double)peak_b * 8.0;
        win->mean_pps           = (have > 0)
            ? (double)total_p / (double)have : 0.0;
        win->mean_bps           = (have > 0)
            ? ((double)total_b * 8.0) / (double)have : 0.0;
        win->attack_seconds     = attack_secs;
        win->suspicious_seconds = susp_secs;
    }
}

/* -------------------------------------------------------------------------
 * 1.8 Convenience accessors
 * ------------------------------------------------------------------------- */

double service_features_unique_src_ips(const struct service_stats *slot) {
    if (!slot) return 0.0;
    return service_hll_estimate(&slot->common.unique_src_ips);
}

double service_features_unique_flows(const struct service_stats *slot) {
    if (!slot) return 0.0;
    return service_hll_estimate(&slot->common.unique_flows);
}
