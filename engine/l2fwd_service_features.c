/**
 * @file   l2fwd_service_features.c
 * @brief  Per-service probabilistic-sketch primitives (HLL + Count-Min).
 *
 * POST-CUTOVER (P5): the EWMA / burst / Welford / per-slot feature
 * orchestrator / temporal-push code that used to live here has moved to the
 * Python detection brain (ddos_monitor/detection); the byte-frozen C copy is
 * the parity oracle in legacy/reference/. What remains is the sketch math the
 * data plane still runs: the hot path INSERTS per packet, and the snapshot
 * producer reads the ESTIMATES once per 1 Hz tick.
 */

#include "l2fwd_service_features.h"
#include "l2fwd_service_stats.h"

#include <math.h>
#include <string.h>

/* -------------------------------------------------------------------------
 * HyperLogLog
 *
 * NOTE on register encoding: the standard HLL definition stores ρ(w) — the
 * position of the leftmost 1-bit in the (W-b)-bit value w, counted from the
 * MSB and 1-indexed. With W=32, b=10 we have 22 bits in w. Converting from
 * __builtin_clz on a 32-bit int (which has 10 leading zero bits before the
 * 22-bit window): ρ = clz(w) - 10 + 1 = clz(w) - 9. The `w | 0x1` guard keeps
 * clz bounded for the w=0 case, yielding ρ=22 there.
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
 * Count-Min sketch
 *
 * Four independent hash functions per CM, seeded with distinct constants. The
 * hash is a 64-bit multiply-shift in the SplitMix family — fast and adequate
 * decorrelation for sketch use (no cryptographic strength needed).
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
    /* Approximate Shannon entropy from row-0 column counts. Using a single row
     * is a low-cost surrogate for the true CM top-K distribution. */
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
