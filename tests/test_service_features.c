/**
 * @file   tests/test_service_features.c
 * @brief  Standalone test harness for the P8 feature-extraction module.
 *
 * Exercises:
 *   1. HLL: 10000 unique inserts → estimate ≈ 10000 (within 10%)
 *   2. HLL: 1000 inserts of the SAME value → estimate ≈ 1
 *   3. CM:  5 buckets × 1000 inserts → top reflects heavy hitter
 *   4. CM:  uniform vs single-bucket entropy
 *   5. EWMA mean convergence on a steady-state input
 *   6. EWMA z-score on a 3σ outlier
 *   7. Burst window: (10, 10, 100) → positive large z_last
 *   8. Welford: sum=10, sum_sq=30, n=4 → mean=2.5, stddev≈1.29
 *   9. service_features_compute_one on a synthetic TCP catchall slot
 *  10. Temporal: 70 pushes → windows[10]=10, [60]=60, [300]=70
 *  11. NULL handling on every entrypoint
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <math.h>

#include "l2fwd_service_features.h"
#include "l2fwd_service_stats.h"
#include "l2fwd_service_temporal_state.h"
#include "l2fwd_service_registry.h"

static int g_pass = 0;
static int g_fail = 0;

#define CHECK(cond, fmt, ...) do {                                       \
    if (cond) {                                                           \
        g_pass++;                                                         \
        fprintf(stderr, "  [PASS] " fmt "\n", ##__VA_ARGS__);             \
    } else {                                                              \
        g_fail++;                                                         \
        fprintf(stderr, "  [FAIL] " fmt "  (%s:%d)\n",                    \
                ##__VA_ARGS__, __FILE__, __LINE__);                       \
    }                                                                     \
} while (0)

/* Fast 32-bit finalizer; same shape as the hot-path hash. */
static uint32_t hash32(uint32_t k) {
    k ^= k >> 16; k *= 0x85ebca6bu;
    k ^= k >> 13; k *= 0xc2b2ae35u;
    k ^= k >> 16;
    return k;
}

/* -------------------------------------------------------------------------
 * 1. HLL — large distinct count
 * ------------------------------------------------------------------------- */
static void test_hll_large_unique(void) {
    fprintf(stderr, "\n=== POSITIVE: HLL 10000 unique → estimate within 10%% ===\n");
    struct service_hll hll;
    memset(&hll, 0, sizeof(hll));
    for (uint32_t i = 1; i <= 10000; i++) {
        service_hll_insert(&hll, hash32(i));
    }
    double est = service_hll_estimate(&hll);
    fprintf(stderr, "  estimate = %.1f  (true = 10000)\n", est);
    CHECK(est >= 9000.0 && est <= 11000.0,
          "HLL estimate within 10%% of 10000 (got %.1f)", est);
}

/* -------------------------------------------------------------------------
 * 2. HLL — repeated single value
 * ------------------------------------------------------------------------- */
static void test_hll_single_value(void) {
    fprintf(stderr, "\n=== POSITIVE: HLL 1000 inserts of same hash → ≈1 ===\n");
    struct service_hll hll;
    memset(&hll, 0, sizeof(hll));
    uint32_t h = hash32(42);
    for (int i = 0; i < 1000; i++) service_hll_insert(&hll, h);
    double est = service_hll_estimate(&hll);
    fprintf(stderr, "  estimate = %.3f  (true = 1)\n", est);
    /* Small-range correction is linear counting: ≈ m * ln(m / (m - 1))
     * ≈ 1.0 for our register layout. Allow a generous band. */
    CHECK(est > 0.5 && est < 2.5,
          "HLL estimate ≈ 1 (got %.3f)", est);
}

/* -------------------------------------------------------------------------
 * 3. CM — heavy-hitter detection
 * ------------------------------------------------------------------------- */
static void test_cm_heavy_hitter(void) {
    fprintf(stderr, "\n=== POSITIVE: CM 5 buckets × 1000 inserts → HH visible ===\n");
    struct service_cm_src_port cm;
    memset(&cm, 0, sizeof(cm));

    /* Each port gets 1000 inserts -> they tie. Then port 80 gets +500
     * extra to make it the unambiguous heavy hitter. */
    const uint16_t ports[5] = { 22, 53, 80, 443, 8080 };
    for (int p = 0; p < 5; p++) {
        for (int n = 0; n < 1000; n++) service_cm_src_port_insert(&cm, ports[p]);
    }
    for (int n = 0; n < 500; n++) service_cm_src_port_insert(&cm, 80);

    fprintf(stderr,
            "  total=%llu  top_port=%u  top_count=%u\n",
            (unsigned long long)cm.total, (unsigned)cm.top_port,
            (unsigned)cm.top_count);
    CHECK(cm.total == 5 * 1000 + 500,
          "CM total = 5500 (got %llu)", (unsigned long long)cm.total);
    CHECK(cm.top_port == 80,
          "CM top_port = 80 (got %u)", (unsigned)cm.top_port);
    CHECK(cm.top_count >= 1500,
          "CM top_count >= 1500 (got %u)", (unsigned)cm.top_count);

    double share = service_cm_top1_share((uint64_t)cm.top_count, cm.total);
    fprintf(stderr, "  top1_share = %.3f\n", share);
    CHECK(share > 0.25 && share < 0.40,
          "top1_share ≈ 1500/5500 ≈ 0.27 (got %.3f)", share);
}

/* -------------------------------------------------------------------------
 * 4. CM — entropy: uniform vs concentrated
 * ------------------------------------------------------------------------- */
static void test_cm_entropy(void) {
    fprintf(stderr, "\n=== POSITIVE: CM /24 entropy: uniform vs concentrated ===\n");

    struct service_cm_src_24 uniform_cm;
    memset(&uniform_cm, 0, sizeof(uniform_cm));
    /* 1000 distinct /24s, one insert each. Uniform spread → high entropy. */
    for (uint32_t i = 0; i < 1000; i++) {
        uint32_t ip = (i << 8);
        service_cm_src_24_insert(&uniform_cm, ip);
    }
    double ent_u = service_cm_src_24_entropy(&uniform_cm);

    struct service_cm_src_24 conc_cm;
    memset(&conc_cm, 0, sizeof(conc_cm));
    /* 1000 inserts to the SAME /24 → concentrated → low entropy. */
    for (uint32_t i = 0; i < 1000; i++) {
        service_cm_src_24_insert(&conc_cm, 0x0A0A0A00u);
    }
    double ent_c = service_cm_src_24_entropy(&conc_cm);

    fprintf(stderr, "  uniform entropy = %.3f, concentrated entropy = %.3f\n",
            ent_u, ent_c);
    CHECK(ent_u > ent_c + 2.0,
          "uniform entropy substantially > concentrated (%.3f vs %.3f)",
          ent_u, ent_c);
    CHECK(ent_c < 1.0,
          "concentrated entropy < 1.0 bit (got %.3f)", ent_c);
}

/* -------------------------------------------------------------------------
 * 5. EWMA mean convergence
 * ------------------------------------------------------------------------- */
static void test_ewma_mean(void) {
    fprintf(stderr, "\n=== POSITIVE: EWMA mean converges on steady input ===\n");
    struct service_ewma_state s;
    memset(&s, 0, sizeof(s));
    for (int i = 0; i < 200; i++) {
        service_ewma_update(&s, 100.0, 0.1, 0.0);   /* C=0 -> winsor disabled */
    }
    fprintf(stderr, "  mean=%.4f variance=%.6f count=%u\n",
            s.mean, s.variance, (unsigned)s.sample_count);
    CHECK(fabs(s.mean - 100.0) < 0.01,
          "mean ≈ 100 after 200 identical samples (got %.4f)", s.mean);
    /* Hardening change: variance no longer decays to ~0 on constant input.
     * The min-stddev floor (intentional anti-poisoning behavior) pins it to
     * (EWMA_MIN_STDDEV_REL*|mean|)^2 = (0.01*100)^2 = 1.0 so z-scores can
     * never go numb against a flat baseline. */
    CHECK(fabs(s.variance - 1.0) < 1e-6,
          "variance floored to (0.01*mean)^2 = 1.0 (min-stddev floor) (got %.6f)",
          s.variance);
    CHECK(s.sample_count == 200, "sample_count = 200");
}

/* -------------------------------------------------------------------------
 * 6. EWMA z-score on outlier
 * ------------------------------------------------------------------------- */
static void test_ewma_zscore(void) {
    fprintf(stderr, "\n=== POSITIVE: EWMA z-score on 3σ outlier ===\n");
    struct service_ewma_state s;
    memset(&s, 0, sizeof(s));

    /* Warm up with mean ~ 100, variance ~ 25 (stddev=5). */
    unsigned int seed = 12345;
    for (int i = 0; i < 500; i++) {
        /* Simple Gaussian-ish sample via Box–Muller-lite. */
        double u1 = ((double)rand_r(&seed) + 1.0) / ((double)RAND_MAX + 2.0);
        double u2 = ((double)rand_r(&seed) + 1.0) / ((double)RAND_MAX + 2.0);
        double z  = sqrt(-2.0 * log(u1)) * cos(2.0 * M_PI * u2);
        service_ewma_update(&s, 100.0 + 5.0 * z, 0.05, 0.0);   /* C=0 -> winsor disabled */
    }
    double mean_warm = s.mean;
    double std_warm  = sqrt(s.variance);
    fprintf(stderr,
            "  after warmup: mean=%.2f stddev=%.2f\n",
            mean_warm, std_warm);

    double outlier   = mean_warm + 3.0 * std_warm;
    double z_outlier = service_ewma_z_score(&s, outlier);
    fprintf(stderr, "  z_score(outlier=%.2f) = %.3f\n", outlier, z_outlier);
    /* Re-verified under the new min-stddev floor: the relative floor here is
     * (0.01*~100)^2 = 1.0, well below the warmed ~25 variance, so it does
     * not bind and the 3σ z-score is unaffected. */
    CHECK(z_outlier > 2.5 && z_outlier < 3.5,
          "z_score on 3σ outlier ≈ 3 (got %.3f)", z_outlier);
}

/* -------------------------------------------------------------------------
 * 6b. EWMA winsorization — the clamp bounds a lone spike's influence on
 *     BOTH the mean and the variance (Change 3 anti-poisoning hardening).
 * ------------------------------------------------------------------------- */
static void test_ewma_winsorization(void) {
    fprintf(stderr, "\n=== POSITIVE: EWMA winsorization clamps a lone spike ===\n");
    struct service_ewma_state a, b;
    memset(&a, 0, sizeof(a));
    memset(&b, 0, sizeof(b));

    /* Warm BOTH identically: 50 steady samples with a REAL ceiling so a
     * stable baseline (mean≈100, variance at the min-stddev floor) forms. */
    for (int i = 0; i < 50; i++) {
        service_ewma_update(&a, 100.0, 0.1, 3.0);
        service_ewma_update(&b, 100.0, 0.1, 3.0);
    }

    /* One massive spike: A with winsor ON (C=3.0), B with winsor OFF (C=0). */
    service_ewma_update(&a, 100000.0, 0.1, 3.0);
    service_ewma_update(&b, 100000.0, 0.1, 0.0);

    fprintf(stderr,
            "  A(winsor) mean=%.4f variance=%.4f | B(no winsor) mean=%.4f variance=%.4f\n",
            a.mean, a.variance, b.mean, b.variance);

    CHECK(fabs(a.mean - 100.0) < fabs(b.mean - 100.0),
          "winsor limited the mean pull (|A-100|=%.4f < |B-100|=%.4f)",
          fabs(a.mean - 100.0), fabs(b.mean - 100.0));
    CHECK(a.variance < b.variance,
          "winsor limited the diff^2 variance inflation (A=%.4f < B=%.4f)",
          a.variance, b.variance);
    CHECK(isfinite(a.mean) && isfinite(a.variance) &&
          isfinite(b.mean) && isfinite(b.variance),
          "all mean/variance values remain finite (no NaN/inf)");
}

/* -------------------------------------------------------------------------
 * 7. Burst window — large outlier
 * ------------------------------------------------------------------------- */
static void test_burst_window(void) {
    fprintf(stderr, "\n=== POSITIVE: burst window (10, 10, 100) → large positive z ===\n");
    struct service_burst_window bw;
    memset(&bw, 0, sizeof(bw));
    service_burst_window_push(&bw, 10.0);
    service_burst_window_push(&bw, 10.0);
    service_burst_window_push(&bw, 100.0);
    fprintf(stderr, "  filled=%d mean=%.2f stddev=%.4f z_last=%.4f\n",
            bw.filled, bw.mean, bw.stddev, bw.z_last);
    CHECK(bw.filled == 3, "filled = 3");
    CHECK(bw.mean > 39.0 && bw.mean < 41.0,
          "mean ≈ 40 (got %.2f)", bw.mean);
    CHECK(bw.z_last > 1.0,
          "z_last positive and large (got %.4f)", bw.z_last);
}

/* -------------------------------------------------------------------------
 * 8. Welford from running sums (Bessel-corrected)
 * ------------------------------------------------------------------------- */
static void test_welford(void) {
    fprintf(stderr, "\n=== POSITIVE: Welford sum=10 sum_sq=30 n=4 → mean=2.5 stddev≈1.29 ===\n");
    double mean = 0.0, stddev = 0.0;
    service_compute_mean_stddev(10, 30, 4, &mean, &stddev);
    fprintf(stderr, "  mean=%.4f stddev=%.4f\n", mean, stddev);
    CHECK(fabs(mean - 2.5) < 1e-9,
          "mean = 2.5 (got %.4f)", mean);
    CHECK(fabs(stddev - sqrt(5.0/3.0)) < 1e-6,
          "stddev ≈ 1.2910 (got %.4f)", stddev);
}

/* -------------------------------------------------------------------------
 * 9. service_features_compute_one on a synthetic TCP catchall slot
 * ------------------------------------------------------------------------- */
static void test_compute_one(void) {
    fprintf(stderr, "\n=== POSITIVE: service_features_compute_one on synthetic slot ===\n");

    static struct service_stats slot;
    memset(&slot, 0, sizeof(slot));
    slot.active        = true;
    slot.proto_kind    = SERVICE_PROTO_CATCHALL_TCP;
    slot.is_catchall   = true;
    slot.profile       = NULL;     /* use default alpha 0.05 */

    /* 1000 inbound packets, mean size 1500, all with TTL=64. */
    slot.common.inbound_pkts  = 1000;
    slot.common.inbound_bytes = 1500u * 1000u;
    slot.common.ttl_sum       = 64u * 1000u;
    slot.common.ttl_sum_sq    = 64u * 64u * 1000u;
    slot.common.off_proto_pkts = 0;
    slot.common.ip_frag_pkts   = 0;

    /* 200 SYN, 100 SYN+ACK, 50 RST, rest ack_data. Numbers are simple
     * proportions used to verify the EWMA gets reasonable values. */
    slot.proto.tcp.stats.tcp_pkts          = 1000;
    slot.proto.tcp.stats.tcp_bytes         = 1500u * 1000u;
    slot.proto.tcp.stats.syn_pkts          = 200;
    slot.proto.tcp.stats.syn_ack_pkts      = 100;
    slot.proto.tcp.stats.rst_pkts          = 50;
    slot.proto.tcp.stats.ack_data_pkts     = 650;
    slot.proto.tcp.stats.empty_ack_pkts    = 0;
    slot.proto.tcp.stats.zero_window_pkts  = 0;
    slot.proto.tcp.stats.small_window_pkts = 0;
    slot.proto.tcp.stats.tcp_pkt_size_sum    = 1500u * 1000u;
    slot.proto.tcp.stats.tcp_pkt_size_sum_sq = 1500u * 1500u * 1000u;

    /* Populate the source-IP HLL with 300 distinct hashes so src_ip_ratio
     * is ~0.3 when divided by 1000 inbound pkts. */
    for (uint32_t i = 1; i <= 300; i++) {
        service_hll_insert(&slot.common.unique_src_ips, hash32(i));
    }

    /* Call the function under test. */
    service_features_compute_one(&slot);

    /* Verify a handful of derived EWMA fields look right after a single
     * sample (mean equals first observation). */
    CHECK(slot.common_ewma.pps.initialized,
          "common_ewma.pps marked initialized");
    CHECK(fabs(slot.common_ewma.pps.mean - 1000.0) < 1e-6,
          "common_ewma.pps.mean = 1000 (got %.2f)", slot.common_ewma.pps.mean);
    CHECK(fabs(slot.common_ewma.bps.mean - 1000.0 * 1500.0 * 8.0) < 1.0,
          "common_ewma.bps.mean = pps*1500*8 (got %.2f)",
          slot.common_ewma.bps.mean);
    CHECK(slot.common_ewma.ttl_stddev.initialized,
          "common_ewma.ttl_stddev initialized (TTL is uniform → stddev=0)");
    CHECK(fabs(slot.common_ewma.ttl_stddev.mean) < 1e-6,
          "ttl_stddev.mean ≈ 0 for uniform TTL (got %.6f)",
          slot.common_ewma.ttl_stddev.mean);

    /* syn_ratio = 200 / 1000 = 0.20 */
    CHECK(fabs(slot.proto.tcp.ewma.syn_ratio.mean - 0.20) < 1e-6,
          "tcp.ewma.syn_ratio = 0.20 (got %.4f)",
          slot.proto.tcp.ewma.syn_ratio.mean);
    /* synack_ratio = 100 / 1000 = 0.10 */
    CHECK(fabs(slot.proto.tcp.ewma.synack_ratio.mean - 0.10) < 1e-6,
          "tcp.ewma.synack_ratio = 0.10 (got %.4f)",
          slot.proto.tcp.ewma.synack_ratio.mean);
    /* syn_to_synack = 200 / 100 = 2.0 */
    CHECK(fabs(slot.proto.tcp.ewma.syn_to_synack_ratio.mean - 2.0) < 1e-6,
          "tcp.ewma.syn_to_synack = 2.0 (got %.4f)",
          slot.proto.tcp.ewma.syn_to_synack_ratio.mean);
    /* tcp_mean_pkt_size = 1500 */
    CHECK(fabs(slot.proto.tcp.ewma.tcp_mean_pkt_size.mean - 1500.0) < 1e-6,
          "tcp.ewma.tcp_mean_pkt_size = 1500 (got %.2f)",
          slot.proto.tcp.ewma.tcp_mean_pkt_size.mean);
    /* Burst window pushed once → filled=1, mean=1000. */
    CHECK(slot.common.bw_pps.filled == 1,
          "bw_pps.filled = 1 (got %d)", slot.common.bw_pps.filled);
    CHECK(fabs(slot.common.bw_pps.mean - 1000.0) < 1e-6,
          "bw_pps.mean = 1000 (got %.2f)", slot.common.bw_pps.mean);

    /* src_ip_ratio: HLL estimate of 300 / 1000 ≈ 0.30 (rough). */
    fprintf(stderr,
            "  common_ewma.src_ip_ratio.mean = %.4f (expected ~0.3)\n",
            slot.common_ewma.src_ip_ratio.mean);
    CHECK(slot.common_ewma.src_ip_ratio.mean > 0.15 &&
          slot.common_ewma.src_ip_ratio.mean < 0.50,
          "src_ip_ratio in [0.15, 0.50]");
}

/* -------------------------------------------------------------------------
 * 10. Temporal push + recompute windows
 * ------------------------------------------------------------------------- */
static void test_temporal_push(void) {
    fprintf(stderr, "\n=== POSITIVE: 70 temporal pushes → windows[10]=10, [60]=60, [300]=70 ===\n");
    struct service_temporal_state tmp;
    service_temporal_state_init(&tmp);

    for (uint64_t i = 0; i < 70; i++) {
        service_temporal_push_sample(&tmp,
                                      1000000000ULL * (i + 1),
                                      100u + i,           /* pkts */
                                      (100u + i) * 1500u, /* bytes */
                                      10u + i,            /* flows */
                                      1);                 /* phase=NORMAL */
    }

    fprintf(stderr,
            "  sample_count=%u  total_seen=%llu\n",
            (unsigned)tmp.sample_count,
            (unsigned long long)tmp.total_samples_seen);
    fprintf(stderr,
            "  10s: filled=%u total_pkts=%llu mean_pps=%.2f peak_pps=%.2f\n",
            (unsigned)tmp.windows[0].samples_filled,
            (unsigned long long)tmp.windows[0].total_pkts,
            tmp.windows[0].mean_pps, tmp.windows[0].peak_pps);
    fprintf(stderr,
            "  60s: filled=%u  300s: filled=%u\n",
            (unsigned)tmp.windows[1].samples_filled,
            (unsigned)tmp.windows[2].samples_filled);

    CHECK(tmp.sample_count == 70, "sample_count = 70");
    CHECK(tmp.total_samples_seen == 70, "total_samples_seen = 70");
    CHECK(tmp.windows[0].samples_filled == 10,
          "windows[10s].samples_filled = 10");
    CHECK(tmp.windows[1].samples_filled == 60,
          "windows[60s].samples_filled = 60");
    CHECK(tmp.windows[2].samples_filled == 70,
          "windows[300s].samples_filled = 70 (capped at sample_count)");

    /* peak_pps in the last 10s = max of samples 60..69 pkts = 100+69 = 169. */
    CHECK(fabs(tmp.windows[0].peak_pps - 169.0) < 1e-9,
          "windows[10s].peak_pps = 169 (got %.2f)",
          tmp.windows[0].peak_pps);
}

/* -------------------------------------------------------------------------
 * 11. NULL handling
 * ------------------------------------------------------------------------- */
static void test_null_handling(void) {
    fprintf(stderr, "\n=== NEGATIVE: NULL handling ===\n");

    service_hll_insert(NULL, 0);            CHECK(true, "hll_insert(NULL) safe");
    service_hll_reset (NULL);               CHECK(true, "hll_reset(NULL) safe");
    CHECK(service_hll_estimate(NULL) == 0.0,
          "hll_estimate(NULL) returns 0");

    service_cm_src_port_insert(NULL, 0);    CHECK(true, "cm_port_insert(NULL) safe");
    service_cm_src_24_insert  (NULL, 0);    CHECK(true, "cm_24_insert(NULL) safe");
    service_cm_src_port_reset (NULL);       CHECK(true, "cm_port_reset(NULL) safe");
    service_cm_src_24_reset   (NULL);       CHECK(true, "cm_24_reset(NULL) safe");
    CHECK(service_cm_top1_share(0, 0) == 0.0,
          "cm_top1_share(0,0) returns 0");
    CHECK(service_cm_src_24_entropy(NULL) == 0.0,
          "cm_24_entropy(NULL) returns 0");

    service_ewma_update(NULL, 0.0, 0.0, 0.0);    CHECK(true, "ewma_update(NULL) safe");
    CHECK(service_ewma_z_score(NULL, 0.0) == 0.0,
          "ewma_z_score(NULL) returns 0");

    service_burst_window_push (NULL, 0.0);  CHECK(true, "burst_push(NULL) safe");
    service_burst_window_reset(NULL);       CHECK(true, "burst_reset(NULL) safe");

    /* compute_mean_stddev: NULL outputs are individually OK. */
    service_compute_mean_stddev(0, 0, 0, NULL, NULL);
    CHECK(true, "compute_mean_stddev(NULL, NULL) safe");
    double m_only = -1.0;
    service_compute_mean_stddev(10, 30, 4, &m_only, NULL);
    CHECK(fabs(m_only - 2.5) < 1e-9, "compute_mean_stddev: mean-only out OK");

    service_features_compute_one(NULL);     CHECK(true, "compute_one(NULL) safe");
    service_features_compute_all(NULL);     CHECK(true, "compute_all(NULL) safe");

    service_temporal_push_sample(NULL, 0, 0, 0, 0, 0);
    CHECK(true, "temporal_push_sample(NULL) safe");
    service_temporal_recompute_windows(NULL);
    CHECK(true, "temporal_recompute(NULL) safe");

    CHECK(service_features_unique_src_ips(NULL) == 0.0,
          "unique_src_ips(NULL) returns 0");
    CHECK(service_features_unique_flows  (NULL) == 0.0,
          "unique_flows(NULL) returns 0");
}

/* -------------------------------------------------------------------------
 * main
 * ------------------------------------------------------------------------- */
int main(void) {
    fprintf(stderr, "\n*** service_features P8 test harness ***\n");

    test_hll_large_unique();
    test_hll_single_value();
    test_cm_heavy_hitter();
    test_cm_entropy();
    test_ewma_mean();
    test_ewma_zscore();
    test_ewma_winsorization();
    test_burst_window();
    test_welford();
    test_compute_one();
    test_temporal_push();
    test_null_handling();

    fprintf(stderr, "\n=== SUMMARY: %d PASS, %d FAIL ===\n", g_pass, g_fail);
    return (g_fail == 0) ? 0 : 1;
}
