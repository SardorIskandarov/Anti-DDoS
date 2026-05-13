/**
 * @file   tests/test_service_scoring.c
 * @brief  Standalone test harness for the P9 detection scoring layer.
 *
 * Exercises:
 *   1. CUSUM primitive: constant input -> S_plus stays 0; jump -> breach
 *   2. CUSUM recovery: after breach, return-to-mean drains S_plus to 0
 *   3. Tier-0 ramp detection across the 6 channels
 *   4. Tier-1 TCP scoring on a synthetic SYN flood
 *   5. Tier-1 distribution: concentrated /24 lifts dist_score
 *   6. Off-protocol detector
 *   7. Phase machine: WARMUP -> NORMAL -> SUSPICIOUS -> ATTACK -> NORMAL
 *   8. Baseline freeze: while in ATTACK, EWMA mean stays unchanged
 *   9. NULL handling on every public entrypoint
 *  10. service_scoring_evaluate_all on a real registry-loaded stats array
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <math.h>

#include "l2fwd_service_scoring.h"
#include "l2fwd_service_features.h"
#include "l2fwd_service_stats.h"
#include "l2fwd_service_detection.h"
#include "l2fwd_service_temporal_state.h"
#include "l2fwd_service_registry.h"

#define SERVICES_JSON_PATH \
    "/home/user_1/Music/Anti-DDoS/service_registry/services.json"

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

/* -------------------------------------------------------------------------
 * Helpers for constructing synthetic slots
 * ------------------------------------------------------------------------- */

/* Initialise a slot with detection_state wired and a fully-warmed EWMA on
 * common_ewma.pps/bps/fps. baseline_mean/var are the EWMA initial values;
 * sample_count is set so the slot looks "post-warmup" to z-score consumers. */
static void
make_warmed_slot(struct service_stats *slot,
                  struct service_detection_state *det,
                  uint8_t proto_kind,
                  double pps_mean, double pps_var,
                  double bps_mean, double bps_var)
{
    memset(slot, 0, sizeof(*slot));
    slot->active      = true;
    slot->proto_kind  = proto_kind;
    slot->is_catchall = (proto_kind >= SERVICE_PROTO_CATCHALL_TCP);
    slot->key.target_ip = 0x0A0A0A01u;
    slot->key.port      = 80;
    slot->profile       = NULL;

    memset(det, 0, sizeof(*det));
    det->active           = true;
    det->phase            = SERVICE_DET_PHASE_NORMAL;
    det->warmup_remaining = 0;
    slot->detection_state = det;

    slot->common_ewma.pps.mean         = pps_mean;
    slot->common_ewma.pps.variance     = pps_var;
    slot->common_ewma.pps.initialized  = true;
    slot->common_ewma.pps.sample_count = 1000;

    slot->common_ewma.bps.mean         = bps_mean;
    slot->common_ewma.bps.variance     = bps_var;
    slot->common_ewma.bps.initialized  = true;
    slot->common_ewma.bps.sample_count = 1000;

    /* fps is small by default — for tests that don't care it stays low. */
    slot->common_ewma.fps.initialized  = true;
    slot->common_ewma.fps.sample_count = 1000;
}

/* -------------------------------------------------------------------------
 * 1. CUSUM basic
 * ------------------------------------------------------------------------- */
static void test_cusum_basic(void) {
    fprintf(stderr, "\n=== POSITIVE: CUSUM basic (constant input -> S=0; jump -> breach) ===\n");
    struct service_cusum_state cs;
    service_scoring_cusum_reset(&cs);

    /* Constant input at mean: deviation=0, S decays toward 0. */
    for (int i = 0; i < 50; i++) {
        bool b = service_scoring_cusum_update(&cs, 100.0, 100.0, 10.0, 0.5, 4.0);
        if (b) { CHECK(false, "no breach expected on constant input"); return; }
    }
    CHECK(cs.S_plus == 0.0, "S_plus stays 0 on constant input (got %.3f)", cs.S_plus);
    CHECK(cs.breach_count == 0, "no breaches on constant input");

    /* Jump to 10 sigma above mean. deviation=10. S_plus = max(0,0 + 10 - 0.5) = 9.5. */
    bool b = service_scoring_cusum_update(&cs, 200.0, 100.0, 10.0, 0.5, 4.0);
    fprintf(stderr, "  after +10σ jump: S_plus=%.3f breach=%d\n", cs.S_plus, (int)b);
    CHECK(b == true, "breach reported on +10σ jump");
    CHECK(cs.S_plus > 4.0, "S_plus > h after jump (got %.3f)", cs.S_plus);
    CHECK(cs.breach_count == 1, "breach_count = 1");
    CHECK(cs.last_value == 200.0, "last_value cached");
}

/* -------------------------------------------------------------------------
 * 2. CUSUM recovery
 * ------------------------------------------------------------------------- */
static void test_cusum_recovery(void) {
    fprintf(stderr, "\n=== POSITIVE: CUSUM recovery (S_plus decays to 0) ===\n");
    struct service_cusum_state cs;
    service_scoring_cusum_reset(&cs);

    /* Seed S_plus with a breach. */
    for (int i = 0; i < 3; i++) {
        service_scoring_cusum_update(&cs, 200.0, 100.0, 10.0, 0.5, 4.0);
    }
    double S_peak = cs.S_plus;
    CHECK(S_peak > 4.0, "S_plus elevated before recovery (%.3f)", S_peak);

    /* Return to mean: deviation=0; S_plus drains by k=0.5 each tick. */
    int decayed_to_zero_in = -1;
    for (int i = 1; i <= 200; i++) {
        service_scoring_cusum_update(&cs, 100.0, 100.0, 10.0, 0.5, 4.0);
        if (cs.S_plus == 0.0) {
            decayed_to_zero_in = i;
            break;
        }
    }
    fprintf(stderr, "  S_plus decayed to 0 after %d ticks of return-to-mean\n",
            decayed_to_zero_in);
    CHECK(decayed_to_zero_in > 0, "S_plus eventually reached 0");
    CHECK(decayed_to_zero_in < 200, "drained within 200 ticks");
}

/* -------------------------------------------------------------------------
 * 3. Tier-0 ramp detection
 * ------------------------------------------------------------------------- */
static void test_tier0_ramp(void) {
    fprintf(stderr, "\n=== POSITIVE: Tier-0 ramp detection ===\n");
    struct service_stats slot;
    struct service_detection_state det;
    make_warmed_slot(&slot, &det,
                     SERVICE_PROTO_TCP,
                     /* pps_mean = */ 100.0, /* pps_var = */ 100.0,
                     /* bps_mean = */ 100.0 * 1500.0 * 8.0,
                     /* bps_var  = */ 1e6);

    /* Baseline tick: inbound_pkts matches mean. Expect low Tier-0. */
    slot.common.inbound_pkts  = 100;
    slot.common.inbound_bytes = 100 * 1500;
    double s_base = service_scoring_tier0_evaluate(&slot);
    fprintf(stderr, "  baseline tier0_score = %.3f\n", s_base);
    CHECK(s_base < 0.1, "Tier-0 score near 0 at baseline (got %.3f)", s_base);

    /* Ramped tick: 10x baseline pps. Expect elevated Tier-0. */
    slot.common.inbound_pkts  = 1000;
    slot.common.inbound_bytes = 1000 * 1500;
    double s_ramp = service_scoring_tier0_evaluate(&slot);
    fprintf(stderr, "  ramped tier0_score   = %.3f\n", s_ramp);
    CHECK(s_ramp > s_base + 0.1,
          "Tier-0 score rose substantially under ramp (%.3f vs %.3f)",
          s_ramp, s_base);
    CHECK(det.last_tier0_risk_pps > 0.5,
          "tier0_risk_pps elevated (%.3f)", det.last_tier0_risk_pps);
}

/* -------------------------------------------------------------------------
 * 4. Tier-1 TCP synthetic SYN flood
 * ------------------------------------------------------------------------- */
static void test_tier1_tcp_synflood(void) {
    fprintf(stderr, "\n=== POSITIVE: Tier-1 TCP scoring on synthetic SYN flood ===\n");
    struct service_stats slot;
    struct service_detection_state det;
    make_warmed_slot(&slot, &det, SERVICE_PROTO_TCP, 100.0, 100.0,
                     1.2e6, 1e8);

    /* Seed TCP EWMA baselines: low SYN ratio (~5%), normal pkt-size CoV. */
    slot.proto.tcp.ewma.syn_ratio.mean         = 0.05;
    slot.proto.tcp.ewma.syn_ratio.variance     = 0.0025;
    slot.proto.tcp.ewma.syn_ratio.initialized  = true;
    slot.proto.tcp.ewma.syn_ratio.sample_count = 1000;
    slot.proto.tcp.ewma.empty_ack_ratio.mean         = 0.10;
    slot.proto.tcp.ewma.empty_ack_ratio.variance     = 0.01;
    slot.proto.tcp.ewma.empty_ack_ratio.initialized  = true;
    slot.proto.tcp.ewma.empty_ack_ratio.sample_count = 1000;
    slot.proto.tcp.ewma.zero_window_ratio.mean         = 0.0;
    slot.proto.tcp.ewma.zero_window_ratio.variance     = 0.0001;
    slot.proto.tcp.ewma.zero_window_ratio.initialized  = true;
    slot.proto.tcp.ewma.zero_window_ratio.sample_count = 1000;
    slot.proto.tcp.ewma.syn_to_synack_ratio.mean         = 1.05;
    slot.proto.tcp.ewma.syn_to_synack_ratio.variance     = 0.1;
    slot.proto.tcp.ewma.syn_to_synack_ratio.initialized  = true;
    slot.proto.tcp.ewma.syn_to_synack_ratio.sample_count = 1000;
    slot.proto.tcp.ewma.tcp_pkt_size_cov.mean         = 0.20;
    slot.proto.tcp.ewma.tcp_pkt_size_cov.variance     = 0.01;
    slot.proto.tcp.ewma.tcp_pkt_size_cov.initialized  = true;
    slot.proto.tcp.ewma.tcp_pkt_size_cov.sample_count = 1000;

    /* Baseline window: matches EWMA -> low score. */
    slot.proto.tcp.stats.tcp_pkts          = 1000;
    slot.proto.tcp.stats.tcp_bytes         = 1500u * 1000u;
    slot.proto.tcp.stats.syn_pkts          =  50;   /* 5%  ratio */
    slot.proto.tcp.stats.syn_ack_pkts      =  48;
    slot.proto.tcp.stats.empty_ack_pkts    = 100;
    slot.proto.tcp.stats.zero_window_pkts  =   0;
    slot.proto.tcp.stats.tcp_pkt_size_sum    = 1500u * 1000u;
    slot.proto.tcp.stats.tcp_pkt_size_sum_sq = 1500u * 1500u * 1000u;
    double s_base = service_scoring_tier1_tcp(&slot);
    fprintf(stderr, "  baseline tier1_tcp = %.3f\n", s_base);
    CHECK(s_base < 0.3, "Tier-1 TCP near 0 at baseline (got %.3f)", s_base);

    /* SYN flood window: 80% SYN, syn_to_synack way off. */
    slot.proto.tcp.stats.tcp_pkts     = 1000;
    slot.proto.tcp.stats.syn_pkts     = 800;
    slot.proto.tcp.stats.syn_ack_pkts =  20;    /* syn_to_synack = 40 */
    slot.proto.tcp.stats.empty_ack_pkts    = 30;
    slot.proto.tcp.stats.zero_window_pkts  = 50;
    double s_attack = service_scoring_tier1_tcp(&slot);
    fprintf(stderr, "  synflood tier1_tcp = %.3f\n", s_attack);
    CHECK(s_attack > s_base + 0.1,
          "Tier-1 TCP rose under SYN flood (%.3f vs %.3f)",
          s_attack, s_base);
    CHECK(s_attack > 0.3,
          "Tier-1 TCP score elevated above 0.3 (got %.3f)", s_attack);
}

/* -------------------------------------------------------------------------
 * 5. Tier-1 distribution
 * ------------------------------------------------------------------------- */
static void test_tier1_distribution(void) {
    fprintf(stderr, "\n=== POSITIVE: Tier-1 distribution (concentration spike) ===\n");
    struct service_stats slot;
    struct service_detection_state det;
    make_warmed_slot(&slot, &det, SERVICE_PROTO_CATCHALL_TCP, 100.0, 100.0,
                     1.2e6, 1e8);

    /* Baseline: a healthy mix of /24s. */
    slot.common.inbound_pkts = 1000;
    slot.common_ewma.src_ip_ratio.mean         = 0.30;
    slot.common_ewma.src_ip_ratio.variance     = 0.01;
    slot.common_ewma.src_ip_ratio.initialized  = true;
    slot.common_ewma.src_ip_ratio.sample_count = 1000;
    slot.common_ewma.src_24_top1_share.mean         = 0.05;
    slot.common_ewma.src_24_top1_share.variance     = 0.001;
    slot.common_ewma.src_24_top1_share.initialized  = true;
    slot.common_ewma.src_24_top1_share.sample_count = 1000;
    slot.common_ewma.src_24_entropy.mean         = 8.0;
    slot.common_ewma.src_24_entropy.variance     = 0.5;
    slot.common_ewma.src_24_entropy.initialized  = true;
    slot.common_ewma.src_24_entropy.sample_count = 1000;

    /* Populate CM /24 with uniform diverse traffic. */
    for (uint32_t i = 0; i < 200; i++) {
        service_cm_src_24_insert(&slot.common.cm_src_24, i << 8);
    }
    /* Populate HLL src ips with 300 unique. */
    for (uint32_t i = 0; i < 300; i++) {
        service_hll_insert(&slot.common.unique_src_ips, i * 0x9E3779B1u);
    }
    double s_base = service_scoring_tier1_distribution(&slot);
    fprintf(stderr, "  baseline dist_score = %.3f\n", s_base);

    /* Concentration spike: 1000 inserts to ONE /24. */
    memset(&slot.common.cm_src_24, 0, sizeof(slot.common.cm_src_24));
    for (int i = 0; i < 1000; i++) {
        service_cm_src_24_insert(&slot.common.cm_src_24, 0xC0A80100u);
    }
    double s_conc = service_scoring_tier1_distribution(&slot);
    fprintf(stderr, "  concentrated dist_score = %.3f\n", s_conc);
    CHECK(s_conc > s_base + 0.05,
          "dist score rises under /24 concentration (%.3f vs %.3f)",
          s_conc, s_base);
}

/* -------------------------------------------------------------------------
 * 6. Off-protocol detector
 * ------------------------------------------------------------------------- */
static void test_offproto(void) {
    fprintf(stderr, "\n=== POSITIVE: off-protocol detector ===\n");
    struct service_stats slot;
    struct service_detection_state det;
    make_warmed_slot(&slot, &det, SERVICE_PROTO_TCP, 100.0, 100.0,
                     1.2e6, 1e8);

    slot.common.inbound_pkts = 1000;
    slot.common.off_proto_pkts = 0;
    slot.common_ewma.off_proto_pkts_ratio.mean         = 0.01;
    slot.common_ewma.off_proto_pkts_ratio.variance     = 0.0001;
    slot.common_ewma.off_proto_pkts_ratio.initialized  = true;
    slot.common_ewma.off_proto_pkts_ratio.sample_count = 1000;

    double s_base = service_scoring_offproto(&slot);
    fprintf(stderr, "  baseline offproto = %.3f\n", s_base);
    CHECK(s_base < 0.2, "offproto baseline near 0 (got %.3f)", s_base);

    /* 30% of inbound is off-proto — way above the 1% EWMA baseline. */
    slot.common.off_proto_pkts = 300;
    double s_high = service_scoring_offproto(&slot);
    fprintf(stderr, "  elevated offproto = %.3f\n", s_high);
    CHECK(s_high > s_base + 0.1,
          "offproto rose under off-proto traffic (%.3f vs %.3f)",
          s_high, s_base);
}

/* -------------------------------------------------------------------------
 * 7. Phase machine
 * ------------------------------------------------------------------------- */
static void test_phase_machine(void) {
    fprintf(stderr, "\n=== POSITIVE: phase machine WARMUP -> NORMAL -> SUSPICIOUS -> ATTACK -> NORMAL ===\n");
    struct service_stats slot;
    struct service_detection_state det;
    make_warmed_slot(&slot, &det, SERVICE_PROTO_TCP, 100.0, 100.0,
                     1.2e6, 1e8);
    det.phase            = SERVICE_DET_PHASE_WARMUP;
    det.warmup_remaining = 3;

    /* Seed the off-protocol EWMA at a tight, low baseline.
     * We'll drive the phase machine through this channel because it
     * needs only one well-warmed feature to produce a saturating score
     * (avoids the "Tier-0 alone caps at 0.333 when only 2/6 channels
     * breach" issue that comes from minimal-state synthetic slots). */
    slot.common_ewma.off_proto_pkts_ratio.mean         = 0.01;
    slot.common_ewma.off_proto_pkts_ratio.variance     = 1e-4;
    slot.common_ewma.off_proto_pkts_ratio.initialized  = true;
    slot.common_ewma.off_proto_pkts_ratio.sample_count = 1000;

    /* 3 warmup ticks at baseline. */
    slot.common.inbound_pkts   = 100;
    slot.common.inbound_bytes  = 100u * 1500u;
    slot.common.off_proto_pkts = 1;
    for (int i = 0; i < 3; i++) service_scoring_update_phase(&slot);
    CHECK(det.phase == SERVICE_DET_PHASE_NORMAL,
          "after warmup_remaining=0, phase = NORMAL (got %s)",
          service_detection_phase_name(det.phase));

    /* One elevated window: 30% off-proto vs 1% baseline → tier1_offproto ~ 1.0. */
    slot.common.inbound_pkts   = 1000;
    slot.common.inbound_bytes  = 1000u * 1500u;
    slot.common.off_proto_pkts = 300;
    service_scoring_update_phase(&slot);
    CHECK(det.phase == SERVICE_DET_PHASE_SUSPICIOUS,
          "NORMAL + high score -> SUSPICIOUS (got %s, evidence=%.3f)",
          service_detection_phase_name(det.phase),
          det.last_attack_evidence);

    /* Sustained elevated for several more windows → ATTACK after
     * PERSISTENCE_WINDOWS = 3 consecutive elevated readings. */
    for (int i = 0; i < 5; i++) service_scoring_update_phase(&slot);
    CHECK(det.phase == SERVICE_DET_PHASE_ATTACK,
          "SUSPICIOUS persists -> ATTACK (got %s, consec=%u, freeze_rem=%u)",
          service_detection_phase_name(det.phase),
          (unsigned)det.consecutive_attack_windows,
          (unsigned)det.baseline_freeze_remaining);
    CHECK(det.baseline_freeze_remaining > 0,
          "baseline_freeze armed (%u)", (unsigned)det.baseline_freeze_remaining);

    /* Recovery: drop back to baseline traffic for many windows. */
    slot.common.inbound_pkts   = 100;
    slot.common.inbound_bytes  = 100u * 1500u;
    slot.common.off_proto_pkts = 1;
    int recovered_at = -1;
    for (int i = 0; i < 50; i++) {
        service_scoring_update_phase(&slot);
        if (det.phase == SERVICE_DET_PHASE_NORMAL) { recovered_at = i + 1; break; }
    }
    fprintf(stderr, "  recovered to NORMAL after %d post-attack windows\n",
            recovered_at);
    CHECK(recovered_at > 0,
          "ATTACK -> NORMAL (got %s after %d windows)",
          service_detection_phase_name(det.phase), recovered_at);
    CHECK(det.thaw_cooldown_remaining > 0,
          "thaw_cooldown armed on exit (%u)",
          (unsigned)det.thaw_cooldown_remaining);
}

/* -------------------------------------------------------------------------
 * 8. Baseline freeze
 * ------------------------------------------------------------------------- */
static void test_freeze(void) {
    fprintf(stderr, "\n=== POSITIVE: baseline freeze blocks EWMA updates ===\n");
    struct service_stats slot;
    struct service_detection_state det;
    make_warmed_slot(&slot, &det, SERVICE_PROTO_TCP, 100.0, 100.0,
                     1.2e6, 1e8);

    /* Freeze active. */
    det.baseline_freeze_remaining = 10;
    CHECK(service_scoring_is_frozen(&slot) == true,
          "service_scoring_is_frozen returns true during freeze");

    double pre_mean_pps = slot.common_ewma.pps.mean;
    double pre_mean_bps = slot.common_ewma.bps.mean;
    uint32_t pre_count  = slot.common_ewma.pps.sample_count;

    /* Push attack-magnitude raw counters and run compute_one. */
    slot.common.inbound_pkts  = 10000;
    slot.common.inbound_bytes = 10000u * 1500u;
    slot.common.ttl_sum       = 64u * 10000u;
    slot.common.ttl_sum_sq    = 64u * 64u * 10000u;
    service_features_compute_one(&slot);

    CHECK(slot.common_ewma.pps.mean == pre_mean_pps,
          "pps.mean unchanged during freeze (%.3f)", slot.common_ewma.pps.mean);
    CHECK(slot.common_ewma.bps.mean == pre_mean_bps,
          "bps.mean unchanged during freeze (%.3f)", slot.common_ewma.bps.mean);
    CHECK(slot.common_ewma.pps.sample_count == pre_count,
          "sample_count unchanged during freeze (was %u, now %u)",
          (unsigned)pre_count, (unsigned)slot.common_ewma.pps.sample_count);

    /* Burst window pushes still happen (no persistent state to corrupt). */
    CHECK(slot.common.bw_pps.filled >= 1,
          "burst window still receives samples during freeze (filled=%d)",
          slot.common.bw_pps.filled);

    /* Unfreeze: next compute_one MUST update the EWMA. */
    det.baseline_freeze_remaining = 0;
    slot.common.inbound_pkts  = 1000;
    slot.common.inbound_bytes = 1000u * 1500u;
    service_features_compute_one(&slot);
    CHECK(slot.common_ewma.pps.mean != pre_mean_pps,
          "pps.mean updated after thaw (%.3f)", slot.common_ewma.pps.mean);
}

/* -------------------------------------------------------------------------
 * 9. NULL handling
 * ------------------------------------------------------------------------- */
static void test_null_handling(void) {
    fprintf(stderr, "\n=== NEGATIVE: NULL handling ===\n");

    CHECK(service_scoring_cusum_update(NULL, 0,0,1,0,1) == false,
          "cusum_update(NULL) safe");
    service_scoring_cusum_reset(NULL);
    CHECK(true, "cusum_reset(NULL) safe");

    CHECK(service_scoring_tier0_evaluate(NULL) == 0.0,
          "tier0_evaluate(NULL) returns 0");
    CHECK(service_scoring_tier1_tcp(NULL)          == 0.0, "tier1_tcp(NULL) safe");
    CHECK(service_scoring_tier1_udp(NULL)          == 0.0, "tier1_udp(NULL) safe");
    CHECK(service_scoring_tier1_icmp(NULL)         == 0.0, "tier1_icmp(NULL) safe");
    CHECK(service_scoring_tier1_distribution(NULL) == 0.0, "tier1_dist(NULL) safe");
    CHECK(service_scoring_tier1_l3(NULL)           == 0.0, "tier1_l3(NULL) safe");
    CHECK(service_scoring_offproto(NULL)           == 0.0, "offproto(NULL) safe");
    CHECK(service_scoring_combine(NULL)            == 0.0, "combine(NULL) safe");

    service_scoring_update_phase(NULL);  CHECK(true, "update_phase(NULL) safe");
    service_scoring_evaluate_all(NULL);  CHECK(true, "evaluate_all(NULL) safe");
    service_scoring_log_slot(NULL);      CHECK(true, "log_slot(NULL) safe");

    CHECK(service_scoring_is_frozen(NULL) == false,
          "is_frozen(NULL) returns false");

    /* Slot with NULL detection_state. */
    struct service_stats s;
    memset(&s, 0, sizeof(s));
    s.active = true;
    s.detection_state = NULL;
    CHECK(service_scoring_is_frozen(&s) == false,
          "is_frozen(slot without det) returns false");
    service_scoring_update_phase(&s);
    CHECK(true, "update_phase(slot without det) safe");
}

/* -------------------------------------------------------------------------
 * 10. evaluate_all on a real registry-loaded stats array
 * ------------------------------------------------------------------------- */
static void test_evaluate_all(void) {
    fprintf(stderr, "\n=== POSITIVE: service_scoring_evaluate_all on real registry ===\n");

    static struct service_registry    reg;
    static struct service_stats_array arr;

    int rc = service_registry_init(&reg);
    CHECK(rc == 0, "registry_init OK");
    rc = service_registry_load(&reg, SERVICES_JSON_PATH);
    CHECK(rc == 0, "registry_load OK (rc=%d)", rc);

    rc = service_stats_array_init(&arr);
    CHECK(rc == 0, "stats_array_init OK");
    rc = service_stats_init_from_registry(&arr, &reg);
    CHECK(rc == 0, "init_from_registry OK");
    rc = service_stats_wire_all(&arr);
    CHECK(rc == 0, "stats_wire_all OK");

    /* Sprinkle some traffic across slots so the scoring has something
     * to compute. We're just checking that evaluate_all doesn't crash
     * and that each slot's detection_state windows_seen advances. */
    for (size_t i = 0; i < arr.capacity; i++) {
        struct service_stats *s = &arr.slots[i];
        if (!s->active) continue;
        s->common.inbound_pkts  = 100 + i;
        s->common.inbound_bytes = (100 + i) * 1500u;
    }

    /* features_compute_all first (needs raw counters), then evaluate_all. */
    service_features_compute_all(&arr);
    service_scoring_evaluate_all(&arr);

    int evaluated = 0;
    for (size_t i = 0; i < arr.capacity; i++) {
        struct service_stats *s = &arr.slots[i];
        if (!s->active || !s->detection_state) continue;
        const struct service_detection_state *det = s->detection_state;
        if (det->windows_seen > 0) evaluated++;
    }
    fprintf(stderr, "  evaluated %d active slots in one pass\n", evaluated);
    CHECK(evaluated == (int)arr.n_active,
          "evaluate_all advanced windows_seen on all %d active slots (got %d)",
          (int)arr.n_active, evaluated);

    /* Diagnostic dump on one slot for eyeball validation. */
    for (size_t i = 0; i < arr.capacity; i++) {
        if (arr.slots[i].active) {
            service_scoring_log_slot(&arr.slots[i]);
            break;
        }
    }

    service_stats_unwire_all(&arr);
    service_stats_array_destroy(&arr);
    service_registry_destroy(&reg);
}

/* -------------------------------------------------------------------------
 * main
 * ------------------------------------------------------------------------- */
int main(void) {
    fprintf(stderr, "\n*** service_scoring P9 test harness ***\n");

    test_cusum_basic();
    test_cusum_recovery();
    test_tier0_ramp();
    test_tier1_tcp_synflood();
    test_tier1_distribution();
    test_offproto();
    test_phase_machine();
    test_freeze();
    test_null_handling();
    test_evaluate_all();

    fprintf(stderr, "\n=== SUMMARY: %d PASS, %d FAIL ===\n", g_pass, g_fail);
    return (g_fail == 0) ? 0 : 1;
}
