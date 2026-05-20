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
 *   7. Phase machine (gated cascade): Tier-0 R0 gate + N-window persistence
 *      filter + immediate single-window Tier-1 verdict (no t0/t1 ladder),
 *      plus the full-freeze + N-window thaw release contract
 *  7b. Absolute volumetric floor: baseline-independent immediate ATTACK
 *  7c. Dual freeze scopes: is_frozen vs cusum_is_frozen (+ CUSUM hold)
 *  7d. Tier-0 fire arms the EWMA-only freeze (Change 2)
 *   8. Baseline freeze: while frozen, EWMA mean stays unchanged
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
#include "l2fwd_l2_profile.h"   /* test_absolute_floor builds a real profile */

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
 * 7. Phase machine — GATED SEQUENTIAL CASCADE
 *
 * Contract under test (matches l2fwd_service_scoring.c):
 *   - Tier-0 produces a weighted composite risk R0; R0 >= 5.0 ("gate
 *     open" risk threshold) fires the gate for that second.
 *   - A persistence filter sits BETWEEN the tiers: the gate must fire for
 *     SCORING_GATE_PERSISTENCE_WINDOWS (= 3) consecutive seconds before
 *     Tier-1 is consulted at all. Until then the phase is forced NORMAL
 *     and Tier-1 is NOT evaluated (last_tier1_evaluated == false).
 *   - Once the gate is open, Tier-1 (combine) makes the FINAL decision
 *     every second with NO trailing persistence: T1 >= 0.7 => ATTACK,
 *     [0.5, 0.7) => SUSPICIOUS, < 0.5 => NORMAL (veto). There is no
 *     NORMAL->SUSPICIOUS->ATTACK ladder — the verdict is the phase.
 *   - ATTACK entry arms baseline freeze; ATTACK exit arms thaw cooldown.
 *
 * The constants SCORING_GATE_PERSISTENCE_WINDOWS / the 5.0 gate threshold
 * / the 0.5 & 0.7 Tier-1 thresholds live as #defines inside the .c, so
 * they are reproduced as literals here (with comments) the same way the
 * legacy test hardcoded PERSISTENCE_WINDOWS.
 * ------------------------------------------------------------------------- */

/* Seed the EWMA baselines the gated cascade reads. Stable, non-zero
 * variance everywhere a CUSUM or z-score channel fires, so a later spike
 * actually breaches h (Tier-0) and saturates the burst z-channels. */
static void seed_gated_baselines(struct service_stats *slot) {
    /* Tier-0 CUSUM volumetric baselines (make_warmed_slot already seeds
     * pps/bps; restate here so this helper is self-contained). */
    slot->common_ewma.pps.mean         = 100.0;
    slot->common_ewma.pps.variance     = 100.0;     /* stddev 10 */
    slot->common_ewma.pps.initialized  = true;
    slot->common_ewma.pps.sample_count = 1000;
    slot->common_ewma.bps.mean         = 1.2e6;
    slot->common_ewma.bps.variance     = 1e8;        /* stddev 1e4 */
    slot->common_ewma.bps.initialized  = true;
    slot->common_ewma.bps.sample_count = 1000;

    /* Tier-0 burst z-score baselines: tight around 0 so a large z_last
     * saturates burst_z_risk to 1.0. */
    struct service_ewma_state *burst[3] = {
        &slot->common_ewma.burst_pps,
        &slot->common_ewma.burst_bps,
        &slot->common_ewma.burst_fps,
    };
    for (int i = 0; i < 3; i++) {
        burst[i]->mean         = 0.0;
        burst[i]->variance     = 1.0;
        burst[i]->initialized  = true;
        burst[i]->sample_count = 1000;
    }

    /* Tier-1 driver: off-protocol ratio baseline ~1% +/- 1%. This is the
     * only Tier-1 channel we leave "live" — every other sub-feature EWMA
     * stays uninitialized, so its z-score is 0 and its z_to_score pins at
     * the ~0.047 floor. T1 therefore tracks the off-proto channel alone. */
    slot->common_ewma.off_proto_pkts_ratio.mean         = 0.01;
    slot->common_ewma.off_proto_pkts_ratio.variance     = 1e-4; /* stddev 0.01 */
    slot->common_ewma.off_proto_pkts_ratio.initialized  = true;
    slot->common_ewma.off_proto_pkts_ratio.sample_count = 1000;
}

/* Volumetric + burst spike -> R0 ~ 5.7 (>= 5.0 gate threshold). */
static void apply_gate_open_traffic(struct service_stats *slot) {
    slot->common.inbound_pkts  = 2000;          /* ~190 sigma over pps mean */
    slot->common.inbound_bytes = 2000u * 1500u; /* bps ~2.4e7, huge sigma   */
    slot->common.bw_pps.z_last = 30.0;          /* burst z -> r = 1.0       */
    slot->common.bw_bps.z_last = 30.0;
    slot->common.bw_fps.z_last = 30.0;
}

/* Quiet volumetric/burst channels -> R0 ~ 0 (gate closed). */
static void apply_gate_closed_traffic(struct service_stats *slot) {
    slot->common.inbound_pkts  = 100;           /* == pps mean, no breach   */
    slot->common.inbound_bytes = 100u * 1500u;  /* == bps mean, no breach   */
    slot->common.bw_pps.z_last = 0.0;
    slot->common.bw_bps.z_last = 0.0;
    slot->common.bw_fps.z_last = 0.0;
}

/* Set the Tier-1 final score via the off-protocol channel only, expressed
 * as a fraction of the current inbound_pkts. With the 0.01 +/- 0.01
 * baseline: 0.30 -> z~29 -> T1~1.0 (ATTACK), 0.044 -> z=3.4 -> T1~0.599
 * (SUSPICIOUS), 0.0 -> z=-1 -> T1~0.119 (NORMAL veto). */
static void set_tier1_offproto_ratio(struct service_stats *slot, double ratio) {
    slot->common.off_proto_pkts =
        (uint64_t)(ratio * (double)slot->common.inbound_pkts + 0.5);
}

static void test_phase_machine(void) {
    fprintf(stderr, "\n=== POSITIVE: gated cascade phase machine ===\n");

    struct service_stats slot;
    struct service_detection_state det;

    /* ---- Warmup still completes to NORMAL (unchanged contract) ---- */
    make_warmed_slot(&slot, &det, SERVICE_PROTO_TCP, 100.0, 100.0, 1.2e6, 1e8);
    seed_gated_baselines(&slot);
    det.phase            = SERVICE_DET_PHASE_WARMUP;
    det.warmup_remaining = 3;
    apply_gate_closed_traffic(&slot);
    set_tier1_offproto_ratio(&slot, 0.0);
    for (int i = 0; i < 3; i++) service_scoring_update_phase(&slot);
    CHECK(det.phase == SERVICE_DET_PHASE_NORMAL,
          "warmup completes to NORMAL (got %s)",
          service_detection_phase_name(det.phase));

    /* ---- (1) Gate CLOSED + strong Tier-1 => stays NORMAL, Tier-1 never
     *          evaluated. A pure behavioral signal with no volumetric
     *          ramp must NOT trip the cascade. ---- */
    fprintf(stderr, "  -- (1) gate-closed + strong T1 stays NORMAL --\n");
    make_warmed_slot(&slot, &det, SERVICE_PROTO_TCP, 100.0, 100.0, 1.2e6, 1e8);
    seed_gated_baselines(&slot);
    apply_gate_closed_traffic(&slot);
    set_tier1_offproto_ratio(&slot, 0.30);   /* would be ATTACK if consulted */
    for (int i = 0; i < 5; i++) service_scoring_update_phase(&slot);
    CHECK(det.phase == SERVICE_DET_PHASE_NORMAL,
          "gate closed: phase NORMAL despite T1=ATTACK-level (got %s)",
          service_detection_phase_name(det.phase));
    CHECK(det.last_tier1_evaluated == false,
          "gate closed: Tier-1 not evaluated (last_tier1_evaluated=%d)",
          (int)det.last_tier1_evaluated);
    CHECK(det.consecutive_attack_windows == 0,
          "gate closed: gate streak stays 0 (got %u)",
          (unsigned)det.consecutive_attack_windows);

    /* ---- (2) Gate opens ONLY on the Nth (3rd) consecutive R0>=5.0
     *          window, not before. ---- */
    fprintf(stderr, "  -- (2) gate opens only on the 3rd consecutive window --\n");
    make_warmed_slot(&slot, &det, SERVICE_PROTO_TCP, 100.0, 100.0, 1.2e6, 1e8);
    seed_gated_baselines(&slot);
    apply_gate_open_traffic(&slot);
    set_tier1_offproto_ratio(&slot, 0.30);   /* strong T1 for when gate opens */

    service_scoring_update_phase(&slot);     /* window 1 */
    CHECK(det.phase == SERVICE_DET_PHASE_NORMAL &&
          det.consecutive_attack_windows == 1 &&
          det.last_tier1_evaluated == false,
          "window 1: streak=1, NORMAL, T1 not yet evaluated (phase=%s streak=%u eval=%d)",
          service_detection_phase_name(det.phase),
          (unsigned)det.consecutive_attack_windows,
          (int)det.last_tier1_evaluated);

    service_scoring_update_phase(&slot);     /* window 2 */
    CHECK(det.phase == SERVICE_DET_PHASE_NORMAL &&
          det.consecutive_attack_windows == 2 &&
          det.last_tier1_evaluated == false,
          "window 2: streak=2, still NORMAL, T1 not yet evaluated (phase=%s streak=%u eval=%d)",
          service_detection_phase_name(det.phase),
          (unsigned)det.consecutive_attack_windows,
          (int)det.last_tier1_evaluated);

    service_scoring_update_phase(&slot);     /* window 3 — gate opens */
    CHECK(det.consecutive_attack_windows == 3 &&
          det.last_tier1_evaluated == true,
          "window 3: streak=3, Tier-1 now evaluated (streak=%u eval=%d)",
          (unsigned)det.consecutive_attack_windows,
          (int)det.last_tier1_evaluated);
    CHECK(det.phase == SERVICE_DET_PHASE_ATTACK,
          "window 3: gate open + T1>=0.7 => ATTACK directly, no ladder (got %s, t1=%.3f)",
          service_detection_phase_name(det.phase),
          det.last_tier1_final_score);

    /* ---- (3) With the gate held open, Tier-1's verdict is immediate and
     *          single-window across all three bands; no t0/t1 ladder. ---- */
    fprintf(stderr, "  -- (3) gate-open: immediate single-window Tier-1 verdict --\n");
    make_warmed_slot(&slot, &det, SERVICE_PROTO_TCP, 100.0, 100.0, 1.2e6, 1e8);
    seed_gated_baselines(&slot);
    apply_gate_open_traffic(&slot);          /* gate stays fed every window */

    /* Prime the gate to OPEN while holding a vetoing (low) Tier-1 so the
     * phase is still NORMAL — proving gate-open + T1<0.5 => NORMAL, which
     * is distinct from gate-closed. */
    set_tier1_offproto_ratio(&slot, 0.0);
    for (int i = 0; i < 3; i++) service_scoring_update_phase(&slot);
    CHECK(det.consecutive_attack_windows >= 3 &&
          det.last_tier1_evaluated == true &&
          det.phase == SERVICE_DET_PHASE_NORMAL,
          "gate open + T1 veto => NORMAL (streak=%u eval=%d phase=%s t1=%.3f)",
          (unsigned)det.consecutive_attack_windows,
          (int)det.last_tier1_evaluated,
          service_detection_phase_name(det.phase),
          det.last_tier1_final_score);

    /* Band: T1 >= 0.7 -> ATTACK in a SINGLE window (NORMAL -> ATTACK, no
     * intermediate SUSPICIOUS step). */
    set_tier1_offproto_ratio(&slot, 0.30);
    service_scoring_update_phase(&slot);
    CHECK(det.phase == SERVICE_DET_PHASE_ATTACK,
          "T1>=0.7 -> ATTACK in one window, no ladder (got %s, t1=%.3f)",
          service_detection_phase_name(det.phase), det.last_tier1_final_score);

    /* Band: T1 in [0.5,0.7) -> SUSPICIOUS in a SINGLE window (ATTACK ->
     * SUSPICIOUS immediately — no persistence holding ATTACK). */
    set_tier1_offproto_ratio(&slot, 0.044);
    service_scoring_update_phase(&slot);
    CHECK(det.phase == SERVICE_DET_PHASE_SUSPICIOUS,
          "T1 in [0.5,0.7) -> SUSPICIOUS in one window (got %s, t1=%.3f)",
          service_detection_phase_name(det.phase), det.last_tier1_final_score);

    /* Band: T1 < 0.5 -> NORMAL veto in a SINGLE window. */
    set_tier1_offproto_ratio(&slot, 0.0);
    service_scoring_update_phase(&slot);
    CHECK(det.phase == SERVICE_DET_PHASE_NORMAL,
          "T1<0.5 -> NORMAL veto in one window (got %s, t1=%.3f)",
          service_detection_phase_name(det.phase), det.last_tier1_final_score);

    /* ---- (4) NEW thaw contract: entering ATTACK arms the FULL freeze
     *          (EWMA + CUSUM). It releases ONLY after thaw_cooldown_windows
     *          consecutive NORMAL windows; a single non-NORMAL window resets
     *          that recovery streak. (The old single-window thaw cooldown is
     *          gone.) ---- */
    fprintf(stderr, "  -- (4) full freeze + N-window thaw release --\n");

    /* SCORING_DEFAULT_THAW_WINDOWS is a #define inside the .c; with this
     * harness's NULL profile, pick_thaw_windows() falls back to it. Mirror
     * it as a literal — if the .c default changes, this must change too. */
    const unsigned THAW_WINDOWS = 30u;   /* == SCORING_DEFAULT_THAW_WINDOWS */

    make_warmed_slot(&slot, &det, SERVICE_PROTO_TCP, 100.0, 100.0, 1.2e6, 1e8);
    seed_gated_baselines(&slot);
    apply_gate_open_traffic(&slot);
    set_tier1_offproto_ratio(&slot, 0.30);   /* drive to ATTACK once gate opens */
    for (int i = 0; i < 3; i++) service_scoring_update_phase(&slot);
    CHECK(det.phase == SERVICE_DET_PHASE_ATTACK,
          "reached ATTACK through the gate (got %s)",
          service_detection_phase_name(det.phase));
    CHECK(det.attack_freeze_active == true,
          "full ATTACK-freeze armed on ATTACK entry");
    CHECK(service_scoring_is_frozen(&slot) == true,
          "is_frozen true in ATTACK (EWMA frozen)");
    CHECK(service_scoring_cusum_is_frozen(&slot) == true,
          "cusum_is_frozen true in ATTACK (CUSUM held)");

    /* ONE Tier-1 veto with the gate still fed: one clean window is NOT
     * enough — the full freeze persists, the streak just starts counting. */
    set_tier1_offproto_ratio(&slot, 0.0);
    service_scoring_update_phase(&slot);
    CHECK(det.phase == SERVICE_DET_PHASE_NORMAL,
          "Tier-1 veto resolves NORMAL (got %s)",
          service_detection_phase_name(det.phase));
    CHECK(det.attack_freeze_active == true,
          "full freeze STILL active after one clean window");
    CHECK(det.consecutive_normal_windows == 1,
          "one clean window counted (consecutive_normal_windows=%u)",
          (unsigned)det.consecutive_normal_windows);
    CHECK(service_scoring_is_frozen(&slot) == true,
          "is_frozen still true after one clean window");

    /* Build the streak partway, then prove a SINGLE non-NORMAL window resets
     * it to 0 while the full freeze stays armed. */
    service_scoring_update_phase(&slot);   /* veto -> NORMAL, streak=2 */
    service_scoring_update_phase(&slot);   /* veto -> NORMAL, streak=3 */
    CHECK(det.consecutive_normal_windows == 3,
          "recovery streak built partway (consecutive_normal_windows=%u)",
          (unsigned)det.consecutive_normal_windows);
    set_tier1_offproto_ratio(&slot, 0.044);   /* SUSPICIOUS band, gate open */
    service_scoring_update_phase(&slot);
    CHECK(det.phase == SERVICE_DET_PHASE_SUSPICIOUS,
          "one SUSPICIOUS window (got %s)",
          service_detection_phase_name(det.phase));
    CHECK(det.consecutive_normal_windows == 0,
          "a single non-NORMAL window resets the recovery streak (got %u)",
          (unsigned)det.consecutive_normal_windows);
    CHECK(det.attack_freeze_active == true,
          "full freeze still armed after the streak reset");

    /* Release mechanism: hold gate-open + Tier-1 veto so every window
     * resolves NORMAL; the full freeze must release after exactly
     * THAW_WINDOWS consecutive NORMAL windows. Bound the loop so a broken
     * release can't hang the suite. */
    set_tier1_offproto_ratio(&slot, 0.0);
    unsigned normal_windows = 0;
    unsigned iters = 0;
    while (det.attack_freeze_active && iters < THAW_WINDOWS + 2u) {
        service_scoring_update_phase(&slot);
        iters++;
        if (det.phase == SERVICE_DET_PHASE_NORMAL) normal_windows++;
    }
    CHECK(det.attack_freeze_active == false,
          "full freeze released within bound (iters=%u)", iters);
    CHECK(normal_windows == THAW_WINDOWS,
          "released after exactly THAW_WINDOWS consecutive NORMAL windows "
          "(got %u, want %u)", normal_windows, THAW_WINDOWS);
}

/* -------------------------------------------------------------------------
 * 7b. Absolute volumetric floor — baseline-independent immediate ATTACK
 *
 * The floor reads raw counters vs profile->absolute_*_threshold and forces
 * ATTACK immediately, bypassing the persistence gate AND Tier-1. A NULL
 * profile or a 0.0 threshold disables it. make_warmed_slot sets
 * profile=NULL, so every case here installs a real profile.
 * ------------------------------------------------------------------------- */
static void test_absolute_floor(void) {
    fprintf(stderr, "\n=== POSITIVE: absolute floor forces immediate ATTACK ===\n");

    /* Production-tuned thresholds. */
    struct l2_profile prof;
    memset(&prof, 0, sizeof(prof));
    prof.absolute_pps_threshold  = 30000.0;
    prof.absolute_bps_threshold  = 310000000.0;
    prof.absolute_fps_threshold  = 300.0;
    prof.baseline_freeze_windows = 12;
    prof.thaw_cooldown_windows   = 15;
    prof.variance_ceiling_factor = 2.0;
    prof.warmup_windows          = 0;     /* skip warmup in this test */
    prof.alpha_tier0             = 0.05;

    struct service_stats slot;
    struct service_detection_state det;

    /* --- pps channel, first window, gate streak 0 -> no persistence wait. --- */
    make_warmed_slot(&slot, &det, SERVICE_PROTO_TCP, 100.0, 100.0, 1.2e6, 1e8);
    seed_gated_baselines(&slot);
    slot.profile         = &prof;
    det.profile          = &prof;
    det.warmup_remaining = 0;
    det.phase            = SERVICE_DET_PHASE_NORMAL;
    apply_gate_closed_traffic(&slot);            /* quiet bytes/burst */
    slot.common.inbound_pkts = 40000;            /* > 30000 pps floor */
    CHECK(det.consecutive_attack_windows == 0,
          "no gate streak going in (streak=%u)",
          (unsigned)det.consecutive_attack_windows);
    service_scoring_update_phase(&slot);
    CHECK(det.phase == SERVICE_DET_PHASE_ATTACK,
          "absolute pps floor -> ATTACK in ONE window, no persistence (got %s)",
          service_detection_phase_name(det.phase));
    CHECK(det.last_absolute_floor_fired == true,
          "last_absolute_floor_fired set on breach");
    CHECK(det.attack_freeze_active == true,
          "full freeze armed by the absolute breach");
    /* Evidence stays the honest Tier-0 number, never a synthetic value. */
    CHECK(det.last_attack_evidence == det.last_tier0_score,
          "evidence == last_tier0_score (Tier-0-origin: %.4f vs %.4f)",
          det.last_attack_evidence, det.last_tier0_score);

    /* --- bps channel on a fresh slot (pps below its floor). --- */
    make_warmed_slot(&slot, &det, SERVICE_PROTO_TCP, 100.0, 100.0, 1.2e6, 1e8);
    seed_gated_baselines(&slot);
    slot.profile         = &prof;
    det.profile          = &prof;
    det.warmup_remaining = 0;
    det.phase            = SERVICE_DET_PHASE_NORMAL;
    apply_gate_closed_traffic(&slot);
    slot.common.inbound_pkts  = 100;             /* below pps floor */
    slot.common.inbound_bytes = 40000000u;       /* *8 = 320 Mbit > 310 Mbit */
    service_scoring_update_phase(&slot);
    CHECK(det.phase == SERVICE_DET_PHASE_ATTACK,
          "absolute bps floor -> ATTACK (got %s)",
          service_detection_phase_name(det.phase));
    CHECK(det.last_absolute_floor_fired == true,
          "bps breach sets last_absolute_floor_fired");

    /* --- disabled channel: 0.0 means OFF, not "floor at zero". --- */
    struct l2_profile prof_off = prof;
    prof_off.absolute_pps_threshold = 0.0;
    prof_off.absolute_bps_threshold = 0.0;
    prof_off.absolute_fps_threshold = 0.0;
    make_warmed_slot(&slot, &det, SERVICE_PROTO_TCP, 100.0, 100.0, 1.2e6, 1e8);
    seed_gated_baselines(&slot);
    slot.profile         = &prof_off;
    det.profile          = &prof_off;
    det.warmup_remaining = 0;
    det.phase            = SERVICE_DET_PHASE_NORMAL;
    apply_gate_closed_traffic(&slot);
    slot.common.inbound_pkts = 40000;            /* above the now-disabled floor */
    service_scoring_update_phase(&slot);
    CHECK(det.last_absolute_floor_fired == false,
          "absolute thresholds of 0.0 are DISABLED (floor did not fire)");
}

/* -------------------------------------------------------------------------
 * 7c. Two freeze predicates with distinct scopes.
 *   is_frozen       = attack_freeze_active || ewma_freeze_remaining > 0
 *   cusum_is_frozen = attack_freeze_active only
 * ------------------------------------------------------------------------- */
static void test_dual_freeze_scopes(void) {
    fprintf(stderr, "\n=== POSITIVE: dual freeze scopes (EWMA-only vs full) ===\n");
    struct service_stats slot;
    struct service_detection_state det;

    /* Case A — EWMA-only freeze: EWMA frozen, CUSUM live. */
    make_warmed_slot(&slot, &det, SERVICE_PROTO_TCP, 100.0, 100.0, 1.2e6, 1e8);
    det.ewma_freeze_remaining = 5;
    det.attack_freeze_active  = false;
    CHECK(service_scoring_is_frozen(&slot) == true,
          "A: EWMA-only freeze -> is_frozen true");
    CHECK(service_scoring_cusum_is_frozen(&slot) == false,
          "A: EWMA-only freeze -> cusum_is_frozen false (CUSUM live)");

    /* Case B — full freeze: both frozen. */
    det.ewma_freeze_remaining = 0;
    det.attack_freeze_active  = true;
    CHECK(service_scoring_is_frozen(&slot) == true,
          "B: full freeze -> is_frozen true");
    CHECK(service_scoring_cusum_is_frozen(&slot) == true,
          "B: full freeze -> cusum_is_frozen true");

    /* Case C — neither. */
    det.ewma_freeze_remaining = 0;
    det.attack_freeze_active  = false;
    CHECK(service_scoring_is_frozen(&slot) == false,
          "C: no freeze -> is_frozen false");
    CHECK(service_scoring_cusum_is_frozen(&slot) == false,
          "C: no freeze -> cusum_is_frozen false");

    /* Case D — CUSUM accumulator HELD under full freeze: tier0_evaluate must
     * NOT advance cusum_pps.S_plus while attack_freeze_active is true. */
    make_warmed_slot(&slot, &det, SERVICE_PROTO_TCP, 100.0, 100.0, 1.2e6, 1e8);
    seed_gated_baselines(&slot);
    det.cusum_pps.S_plus     = 7.0;
    det.attack_freeze_active = true;             /* CUSUM frozen */
    slot.common.inbound_pkts = 40000;            /* huge spike */
    (void)service_scoring_tier0_evaluate(&slot);
    CHECK(det.cusum_pps.S_plus == 7.0,
          "D: full freeze HOLDS cusum_pps.S_plus (got %.4f, want 7.0)",
          det.cusum_pps.S_plus);

    /* Contrast: with no full freeze the same spike ADVANCES S_plus. */
    make_warmed_slot(&slot, &det, SERVICE_PROTO_TCP, 100.0, 100.0, 1.2e6, 1e8);
    seed_gated_baselines(&slot);
    det.cusum_pps.S_plus     = 7.0;
    det.attack_freeze_active = false;            /* CUSUM live */
    slot.common.inbound_pkts = 40000;
    (void)service_scoring_tier0_evaluate(&slot);
    CHECK(det.cusum_pps.S_plus > 7.0,
          "D(contrast): CUSUM live ADVANCES S_plus (got %.4f > 7.0)",
          det.cusum_pps.S_plus);
}

/* -------------------------------------------------------------------------
 * 7d. Change 2 — the instant Tier-0 fires (even once, pre-persistence,
 *     pre-Tier-1), the EWMA-only freeze arms.
 * ------------------------------------------------------------------------- */
static void test_tier0_fire_arms_ewma_freeze(void) {
    fprintf(stderr, "\n=== POSITIVE: Tier-0 fire arms EWMA-only freeze (Change 2) ===\n");

    /* NULL profile -> the EWMA-freeze duration falls back to this .c default.
     * Mirror it as a literal; if the .c default changes, this must too. */
    const unsigned FREEZE_WINDOWS = 60u;   /* == SCORING_DEFAULT_FREEZE_WINDOWS */

    struct service_stats slot;
    struct service_detection_state det;
    make_warmed_slot(&slot, &det, SERVICE_PROTO_TCP, 100.0, 100.0, 1.2e6, 1e8);
    seed_gated_baselines(&slot);
    det.warmup_remaining = 0;
    det.phase            = SERVICE_DET_PHASE_NORMAL;

    /* ONE gate-open window with a Tier-1 veto: t0_fired is true but the
     * persistence gate is not yet open, so the phase stays NORMAL — yet the
     * EWMA-only freeze must arm on this very first Tier-0 fire. */
    apply_gate_open_traffic(&slot);
    set_tier1_offproto_ratio(&slot, 0.0);
    service_scoring_update_phase(&slot);

    CHECK(det.phase == SERVICE_DET_PHASE_NORMAL,
          "phase still NORMAL (gate not yet open by persistence) (got %s)",
          service_detection_phase_name(det.phase));
    CHECK(det.attack_freeze_active == false,
          "full freeze NOT armed (not in ATTACK)");
    CHECK(det.ewma_freeze_remaining > 0 &&
          det.ewma_freeze_remaining <= FREEZE_WINDOWS,
          "EWMA-only freeze armed on first Tier-0 fire (rem=%u, max %u)",
          (unsigned)det.ewma_freeze_remaining, FREEZE_WINDOWS);
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

    /* Freeze active. baseline_freeze_remaining is now a DERIVED wire field,
     * not a freeze input — the authoritative EWMA-freeze input is
     * ewma_freeze_remaining. */
    det.ewma_freeze_remaining = 10;
    CHECK(service_scoring_is_frozen(&slot) == true,
          "service_scoring_is_frozen returns true during ewma_freeze_remaining>0");

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

    /* Unfreeze: clear the EWMA-freeze input (and confirm no full freeze is
     * lingering) so is_frozen is fully cleared; next compute_one MUST update
     * the EWMA. */
    det.ewma_freeze_remaining = 0;
    CHECK(det.attack_freeze_active == false,
          "no full ATTACK-freeze lingering before thaw");
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
    test_absolute_floor();
    test_dual_freeze_scopes();
    test_tier0_fire_arms_ewma_freeze();
    test_freeze();
    test_null_handling();
    test_evaluate_all();

    fprintf(stderr, "\n=== SUMMARY: %d PASS, %d FAIL ===\n", g_pass, g_fail);
    return (g_fail == 0) ? 0 : 1;
}
