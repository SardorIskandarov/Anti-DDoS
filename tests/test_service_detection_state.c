/**
 * @file   tests/test_service_detection_state.c
 * @brief  Standalone test harness for the P5 per-service detection state.
 *
 * Exercises:
 *   - alloc + init lifecycle
 *   - init with NULL profile uses fallback warmup
 *   - init with a real profile reads profile->warmup_windows
 *   - initial phase / score / CUSUM state invariants
 *   - reset_window preserves phase + CUSUM + warmup, zeros last_*
 *   - phase_name strings for all enum values + UNKNOWN
 *   - NULL handling on all entrypoints
 *
 * Build:  ninja -C build test_service_detection_state
 * Run:    ./build/test_service_detection_state
 * Returns 0 on full pass, 1 on any FAIL.
 *
 * Loads the real services.json fixture (the same one P2-P4 tests use) for
 * the profile-aware init test.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>

#include "l2fwd_service_registry.h"
#include "l2fwd_l2_profile.h"
#include "l2fwd_service_detection.h"

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
 * Tests
 * ------------------------------------------------------------------------- */

static void test_alloc_init_null_profile(void) {
    fprintf(stderr,
            "\n=== POSITIVE: alloc + init (NULL profile -> fallback warmup) ===\n");

    struct service_detection_state *det = service_detection_state_alloc();
    CHECK(det != NULL, "alloc returned non-NULL");
    if (!det) return;

    int rc = service_detection_state_init(det, NULL);
    CHECK(rc == 0, "init(NULL profile) returned 0 (rc=%d)", rc);

    CHECK(det->phase == (uint8_t)SERVICE_DET_PHASE_WARMUP,
          "initial phase = WARMUP (got %u)", (unsigned)det->phase);
    CHECK(det->prev_phase == (uint8_t)SERVICE_DET_PHASE_WARMUP,
          "initial prev_phase = WARMUP");
    CHECK(det->active == true, "active = true after init");
    CHECK(det->profile == NULL, "profile pointer preserved (NULL)");

    CHECK(det->warmup_remaining == SERVICE_DETECTION_DEFAULT_WARMUP_WINDOWS,
          "warmup_remaining = %u (fallback default)",
          (unsigned)det->warmup_remaining);
    CHECK(det->warmup_windows_completed == 0,
          "warmup_windows_completed = 0");

    CHECK(det->consecutive_attack_windows == 0,
          "consecutive_attack_windows = 0");
    CHECK(det->baseline_freeze_remaining == 0,
          "baseline_freeze_remaining = 0");
    CHECK(det->thaw_cooldown_remaining == 0,
          "thaw_cooldown_remaining = 0");

    /* CUSUM channels all zero. */
    CHECK(det->cusum_pps.S_plus == 0.0,        "cusum_pps.S_plus = 0");
    CHECK(det->cusum_pps.last_value == 0.0,    "cusum_pps.last_value = 0");
    CHECK(det->cusum_pps.breach_count == 0,    "cusum_pps.breach_count = 0");
    CHECK(det->cusum_bps.S_plus == 0.0,        "cusum_bps.S_plus = 0");
    CHECK(det->cusum_fps.S_plus == 0.0,        "cusum_fps.S_plus = 0");
    CHECK(det->cusum_burst_pps.S_plus == 0.0,  "cusum_burst_pps.S_plus = 0");
    CHECK(det->cusum_burst_bps.S_plus == 0.0,  "cusum_burst_bps.S_plus = 0");
    CHECK(det->cusum_burst_fps.S_plus == 0.0,  "cusum_burst_fps.S_plus = 0");

    /* last_* scores all zero. */
    CHECK(det->last_tier0_score == 0.0,        "last_tier0_score = 0");
    CHECK(det->last_tier1_final_score == 0.0,  "last_tier1_final_score = 0");
    CHECK(det->last_tier1_evaluated == false,  "last_tier1_evaluated = false");
    CHECK(det->windows_seen == 0,              "windows_seen = 0");

    service_detection_state_destroy(det);
}

static void test_init_with_profile(void) {
    fprintf(stderr, "\n=== POSITIVE: init with profile sets warmup from profile ===\n");

    static struct service_registry reg;
    int rc = service_registry_init(&reg);
    CHECK(rc == 0, "registry_init OK");
    rc = service_registry_load(&reg, SERVICES_JSON_PATH);
    CHECK(rc == 0, "registry_load OK (rc=%d)", rc);
    CHECK(reg.n_profiles > 0,
          "registry has %zu profiles", reg.n_profiles);

    /* Pick the first profile from the registry. */
    const struct l2_profile *prof = (reg.n_profiles > 0) ? &reg.profiles[0] : NULL;
    CHECK(prof != NULL, "got a profile pointer");

    if (prof) {
        uint32_t expected_warmup = prof->warmup_windows;
        fprintf(stderr,
                "  (profile[0] name='%s' warmup_windows=%u)\n",
                reg.profile_names[0], (unsigned)expected_warmup);

        struct service_detection_state *det = service_detection_state_alloc();
        CHECK(det != NULL, "alloc OK");
        if (det) {
            rc = service_detection_state_init(det, prof);
            CHECK(rc == 0, "init(profile) returned 0");
            CHECK(det->profile == prof, "profile pointer cached");

            if (expected_warmup > 0) {
                CHECK(det->warmup_remaining == expected_warmup,
                      "warmup_remaining=%u matches profile->warmup_windows=%u",
                      (unsigned)det->warmup_remaining, (unsigned)expected_warmup);
            } else {
                CHECK(det->warmup_remaining == SERVICE_DETECTION_DEFAULT_WARMUP_WINDOWS,
                      "warmup_remaining=%u (fallback default, profile had 0)",
                      (unsigned)det->warmup_remaining);
            }
            service_detection_state_destroy(det);
        }
    }

    service_registry_destroy(&reg);
}

static void test_reset_window_preserves_state(void) {
    fprintf(stderr, "\n=== POSITIVE: reset_window preserves phase + CUSUM, zeros last_* ===\n");

    struct service_detection_state *det = service_detection_state_alloc();
    CHECK(det != NULL, "alloc OK");
    if (!det) return;

    int rc = service_detection_state_init(det, NULL);
    CHECK(rc == 0, "init OK");

    /* Manually fake some state to simulate a populated window. */
    det->phase                       = (uint8_t)SERVICE_DET_PHASE_SUSPICIOUS;
    det->prev_phase                  = (uint8_t)SERVICE_DET_PHASE_NORMAL;
    det->warmup_remaining            = 12;
    det->warmup_windows_completed    = 388;
    det->consecutive_attack_windows  = 3;
    det->baseline_freeze_remaining   = 8;
    det->thaw_cooldown_remaining     = 5;

    det->cusum_pps.S_plus            = 17.5;
    det->cusum_pps.last_value        = 4200.0;
    det->cusum_pps.breach_count      = 2;
    det->cusum_bps.S_plus            = 9.1;
    det->cusum_burst_fps.S_plus      = 3.3;

    det->last_tier0_score            = 5.7;
    det->last_tier0_risk_pps         = 0.92;
    det->last_tier1_final_score      = 0.81;
    det->last_tier1_evaluated        = true;
    det->last_attack_evidence        = 12.0;
    det->last_phase_change_window    = 42;

    uint64_t prev_windows_seen = det->windows_seen;

    /* Reset. */
    service_detection_state_reset_window(det);

    /* Preserved fields. */
    CHECK(det->phase == (uint8_t)SERVICE_DET_PHASE_SUSPICIOUS,
          "phase preserved (SUSPICIOUS)");
    CHECK(det->prev_phase == (uint8_t)SERVICE_DET_PHASE_NORMAL,
          "prev_phase preserved (NORMAL)");
    CHECK(det->warmup_remaining == 12,           "warmup_remaining preserved");
    CHECK(det->warmup_windows_completed == 388,  "warmup_windows_completed preserved");
    CHECK(det->consecutive_attack_windows == 3,  "consecutive_attack_windows preserved");
    CHECK(det->baseline_freeze_remaining == 8,   "baseline_freeze_remaining preserved");
    CHECK(det->thaw_cooldown_remaining == 5,     "thaw_cooldown_remaining preserved");
    CHECK(det->cusum_pps.S_plus == 17.5,         "cusum_pps.S_plus preserved");
    CHECK(det->cusum_pps.last_value == 4200.0,   "cusum_pps.last_value preserved");
    CHECK(det->cusum_pps.breach_count == 2,      "cusum_pps.breach_count preserved");
    CHECK(det->cusum_bps.S_plus == 9.1,          "cusum_bps.S_plus preserved");
    CHECK(det->cusum_burst_fps.S_plus == 3.3,    "cusum_burst_fps.S_plus preserved");
    CHECK(det->last_phase_change_window == 42,   "last_phase_change_window preserved");

    /* Cleared fields. */
    CHECK(det->last_tier0_score == 0.0,          "last_tier0_score cleared");
    CHECK(det->last_tier0_risk_pps == 0.0,       "last_tier0_risk_pps cleared");
    CHECK(det->last_tier1_final_score == 0.0,    "last_tier1_final_score cleared");
    CHECK(det->last_tier1_evaluated == false,    "last_tier1_evaluated cleared");
    CHECK(det->last_attack_evidence == 0.0,      "last_attack_evidence cleared");

    /* windows_seen incremented. */
    CHECK(det->windows_seen == prev_windows_seen + 1,
          "windows_seen incremented to %llu",
          (unsigned long long)det->windows_seen);

    service_detection_state_destroy(det);
}

static void test_phase_name(void) {
    fprintf(stderr, "\n=== POSITIVE: phase_name strings ===\n");

    CHECK(strcmp(service_detection_phase_name(SERVICE_DET_PHASE_WARMUP),     "WARMUP")     == 0,
          "WARMUP -> 'WARMUP'");
    CHECK(strcmp(service_detection_phase_name(SERVICE_DET_PHASE_NORMAL),     "NORMAL")     == 0,
          "NORMAL -> 'NORMAL'");
    CHECK(strcmp(service_detection_phase_name(SERVICE_DET_PHASE_SUSPICIOUS), "SUSPICIOUS") == 0,
          "SUSPICIOUS -> 'SUSPICIOUS'");
    CHECK(strcmp(service_detection_phase_name(SERVICE_DET_PHASE_ATTACK),     "ATTACK")     == 0,
          "ATTACK -> 'ATTACK'");
    CHECK(strcmp(service_detection_phase_name(99),                           "UNKNOWN")    == 0,
          "99 -> 'UNKNOWN'");
    CHECK(strcmp(service_detection_phase_name(255),                          "UNKNOWN")    == 0,
          "255 -> 'UNKNOWN'");
}

static void test_null_handling(void) {
    fprintf(stderr, "\n=== NEGATIVE: NULL handling ===\n");

    /* init(NULL, NULL) returns negative */
    int rc = service_detection_state_init(NULL, NULL);
    CHECK(rc < 0, "init(NULL, NULL) returned negative (rc=%d)", rc);

    /* reset_window(NULL) is a no-op (no crash) */
    service_detection_state_reset_window(NULL);
    CHECK(true, "reset_window(NULL) did not crash");

    /* destroy(NULL) is a no-op (no crash) */
    service_detection_state_destroy(NULL);
    CHECK(true, "destroy(NULL) did not crash");

    /* log(NULL) does not crash */
    service_detection_state_log(NULL);
    CHECK(true, "log(NULL) did not crash");
}

/* -------------------------------------------------------------------------
 * Main
 * ------------------------------------------------------------------------- */

int main(void) {
    fprintf(stderr, "\n*** service_detection P5 test harness ***\n");

    test_alloc_init_null_profile();
    test_init_with_profile();
    test_reset_window_preserves_state();
    test_phase_name();
    test_null_handling();

    /* Diagnostic log line. */
    fprintf(stderr, "\n=== diagnostic: service_detection_state_log ===\n");
    struct service_detection_state *d = service_detection_state_alloc();
    if (d) {
        service_detection_state_init(d, NULL);
        d->phase = (uint8_t)SERVICE_DET_PHASE_NORMAL;
        d->last_tier1_final_score = 0.37;
        service_detection_state_log(d);
        service_detection_state_destroy(d);
    }

    fprintf(stderr, "\n=== SUMMARY: %d PASS, %d FAIL ===\n", g_pass, g_fail);
    return (g_fail == 0) ? 0 : 1;
}
