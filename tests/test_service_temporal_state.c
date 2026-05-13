/**
 * @file   tests/test_service_temporal_state.c
 * @brief  Standalone test harness for the P5 per-service temporal state.
 *
 * Exercises:
 *   - alloc + init lifecycle
 *   - windows[0..2].size_seconds = {10, 60, 300} after init
 *   - sample ring buffer write + reset semantics
 *   - reset preserves active + size_seconds, zeroes everything else
 *   - NULL safety
 *   - sizeof report + log not crashing
 *
 * Build:  ninja -C build test_service_temporal_state
 * Run:    ./build/test_service_temporal_state
 * Returns 0 on full pass, 1 on any FAIL.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>

#include "l2fwd_service_temporal_state.h"

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

static void test_alloc_init(void) {
    fprintf(stderr, "\n=== POSITIVE: alloc + init ===\n");

    struct service_temporal_state *tmp = service_temporal_state_alloc();
    CHECK(tmp != NULL, "alloc returned non-NULL");
    if (!tmp) return;

    int rc = service_temporal_state_init(tmp);
    CHECK(rc == 0, "init returned 0 (rc=%d)", rc);

    CHECK(tmp->active == true, "active = true after init");
    CHECK(tmp->sample_head == 0, "sample_head = 0");
    CHECK(tmp->sample_count == 0, "sample_count = 0");
    CHECK(tmp->total_samples_seen == 0, "total_samples_seen = 0");
    CHECK(tmp->last_update_ns == 0, "last_update_ns = 0");

    /* Window slot identities. */
    CHECK(tmp->windows[SERVICE_TEMPORAL_WINDOW_10S_INDEX].size_seconds  == 10,
          "windows[0].size_seconds = 10");
    CHECK(tmp->windows[SERVICE_TEMPORAL_WINDOW_60S_INDEX].size_seconds  == 60,
          "windows[1].size_seconds = 60");
    CHECK(tmp->windows[SERVICE_TEMPORAL_WINDOW_300S_INDEX].size_seconds == 300,
          "windows[2].size_seconds = 300");

    /* Window aggregates all zero. */
    CHECK(tmp->windows[0].total_pkts == 0, "windows[0].total_pkts = 0");
    CHECK(tmp->windows[1].mean_pps == 0.0,  "windows[1].mean_pps = 0");
    CHECK(tmp->windows[2].peak_bps == 0.0,  "windows[2].peak_bps = 0");
    CHECK(tmp->windows[1].attack_seconds == 0,
          "windows[1].attack_seconds = 0");

    service_temporal_state_destroy(tmp);
}

static void test_ring_populate_then_reset(void) {
    fprintf(stderr, "\n=== POSITIVE: ring populate + reset ===\n");

    struct service_temporal_state *tmp = service_temporal_state_alloc();
    CHECK(tmp != NULL, "alloc OK");
    if (!tmp) return;
    service_temporal_state_init(tmp);

    /* Populate samples[0..4] with synthetic 1Hz entries. */
    for (uint32_t i = 0; i < 5; i++) {
        tmp->samples[i].timestamp_ns    = 1000000000ULL * (i + 1);
        tmp->samples[i].pkts            = 100ULL + i;
        tmp->samples[i].bytes           = 1500ULL * (100ULL + i);
        tmp->samples[i].flows           = 10ULL + i;
        tmp->samples[i].detection_phase = (uint8_t)(i % 4);
    }
    tmp->sample_head        = 4;
    tmp->sample_count       = 5;
    tmp->total_samples_seen = 5;
    tmp->last_update_ns     = 5000000000ULL;

    /* Also populate some window aggregates so we can verify they clear. */
    tmp->windows[0].total_pkts        = 500;
    tmp->windows[0].total_bytes       = 750000;
    tmp->windows[0].mean_pps          = 102.0;
    tmp->windows[0].peak_pps          = 104.0;
    tmp->windows[0].attack_seconds    = 1;
    tmp->windows[0].suspicious_seconds = 1;
    tmp->windows[1].total_pkts        = 500;
    tmp->windows[2].total_pkts        = 500;

    CHECK(tmp->sample_count == 5, "pre-reset sample_count = 5");
    CHECK(tmp->samples[3].pkts == 103, "samples[3].pkts populated");
    CHECK(tmp->windows[0].mean_pps == 102.0, "windows[0].mean_pps populated");

    /* Reset. */
    service_temporal_state_reset(tmp);

    /* Cleared fields. */
    CHECK(tmp->sample_head == 0,        "sample_head reset to 0");
    CHECK(tmp->sample_count == 0,       "sample_count reset to 0");
    CHECK(tmp->total_samples_seen == 0, "total_samples_seen reset to 0");
    CHECK(tmp->last_update_ns == 0,     "last_update_ns reset to 0");

    /* All sample slots zeroed. */
    int all_zero = 1;
    for (uint32_t i = 0; i < SERVICE_TEMPORAL_MAX_SAMPLES; i++) {
        if (tmp->samples[i].timestamp_ns != 0 ||
            tmp->samples[i].pkts         != 0 ||
            tmp->samples[i].bytes        != 0 ||
            tmp->samples[i].flows        != 0 ||
            tmp->samples[i].detection_phase != 0) {
            all_zero = 0;
            break;
        }
    }
    CHECK(all_zero == 1, "all %d sample slots zeroed", SERVICE_TEMPORAL_MAX_SAMPLES);

    /* Window aggregates cleared. */
    CHECK(tmp->windows[0].total_pkts == 0,        "windows[0].total_pkts cleared");
    CHECK(tmp->windows[0].mean_pps == 0.0,        "windows[0].mean_pps cleared");
    CHECK(tmp->windows[0].peak_pps == 0.0,        "windows[0].peak_pps cleared");
    CHECK(tmp->windows[0].attack_seconds == 0,    "windows[0].attack_seconds cleared");
    CHECK(tmp->windows[1].total_pkts == 0,        "windows[1].total_pkts cleared");
    CHECK(tmp->windows[2].total_pkts == 0,        "windows[2].total_pkts cleared");

    /* PRESERVED. */
    CHECK(tmp->active == true, "active preserved after reset");
    CHECK(tmp->windows[0].size_seconds == 10,
          "windows[0].size_seconds preserved (10)");
    CHECK(tmp->windows[1].size_seconds == 60,
          "windows[1].size_seconds preserved (60)");
    CHECK(tmp->windows[2].size_seconds == 300,
          "windows[2].size_seconds preserved (300)");

    service_temporal_state_destroy(tmp);
}

static void test_null_handling(void) {
    fprintf(stderr, "\n=== NEGATIVE: NULL handling ===\n");

    int rc = service_temporal_state_init(NULL);
    CHECK(rc < 0, "init(NULL) returned negative (rc=%d)", rc);

    service_temporal_state_reset(NULL);
    CHECK(true, "reset(NULL) did not crash");

    service_temporal_state_destroy(NULL);
    CHECK(true, "destroy(NULL) did not crash");

    service_temporal_state_log(NULL);
    CHECK(true, "log(NULL) did not crash");
}

static void test_sizeof_and_log(void) {
    fprintf(stderr, "\n=== POSITIVE: sizeof + diagnostic log ===\n");
    size_t sz = service_temporal_state_sizeof();
    fprintf(stderr,
            "  sizeof(struct service_temporal_state) = %zu bytes (~%.1f KB)\n",
            sz, (double)sz / 1024.0);
    CHECK(sz == sizeof(struct service_temporal_state),
          "sizeof helper matches direct sizeof");
    CHECK(sz > 0, "sizeof > 0");

    struct service_temporal_state *tmp = service_temporal_state_alloc();
    if (tmp) {
        service_temporal_state_init(tmp);
        tmp->windows[0].total_pkts = 12345;
        tmp->windows[1].total_pkts = 67890;
        tmp->windows[2].total_pkts = 100;
        tmp->sample_count = 7;
        tmp->total_samples_seen = 42;
        service_temporal_state_log(tmp);
        CHECK(true, "log on populated state did not crash");
        service_temporal_state_destroy(tmp);
    }
}

/* -------------------------------------------------------------------------
 * Main
 * ------------------------------------------------------------------------- */

int main(void) {
    fprintf(stderr, "\n*** service_temporal P5 test harness ***\n");

    test_alloc_init();
    test_ring_populate_then_reset();
    test_null_handling();
    test_sizeof_and_log();

    fprintf(stderr, "\n=== SUMMARY: %d PASS, %d FAIL ===\n", g_pass, g_fail);
    return (g_fail == 0) ? 0 : 1;
}
