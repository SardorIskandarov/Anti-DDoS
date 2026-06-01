/**
 * @file   tests/test_service_reload.c
 * @brief  Standalone test harness for the P6 SIGHUP reload subsystem.
 *
 * Exercises:
 *   - install_handler success
 *   - pending-flag lifecycle (request -> perform clears)
 *   - end-to-end successful reload (active registry survives, stats wired)
 *   - reload from a corrupted JSON keeps the old registry intact
 *   - perform with no pending flag returns NO_FLAG
 *   - three sequential reloads succeed and counters increment correctly
 *   - raise(SIGHUP) sets the pending flag
 *   - NULL argument handling
 *
 * The test uses a TEMP copy of services.json under /tmp so we can mutate
 * the file (overwrite with garbage, then restore) without touching the
 * real one in the repo.
 *
 * Build:  ninja -C build test_service_reload
 * Run:    ./build/test_service_reload
 * Returns 0 on full pass, 1 on any FAIL.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <unistd.h>
#include <signal.h>
#include <sys/stat.h>
#include <sys/types.h>

#include "l2fwd_service_registry.h"
#include "l2fwd_service_stats.h"
#include "l2fwd_service_reload.h"

/* Stable known-good fixture: the preserved 11-IP / 44-slot phase-0
 * registry. Decoupled from the live operational services.json. */
#define SOURCE_JSON \
    "/home/user_1/Music/Anti-DDoS/config/services_v1_phase0_backup.json"

/* The test mutates this file in place to simulate a corrupt-config push.
 * Path includes the PID so concurrent runs do not collide. */
static char g_tmp_json[256];

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

/* ----- BSS-stable fixtures used across most tests -------------------- */
static struct service_registry    g_active_reg;
static struct service_stats_array g_active_arr;
static struct service_stats_array g_active_arr_b;   /* hot-path double-buffer bank 1 */
static struct service_registry    g_staging_reg;
static struct service_stats_array g_staging_arr;

/* -------------------------------------------------------------------------
 * Helpers
 * ------------------------------------------------------------------------- */

static int copy_file(const char *src, const char *dst) {
    FILE *fs = fopen(src, "rb");
    if (!fs) { perror("fopen src"); return -1; }
    FILE *fd = fopen(dst, "wb");
    if (!fd) { perror("fopen dst"); fclose(fs); return -2; }
    char buf[8192];
    size_t n;
    while ((n = fread(buf, 1, sizeof(buf), fs)) > 0) {
        if (fwrite(buf, 1, n, fd) != n) { fclose(fs); fclose(fd); return -3; }
    }
    fclose(fs);
    fclose(fd);
    return 0;
}

static int write_garbage(const char *path) {
    FILE *f = fopen(path, "wb");
    if (!f) return -1;
    fputs("{ this is not valid JSON :::: !@#$ %^&* (", f);
    fclose(f);
    return 0;
}

/* Drain the pending flag (used to ensure baseline state between tests). */
static void clear_pending_flag(void) {
    /* perform() clears the flag; but we need it set first to even reach
     * the body. Easier: request + perform with all NULL succeeds at
     * INTERNAL but clears the flag. Or just call perform with no-flag —
     * it returns NO_FLAG without touching the flag. So flip via request
     * then perform-with-valid-buffers. We're in test setup so a full
     * perform is fine. */
    if (service_reload_pending()) {
        service_reload_perform(&g_staging_reg, &g_staging_arr,
                               &g_active_reg, &g_active_arr, &g_active_arr_b);
    }
}

/* -------------------------------------------------------------------------
 * Tests
 * ------------------------------------------------------------------------- */

static void test_install_handler(void) {
    fprintf(stderr, "\n=== POSITIVE: install_handler ===\n");
    int rc = service_reload_install_handler();
    CHECK(rc == 0, "install_handler returned 0 (rc=%d)", rc);
}

static void test_pending_lifecycle(void) {
    fprintf(stderr, "\n=== POSITIVE: pending-flag lifecycle ===\n");
    /* Drain anything left over from prior tests. */
    clear_pending_flag();

    CHECK(service_reload_pending() == false,
          "initially pending = false");

    service_reload_request();
    CHECK(service_reload_pending() == true,
          "after request, pending = true");

    /* perform() with no path/no active registry should clear the flag
     * (returns INTERNAL but still clears, by design). */
    int rc = service_reload_perform(&g_staging_reg, &g_staging_arr,
                                     &g_active_reg, &g_active_arr, &g_active_arr_b);
    /* Could be INTERNAL (no path yet) or VALIDATE — either way the flag
     * is cleared. */
    (void)rc;
    CHECK(service_reload_pending() == false,
          "after perform, pending = false (rc=%d)", rc);
}

static void test_end_to_end_success(void) {
    fprintf(stderr, "\n=== POSITIVE: end-to-end successful reload ===\n");

    /* Initial load — emulates the engine's startup path. */
    int rc = service_registry_init(&g_active_reg);
    CHECK(rc == SERVICE_REGISTRY_OK, "active registry_init OK");
    rc = service_registry_load(&g_active_reg, g_tmp_json);
    CHECK(rc == SERVICE_REGISTRY_OK,
          "active registry_load(%s) OK (rc=%d)", g_tmp_json, rc);

    rc = service_stats_array_init(&g_active_arr);
    CHECK(rc == 0, "active stats_array_init OK");
    rc = service_stats_init_from_registry(&g_active_arr, &g_active_reg);
    CHECK(rc == 0, "active stats_init_from_registry OK");

    /* Publish — required so get_source_path() returns the path. */
    service_registry_set_global(&g_active_reg);
    CHECK(service_registry_get_global() == &g_active_reg,
          "get_global() == &g_active_reg after set_global");
    CHECK(service_registry_get_source_path() != NULL,
          "get_source_path() returns non-NULL after set_global");

    /* Trigger reload. */
    uint64_t prev_attempts = service_reload_get_attempt_count();
    uint64_t prev_successes = service_reload_get_success_count();

    service_reload_request();
    CHECK(service_reload_pending() == true, "pending = true after request");

    rc = service_reload_perform(&g_staging_reg, &g_staging_arr,
                                 &g_active_reg, &g_active_arr, &g_active_arr_b);
    CHECK(rc == SERVICE_RELOAD_OK,
          "perform returned OK (rc=%d, last_error='%s')",
          rc, service_reload_get_last_error_message());

    CHECK(service_reload_pending() == false,
          "pending = false after successful perform");
    CHECK(service_reload_get_attempt_count() == prev_attempts + 1,
          "attempt counter incremented (%llu -> %llu)",
          (unsigned long long)prev_attempts,
          (unsigned long long)service_reload_get_attempt_count());
    CHECK(service_reload_get_success_count() == prev_successes + 1,
          "success counter incremented");

    /* Active registry pointer should equal &g_active_reg, not staging. */
    CHECK(service_registry_get_global() == &g_active_reg,
          "after reload, global == &g_active_reg (re-published)");

    /* Active arr should still have 44 active slots after the reload swap. */
    CHECK(g_active_arr.n_active == 44,
          "active_arr.n_active = %zu (expect 44)",
          g_active_arr.n_active);
}

static void test_corrupt_reload_preserves_old(void) {
    fprintf(stderr, "\n=== POSITIVE: corrupt-file reload preserves old registry ===\n");

    /* Snapshot the live registry's identity invariants. */
    size_t old_n_slots         = g_active_reg.n_slots;
    size_t old_n_profiles      = g_active_reg.n_profiles;
    size_t old_n_protected_ips = g_active_reg.n_protected_ips;
    uint64_t prev_failures     = service_reload_get_failure_count();
    uint64_t prev_successes    = service_reload_get_success_count();

    /* Replace the on-disk JSON with garbage. */
    int rc = write_garbage(g_tmp_json);
    CHECK(rc == 0, "wrote garbage to %s", g_tmp_json);

    service_reload_request();
    rc = service_reload_perform(&g_staging_reg, &g_staging_arr,
                                 &g_active_reg, &g_active_arr, &g_active_arr_b);
    CHECK(rc == SERVICE_RELOAD_ERR_PARSE || rc == SERVICE_RELOAD_ERR_VALIDATE,
          "perform on garbage returned PARSE or VALIDATE (rc=%d)", rc);
    CHECK(service_reload_pending() == false,
          "pending cleared even on failure");
    CHECK(service_reload_get_failure_count() == prev_failures + 1,
          "failure counter incremented (%llu -> %llu)",
          (unsigned long long)prev_failures,
          (unsigned long long)service_reload_get_failure_count());
    CHECK(service_reload_get_success_count() == prev_successes,
          "success counter UNCHANGED");
    CHECK(strlen(service_reload_get_last_error_message()) > 0,
          "last_error_message non-empty: \"%s\"",
          service_reload_get_last_error_message());

    /* Active registry should be untouched. */
    CHECK(g_active_reg.n_slots == old_n_slots,
          "active n_slots preserved (%zu)", g_active_reg.n_slots);
    CHECK(g_active_reg.n_profiles == old_n_profiles,
          "active n_profiles preserved (%zu)", g_active_reg.n_profiles);
    CHECK(g_active_reg.n_protected_ips == old_n_protected_ips,
          "active n_protected_ips preserved (%zu)",
          g_active_reg.n_protected_ips);
    CHECK(service_registry_get_global() == &g_active_reg,
          "global pointer still == &g_active_reg");
    CHECK(g_active_arr.n_active == 44,
          "active_arr.n_active still 44");

    /* Restore the file so subsequent tests work. */
    rc = copy_file(SOURCE_JSON, g_tmp_json);
    CHECK(rc == 0, "restored valid JSON at %s", g_tmp_json);
}

static void test_no_flag_path(void) {
    fprintf(stderr, "\n=== POSITIVE: perform without pending flag returns NO_FLAG ===\n");

    /* Ensure the flag is clear. */
    clear_pending_flag();
    CHECK(service_reload_pending() == false, "pending = false going in");

    uint64_t prev_attempts = service_reload_get_attempt_count();
    int rc = service_reload_perform(&g_staging_reg, &g_staging_arr,
                                     &g_active_reg, &g_active_arr, &g_active_arr_b);
    CHECK(rc == SERVICE_RELOAD_ERR_NO_FLAG,
          "perform without flag returned NO_FLAG (rc=%d)", rc);
    CHECK(service_reload_get_attempt_count() == prev_attempts,
          "attempt counter NOT incremented (NO_FLAG short-circuits)");
}

static void test_multiple_sequential_reloads(void) {
    fprintf(stderr, "\n=== POSITIVE: multiple sequential reloads ===\n");

    uint64_t prev_successes = service_reload_get_success_count();

    for (int i = 1; i <= 3; i++) {
        service_reload_request();
        int rc = service_reload_perform(&g_staging_reg, &g_staging_arr,
                                         &g_active_reg, &g_active_arr, &g_active_arr_b);
        CHECK(rc == SERVICE_RELOAD_OK,
              "reload #%d returned OK (rc=%d)", i, rc);
        CHECK(g_active_reg.n_protected_ips == 11,
              "reload #%d preserved n_protected_ips = 11 (got %zu)",
              i, g_active_reg.n_protected_ips);
        CHECK(g_active_arr.n_active == 44,
              "reload #%d preserved n_active = 44 (got %zu)",
              i, g_active_arr.n_active);
    }

    CHECK(service_reload_get_success_count() == prev_successes + 3,
          "success counter advanced by 3 (was %llu, now %llu)",
          (unsigned long long)prev_successes,
          (unsigned long long)service_reload_get_success_count());
}

static void test_counter_accuracy(void) {
    fprintf(stderr, "\n=== POSITIVE: counter accuracy ===\n");
    uint64_t a = service_reload_get_attempt_count();
    uint64_t s = service_reload_get_success_count();
    uint64_t f = service_reload_get_failure_count();
    fprintf(stderr,
            "  attempts=%llu successes=%llu failures=%llu (a == s + f? %s)\n",
            (unsigned long long)a, (unsigned long long)s,
            (unsigned long long)f, (a == s + f) ? "yes" : "no");
    CHECK(a == s + f, "attempts == successes + failures (%llu == %llu + %llu)",
          (unsigned long long)a, (unsigned long long)s,
          (unsigned long long)f);
    CHECK(service_reload_get_last_success_unix() > 0,
          "last_success_unix non-zero after successes");
}

static void test_raise_sighup(void) {
    fprintf(stderr, "\n=== POSITIVE: raise(SIGHUP) sets pending ===\n");
    clear_pending_flag();
    CHECK(service_reload_pending() == false, "pending = false going in");

    int rc = raise(SIGHUP);
    CHECK(rc == 0, "raise(SIGHUP) returned 0");
    CHECK(service_reload_pending() == true,
          "service_reload_pending() == true after raise(SIGHUP)");

    /* Consume the flag so it doesn't bleed into later tests. */
    clear_pending_flag();
}

static void test_null_handling(void) {
    fprintf(stderr, "\n=== NEGATIVE: NULL handling ===\n");

    service_reload_request();
    int rc = service_reload_perform(NULL, &g_staging_arr,
                                     &g_active_reg, &g_active_arr, &g_active_arr_b);
    CHECK(rc == SERVICE_RELOAD_ERR_INTERNAL,
          "perform(NULL, ..., ..., ...) returned INTERNAL (rc=%d)", rc);
    CHECK(service_reload_pending() == false,
          "pending cleared even on NULL-arg failure");

    service_reload_request();
    rc = service_reload_perform(&g_staging_reg, NULL,
                                 &g_active_reg, &g_active_arr, &g_active_arr_b);
    CHECK(rc == SERVICE_RELOAD_ERR_INTERNAL,
          "perform(..., NULL, ..., ...) returned INTERNAL (rc=%d)", rc);

    service_reload_request();
    rc = service_reload_perform(&g_staging_reg, &g_staging_arr,
                                 NULL, &g_active_arr, &g_active_arr_b);
    CHECK(rc == SERVICE_RELOAD_ERR_INTERNAL,
          "perform(..., ..., NULL, ...) returned INTERNAL (rc=%d)", rc);

    service_reload_request();
    rc = service_reload_perform(&g_staging_reg, &g_staging_arr,
                                 &g_active_reg, NULL, &g_active_arr_b);
    CHECK(rc == SERVICE_RELOAD_ERR_INTERNAL,
          "perform(..., ..., ..., NULL) returned INTERNAL (rc=%d)", rc);
}

/* -------------------------------------------------------------------------
 * Main
 * ------------------------------------------------------------------------- */

int main(void) {
    fprintf(stderr, "\n*** service_reload P6 test harness ***\n");

    /* Set up the on-disk fixture under /tmp. */
    snprintf(g_tmp_json, sizeof(g_tmp_json),
             "/tmp/test_reload_%d.json", (int)getpid());
    int rc = copy_file(SOURCE_JSON, g_tmp_json);
    if (rc != 0) {
        fprintf(stderr, "FATAL: could not copy %s -> %s (rc=%d)\n",
                SOURCE_JSON, g_tmp_json, rc);
        return 2;
    }
    fprintf(stderr, "  fixture: %s\n", g_tmp_json);

    test_install_handler();
    test_pending_lifecycle();
    test_end_to_end_success();
    test_corrupt_reload_preserves_old();
    test_no_flag_path();
    test_multiple_sequential_reloads();
    test_counter_accuracy();
    test_raise_sighup();
    test_null_handling();

    /* Diagnostic. */
    fprintf(stderr, "\n=== diagnostic: service_reload_log_summary ===\n");
    service_reload_log_summary();

    /* Cleanup. */
    service_registry_set_global(NULL);
    service_stats_array_destroy(&g_active_arr);
    service_stats_array_destroy(&g_active_arr_b);
    service_registry_destroy(&g_active_reg);
    /* staging structs already zeroed by perform() on success. */
    (void)unlink(g_tmp_json);

    fprintf(stderr, "\n=== SUMMARY: %d PASS, %d FAIL ===\n", g_pass, g_fail);
    return (g_fail == 0) ? 0 : 1;
}
