/**
 * @file   l2fwd_service_reload.c
 * @brief  SIGHUP-driven service registry reload — P6 implementation.
 *
 * Algorithm overview (see header for full contract):
 *
 *   1. Check the pending flag; return NO_FLAG if not requested.
 *   2. Snapshot the active registry's source path (it lives inside
 *      active_reg.source_path, which we'll later overwrite — so take a
 *      local copy first).
 *   3. Load services.json into staging_reg. On parse/validate failure,
 *      record last_error, increment failure counter, clear flag, return.
 *   4. Allocate staging stats array and init slots from staging_reg.
 *   5. Wire detection_state + temporal_state on every active staging slot.
 *      Any failure rolls back (destroy stats array, destroy registry) and
 *      returns _ALLOC.
 *   6. Publish staging_reg via service_registry_set_global() (release).
 *   7. Tear down old active_arr (unwire + destroy).
 *   8. Copy *staging_reg into *active_reg and *staging_arr into *active_arr.
 *      The heap allocations (slots, per-slot det/tmp states) transfer by
 *      pointer-copy — the staging structs are zeroed afterwards so destroy
 *      on staging is harmless.
 *   9. Re-publish active_reg (so get_global() returns the stable address).
 *  10. Increment success counter, record timestamp, clear flag.
 */

#include "l2fwd_service_reload.h"
#include "l2fwd_service_registry.h"
#include "l2fwd_service_stats.h"
#include "l2fwd_service_detection.h"
#include "l2fwd_service_temporal_state.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <signal.h>
#include <stdatomic.h>
#include <time.h>
#include <errno.h>

/* -------------------------------------------------------------------------
 * File-static state
 * ------------------------------------------------------------------------- */

/* signal-safe flag; set by the SIGHUP handler, cleared by perform(). */
static volatile sig_atomic_t g_sighup_pending = 0;

/* Audit counters — atomic so observability code can read them from any
 * thread without taking a lock. */
static _Atomic uint64_t g_attempts     = 0;
static _Atomic uint64_t g_successes    = 0;
static _Atomic uint64_t g_failures     = 0;
static _Atomic uint64_t g_last_success = 0;

/* Last error message; written only by the main thread inside perform(),
 * read by observability accessors. Plain char[] is fine — readers may see
 * a torn string under contention, but the worst case is a misformatted
 * log line. No correctness risk. */
static char g_last_error_message[256] = "";

/* -------------------------------------------------------------------------
 * Signal handler — minimal, async-signal-safe
 * ------------------------------------------------------------------------- */
static void sighup_handler(int signo) {
    (void)signo;
    g_sighup_pending = 1;
    /* DO NOT call printf, malloc, fprintf, or anything not on the
     * async-signal-safe list. The flag is read by the main thread which
     * does the actual work. */
}

int service_reload_install_handler(void) {
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = sighup_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = SA_RESTART;
    if (sigaction(SIGHUP, &sa, NULL) != 0) {
        fprintf(stderr,
                "[service_reload] [ERROR] sigaction(SIGHUP) failed: %s\n",
                strerror(errno));
        return -1;
    }
    fprintf(stderr, "[service_reload] SIGHUP handler installed\n");
    return 0;
}

bool service_reload_pending(void) {
    return g_sighup_pending != 0;
}

void service_reload_request(void) {
    g_sighup_pending = 1;
}

/* -------------------------------------------------------------------------
 * Internal helpers
 * ------------------------------------------------------------------------- */

static void record_failure(const char *fmt, ...)
{
    /* Tiny vsnprintf wrapper that also bumps the failure counter and
     * clears the pending flag. */
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(g_last_error_message, sizeof(g_last_error_message), fmt, ap);
    va_end(ap);
    fprintf(stderr, "[service_reload] [ERROR] %s\n", g_last_error_message);
    atomic_fetch_add_explicit(&g_failures, 1, memory_order_relaxed);
    g_sighup_pending = 0;
}

/* -------------------------------------------------------------------------
 * The main reload routine
 * ------------------------------------------------------------------------- */

int service_reload_perform(
    struct service_registry      *staging_reg,
    struct service_stats_array   *staging_arr,
    struct service_registry      *active_reg,
    struct service_stats_array   *active_arr)
{
    if (!service_reload_pending()) {
        return SERVICE_RELOAD_ERR_NO_FLAG;
    }

    /* Every code path below clears the pending flag exactly once. */
    atomic_fetch_add_explicit(&g_attempts, 1, memory_order_relaxed);

    if (!staging_reg || !staging_arr || !active_reg || !active_arr) {
        record_failure("NULL argument to service_reload_perform "
                       "(staging_reg=%p staging_arr=%p active_reg=%p active_arr=%p)",
                       (void *)staging_reg, (void *)staging_arr,
                       (void *)active_reg, (void *)active_arr);
        return SERVICE_RELOAD_ERR_INTERNAL;
    }

    const char *path = service_registry_get_source_path();
    if (!path || !*path) {
        record_failure("no source path recorded — initial load never happened?");
        return SERVICE_RELOAD_ERR_INTERNAL;
    }

    /* Copy the path locally — it lives inside active_reg.source_path,
     * which we'll overwrite later in this function. */
    char path_copy[256];
    snprintf(path_copy, sizeof(path_copy), "%s", path);

    fprintf(stderr, "[service_reload] reload requested for %s\n", path_copy);

    /* --- Step 1: load into staging --------------------------------- */
    /* Zero the staging registry to a known empty state before reloading. */
    int rc = service_registry_init(staging_reg);
    if (rc != SERVICE_REGISTRY_OK) {
        record_failure("staging registry_init failed: rc=%d", rc);
        return SERVICE_RELOAD_ERR_INTERNAL;
    }

    rc = service_registry_load(staging_reg, path_copy);
    if (rc != SERVICE_REGISTRY_OK) {
        record_failure("registry_load failed for %s: rc=%d "
                       "(keeping current active registry)",
                       path_copy, rc);
        /* Discard whatever partial state ended up in staging. */
        service_registry_destroy(staging_reg);
        if (rc == SERVICE_REGISTRY_ERR_PARSE) {
            return SERVICE_RELOAD_ERR_PARSE;
        }
        if (rc == SERVICE_REGISTRY_ERR_VALIDATE) {
            return SERVICE_RELOAD_ERR_VALIDATE;
        }
        /* IO / CAPACITY / INTERNAL all map to VALIDATE for the caller's
         * coarse classification; the precise rc is in the error message. */
        return SERVICE_RELOAD_ERR_VALIDATE;
    }

    /* --- Step 2: allocate staging stats array ---------------------- */
    rc = service_stats_array_init(staging_arr);
    if (rc != 0) {
        record_failure("stats_array_init failed: rc=%d", rc);
        service_registry_destroy(staging_reg);
        return SERVICE_RELOAD_ERR_ALLOC;
    }

    /* --- Step 3: init slots from staging registry ------------------ */
    rc = service_stats_init_from_registry(staging_arr, staging_reg);
    if (rc != 0) {
        record_failure("stats_init_from_registry failed: rc=%d", rc);
        service_stats_array_destroy(staging_arr);
        service_registry_destroy(staging_reg);
        return SERVICE_RELOAD_ERR_ALLOC;
    }

    /* --- Step 4: wire detection + temporal state ------------------- */
    rc = service_stats_wire_all(staging_arr);
    if (rc != 0) {
        record_failure("stats_wire_all failed: rc=%d", rc);
        service_stats_array_destroy(staging_arr);
        service_registry_destroy(staging_reg);
        return SERVICE_RELOAD_ERR_ALLOC;
    }

    /* --- Step 5: log staging summary ------------------------------- */
    fprintf(stderr, "[service_reload] staging registry validated:\n");
    service_registry_log_summary(staging_reg);

    /* --- Step 6: atomic swap of the global pointer ----------------- *
     * Release semantics — any hot-path reader that subsequently sees
     * staging_reg via the acquire-load in service_registry_get_global()
     * is guaranteed to observe a fully-initialised registry. P6 has no
     * such readers; this is for P7+. */
    (void)service_registry_set_global(staging_reg);

    /* --- Step 7: tear down old active stats array ------------------ *
     * In P6 nothing reads active_arr from the hot path, so this is
     * safe. P7 will need an RCU grace period here.                      */
    service_stats_unwire_all(active_arr);
    service_stats_array_destroy(active_arr);

    /* Clear old active_reg (no heap to free — just zero it). */
    memset(active_reg, 0, sizeof(*active_reg));

    /* --- Step 8: move staging contents into stable active slots ---- *
     * Shallow copy is correct: the heap pointers inside service_stats_array
     * (slots[]) and inside each slot's detection_state / temporal_state
     * transfer ownership by pointer-copy. We then zero the staging
     * structs so a stray destroy() on them is a no-op.                  */
    *active_reg = *staging_reg;
    *active_arr = *staging_arr;
    memset(staging_reg, 0, sizeof(*staging_reg));
    memset(staging_arr, 0, sizeof(*staging_arr));

    /* --- Step 9: re-publish the global to the stable active address - */
    (void)service_registry_set_global(active_reg);

    /* --- Step 10: success accounting ------------------------------- */
    atomic_fetch_add_explicit(&g_successes, 1, memory_order_relaxed);
    atomic_store_explicit(&g_last_success, (uint64_t)time(NULL),
                          memory_order_relaxed);
    g_last_error_message[0] = '\0';
    g_sighup_pending = 0;

    fprintf(stderr,
            "[service_reload] [SUCCESS] reload complete: %s "
            "(attempts=%llu successes=%llu failures=%llu)\n",
            path_copy,
            (unsigned long long)atomic_load_explicit(&g_attempts, memory_order_relaxed),
            (unsigned long long)atomic_load_explicit(&g_successes, memory_order_relaxed),
            (unsigned long long)atomic_load_explicit(&g_failures, memory_order_relaxed));

    return SERVICE_RELOAD_OK;
}

/* -------------------------------------------------------------------------
 * Observability accessors
 * ------------------------------------------------------------------------- */

uint64_t service_reload_get_attempt_count(void) {
    return atomic_load_explicit(&g_attempts, memory_order_relaxed);
}
uint64_t service_reload_get_success_count(void) {
    return atomic_load_explicit(&g_successes, memory_order_relaxed);
}
uint64_t service_reload_get_failure_count(void) {
    return atomic_load_explicit(&g_failures, memory_order_relaxed);
}
uint64_t service_reload_get_last_success_unix(void) {
    return atomic_load_explicit(&g_last_success, memory_order_relaxed);
}
const char *service_reload_get_last_error_message(void) {
    return g_last_error_message;
}

void service_reload_log_summary(void) {
    fprintf(stderr,
            "[service_reload] summary: attempts=%llu successes=%llu failures=%llu "
            "last_success_unix=%llu pending=%d last_error=\"%s\"\n",
            (unsigned long long)service_reload_get_attempt_count(),
            (unsigned long long)service_reload_get_success_count(),
            (unsigned long long)service_reload_get_failure_count(),
            (unsigned long long)service_reload_get_last_success_unix(),
            (int)service_reload_pending(),
            g_last_error_message);
}
