#ifndef __L2FWD_SERVICE_RELOAD_H__
#define __L2FWD_SERVICE_RELOAD_H__

/**
 * @file   l2fwd_service_reload.h
 * @brief  SIGHUP-driven service registry reload — P6 of the big-bang refactor.
 *
 * Wires P1-P5 together into a live-reload subsystem:
 *
 *   - SIGHUP handler sets a volatile flag (signal-safe; no allocation)
 *   - service_reload_perform() runs on the main thread, parses the new
 *     services.json into a staging registry, validates it, allocates +
 *     wires a staging stats array, atomically swaps the global pointer,
 *     then tears down the old stats array.
 *   - On validation failure, the OLD registry stays active. The engine
 *     never aborts on a bad reload.
 *
 * Atomic ordering: the global pointer swap uses
 * service_registry_set_global() (release semantics). Hot-path readers use
 * service_registry_get_global() (acquire semantics). Together they form
 * the happens-before relationship hot-path code needs.
 *
 * Hot-path coupling at P6: none. P7+ wires hot-path consumption.
 */

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

/* Forward declarations — keep the header decoupled from the underlying
 * modules. The .c file pulls in the full struct definitions. */
struct service_registry;
struct service_stats_array;

/* -------------------------------------------------------------------------
 * Return codes
 * ------------------------------------------------------------------------- */
#define SERVICE_RELOAD_OK             0
#define SERVICE_RELOAD_ERR_NO_FLAG   -1   /* reload not requested              */
#define SERVICE_RELOAD_ERR_PARSE     -2   /* JSON parse failed (structural)    */
#define SERVICE_RELOAD_ERR_VALIDATE  -3   /* validation rule violation         */
#define SERVICE_RELOAD_ERR_ALLOC     -4   /* stats wire / alloc failure        */
#define SERVICE_RELOAD_ERR_INTERNAL  -5   /* NULL arg, no source path, etc.    */

/* -------------------------------------------------------------------------
 * Public API
 * ------------------------------------------------------------------------- */

/**
 * Install the SIGHUP signal handler. Call once at engine startup, AFTER
 * service_registry_set_global() has been called with the initial registry
 * but BEFORE the main packet-processing loop starts.
 *
 * Uses sigaction with SA_RESTART so existing blocking syscalls (read,
 * select, etc.) continue across the signal. The handler itself only sets
 * a volatile sig_atomic_t flag.
 *
 * Returns 0 on success, negative on sigaction failure.
 */
int service_reload_install_handler(void);

/**
 * Returns true if a SIGHUP has been received since the last clearing
 * (successful reload, failed reload, or perform-with-no-flag). Safe to
 * call from any thread; reads a volatile sig_atomic_t.
 */
bool service_reload_pending(void);

/**
 * Manually request a reload. Equivalent to receiving a SIGHUP. Useful for
 * test harnesses and admin endpoints.
 */
void service_reload_request(void);

/**
 * Perform the reload. MUST be called from the main thread only — it
 * mutates the active registry storage and rewires stats arrays.
 *
 * Behaviour summary:
 *   - If no SIGHUP is pending, returns SERVICE_RELOAD_ERR_NO_FLAG (cheap).
 *   - Reads the current source path via service_registry_get_source_path().
 *   - Loads services.json into `staging_reg`. On parse/validation failure,
 *     keeps the old active registry, sets the last-error message, clears
 *     the flag, returns _PARSE or _VALIDATE.
 *   - Allocates a stats array in `staging_arr` and wires
 *     detection_state + temporal_state for every active slot.
 *   - Atomically swaps the global registry pointer (release semantics).
 *   - Tears down the old `active_arr` (unwire + destroy).
 *   - Copies `*staging_reg -> *active_reg` and `*staging_arr -> *active_arr`
 *     so external callers' references stay valid, then re-publishes
 *     the global pointer to active_reg.
 *
 * @param staging_reg   pre-allocated registry storage used as staging buffer
 * @param staging_arr   pre-allocated stats-array storage used as staging buffer
 * @param active_reg    current active registry (BSS-stable address)
 * @param active_arr    current active stats array (BSS-stable address)
 * @return SERVICE_RELOAD_OK on success, negative error code otherwise.
 *
 * P6 note: this function is NOT yet coordinated with hot-path readers
 * dropping their references to old slots. P6 is safe because the hot
 * path doesn't read the new structures yet. P7 will add an RCU-style
 * grace period.
 */
int service_reload_perform(
    struct service_registry      *staging_reg,
    struct service_stats_array   *staging_arr,
    struct service_registry      *active_reg,
    struct service_stats_array   *active_arr);

/* -------------------------------------------------------------------------
 * Observability accessors
 * ------------------------------------------------------------------------- */
uint64_t    service_reload_get_attempt_count(void);
uint64_t    service_reload_get_success_count(void);
uint64_t    service_reload_get_failure_count(void);
uint64_t    service_reload_get_last_success_unix(void);
const char *service_reload_get_last_error_message(void);

/** Diagnostic: one-line summary line to stderr. */
void service_reload_log_summary(void);

#endif /* __L2FWD_SERVICE_RELOAD_H__ */
