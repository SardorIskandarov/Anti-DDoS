/*
 * l2fwd_policy.h — Layer 3 V1 per-packet policy enforcement (C side)
 *
 * ROLE
 *   Enforcement only.  This module has no knowledge of:
 *     - DDoS detection logic        (Layer 2 responsibility)
 *     - suspicious scoring          (Python responsibility)
 *     - policy decisions            (Python responsibility)
 *
 *   It reads a pre-built policy file that the Python scoring engine writes
 *   atomically once per second, stores the contents in a fixed-size hash
 *   table, and enforces them per-packet in the forwarding hot path.
 *
 * COMPILE-TIME ENABLE FLAG
 *   Build with -DL3_POLICY_ENFORCE=1 to activate enforcement.
 *   The default (0) is shadow mode: the table is built and maintained
 *   normally but l3_policy_check() always returns true (pass all packets).
 *   Shadow mode lets you observe policy decisions without dropping traffic.
 *
 * BYTE ORDER
 *   All IP addresses are stored and compared in HOST byte order throughout.
 *   The hot path (l3_policy_check) receives host-byte-order values.
 *   l3_policy_reload() converts from the dotted-decimal file format using
 *   ntohl() after inet_pton().
 *
 * THREAD MODEL
 *   Slow-path writer  (timer lcore, once per second):
 *       l3_policy_reload()       — rebuild table from policy file
 *       l3_policy_expire_tick()  — decrement TTLs, refill token buckets
 *   Hot-path readers  (forwarding lcores, once per packet):
 *       l3_policy_check()        — lookup + enforce
 *
 *   A double-buffered table with an atomic index flip ensures readers
 *   always see a fully-built, consistent snapshot.
 */

#ifndef __L2FWD_POLICY_H__
#define __L2FWD_POLICY_H__

#include <stdint.h>
#include <stdbool.h>


/* =========================================================================
 * COMPILE-TIME ENABLE FLAG
 *
 *   L3_POLICY_ENFORCE = 0  (default, shadow mode)
 *       l3_policy_check() always returns true.
 *       All other functions (reload, tick) operate normally — the table is
 *       kept current so switching to enforce mode is instant.
 *
 *   L3_POLICY_ENFORCE = 1  (enforce mode)
 *       l3_policy_check() applies BLOCK and RATE_LIMIT_* actions.
 *
 *   Override at compile time:  make CFLAGS="-DL3_POLICY_ENFORCE=1"
 * ========================================================================= */
#ifndef L3_POLICY_ENFORCE
#define L3_POLICY_ENFORCE 0
#endif


/* =========================================================================
 * CONFIGURATION
 * ========================================================================= */

/*
 * Hash table capacity.
 * MUST be a power of two — the hash mask is (L3_POLICY_TABLE_SIZE - 1).
 *
 * Keep the load factor below ~50% for O(1) amortised lookup with linear
 * probing.  With the Python engine capped at L3_MAX_TOP_SOURCES_PER_VICTIM
 * sources × 1024 victims the worst case is 20 480 entries; 65 536 here
 * gives comfortable headroom.  Reduce for memory-constrained deployments.
 */
#define L3_POLICY_TABLE_SIZE  65536

/*
 * Path to the policy file written by the Python scoring engine.
 * Python writes to a .tmp file first, then renames atomically so C never
 * reads a partially-written file.
 *
 * File format — one entry per line, space-separated:
 *   ACTION  SRC_IP  DST_IP  TTL_SEC  RATE_PPS
 *
 * Example lines:
 *   BLOCK            203.0.113.10  10.0.0.1  10    0
 *   RATE_LIMIT_HARD  203.0.113.20  10.0.0.1  20  100
 *   RATE_LIMIT_SOFT  203.0.113.30  10.0.0.1  15 1000
 *
 * Lines beginning with '#', blank lines, and malformed lines are skipped.
 * ALLOW entries are not stored (ALLOW is the implicit default).
 */
#define L3_POLICY_FILE_PATH  "/tmp/l3_policies.txt"

/*
 * Token bucket burst multiplier.
 *   max_tokens = rate_pps * L3_TOKEN_BURST_FACTOR
 *
 * A value of 2 allows a burst of up to 2 seconds' worth of tokens when a
 * policy is first installed or after a quiet period, then converges to
 * exactly rate_pps packets/second once the bucket is depleted.
 */
#define L3_TOKEN_BURST_FACTOR  2


/* =========================================================================
 * ACTION ENUM
 * ========================================================================= */

typedef enum {
    L3_ACTION_ALLOW           = 0,  /* pass all packets — no restriction      */
    L3_ACTION_RATE_LIMIT_SOFT = 1,  /* token-bucket soft ceiling (rate_pps)   */
    L3_ACTION_RATE_LIMIT_HARD = 2,  /* token-bucket hard ceiling (rate_pps)   */
    L3_ACTION_BLOCK           = 3,  /* drop all packets from (src_ip, dst_ip) */
} l3_action_t;


/* =========================================================================
 * PUBLIC API
 * ========================================================================= */

/*
 * l3_policy_init
 *
 * Initialise the policy subsystem: zero-fill both table buffers and reset
 * the active-index to 0.  Call once at process startup before any other
 * l3_policy_* function.
 */
void l3_policy_init(void);

/*
 * l3_policy_reload
 *
 * Replace the policy table from L3_POLICY_FILE_PATH.
 *
 * Algorithm:
 *   1. Clear the inactive (staging) buffer.
 *   2. Open and parse the policy file line by line.
 *   3. Insert each valid entry into the staging buffer.
 *   4. Atomically flip the active-buffer index so hot-path readers
 *      immediately start using the new table.
 *
 * If the file cannot be opened, the staging buffer is activated as-is
 * (empty), causing all packets to be passed — fail-open is the safe
 * default.
 *
 * Call from the slow path (timer callback) approximately once per second.
 * Never call from the packet-forwarding hot path.
 */
void l3_policy_reload(void);

/*
 * l3_policy_expire_tick
 *
 * Per-second maintenance tick.  Walks the active table and:
 *   - Decrements ttl_sec on every valid entry.
 *   - Marks entries whose TTL reaches zero as tombstones (removed from
 *     future lookups).
 *   - Refills token buckets for RATE_LIMIT_* entries by rate_pps tokens,
 *     capped at max_tokens.
 *
 * Purpose: safety net.  If the Python engine stops writing the policy file
 * (e.g., crash), TTL expiry here ensures stale BLOCK or RATE_LIMIT entries
 * are automatically removed within their configured TTL rather than
 * persisting indefinitely.
 *
 * Call from the same timer callback as l3_policy_reload(), once per second,
 * after reload() so it operates on the freshly-built table.
 */
void l3_policy_expire_tick(void);

/*
 * l3_policy_check
 *
 * Hot-path per-packet enforcement.
 *
 *   src_ip, dst_ip : source and destination IP in HOST byte order.
 *
 *   Returns: true  — forward the packet
 *                    (no entry, L3_ACTION_ALLOW, or rate-limit token available)
 *            false — drop the packet
 *                    (L3_ACTION_BLOCK, or rate-limit token bucket exhausted)
 *
 * When L3_POLICY_ENFORCE == 0 (shadow mode): always returns true.
 * When L3_POLICY_ENFORCE == 1 (enforce mode): applies the matched action.
 *
 * Lock-free.  Safe to call concurrently from multiple forwarding lcores.
 */
bool l3_policy_check(uint32_t src_ip, uint32_t dst_ip);

/*
 * l3_policy_clear
 *
 * Remove all entries from the active table by zeroing it.
 * Intended for graceful shutdown and unit tests.
 * Do not call while forwarding lcores are running.
 */
void l3_policy_clear(void);


#endif /* __L2FWD_POLICY_H__ */
