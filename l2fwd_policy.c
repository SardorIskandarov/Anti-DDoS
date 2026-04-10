/*
 * l2fwd_policy.c — Layer 3 V1 policy enforcement (C enforcement layer)
 *
 * Enforcement-only module.  No detection, no scoring, no decisions.
 * The Python scoring engine makes all policy decisions and writes them to
 * L3_POLICY_FILE_PATH.  This module reads that file, stores entries in a
 * hash table, and enforces them per-packet.
 *
 * ── DESIGN OVERVIEW ────────────────────────────────────────────────────────
 *
 * Hash table
 *   Fixed-size open-addressing table with linear probing.
 *   Key: (src_ip, dst_ip), both in host byte order.
 *   Size: L3_POLICY_TABLE_SIZE (must be power-of-two).
 *   Load factor kept below 50% so amortised lookup is O(1).
 *   Deletions use tombstones (SLOT_DELETED) to preserve probe chains.
 *   Tombstones are reclaimed on every full rebuild (l3_policy_reload).
 *
 * Double-buffered table
 *   Two equal-sized buffers: g_tables[0] and g_tables[1].
 *   g_active_idx (atomic uint32) always points to the buffer currently
 *   being read by the hot path.  l3_policy_reload() builds a fresh table
 *   in the inactive buffer, then atomically flips g_active_idx.  Readers
 *   always see a complete, consistent table — never a half-written one.
 *   The previously-active buffer becomes staging for the next reload.
 *
 * Token bucket (rate limiting)
 *   Each RATE_LIMIT_* entry has a token counter (uint64, 1 token = 1 pkt).
 *   max_tokens = rate_pps × L3_TOKEN_BURST_FACTOR (ceiling).
 *   Refill: expire_tick() adds rate_pps tokens per second, capped at max.
 *   Consume: l3_policy_check() atomically subtracts 1 token; drops if empty.
 *
 * TTL expiry
 *   expire_tick() decrements ttl_sec each second.  When ttl_sec hits zero
 *   the entry is tombstoned.  l3_policy_reload() rebuilds from the current
 *   file, so expired entries (not in the file) are absent after the next
 *   reload anyway.  expire_tick() is a safety net for when Python stops.
 *
 * ── THREAD SAFETY ──────────────────────────────────────────────────────────
 *
 * l3_policy_reload() and l3_policy_expire_tick() are called from the timer
 * callback (single writer, one lcore).  They MUST NOT be called concurrently
 * with each other.
 *
 * l3_policy_check() is called per-packet from forwarding lcores (multiple
 * readers).  It is lock-free:
 *   - The active-buffer index is read with __ATOMIC_ACQUIRE.
 *   - Reload writes to the inactive buffer and flips the index with
 *     __ATOMIC_RELEASE, so no reader ever touches a buffer while it is
 *     being rebuilt.
 *   - expire_tick() modifies the active buffer (state, ttl_sec, tokens).
 *     state and ttl_sec are not read by l3_policy_check() — only action
 *     and tokens matter in the hot path.  tokens is accessed atomically.
 *     A reader that started before a TTL expiry might use an entry for one
 *     more packet after it expires — acceptable for a TTL safety net.
 */

#include <arpa/inet.h>   /* inet_pton, ntohl                                 */
#include <stdio.h>       /* fopen, fgets, fclose                             */
#include <string.h>      /* memset, strcmp                                   */
#include <stdint.h>
#include <stdbool.h>

#include "l2fwd_policy.h"


/* =========================================================================
 * SLOT STATE CONSTANTS
 * ========================================================================= */

#define SLOT_EMPTY    ((uint8_t)0)  /* slot was never used                  */
#define SLOT_VALID    ((uint8_t)1)  /* slot holds an active entry           */
#define SLOT_DELETED  ((uint8_t)2)  /* tombstone: entry removed, probe chain
                                       must step over this slot             */


/* =========================================================================
 * POLICY SLOT (INTERNAL)
 * ========================================================================= */

struct l3_policy_slot {
    uint8_t     state;        /* SLOT_EMPTY / SLOT_VALID / SLOT_DELETED     */
    uint32_t    src_ip;       /* source IP, host byte order                 */
    uint32_t    dst_ip;       /* destination IP, host byte order            */
    l3_action_t action;       /* L3_ACTION_*                                */
    uint16_t    ttl_sec;      /* remaining TTL in whole seconds             */
    uint32_t    rate_pps;     /* token refill rate (packets per second)     */
    uint64_t    tokens;       /* current token count; 1 token = 1 packet    */
    uint64_t    max_tokens;   /* upper bound for token bucket               */
};


/* =========================================================================
 * DOUBLE-BUFFERED TABLE
 * ========================================================================= */

static struct l3_policy_slot g_tables[2][L3_POLICY_TABLE_SIZE];

/*
 * g_active_idx is 0 or 1.
 * Readers load it with __ATOMIC_ACQUIRE.
 * The writer (reload) stores it with __ATOMIC_RELEASE after building the
 * staging buffer, so readers see the completed table immediately.
 */
static volatile uint32_t g_active_idx = 0;


/* =========================================================================
 * HASH FUNCTION
 *
 * Maps (src_ip, dst_ip) → index in [0, L3_POLICY_TABLE_SIZE).
 *
 * The XOR-rotate ensures (A→B) and (B→A) land at different buckets.
 * Knuth's multiplicative constant disperses the bits further.
 * The final mask replaces a modulo because the table size is a power of two.
 * ========================================================================= */

static inline uint32_t
policy_hash(uint32_t src_ip, uint32_t dst_ip)
{
    uint32_t key = src_ip ^ ((dst_ip << 7) | (dst_ip >> 25));
    key *= 2654435761U;   /* Knuth multiplicative hash constant              */
    key ^= key >> 16;
    return key & (uint32_t)(L3_POLICY_TABLE_SIZE - 1);
}


/* =========================================================================
 * slot_find — linear-probe lookup
 *
 * Scans from the hash position forward, skipping SLOT_DELETED tombstones,
 * and returns the first SLOT_VALID entry matching (src_ip, dst_ip).
 *
 * Returns NULL if not found (SLOT_EMPTY encountered) or table fully scanned.
 * ========================================================================= */

static struct l3_policy_slot *
slot_find(struct l3_policy_slot *table, uint32_t src_ip, uint32_t dst_ip)
{
    uint32_t start = policy_hash(src_ip, dst_ip);
    uint32_t i;

    for (i = 0; i < L3_POLICY_TABLE_SIZE; i++) {
        uint32_t idx = (start + i) & (uint32_t)(L3_POLICY_TABLE_SIZE - 1);
        struct l3_policy_slot *s = &table[idx];

        if (s->state == SLOT_EMPTY)
            return NULL;          /* probe chain ends here; key not present */

        if (s->state == SLOT_VALID  &&
            s->src_ip == src_ip    &&
            s->dst_ip == dst_ip)
            return s;             /* found */

        /* SLOT_DELETED: step over and keep probing */
    }

    return NULL;  /* full table scanned; key not present */
}


/* =========================================================================
 * slot_insert — insert or update one entry in a table
 *
 * On insert: fills the earliest available slot (tombstone preferred over
 * empty slot to minimise probe-chain growth).
 *
 * On update (key already present): refreshes action, TTL, rate_pps, and
 * max_tokens.  The token bucket is reset only when rate_pps changes, so
 * a TTL renewal does not cause an unnecessary burst.
 *
 * Returns: true on success, false if the table is completely full
 *          (should never happen if the table is sized > 2× expected entries).
 * ========================================================================= */

static bool
slot_insert(struct l3_policy_slot *table,
            uint32_t src_ip, uint32_t dst_ip,
            l3_action_t action, uint16_t ttl_sec, uint32_t rate_pps)
{
    uint32_t start     = policy_hash(src_ip, dst_ip);
    uint32_t first_del = UINT32_MAX;   /* index of first tombstone seen */
    uint32_t i;

    for (i = 0; i < L3_POLICY_TABLE_SIZE; i++) {
        uint32_t idx = (start + i) & (uint32_t)(L3_POLICY_TABLE_SIZE - 1);
        struct l3_policy_slot *s = &table[idx];

        /* ── Update existing entry ─────────────────────────────────────── */
        if (s->state == SLOT_VALID  &&
            s->src_ip == src_ip    &&
            s->dst_ip == dst_ip) {
            bool rate_changed = (s->rate_pps != rate_pps);
            s->action     = action;
            s->ttl_sec    = ttl_sec;
            s->rate_pps   = rate_pps;
            s->max_tokens = (uint64_t)rate_pps * L3_TOKEN_BURST_FACTOR;
            /*
             * Reset the bucket when the configured rate changes.
             * On a simple TTL renewal (same rate) keep the current token
             * count so there is no burst advantage from frequent renewals.
             */
            if (rate_changed)
                s->tokens = s->max_tokens;
            return true;
        }

        /* ── Record first tombstone ─────────────────────────────────────── */
        if (s->state == SLOT_DELETED) {
            if (first_del == UINT32_MAX)
                first_del = idx;
            continue;
        }

        /* ── Empty slot: insert here (or at the earliest tombstone) ──────── */
        if (s->state == SLOT_EMPTY) {
            if (first_del != UINT32_MAX)
                s = &table[first_del];   /* reclaim tombstone slot */

            s->state      = SLOT_VALID;
            s->src_ip     = src_ip;
            s->dst_ip     = dst_ip;
            s->action     = action;
            s->ttl_sec    = ttl_sec;
            s->rate_pps   = rate_pps;
            s->max_tokens = (uint64_t)rate_pps * L3_TOKEN_BURST_FACTOR;
            s->tokens     = s->max_tokens;  /* start with a full bucket */
            return true;
        }
    }

    /*
     * Entire table traversed without finding an empty slot.
     * If a tombstone was found, recycle it as a last resort.
     */
    if (first_del != UINT32_MAX) {
        struct l3_policy_slot *s = &table[first_del];
        s->state      = SLOT_VALID;
        s->src_ip     = src_ip;
        s->dst_ip     = dst_ip;
        s->action     = action;
        s->ttl_sec    = ttl_sec;
        s->rate_pps   = rate_pps;
        s->max_tokens = (uint64_t)rate_pps * L3_TOKEN_BURST_FACTOR;
        s->tokens     = s->max_tokens;
        return true;
    }

    return false;   /* table is 100% full — should not happen in practice */
}


/* =========================================================================
 * PUBLIC: l3_policy_init
 * ========================================================================= */

void l3_policy_init(void)
{
    memset(g_tables, 0, sizeof(g_tables));
    __atomic_store_n(&g_active_idx, 0, __ATOMIC_RELEASE);
}


/* =========================================================================
 * PUBLIC: l3_policy_reload
 * ========================================================================= */

void l3_policy_reload(void)
{
    /*
     * Identify the staging buffer (the one NOT currently in use by readers).
     * XOR with 1 flips between 0 and 1.
     */
    uint32_t staging = __atomic_load_n(&g_active_idx, __ATOMIC_ACQUIRE) ^ 1;
    struct l3_policy_slot *table = g_tables[staging];
    FILE *fp;
    char  line[256];

    /* Zero the staging buffer — no tombstones, no stale entries. */
    memset(table, 0, L3_POLICY_TABLE_SIZE * sizeof(*table));

    fp = fopen(L3_POLICY_FILE_PATH, "r");
    if (!fp) {
        /*
         * Policy file absent or unreadable.
         * Activate the empty staging buffer so no stale policies remain.
         * Default action for every packet will be ALLOW (pass-through).
         * Fail-open is safe: it is better to allow traffic than to drop
         * legitimate packets because the control plane is temporarily down.
         */
        __atomic_store_n(&g_active_idx, staging, __ATOMIC_RELEASE);
        return;
    }

    while (fgets(line, (int)sizeof(line), fp)) {

        char     action_str[32];
        char     src_str[INET_ADDRSTRLEN];   /* max 15 chars + '\0' */
        char     dst_str[INET_ADDRSTRLEN];
        unsigned ttl_raw, rate_raw;
        struct   in_addr src_in, dst_in;
        l3_action_t action;

        /* Skip blank lines and comment lines. */
        if (line[0] == '\n' || line[0] == '\r' || line[0] == '#')
            continue;

        /*
         * Parse: ACTION SRC_IP DST_IP TTL RATE_PPS
         *
         * sscanf field widths match the buffer sizes above minus 1 for '\0'.
         * A line that does not provide exactly 5 fields is silently skipped.
         */
        if (sscanf(line, "%31s %15s %15s %u %u",
                   action_str, src_str, dst_str, &ttl_raw, &rate_raw) != 5)
            continue;

        /* TTL must be at least 1 second and fit in uint16_t. */
        if (ttl_raw == 0 || ttl_raw > 65535)
            continue;

        /* Map action string to enum.  Unknown strings are skipped. */
        if      (strcmp(action_str, "BLOCK")           == 0)
            action = L3_ACTION_BLOCK;
        else if (strcmp(action_str, "RATE_LIMIT_HARD") == 0)
            action = L3_ACTION_RATE_LIMIT_HARD;
        else if (strcmp(action_str, "RATE_LIMIT_SOFT") == 0)
            action = L3_ACTION_RATE_LIMIT_SOFT;
        else
            /*
             * ALLOW and any unrecognised string: skip.
             * ALLOW is the implicit default; there is no benefit to
             * storing it in the table.
             */
            continue;

        /* Parse IPv4 addresses.  inet_pton writes network byte order. */
        if (inet_pton(AF_INET, src_str, &src_in) != 1) continue;
        if (inet_pton(AF_INET, dst_str, &dst_in) != 1) continue;

        /*
         * Convert to host byte order for uniform internal representation.
         * All comparisons inside the table (slot_find, slot_insert) use
         * host byte order exclusively.
         */
        slot_insert(table,
                    ntohl(src_in.s_addr),
                    ntohl(dst_in.s_addr),
                    action,
                    (uint16_t)ttl_raw,
                    (uint32_t)rate_raw);
    }

    fclose(fp);

    /*
     * The staging buffer is fully built.  Flip g_active_idx so forwarding
     * lcores immediately start reading from the new table.
     *
     * __ATOMIC_RELEASE pairs with the __ATOMIC_ACQUIRE in l3_policy_check()
     * to guarantee all writes to g_tables[staging] are visible to readers
     * after they observe the new index value.
     */
    __atomic_store_n(&g_active_idx, staging, __ATOMIC_RELEASE);
}


/* =========================================================================
 * PUBLIC: l3_policy_expire_tick
 * ========================================================================= */

void l3_policy_expire_tick(void)
{
    uint32_t active = __atomic_load_n(&g_active_idx, __ATOMIC_ACQUIRE);
    struct l3_policy_slot *table = g_tables[active];
    uint32_t i;

    for (i = 0; i < L3_POLICY_TABLE_SIZE; i++) {
        struct l3_policy_slot *s = &table[i];

        if (s->state != SLOT_VALID)
            continue;

        /* ── TTL countdown ──────────────────────────────────────────────── */
        if (s->ttl_sec > 0)
            s->ttl_sec--;

        if (s->ttl_sec == 0) {
            /*
             * Entry expired.  Mark as tombstone rather than SLOT_EMPTY so
             * probe chains that pass through this slot remain intact.
             * The slot is reclaimed on the next l3_policy_reload() which
             * starts from a fully-zeroed staging buffer.
             */
            s->state = SLOT_DELETED;
            continue;
        }

        /* ── Token bucket refill ────────────────────────────────────────── */
        /*
         * Add rate_pps tokens and cap at max_tokens.
         *
         * We use atomic load/store rather than a plain increment because
         * l3_policy_check() on forwarding lcores atomically decrements the
         * same field.  The load-compute-store sequence here is not strictly
         * atomic (a decrement may be "lost" between our load and store), but
         * the consequence is at most one extra packet passing through — fully
         * acceptable for a rate limiter that is already approximate.
         */
        if (s->action == L3_ACTION_RATE_LIMIT_SOFT ||
            s->action == L3_ACTION_RATE_LIMIT_HARD) {
            uint64_t cur     = __atomic_load_n(&s->tokens, __ATOMIC_RELAXED);
            uint64_t refilled = cur + s->rate_pps;
            if (refilled > s->max_tokens)
                refilled = s->max_tokens;
            __atomic_store_n(&s->tokens, refilled, __ATOMIC_RELAXED);
        }
    }
}


/* =========================================================================
 * PUBLIC: l3_policy_check (hot path)
 * ========================================================================= */

bool l3_policy_check(uint32_t src_ip, uint32_t dst_ip)
{
#if L3_POLICY_ENFORCE == 0

    /*
     * Shadow mode: the table is maintained normally but no packet is ever
     * dropped or rate-limited.  This lets operators verify that the policy
     * engine is producing sensible decisions before enabling enforcement.
     */
    (void)src_ip;
    (void)dst_ip;
    return true;

#else   /* L3_POLICY_ENFORCE == 1 */

    uint32_t active = __atomic_load_n(&g_active_idx, __ATOMIC_ACQUIRE);
    struct l3_policy_slot *s = slot_find(g_tables[active], src_ip, dst_ip);

    if (!s)
        return true;   /* no policy for this (src, dst): default ALLOW */

    switch (s->action) {

    case L3_ACTION_ALLOW:
        /*
         * Explicit ALLOW entries are not stored during reload, so this
         * branch is unreachable in normal operation.  Handled defensively.
         */
        return true;

    case L3_ACTION_BLOCK:
        /*
         * Temporary BLOCK.
         * The Python engine sets a short TTL (config.TTL_DEFAULTS["BLOCK"]
         * = 10 s) and renews it each window only if the suspicious score
         * still warrants it.  If Python stops, expire_tick() removes the
         * entry within ttl_sec seconds — BLOCK is never permanent.
         */
        return false;

    case L3_ACTION_RATE_LIMIT_SOFT:
    case L3_ACTION_RATE_LIMIT_HARD: {
        /*
         * Token bucket enforcement.
         *
         * Atomically subtract one token from the bucket.
         * __atomic_fetch_sub returns the value BEFORE the subtraction.
         *
         * Case 1 — bucket has tokens (prev > 0):
         *     Token consumed.  Forward the packet.
         *
         * Case 2 — bucket is empty (prev == 0):
         *     The subtraction wrapped around to UINT64_MAX.  Restore the
         *     token to keep the counter at 0 (not wrapped), then drop.
         *
         * RELAXED ordering is sufficient here: we only need atomicity of
         * the fetch-sub itself, not ordering relative to other memory ops.
         */
        uint64_t prev = __atomic_fetch_sub(&s->tokens, 1, __ATOMIC_RELAXED);
        if (prev == 0) {
            __atomic_fetch_add(&s->tokens, 1, __ATOMIC_RELAXED);
            return false;  /* bucket exhausted: drop */
        }
        return true;   /* token consumed: forward */
    }

    default:
        return true;   /* unknown action: safe default is to pass */
    }

#endif /* L3_POLICY_ENFORCE */
}


/* =========================================================================
 * PUBLIC: l3_policy_clear
 * ========================================================================= */

void l3_policy_clear(void)
{
    uint32_t active = __atomic_load_n(&g_active_idx, __ATOMIC_ACQUIRE);
    memset(g_tables[active], 0,
           L3_POLICY_TABLE_SIZE * sizeof(g_tables[0][0]));
}
