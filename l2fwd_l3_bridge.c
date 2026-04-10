/*
 * l2fwd_l3_bridge.c — Layer 3 V1 per-packet collection bridge (C side)
 *
 * See l2fwd_l3_bridge.h for the full design description.
 *
 * CONCURRENCY SUMMARY
 *   Hot-path operations (collect_src_packet, is_under_attack) are lock-free
 *   and use GCC __atomic_* built-ins with RELAXED ordering for counters and
 *   ACQUIRE/RELEASE ordering for slot ownership (src_ip / dst_ip fields).
 *
 *   Slow-path operations (set_attack_state, export_and_reset) run on the
 *   single timer lcore and never race with each other.  They race only with
 *   the hot path on the counter fields, which is acceptable for a monitoring
 *   bridge: slight over/under-counting across a window boundary is harmless.
 *
 * RESET PROTOCOL (export_and_reset)
 *   1. Zero all counters first (RELAXED stores).
 *   2. Zero src_ip last (RELEASE store) — makes the slot appear empty to the
 *      hot path.  A forwarding lcore that races between step 1 and step 2
 *      increments a counter that is immediately zeroed; those few packets are
 *      lost from this window.  The Python scorer tolerates gaps in monitoring.
 */

#include "l2fwd_l3_bridge.h"

#include <string.h>
#include <stdio.h>
#include <inttypes.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>
#include <errno.h>


/* =========================================================================
 * Internal constants
 * ========================================================================= */

/* Hash table mask — works because MAX_SOURCES_PER_VICTIM is a power of two */
#define SRC_TABLE_MASK  ((uint32_t)(L3_BRIDGE_MAX_SOURCES_PER_VICTIM - 1))

/*
 * Number of uint64_t words in each approximate-unique bitmap.
 * words × 64 = number of distinct bit positions.
 *   8 words → 512 positions
 *   dst_port is mapped by:  dst_port % 512
 *   flow key is mapped by:  (src_port ^ dst_port) % 512
 *
 * Collisions mean popcount slightly underestimates unique counts, which is
 * acceptable — Python scoring already treats these as heuristics.
 */
#define PORT_BITMAP_WORDS  8u
#define FLOW_BITMAP_WORDS  8u


/* =========================================================================
 * Data structures (all statically allocated — no heap in hot path)
 * ========================================================================= */

/*
 * One row in the per-victim source hash table.
 *
 * src_ip == 0 means the slot is empty.  Ownership of a slot is claimed by
 * a CAS on src_ip (0 → actual IP) with RELEASE ordering so that counters
 * written before the RELEASE are visible to other lcores that load src_ip
 * with ACQUIRE.
 *
 * Layout note: src_ip is first and uint32_t so the struct starts on a
 * 4-byte boundary; the compiler pads 4 bytes before the first uint64_t
 * counter so all 8-byte fields are naturally aligned for lock-free atomics.
 */
typedef struct {
    uint32_t src_ip;           /* host byte order; 0 = empty slot           */
    uint32_t _pad;             /* explicit align padding                     */

    uint64_t pkt_count;        /* total packets from src_ip this window      */
    uint64_t byte_count;       /* total bytes  from src_ip this window       */

    uint32_t tcp_pkts;         /* packets carrying a TCP segment             */
    uint32_t syn_pkts;         /* packets with TCP SYN flag                  */
    uint32_t rst_pkts;         /* packets with TCP RST flag                  */
    uint32_t ack_only_pkts;    /* ACK-only (no data, no SYN/RST)            */
    uint32_t _pad2;            /* align next uint64_t[] to 8 bytes           */
    uint32_t _pad3;

    /*
     * Approximate unique-count bitmaps.
     * Bit i is set when a packet arrives with:
     *   dst_port_bitmap : dst_port % (PORT_BITMAP_WORDS * 64) == i
     *   flow_bitmap     : (src_port ^ dst_port) % (FLOW_BITMAP_WORDS * 64) == i
     * popcount at export time gives an approximation of unique ports/flows.
     */
    uint64_t dst_port_bitmap[PORT_BITMAP_WORDS];
    uint64_t flow_bitmap[FLOW_BITMAP_WORDS];
} bridge_src_entry_t;


/*
 * One entry in the victim table.
 *
 * dst_ip == 0 means the slot is unused.  under_attack drives hot-path
 * gating: collect_src_packet() bails out immediately if it is zero.
 *
 * Metadata fields (det_state, attack_type, window_ms, totals) are written
 * exclusively by set_attack_state() on the timer lcore and read by
 * export_and_reset() on the same lcore — no races on those fields.
 */
typedef struct {
    uint32_t dst_ip;                         /* host byte order; 0 = unused  */
    uint8_t  under_attack;                   /* 0 or 1, atomic               */
    uint8_t  _pad[3];

    char     det_state[16];                  /* "WARMUP"|"NORMAL"|...        */
    char     attack_type[32];                /* "SYN_FLOOD"|""| ...          */

    uint64_t window_ms;                      /* epoch ms for current window  */
    uint64_t total_pkts;                     /* L2 victim total, this window */
    uint64_t total_bytes;

    bridge_src_entry_t sources[L3_BRIDGE_MAX_SOURCES_PER_VICTIM];
} bridge_victim_entry_t;


/* =========================================================================
 * Global state
 * ========================================================================= */

static bridge_victim_entry_t g_victims[L3_BRIDGE_MAX_VICTIMS];
static int g_sock_fd = -1;   /* UNIX stream socket fd, -1 = disconnected */


/* =========================================================================
 * Helper: IP address formatting (host byte order → dotted-decimal string)
 * ========================================================================= */

static void ip_to_str(uint32_t host_ip, char *buf, size_t len)
{
    uint32_t net = htonl(host_ip);
    inet_ntop(AF_INET, &net, buf, (socklen_t)len);
}


/* =========================================================================
 * Helper: popcount over a uint64_t bitmap array
 *
 * Loads each word with RELAXED ordering (acceptable: we're taking a
 * best-effort snapshot of an approximate counter).
 * ========================================================================= */

static uint32_t popcount_words(const uint64_t *words, uint32_t n)
{
    uint32_t total = 0;
    for (uint32_t i = 0; i < n; i++) {
        uint64_t w = __atomic_load_n(&words[i], __ATOMIC_RELAXED);
        total += (uint32_t)__builtin_popcountll(w);
    }
    return total;
}


/* =========================================================================
 * Source table: hash function
 *
 * Knuth multiplicative hash, masked to table size.
 * ========================================================================= */

static uint32_t src_hash(uint32_t src_ip)
{
    return (src_ip * 2654435761u) & SRC_TABLE_MASK;
}


/* =========================================================================
 * Source table: find-or-create (lock-free, hot-path safe)
 *
 * Algorithm:
 *   1. Hash src_ip to a start index.
 *   2. Linear probe: if we find a slot whose src_ip matches, return it.
 *   3. If we find an empty slot (src_ip == 0), attempt a CAS to claim it.
 *      On success: the slot belongs to src_ip, return it.
 *      On failure: another lcore claimed it first; check if it's ours or
 *                  continue probing.
 *
 * Multiple lcores may race to create a slot for the same src_ip.  In the
 * rare case that two lcores both pass the "no existing slot" check before
 * either writes, two slots end up tracking the same src_ip.  Python sees
 * two src_snapshot records with the same src_ip and sums them — harmless.
 *
 * Returns NULL if the table is full (caller silently skips collection).
 * ========================================================================= */

static bridge_src_entry_t *src_find_or_create(bridge_victim_entry_t *v,
                                              uint32_t src_ip)
{
    uint32_t start = src_hash(src_ip);

    /*
     * Pass 1: scan for an existing slot for src_ip.
     * Stop at the first empty slot — can't probe past a gap in linear
     * probing without full-table fallback (handled in pass 2).
     */
    for (uint32_t i = 0; i < L3_BRIDGE_MAX_SOURCES_PER_VICTIM; i++) {
        uint32_t idx = (start + i) & SRC_TABLE_MASK;
        bridge_src_entry_t *s = &v->sources[idx];
        uint32_t cur = __atomic_load_n(&s->src_ip, __ATOMIC_ACQUIRE);
        if (cur == src_ip)
            return s;
        if (cur == 0)
            break;   /* empty slot found — try to claim it in pass 2 */
    }

    /*
     * Pass 2: claim an empty slot via CAS.
     * A full scan is needed because a slot vacated between pass 1 and
     * pass 2 may not be at the same position.
     */
    for (uint32_t i = 0; i < L3_BRIDGE_MAX_SOURCES_PER_VICTIM; i++) {
        uint32_t idx = (start + i) & SRC_TABLE_MASK;
        bridge_src_entry_t *s = &v->sources[idx];
        uint32_t expected = 0;

        if (__atomic_compare_exchange_n(&s->src_ip, &expected, src_ip,
                                        /*weak=*/false,
                                        __ATOMIC_RELEASE,
                                        __ATOMIC_RELAXED)) {
            /* CAS succeeded: this slot is ours */
            return s;
        }

        /*
         * CAS failed.  Another lcore wrote src_ip here (our IP or a
         * different one).  Re-load and check.
         */
        uint32_t cur = __atomic_load_n(&s->src_ip, __ATOMIC_ACQUIRE);
        if (cur == src_ip)
            return s;   /* another lcore created our slot — use it */
        /* Different src_ip: continue probing */
    }

    return NULL;   /* table full — caller skips tracking for this source */
}


/* =========================================================================
 * Socket helpers (timer path only — never called from forwarding lcores)
 * ========================================================================= */

static void sock_disconnect(void)
{
    if (g_sock_fd >= 0) {
        close(g_sock_fd);
        g_sock_fd = -1;
    }
}

static bool sock_connect(void)
{
    g_sock_fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (g_sock_fd < 0)
        return false;

    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, L3_BRIDGE_SOCKET_PATH,
            sizeof(addr.sun_path) - 1);

    if (connect(g_sock_fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        sock_disconnect();
        return false;
    }
    return true;
}

/*
 * Write a NUL-terminated line (including its '\n') to the socket.
 * Returns false and disconnects on any send error.
 */
static bool sock_send_line(const char *line)
{
    size_t  len = strlen(line);
    ssize_t n   = send(g_sock_fd, line, len, MSG_NOSIGNAL);
    if (n < 0 || (size_t)n != len) {
        sock_disconnect();
        return false;
    }
    return true;
}


/* =========================================================================
 * JSON emission helpers (timer path only)
 * ========================================================================= */

/*
 * Emit one src_snapshot record for source slot s attacking victim at dst_str.
 * Returns false on socket error.
 */
static bool emit_src_snapshot(const char           *dst_str,
                               const char           *src_str,
                               uint64_t              window_ms,
                               const bridge_src_entry_t *s)
{
    uint32_t u_dst_ports = popcount_words(s->dst_port_bitmap, PORT_BITMAP_WORDS);
    uint32_t u_flows     = popcount_words(s->flow_bitmap,     FLOW_BITMAP_WORDS);

    /*
     * duration_sec: one window ≈ 1 second.  We use a fixed value rather
     * than a per-source timestamp to avoid adding TSC reads to the hot path.
     * Python scoring normalises by this value; 1.0 is the correct denominator
     * for a 1-second collection window.
     */
    const double duration_sec = 1.0;

    char buf[512];
    int n = snprintf(buf, sizeof(buf),
        "{\"type\":\"src_snapshot\","
        "\"dst_ip\":\"%s\","
        "\"src_ip\":\"%s\","
        "\"window_ms\":%" PRIu64 ","
        "\"pkt_count\":%" PRIu64 ","
        "\"byte_count\":%" PRIu64 ","
        "\"tcp_pkts\":%" PRIu32 ","
        "\"syn_pkts\":%" PRIu32 ","
        "\"rst_pkts\":%" PRIu32 ","
        "\"ack_only_pkts\":%" PRIu32 ","
        "\"unique_dst_ports\":%" PRIu32 ","
        "\"unique_flows\":%" PRIu32 ","
        "\"duration_sec\":%.3f}\n",
        dst_str, src_str, window_ms,
        __atomic_load_n(&s->pkt_count,     __ATOMIC_RELAXED),
        __atomic_load_n(&s->byte_count,    __ATOMIC_RELAXED),
        __atomic_load_n(&s->tcp_pkts,      __ATOMIC_RELAXED),
        __atomic_load_n(&s->syn_pkts,      __ATOMIC_RELAXED),
        __atomic_load_n(&s->rst_pkts,      __ATOMIC_RELAXED),
        __atomic_load_n(&s->ack_only_pkts, __ATOMIC_RELAXED),
        u_dst_ports, u_flows, duration_sec);

    if (n <= 0 || (size_t)n >= sizeof(buf))
        return true;   /* malformed line: skip, don't abort the window */

    return sock_send_line(buf);
}

/*
 * Emit one window_end record for victim v.
 * Returns false on socket error.
 */
static bool emit_window_end(const char *dst_str, const bridge_victim_entry_t *v)
{
    char buf[256];
    int n = snprintf(buf, sizeof(buf),
        "{\"type\":\"window_end\","
        "\"dst_ip\":\"%s\","
        "\"det_state\":\"%s\","
        "\"attack_type\":\"%s\","
        "\"window_ms\":%" PRIu64 ","
        "\"victim_total_pkts\":%" PRIu64 ","
        "\"victim_total_bytes\":%" PRIu64 "}\n",
        dst_str,
        v->det_state,
        v->attack_type,
        v->window_ms,
        v->total_pkts,
        v->total_bytes);

    if (n <= 0 || (size_t)n >= sizeof(buf))
        return true;

    return sock_send_line(buf);
}


/* =========================================================================
 * Source slot reset (timer path — called after export, before next window)
 *
 * Zeroes all counter fields with RELAXED stores, then clears src_ip with a
 * RELEASE store so the hot path sees the slot as empty.
 *
 * A forwarding lcore that races between the counter zeroing and the src_ip
 * RELEASE will increment counters that are immediately zeroed — those few
 * packets are lost from this window.  The Python scorer tolerates sparse
 * data within a window.
 * ========================================================================= */

static void src_reset_slot(bridge_src_entry_t *s)
{
    __atomic_store_n(&s->pkt_count,     0, __ATOMIC_RELAXED);
    __atomic_store_n(&s->byte_count,    0, __ATOMIC_RELAXED);
    __atomic_store_n(&s->tcp_pkts,      0, __ATOMIC_RELAXED);
    __atomic_store_n(&s->syn_pkts,      0, __ATOMIC_RELAXED);
    __atomic_store_n(&s->rst_pkts,      0, __ATOMIC_RELAXED);
    __atomic_store_n(&s->ack_only_pkts, 0, __ATOMIC_RELAXED);

    for (uint32_t j = 0; j < PORT_BITMAP_WORDS; j++)
        __atomic_store_n(&s->dst_port_bitmap[j], 0, __ATOMIC_RELAXED);
    for (uint32_t j = 0; j < FLOW_BITMAP_WORDS; j++)
        __atomic_store_n(&s->flow_bitmap[j], 0, __ATOMIC_RELAXED);

    /* Release: makes slot appear empty to the hot path */
    __atomic_store_n(&s->src_ip, 0u, __ATOMIC_RELEASE);
}


/* =========================================================================
 * Public API implementation
 * ========================================================================= */

void l3_bridge_init(void)
{
    memset(g_victims, 0, sizeof(g_victims));
    g_sock_fd = -1;
}


void l3_bridge_set_attack_state(uint32_t    dst_ip,
                                bool        under_attack,
                                const char *det_state,
                                const char *attack_type,
                                uint64_t    window_ms,
                                uint64_t    total_pkts,
                                uint64_t    total_bytes)
{
    bridge_victim_entry_t *victim = NULL;
    bridge_victim_entry_t *empty  = NULL;

    /* Linear scan: find existing slot or the first empty one */
    for (int i = 0; i < L3_BRIDGE_MAX_VICTIMS; i++) {
        uint32_t ip = __atomic_load_n(&g_victims[i].dst_ip, __ATOMIC_ACQUIRE);
        if (ip == dst_ip) {
            victim = &g_victims[i];
            break;
        }
        if (ip == 0 && empty == NULL)
            empty = &g_victims[i];
    }

    if (victim == NULL) {
        /* Victim not tracked yet */
        if (!under_attack || empty == NULL)
            return;   /* not attacking, or victim table full — nothing to do */

        /* Claim the empty slot (timer lcore only: no CAS needed here) */
        victim = empty;
        __atomic_store_n(&victim->dst_ip, dst_ip, __ATOMIC_RELEASE);
    }

    /* Update slow-path metadata (timer lcore only — no races on these) */
    strncpy(victim->det_state,   det_state,   sizeof(victim->det_state)   - 1);
    strncpy(victim->attack_type, attack_type, sizeof(victim->attack_type) - 1);
    victim->det_state  [sizeof(victim->det_state)   - 1] = '\0';
    victim->attack_type[sizeof(victim->attack_type) - 1] = '\0';
    victim->window_ms   = window_ms;
    victim->total_pkts  = total_pkts;
    victim->total_bytes = total_bytes;

    /*
     * under_attack is read by hot-path lcores: use a RELEASE store so that
     * all the metadata writes above are visible before the flag flip.
     */
    __atomic_store_n(&victim->under_attack,
                     (uint8_t)(under_attack ? 1 : 0),
                     __ATOMIC_RELEASE);
}


bool l3_bridge_is_under_attack(uint32_t dst_ip)
{
    for (int i = 0; i < L3_BRIDGE_MAX_VICTIMS; i++) {
        uint32_t ip = __atomic_load_n(&g_victims[i].dst_ip, __ATOMIC_ACQUIRE);
        if (ip == dst_ip) {
            return __atomic_load_n(&g_victims[i].under_attack,
                                   __ATOMIC_RELAXED) != 0;
        }
    }
    return false;
}


void l3_bridge_collect_src_packet(uint32_t dst_ip,
                                  uint32_t src_ip,
                                  uint16_t dst_port,
                                  uint16_t src_port,
                                  uint32_t pkt_len,
                                  uint32_t pkt_flags)
{
    if (src_ip == 0)
        return;

    /* Locate the victim slot; bail out if not found or not under attack */
    bridge_victim_entry_t *victim = NULL;
    for (int i = 0; i < L3_BRIDGE_MAX_VICTIMS; i++) {
        uint32_t ip = __atomic_load_n(&g_victims[i].dst_ip, __ATOMIC_ACQUIRE);
        if (ip == dst_ip) {
            if (__atomic_load_n(&g_victims[i].under_attack,
                                __ATOMIC_RELAXED) != 0)
                victim = &g_victims[i];
            break;
        }
    }
    if (victim == NULL)
        return;

    /* Find or create the per-source slot */
    bridge_src_entry_t *s = src_find_or_create(victim, src_ip);
    if (s == NULL)
        return;   /* source table full — silently skip (packet still forwarded) */

    /* Atomic counter increments — safe across concurrent forwarding lcores */
    __atomic_fetch_add(&s->pkt_count,  (uint64_t)1,      __ATOMIC_RELAXED);
    __atomic_fetch_add(&s->byte_count, (uint64_t)pkt_len, __ATOMIC_RELAXED);

    if (pkt_flags & L3_BRIDGE_PKT_TCP)
        __atomic_fetch_add(&s->tcp_pkts,      1u, __ATOMIC_RELAXED);
    if (pkt_flags & L3_BRIDGE_PKT_SYN)
        __atomic_fetch_add(&s->syn_pkts,      1u, __ATOMIC_RELAXED);
    if (pkt_flags & L3_BRIDGE_PKT_RST)
        __atomic_fetch_add(&s->rst_pkts,      1u, __ATOMIC_RELAXED);
    if (pkt_flags & L3_BRIDGE_PKT_ACK_ONLY)
        __atomic_fetch_add(&s->ack_only_pkts, 1u, __ATOMIC_RELAXED);

    /*
     * Bitmap updates for approximate unique port / flow tracking.
     * Each sets one bit determined by a modulo-reduced index.
     * popcount at export time gives the cardinality estimate.
     */
    {
        uint32_t port_pos  = (uint32_t)dst_port % (PORT_BITMAP_WORDS * 64u);
        uint32_t port_word = port_pos / 64u;
        uint64_t port_mask = UINT64_C(1) << (port_pos % 64u);
        __atomic_fetch_or(&s->dst_port_bitmap[port_word], port_mask,
                          __ATOMIC_RELAXED);
    }
    {
        uint32_t flow_pos  = ((uint32_t)src_port ^ (uint32_t)dst_port)
                             % (FLOW_BITMAP_WORDS * 64u);
        uint32_t flow_word = flow_pos / 64u;
        uint64_t flow_mask = UINT64_C(1) << (flow_pos % 64u);
        __atomic_fetch_or(&s->flow_bitmap[flow_word], flow_mask,
                          __ATOMIC_RELAXED);
    }
}


void l3_bridge_export_and_reset(void)
{
    /* Connect to the Python listener if not already connected */
    if (g_sock_fd < 0) {
        if (!sock_connect())
            return;   /* listener not up yet — skip this tick, retry next */
    }

    char dst_str[INET_ADDRSTRLEN];
    char src_str[INET_ADDRSTRLEN];

    for (int vi = 0; vi < L3_BRIDGE_MAX_VICTIMS; vi++) {
        bridge_victim_entry_t *v = &g_victims[vi];

        uint32_t dst_ip = __atomic_load_n(&v->dst_ip, __ATOMIC_ACQUIRE);
        if (dst_ip == 0)
            continue;

        ip_to_str(dst_ip, dst_str, sizeof(dst_str));

        /*
         * Emit one src_snapshot per non-empty, non-idle source slot.
         * Slots are checked in hash-table order; gaps (src_ip == 0) are skipped.
         */
        for (int si = 0; si < L3_BRIDGE_MAX_SOURCES_PER_VICTIM; si++) {
            bridge_src_entry_t *s = &v->sources[si];

            uint32_t s_ip = __atomic_load_n(&s->src_ip, __ATOMIC_ACQUIRE);
            if (s_ip == 0)
                continue;

            /* Skip slots claimed but not yet written (race during hot path) */
            if (__atomic_load_n(&s->pkt_count, __ATOMIC_RELAXED) == 0)
                continue;

            ip_to_str(s_ip, src_str, sizeof(src_str));

            if (!emit_src_snapshot(dst_str, src_str, v->window_ms, s)) {
                /*
                 * Socket error mid-export.  Give up for this tick.
                 * src counters are NOT reset: we'll try again next second
                 * with accumulated data (slightly stale window_ms, but
                 * Python timestamps from window_ms anyway).
                 */
                return;
            }
        }

        /* window_end must follow all src_snapshots for this victim */
        if (!emit_window_end(dst_str, v))
            return;

        /* Reset all source slots for the next window */
        for (int si = 0; si < L3_BRIDGE_MAX_SOURCES_PER_VICTIM; si++) {
            bridge_src_entry_t *s = &v->sources[si];
            if (__atomic_load_n(&s->src_ip, __ATOMIC_RELAXED) != 0)
                src_reset_slot(s);
        }

        /*
         * If the victim is no longer under attack, free its slot so it can
         * be reused by a new victim.
         * RELEASE so that a hot-path lcore that races here either:
         *   - finds dst_ip == dst_ip (before our store) and sees under_attack=0
         *     → bails out in collect_src_packet
         *   - finds dst_ip == 0 (after our store) → not tracked, bails out
         */
        if (__atomic_load_n(&v->under_attack, __ATOMIC_RELAXED) == 0) {
            __atomic_store_n(&v->dst_ip, 0u, __ATOMIC_RELEASE);
        }
    }
}
