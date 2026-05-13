#ifndef __L2FWD_SERVICE_HOTPATH_H__
#define __L2FWD_SERVICE_HOTPATH_H__

/**
 * @file   l2fwd_service_hotpath.h
 * @brief  Per-service packet hot path — P7 of the big-bang refactor.
 *
 * After P7 this module owns:
 *   - Per-packet classification (IPv4 → TCP/UDP/ICMP/OTHER).
 *   - Three-tier registry lookup:
 *       Tier 1 — exact (target_ip, port, proto)
 *       Tier 2 — per-protocol catchall (target_ip, *, proto)
 *       Tier 3 — OTHER catchall (target_ip, *, *)
 *   - Inbound vs outbound classification via the registry's protected_ips
 *     set, then incrementing the matching service_stats slot.
 *   - Per-1Hz tick emission to the Unix socket and per-window counter
 *     reset.
 *
 * The legacy per-IP collector / detection / temporal stack has been
 * retired at P7 — its source files are under legacy/. P7 ships RAW
 * COUNTERS ONLY; feature extraction is P8 and detection scoring is P9.
 *
 * Concurrency note: the per-slot counter increments use plain ++ on
 * uint64_t fields. This is SAFE only as long as no two lcores ever write
 * to the same slot concurrently. With one RX queue per port and DPDK's
 * one-lcore-per-port assignment that condition holds. If the engine ever
 * grows multi-queue or multi-lcore-per-port RX, P8 will introduce
 * per-lcore stats arrays + a fold-on-tick step.
 */

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

/* Forward declarations — header is decoupled from DPDK and the data
 * model. The .c file pulls in the full definitions. */
struct rte_mbuf;
struct service_registry;
struct service_stats_array;
struct service_stats;

/* -------------------------------------------------------------------------
 * Three-tier lookup result
 * ------------------------------------------------------------------------- */
struct service_hotpath_lookup_result {
    struct service_stats *slot;   /**< NULL if no match (non-protected IP)        */
    int                   tier;   /**< 1 exact / 2 per-proto / 3 OTHER / 0 miss   */
    bool                  off_proto; /**< slot is OTHER catchall but pkt is T/U/I */
};

/* -------------------------------------------------------------------------
 * Lifecycle
 * ------------------------------------------------------------------------- */

/**
 * One-time hot-path init. Caches the registry and stats array pointers
 * for fast lookup. Opens a non-blocking Unix-stream socket to the Python
 * collector (best-effort — failure is logged but non-fatal).
 *
 * Must be called AFTER service_registry_set_global() and AFTER
 * service_stats_array_init() in main.c, but BEFORE the packet loop starts.
 *
 * Returns 0 on success, negative on NULL args.
 */
int service_hotpath_init(struct service_registry    *reg,
                         struct service_stats_array *arr);

/**
 * Tear down the hot path. Closes the stats socket and clears cached
 * pointers. Idempotent.
 */
void service_hotpath_destroy(void);

/* -------------------------------------------------------------------------
 * Hot-path entrypoints — called from l2fwd_main_loop()
 * ------------------------------------------------------------------------- */

/**
 * Process one packet through the per-service hot path.
 *
 * Parses Ethernet → IPv4 → L4 headers from the mbuf, classifies direction
 * (inbound if dst_ip is protected, outbound if src_ip is, otherwise
 * dropped), performs the three-tier lookup, and increments per-service
 * counters.
 *
 * @return  0 if the packet was accounted; -1 if dropped (non-IPv4, no
 *          protected IP on either side, or lookup miss).
 */
int service_hotpath_process_packet(struct rte_mbuf *m, unsigned int port_id);

/**
 * Per-1Hz tick. Called from the main-lcore timer block in
 * l2fwd_main_loop() at the spot the legacy ddos_log_and_reset_stats()
 * used to occupy.
 *
 *   1. Emit one debug line per active slot to the Unix socket
 *      (key=value text; the binary protocol arrives in P10).
 *   2. Reset per-window counters on all active slots via
 *      service_stats_reset_window_all().
 */
void service_hotpath_tick(void);

/* -------------------------------------------------------------------------
 * Diagnostics
 * ------------------------------------------------------------------------- */
struct service_hotpath_diag {
    uint64_t pkts_processed;
    uint64_t pkts_dropped_non_protected;
    uint64_t lookups_tier1_exact;
    uint64_t lookups_tier2_per_proto_catchall;
    uint64_t lookups_tier3_other_catchall;
    uint64_t lookups_miss;
    uint64_t off_proto_counts;
};

void service_hotpath_get_diag(struct service_hotpath_diag *out);

#endif /* __L2FWD_SERVICE_HOTPATH_H__ */
