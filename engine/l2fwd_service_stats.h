#ifndef __L2FWD_SERVICE_STATS_H__
#define __L2FWD_SERVICE_STATS_H__

/**
 * @file   l2fwd_service_stats.h
 * @brief  Per-service runtime stats data model (data plane).
 *
 * POST-CUTOVER (P5): this struct holds ONLY the raw per-window telemetry the C
 * data plane produces — counters + probabilistic sketches (HLL/CM). The
 * derived state that used to live here (per-feature EWMA baselines, burst
 * windows, the heap-allocated detection_state + temporal_state) has moved to
 * the Python detection brain (ddos_monitor/detection); the snapshot producer
 * reads these raw fields + sketch estimates once per 1 Hz tick and ships the
 * scalars over shared memory.
 *
 * Layout principles:
 *   - One service_stats per registry slot (parallel arrays indexed 0..N).
 *   - Inline sub-structs (HLL, CM sketches): no nested heap allocation.
 *   - Discriminated union for protocol-specific stats, gated by proto_kind.
 *   - Zero is a valid initial state for every field, so a single memset()
 *     suffices for the runtime initialisation path (see _init_slot).
 */

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include <time.h>

#include "l2fwd_service_registry.h"   /* service_key_t, service_descriptor */

/* Forward declaration — keep this header decoupled from the profile module.
 * The .c file pulls in the full struct definition. */
struct l2_profile;

/* -------------------------------------------------------------------------
 * 1.1 Probabilistic-sketch primitives
 * ------------------------------------------------------------------------- */

/**
 * HyperLogLog cardinality estimator — 1024 registers, 1 byte per register.
 * Tracks approximate distinct-count of e.g. unique source IPs or flows.
 */
struct service_hll {
    uint8_t registers[1024];
};

/**
 * Count-Min sketch for source-port concentration.
 * Width 256, depth 4 → 4 KB per sketch.
 */
struct service_cm_src_port {
    uint32_t table[4][256];
    uint64_t total;       /**< total events inserted; denominator for ratios */
    uint16_t top_port;    /**< port with highest observed count this window  */
    uint32_t top_count;   /**< its count                                     */
};

/**
 * Count-Min sketch for /24 source-network concentration.
 * Width 512, depth 4 → 8 KB per sketch.
 */
struct service_cm_src_24 {
    uint32_t table[4][512];
    uint64_t total;
    uint32_t top_net24;   /**< /24 prefix (host byte order, low byte zeroed) */
    uint32_t top_count;
};

/* -------------------------------------------------------------------------
 * 1.2 Per-protocol raw counters
 *
 * One struct per protocol family. All scalar counters reset to zero at the
 * end of each 1Hz window (see service_stats_reset_window); the HLL/CM
 * sketches PERSIST across windows by design.
 * ------------------------------------------------------------------------- */

/** TCP raw counters per 1-second window. */
struct service_tcp_stats {
    uint64_t tcp_pkts;
    uint64_t tcp_bytes;
    uint64_t syn_pkts;
    uint64_t syn_ack_pkts;
    uint64_t fin_ack_pkts;
    uint64_t rst_pkts;
    uint64_t ack_data_pkts;
    uint64_t empty_ack_pkts;
    uint64_t zero_window_pkts;
    uint64_t small_window_pkts;
    /* Welford running statistics for TCP packet size (per 1-second window).
     * Maintained by account_inbound_tcp with the Welford online update — no
     * `Σx² − (Σx)²/n` catastrophic cancellation at high Gbps volumes. */
    double   tcp_pkt_size_mean;
    double   tcp_pkt_size_M2;
    struct service_hll          unique_new_flows;
    struct service_cm_src_port  cm_src_port;
};

/** UDP raw counters per 1-second window. */
struct service_udp_stats {
    uint64_t udp_pkts;
    uint64_t udp_bytes;
    /* Welford running statistics for UDP packet size (see TCP note above). */
    double   udp_pkt_size_mean;
    double   udp_pkt_size_M2;
    struct service_hll          udp_flows;
    struct service_cm_src_port  cm_src_port;
};

/** ICMP raw counters per 1-second window. */
struct service_icmp_stats {
    uint64_t icmp_pkts;
    uint64_t icmp_echo_pkts;
    uint64_t icmp_bytes;
};

/**
 * "Other" protocol bucket — for GRE/ESP/IP-in-IP and any other IP proto that
 * lands on the OTHER catchall. proto_counts[N] holds the per-1Hz packet count
 * for IP protocol number N.
 */
struct service_other_stats {
    uint64_t other_pkts;
    uint64_t other_bytes;
    uint64_t proto_counts[256];   /**< per IP proto number */
};

/* -------------------------------------------------------------------------
 * 1.3 Common inbound / outbound stats
 * ------------------------------------------------------------------------- */

/** Common stats every service has — independent of protocol kind. */
struct service_common_stats {
    uint64_t inbound_pkts;
    uint64_t inbound_bytes;
    uint64_t off_proto_pkts;
    /* Welford running statistics for TTL (per 1-second window). The hot path
     * updates these with the Welford online algorithm so the snapshot ships
     * mean/M2 directly — no `Σx² − (Σx)²/n` catastrophic cancellation. */
    double   ttl_mean;
    double   ttl_M2;
    uint64_t ip_frag_pkts;
    struct service_hll          unique_src_ips;
    struct service_hll          unique_flows;
    struct service_cm_src_24    cm_src_24;
};

/** Outbound stats (when this IP is observed as the source). */
struct service_outbound_stats {
    uint64_t out_pkts;
    uint64_t out_bytes;
    uint64_t out_tcp_pkts;
    uint64_t out_udp_pkts;
    uint64_t out_icmp_pkts;
    struct service_hll unique_dst_ips;
    struct service_hll unique_dst_ports;
};

/* -------------------------------------------------------------------------
 * 1.4 service_stats — the main per-slot struct
 *
 * Discriminated union: `proto_kind` selects which arm of the `proto` union is
 * active. Zero is a valid initial state for every arm, so a single memset()
 * inside service_stats_init_slot() correctly initialises ALL variants.
 * ------------------------------------------------------------------------- */
struct service_stats {
    /* Identity (cached at allocation from the registry descriptor). */
    service_key_t            key;
    uint8_t                  proto_kind;     /**< enum service_proto_kind */
    bool                     is_catchall;
    bool                     active;         /**< set true at init        */

    /* Profile pointer (cached at allocation; never owned). */
    const struct l2_profile *profile;

    /* Common inbound stats — always present. */
    struct service_common_stats common;

    /* Protocol-specific raw counters. Discriminator is proto_kind above; the
     * union is anonymous so callers write e.g. slot->proto.tcp.stats.syn_pkts. */
    union {
        struct {
            struct service_tcp_stats stats;
        } tcp;
        struct {
            struct service_udp_stats stats;
        } udp;
        struct {
            struct service_icmp_stats stats;
        } icmp;
        /* OTHER catchall: carries all three protocol arms plus the
         * protocol-number breakdown and a separate dst-port HLL. */
        struct {
            struct service_tcp_stats   tcp_stats;
            struct service_udp_stats   udp_stats;
            struct service_icmp_stats  icmp_stats;
            struct service_other_stats other_stats;
            struct service_hll         unique_dst_ports;
        } other_catchall;
    } proto;

    /* Outbound stats — always present. */
    struct service_outbound_stats outbound;

    /* Window bookkeeping. */
    uint64_t window_start_ns;       /**< monotonic ns when current window opened */
    uint64_t last_update_ns;
    uint32_t window_count;          /**< increments on every reset_window() call */
};

/* -------------------------------------------------------------------------
 * 1.5 service_stats_array — the runtime container
 *
 * Parallel array to service_registry.slots[]; index i in arr->slots maps
 * 1:1 to index i in reg->slots.
 * ------------------------------------------------------------------------- */
struct service_stats_array {
    struct service_stats *slots;    /**< capacity-sized array, NULL until init */
    size_t                capacity; /**< always SERVICE_REGISTRY_MAX_TOTAL_SLOTS */
    size_t                n_active; /**< count of slots with active == true     */
};

/* -------------------------------------------------------------------------
 * 1.6 Public API
 * ------------------------------------------------------------------------- */

/**
 * Allocate the runtime stats array, sized to SERVICE_REGISTRY_MAX_TOTAL_SLOTS.
 * Zero-initialised (calloc). Returns 0 on success, negative on failure.
 */
int  service_stats_array_init(struct service_stats_array *arr);

/**
 * Initialise one slot from a registry descriptor: copy identity + profile
 * pointer; zero all stats; set active = true. Returns 0 on success.
 */
int  service_stats_init_slot(struct service_stats *slot,
                              const struct service_descriptor *desc);

/**
 * Initialise every populated slot of the array from the registry. Walks
 * reg->slots[0..n_slots) and calls init_slot on each. arr->n_active is set to
 * reg->n_slots on success. Returns 0 on success.
 */
int  service_stats_init_from_registry(struct service_stats_array *arr,
                                       const struct service_registry *reg);

/**
 * Reset per-window scalar counters for one slot. Zeros the raw counters in
 * common.*, the proto-specific union arm, and outbound.*. Does NOT zero
 * HLL/CM sketches or identity. Safe to call on an inactive slot (no-op).
 */
void service_stats_reset_window(struct service_stats *slot);

/** Reset all active slots in the array. */
void service_stats_reset_window_all(struct service_stats_array *arr);

/** Destroy the runtime stats array; free internal heap; idempotent. */
void service_stats_array_destroy(struct service_stats_array *arr);

/* Helpers */

/** Return a void* to the proto union arm for slot->proto_kind, or NULL. */
void *service_stats_get_proto_arm(struct service_stats *slot);

/** Diagnostic one-line summary to stderr. */
void service_stats_log_slot(const struct service_stats *slot);

/** Size of one service_stats slot in bytes (for memory-budget tests). */
size_t service_stats_sizeof(void);

/* -------------------------------------------------------------------------
 * 1.7 Compile-time invariants
 * ------------------------------------------------------------------------- */
_Static_assert(sizeof(struct service_stats) > 0,
               "service_stats must have non-zero size");
_Static_assert(sizeof(struct service_hll) == 1024,
               "service_hll size mismatch");

#endif /* __L2FWD_SERVICE_STATS_H__ */
