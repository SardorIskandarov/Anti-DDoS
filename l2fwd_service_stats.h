#ifndef __L2FWD_SERVICE_STATS_H__
#define __L2FWD_SERVICE_STATS_H__

/**
 * @file   l2fwd_service_stats.h
 * @brief  Per-service runtime stats data model — P4 of the big-bang refactor.
 *
 * This module owns the runtime data structure that future P7+ hot-path code
 * will populate from packets and P9+ detection code will read. At P4 the
 * struct exists, can be allocated, initialised from a service registry,
 * reset per 1Hz window, and destroyed — but NOTHING in main.c or the
 * existing collector touches it yet. Wiring arrives in later prompts.
 *
 * Layout principles:
 *   - One service_stats per registry slot (parallel arrays indexed 0..N).
 *   - Inline sub-structs (HLL, CM sketches): no nested heap allocation.
 *   - Discriminated union for protocol-specific stats, gated by proto_kind.
 *   - Zero is a valid initial state for every field, so a single memset()
 *     suffices for the runtime initialisation path (see _init_slot).
 *
 * Memory budget (per slot, dominated by the "other_catchall" union arm):
 *   ~27 KB × 328 slots ≈ 8.9 MB total. Well within the 10 MB target.
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
 * 1.1 Sub-counter primitives
 *
 * These are new types specifically for the service_stats module. They are
 * intentionally NOT reused from l2fwd_ddos_collector.h — the collector's
 * existing types stay frozen so the legacy hot path keeps working
 * unchanged through P4-P6.
 * ------------------------------------------------------------------------- */

/**
 * HyperLogLog cardinality estimator — 1024 registers, 1 byte per register.
 * Tracks approximate distinct-count of e.g. unique source IPs or flows
 * within a window. 1 KB per counter; we'll pack to 5-bit-per-register if
 * memory pressure becomes a real concern later (P12+).
 */
struct service_hll {
    uint8_t registers[1024];
};

/**
 * Count-Min sketch for source-port concentration.
 * Width 256, depth 4 → 4 KB per sketch.
 * top_port / top_count track the heavy-hitter for top-1-share metrics.
 */
struct service_cm_src_port {
    uint32_t table[4][256];
    uint64_t total;       /**< total events inserted; denominator for ratios */
    uint16_t top_port;    /**< port with highest observed count this window  */
    uint32_t top_count;   /**< its count                                     */
};

/**
 * Count-Min sketch for /24 source-network concentration.
 * Width 512, depth 4 → 8 KB per sketch. Wider than the port sketch because
 * /24 prefixes have a larger keyspace and we care about entropy across them.
 */
struct service_cm_src_24 {
    uint32_t table[4][512];
    uint64_t total;
    uint32_t top_net24;   /**< /24 prefix (host byte order, low byte zeroed) */
    uint32_t top_count;
};

/**
 * Rolling 3-second window for burst detection.
 * Stores the last 3 per-second samples; mean / stddev / z_last are recomputed
 * on each push by the EWMA-update step (P8).
 */
struct service_burst_window {
    double samples[3];
    int    filled;        /**< how many of 3 slots are valid */
    double mean;
    double stddev;
    double z_last;
};

/**
 * EWMA state for one feature.
 *
 * Welford-style mean+variance with a sample counter so per-feature warmup
 * can be checked in P8 without re-walking the whole history.
 */
struct service_ewma_state {
    double   mean;
    double   variance;
    bool     initialized;
    uint32_t sample_count;
};

/* -------------------------------------------------------------------------
 * 1.2 Per-protocol raw counters
 *
 * One struct per protocol family. All counters reset to zero at the end
 * of each 1Hz window (see service_stats_reset_window).
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
    uint64_t tcp_pkt_size_sum;
    uint64_t tcp_pkt_size_sum_sq;
    struct service_hll          unique_new_flows;
    struct service_cm_src_port  cm_src_port;
};

/** UDP raw counters per 1-second window. */
struct service_udp_stats {
    uint64_t udp_pkts;
    uint64_t udp_bytes;
    uint64_t udp_pkt_size_sum;
    uint64_t udp_pkt_size_sum_sq;
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
 * "Other" protocol bucket — for GRE/ESP/IP-in-IP and any other IP proto
 * that lands on the OTHER catchall. proto_counts[N] holds the per-1Hz
 * packet count for IP protocol number N so the dashboard can identify
 * what's actually showing up in this bucket.
 */
struct service_other_stats {
    uint64_t other_pkts;
    uint64_t other_bytes;
    uint64_t proto_counts[256];   /**< per IP proto number */
};

/* -------------------------------------------------------------------------
 * 1.3 EWMA state structs
 *
 * Per-feature mean+variance tracked across windows. EWMA state is NOT
 * reset between windows (it's what carries history forward).
 * ------------------------------------------------------------------------- */

/** Per-feature EWMA state for the TCP channel (15 features). */
struct service_tcp_ewma {
    struct service_ewma_state syn_ratio;
    struct service_ewma_state synack_ratio;
    struct service_ewma_state finack_ratio;
    struct service_ewma_state rst_ratio;
    struct service_ewma_state ack_data_ratio;
    struct service_ewma_state tcp_pps_ratio;
    struct service_ewma_state tcp_bps_ratio;
    struct service_ewma_state empty_ack_ratio;
    struct service_ewma_state zero_window_ratio;
    struct service_ewma_state small_window_ratio;
    struct service_ewma_state new_flow_ratio;
    struct service_ewma_state syn_fin_ratio;
    struct service_ewma_state syn_to_synack_ratio;
    struct service_ewma_state tcp_pkt_size_cov;
    struct service_ewma_state tcp_mean_pkt_size;
};

/** Per-feature EWMA state for the UDP channel (5 features). */
struct service_udp_ewma {
    struct service_ewma_state udp_pps_ratio;
    struct service_ewma_state udp_bps_ratio;
    struct service_ewma_state udp_flow_ratio;
    struct service_ewma_state udp_pkt_size_cov;
    struct service_ewma_state udp_mean_pkt_size;
};

/** Per-feature EWMA state for the ICMP channel (2 features). */
struct service_icmp_ewma {
    struct service_ewma_state icmp_echo_ratio;
    struct service_ewma_state icmp_pps_ratio;
};

/**
 * Common EWMA state — present on every service regardless of proto_kind.
 * Holds volumetric, distribution, and L3 features. The dst_port_ratio and
 * other_proto_ratio fields are only meaningful for the OTHER catchall but
 * are kept here to simplify the hot-path EWMA dispatch in P9.
 */
struct service_common_ewma {
    struct service_ewma_state pps;
    struct service_ewma_state bps;
    struct service_ewma_state fps;
    struct service_ewma_state burst_pps;
    struct service_ewma_state burst_bps;
    struct service_ewma_state burst_fps;
    struct service_ewma_state src_ip_ratio;
    struct service_ewma_state dst_port_ratio;       /**< OTHER catchall only */
    struct service_ewma_state ttl_stddev;
    struct service_ewma_state src_port_top1_share;
    struct service_ewma_state src_24_top1_share;
    struct service_ewma_state src_24_entropy;
    struct service_ewma_state off_proto_pkts_ratio;
    struct service_ewma_state other_proto_ratio;    /**< OTHER catchall only */
};

/* -------------------------------------------------------------------------
 * 1.4 Common inbound / outbound stats
 * ------------------------------------------------------------------------- */

/** Common stats every service has — independent of protocol kind. */
struct service_common_stats {
    uint64_t inbound_pkts;
    uint64_t inbound_bytes;
    uint64_t off_proto_pkts;
    uint64_t ttl_sum;
    uint64_t ttl_sum_sq;
    uint64_t ip_frag_pkts;
    struct service_hll          unique_src_ips;
    struct service_hll          unique_flows;
    struct service_cm_src_24    cm_src_24;
    struct service_burst_window bw_pps;
    struct service_burst_window bw_bps;
    struct service_burst_window bw_fps;
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
 * 1.5 service_stats — the main per-slot struct
 *
 * Discriminated union: `proto_kind` selects which arm of the `proto` union
 * is active. Zero is a valid initial state for every arm, so a single
 * memset() inside service_stats_init_slot() correctly initialises ALL
 * variants without needing per-arm dispatch.
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
    struct service_common_ewma  common_ewma;

    /* Protocol-specific stats. Discriminator is proto_kind above; the
     * union itself is anonymous so callers can write e.g.
     * slot->proto.tcp.stats.syn_pkts. */
    union {
        struct {
            struct service_tcp_stats stats;
            struct service_tcp_ewma  ewma;
        } tcp;
        struct {
            struct service_udp_stats stats;
            struct service_udp_ewma  ewma;
        } udp;
        struct {
            struct service_icmp_stats stats;
            struct service_icmp_ewma  ewma;
        } icmp;
        /* OTHER catchall: carries all three protocol arms plus
         * the protocol-number breakdown and a separate dst-port HLL. */
        struct {
            struct service_tcp_stats   tcp_stats;
            struct service_udp_stats   udp_stats;
            struct service_icmp_stats  icmp_stats;
            struct service_other_stats other_stats;
            struct service_tcp_ewma    tcp_ewma;
            struct service_udp_ewma    udp_ewma;
            struct service_icmp_ewma   icmp_ewma;
            struct service_hll         unique_dst_ports;
        } other_catchall;
    } proto;

    /* Outbound stats — always present. */
    struct service_outbound_stats outbound;

    /* Window bookkeeping. */
    uint64_t window_start_ns;       /**< monotonic ns when current window opened */
    uint64_t last_update_ns;
    uint32_t window_count;          /**< increments on every reset_window() call */

    /* Future-prompt placeholders. P5 wires these; P4 leaves NULL. */
    void *detection_state;
    void *temporal_state;
};

/* -------------------------------------------------------------------------
 * 1.6 service_stats_array — the runtime container
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
 * 1.7 Public API
 * ------------------------------------------------------------------------- */

/**
 * Allocate the runtime stats array, sized to SERVICE_REGISTRY_MAX_TOTAL_SLOTS.
 * Zero-initialised (calloc). Returns 0 on success, negative on allocation
 * failure.
 *
 * P4 uses plain calloc; if hugepage allocation becomes necessary in P7
 * we'll revisit (the registry itself is already non-DPDK-allocated, so
 * keeping the parallel stats array on the same allocator is consistent).
 */
int  service_stats_array_init(struct service_stats_array *arr);

/**
 * Initialise one slot from a registry descriptor: copy identity, profile
 * pointer; zero all stats and EWMA state; set active = true.
 * Returns 0 on success, negative on NULL arg.
 */
int  service_stats_init_slot(struct service_stats *slot,
                              const struct service_descriptor *desc);

/**
 * Initialise every populated slot of the array from the registry. Walks
 * reg->slots[0..n_slots) and calls init_slot on each. arr->n_active is
 * set to reg->n_slots on success.
 *
 * Returns 0 on success; negative if any slot fails to initialise.
 */
int  service_stats_init_from_registry(struct service_stats_array *arr,
                                       const struct service_registry *reg);

/**
 * Reset per-window counters for one slot. Called at end of every 1Hz tick
 * AFTER feature extraction (P8) and EWMA update (P9). Zeros the raw
 * counters in common.* and the proto-specific union arm and outbound.*.
 * Does NOT zero EWMA state, burst windows, HLL/CM sketches, or identity.
 *
 * Safe to call on an inactive slot — it's a no-op.
 */
void service_stats_reset_window(struct service_stats *slot);

/** Reset all active slots in the array. */
void service_stats_reset_window_all(struct service_stats_array *arr);

/**
 * Destroy the runtime stats array; free internal heap; idempotent.
 */
void service_stats_array_destroy(struct service_stats_array *arr);

/* Helpers */

/** Return a void* to the proto union arm for slot->proto_kind, or NULL. */
void *service_stats_get_proto_arm(struct service_stats *slot);

/** Return a void* to the EWMA arm matching slot->proto_kind, or NULL. */
void *service_stats_get_proto_ewma(struct service_stats *slot);

/** Diagnostic one-line summary to stderr. */
void service_stats_log_slot(const struct service_stats *slot);

/** Size of one service_stats slot in bytes (for memory-budget tests). */
size_t service_stats_sizeof(void);

/* -------------------------------------------------------------------------
 * 1.7b P5 — detection_state + temporal_state wiring helpers
 *
 * P4 left slot->detection_state and slot->temporal_state as NULL voids.
 * P5 introduces the two new modules (l2fwd_service_detection,
 * l2fwd_service_temporal_state) and these helpers allocate the per-slot
 * state and install the pointers. The hot path still doesn't call these —
 * P7 will, once packet writes start populating the per-service path.
 * ------------------------------------------------------------------------- */

/**
 * Allocate + init a service_detection_state and a service_temporal_state,
 * then install the pointers into slot->detection_state / temporal_state.
 *
 * The slot MUST already be initialised via service_stats_init_slot() — the
 * helper reads slot->profile to seed the detection-state warmup.
 *
 * Returns 0 on success, negative on allocation/init failure. On failure
 * any partially-allocated state is cleaned up before returning, so the
 * slot pointers are left NULL.
 */
int  service_stats_wire_detection_and_temporal(struct service_stats *slot);

/**
 * Free both pointer-allocated states and clear the slot pointers. Idempotent
 * — safe to call on a slot that was never wired (no-op on NULL pointers).
 */
void service_stats_unwire_detection_and_temporal(struct service_stats *slot);

/**
 * Convenience: wire every active slot in the array. On first failure, all
 * previously-wired slots in this call are unwired before returning a
 * negative rc (atomic-ish; pre-existing wired slots from a previous call
 * are unaffected).
 */
int  service_stats_wire_all(struct service_stats_array *arr);

/** Convenience: unwire every slot in the array. Idempotent. */
void service_stats_unwire_all(struct service_stats_array *arr);

/* -------------------------------------------------------------------------
 * 1.8 Compile-time invariants
 * ------------------------------------------------------------------------- */
_Static_assert(sizeof(struct service_stats) > 0,
               "service_stats must have non-zero size");
_Static_assert(sizeof(struct service_hll) == 1024,
               "service_hll size mismatch");

#endif /* __L2FWD_SERVICE_STATS_H__ */
