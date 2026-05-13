#ifndef __L2FWD_DDOS_COLLECTOR_H__
#define __L2FWD_DDOS_COLLECTOR_H__
#include <stdint.h>
#include <rte_mbuf.h>
#include "l2fwd_l2_profile.h"

/* Forward declaration — avoids circular include with detection engine */
struct detection_engine;

// ============================================================================
// TIMING
// ============================================================================

/** Stats export period: 1 second */
#define STATS_PERIOD_US 1000000ULL

// ============================================================================
// HYPERLOGLOG
// ============================================================================

#define HLL_PRECISION   14
#define HLL_SIZE        (1 << HLL_PRECISION)
#define HLL_ALPHA_16384 (0.7213 / (1.0 + 1.079 / HLL_SIZE))

struct hll_counter {
    uint8_t  registers[HLL_SIZE];
    uint64_t seed;
};

// ============================================================================
// BURST FACTOR WINDOW CONFIGURATION
// ============================================================================

#define BURST_LONG_WINDOW_SEC     20
#define BURST_WINDOW_MAX_SEC     100

// ============================================================================
// EWMA CONFIGURATION
// ============================================================================

/**
 * Per-tier smoothing factors (single EWMA baseline).
 *
 * Tier 0: alpha = 0.10 (slower, more stable baseline)
 * Tier 1: alpha = 0.20 (behavioral patterns)
 */
#define EWMA_ALPHA_TIER0   0.02   /* even slower on volumetric */
#define EWMA_ALPHA_TIER1_1 0.04
#define EWMA_ALPHA_TIER1_2 0.07
#define EWMA_ALPHA_TIER1_3 0.03
#define EWMA_ALPHA_TIER1_4 0.06

/** Minimum observations before EWMA mean is stable */
#define EWMA_WARMUP_PERIODS 12

/** Small epsilon to avoid division-by-zero */
#define EWMA_EPSILON 1e-9

// ============================================================================
// EWMA STATE
// ============================================================================

/**
 * Single EWMA state (used by all tiers).
 * 
 * IMPROVEMENT 1: Added variance tracking with ceiling (3× initial variance)
 * to prevent Tier-1 baseline drift during pre-attack anomalies.
 */
struct ewma_state {
    double   mean;
    uint32_t n;
    double   alpha;
    
    /* Variance ceiling infrastructure (IMPROVEMENT 1) */
    double   variance;           /* Variance tracking (EWMA on squared residuals) */
    double   initial_std;        /* Captured at warmup completion */
    double   variance_max;       /* 3.0 × initial_std (squared) - ceiling */
    bool     ceiling_initialized; /* Has ceiling been initialized? */
};

// ============================================================================
// PER-TIER EWMA COLLECTIONS
// ============================================================================

/**
 * Tier 0 — Single EWMA baselines (6 features, always active)
 */
struct tier0_ewma {
    struct ewma_state pps;
    struct ewma_state bps;
    struct ewma_state fps;
    struct ewma_state burst_pps;
    struct ewma_state burst_bps;
    struct ewma_state burst_fps;
};

/** Tier 1 — Single EWMA (behavioral features) */
struct tier1_tcp_ewma {
    struct ewma_state syn_ratio;
    struct ewma_state synack_ratio;
    struct ewma_state finack_ratio;
    struct ewma_state rst_ratio;
    struct ewma_state ack_data_ratio;
    struct ewma_state tcp_pps_ratio;
    struct ewma_state tcp_bps_ratio;
    /* V2 features */
    struct ewma_state empty_ack_ratio;
    struct ewma_state zero_window_ratio;
    struct ewma_state small_window_ratio;
    struct ewma_state new_flow_ratio;
    struct ewma_state syn_fin_ratio;
    struct ewma_state syn_to_synack_ratio;
    struct ewma_state tcp_pkt_size_cov;
    struct ewma_state tcp_mean_pkt_size;
};

struct tier1_udp_ewma {
    struct ewma_state udp_bps_ratio;
    struct ewma_state udp_pps_ratio;
    struct ewma_state udp_flow_ratio;
    /* V2 features */
    struct ewma_state udp_pkt_size_cov;
    struct ewma_state udp_mean_pkt_size;
};

struct tier1_icmp_ewma {
    struct ewma_state icmp_echo_ratio;
    struct ewma_state icmp_pps_ratio;
};

struct tier1_dist_ewma {
    struct ewma_state src_ip_ratio;
    struct ewma_state dst_port_ratio;
};

/* V3.0/V3.1: EWMA tracking for L3-channel features.
 *
 * ttl_stddev, src_port_top1_share, src_24_top1_share, and
 * src_24_entropy are EWMA-tracked. ip_frag_ratio and
 * other_proto_ratio use threshold math, not deviation math,
 * so they have NO EWMA state. */
struct tier1_l3_ewma {
    struct ewma_state ttl_stddev;             /* v3.0 */
    struct ewma_state src_port_top1_share;    /* v3.1 */
    struct ewma_state src_24_top1_share;      /* v3.1 */
    struct ewma_state src_24_entropy;         /* v3.1 */
};

/* ============================================================
 * V3.1: Count-min sketch + heavy-hitter tracker.
 *
 * Used for two features:
 *   - src_port_top1_share (key = src_port, 16 bits)
 *   - src_24_top1_share   (key = src_ip & 0xFFFFFF00, 32 bits)
 *   - src_24_entropy      (derived from the same sketch as above)
 *
 * Approximation: counts are min-of-rows. Top-K is an unsorted
 * heavy-hitter array maintained on the fast path: when a key's
 * estimated count exceeds the array minimum, the key replaces
 * the minimum slot.
 * ============================================================ */
#define L3_TOPK 16

struct cm_topk_entry {
    uint32_t key;     /* src_port (16-bit) or /24 prefix (32-bit) */
    uint32_t count;   /* estimated count from the sketch */
};

struct cm_sketch_src_port {
    uint32_t counters[4][16];   /* SRC_PORT_CM_ROWS x SRC_PORT_CM_COLS */
    struct cm_topk_entry topk[L3_TOPK];
};

struct cm_sketch_src_24 {
    uint32_t counters[4][32];   /* SRC_24_CM_ROWS x SRC_24_CM_COLS */
    struct cm_topk_entry topk[L3_TOPK];
};

// ============================================================================
// BURST WINDOW TRACKING
// ============================================================================

struct burst_window {
    uint64_t buckets[BURST_WINDOW_MAX_SEC];
    uint8_t  index;
    uint64_t total;
    uint8_t  filled;
};

/* Multi-timescale temporal observability state. Included here (after
 * struct ewma_state and the per-tier EWMA collections, before
 * struct dst_ip_stats) so the field embedding below is well-formed.
 * Standard include guards break the resulting mutual include with
 * l2fwd_temporal.h cleanly — see the include-cycle note in
 * l2fwd_temporal.h for the full chain. */
#include "l2fwd_temporal.h"

// ============================================================================
// PER-DESTINATION-IP STATISTICS
// ============================================================================

struct dst_ip_stats {
    uint32_t dst_ip;
    uint64_t last_update;

    /* Current 1-second window counters */
    uint64_t total_pkts;
    uint64_t total_bytes;
    uint64_t tcp_pkts;
    uint64_t udp_pkts;
    uint64_t icmp_pkts;
    uint64_t icmp_echo_pkts;
    uint64_t tcp_bytes;
    uint64_t udp_bytes;
    uint64_t syn_pkts;
    uint64_t syn_ack_pkts;
    uint64_t fin_ack_pkts;
    uint64_t rst_pkts;
    uint64_t ack_data_pkts;

    /* V2: TCP behavioral signatures (Tier-1) */
    uint64_t empty_ack_pkts;       /* ACK only, no SYN/FIN/RST, payload_len == 0 */
    uint64_t zero_window_pkts;     /* tcp_hdr->rx_win == 0 */
    uint64_t small_window_pkts;    /* 0 < tcp_hdr->rx_win < SMALL_WINDOW_THRESHOLD */

    /* V2: per-protocol packet-size sum-of-squares for CoV computation */
    uint64_t tcp_pkt_size_sum_sq;
    uint64_t udp_pkt_size_sum_sq;

    /* V3.0: L3-channel raw counters
     *
     * ttl_sum + ttl_sum_sq: Welford-style accumulation for ttl_stddev
     * ip_frag_pkts: count of fragmented IP packets
     * other_proto_pkts: count of non-TCP/UDP/ICMP packets
     */
    uint64_t ttl_sum;
    uint64_t ttl_sum_sq;
    uint64_t ip_frag_pkts;
    uint64_t other_proto_pkts;

    /* V3.1: count-min sketches for top-1 share and entropy features */
    struct cm_sketch_src_port cm_src_port;
    struct cm_sketch_src_24   cm_src_24;

    /* HyperLogLog estimators */
    struct hll_counter unique_src_ips;
    struct hll_counter unique_dst_ports;
    struct hll_counter udp_flows;
    struct hll_counter unique_flows;
    /* V2: TCP flows where a SYN-only packet was observed in this window.
     * Used for new_flow_ratio = unique_new_flows / unique_flows.
     *
     * RACE NOTE: hll_add and hll_init race with no lock. Bounded error
     * within the HLL precision-14 noise floor (~0.8%). Same race profile
     * as the existing HLL counters above. */
    struct hll_counter unique_new_flows;

    /* Burst windows */
    struct burst_window bw_pps;
    struct burst_window bw_bps;
    struct burst_window bw_fps;

    /* EWMA baselines */
    struct tier0_ewma      ewma_t0;      /* Dual-EWMA */
    struct tier1_tcp_ewma  ewma_t1_tcp;  /* Single EWMA */
    struct tier1_udp_ewma  ewma_t1_udp;
    struct tier1_icmp_ewma ewma_t1_icmp;
    struct tier1_dist_ewma ewma_t1_dist;
    struct tier1_l3_ewma   ewma_t1_l3;

    /* Detection engine */
    struct detection_engine *detection;

    /* Layer-2 profile (per-IP tunables). Points to l2_profile_default
     * unless a later resolver assigns a non-default profile. Read-only
     * at runtime; not consumed by the detector yet. */
    const struct l2_profile *profile;

    uint8_t active;

    /* Multi-timescale temporal observability state (shadow / read-only
     * outside l2fwd_temporal.c). Appended after every pre-existing field
     * so the offsets of fields above are preserved, minimising the diff
     * surface for any tooling that walks struct dst_ip_stats by offset.
     * Updated once per active dst_ip per 1s window in a later commit;
     * not yet read or written by any module. */
    struct l2_temporal_state temporal;

    /* ============================================================
     * EXPERIMENTAL — DIRECTIONALITY DIAGNOSTIC (REMOVE WHEN DONE)
     * Added to count inbound vs outbound packets per protected IP.
     * Search for "DIRECTIONALITY_EXPERIMENT" to find all related code.
     * ============================================================ */
    /* DIRECTIONALITY_EXPERIMENT */
    uint64_t inbound_pkts;
    /* DIRECTIONALITY_EXPERIMENT */
    uint64_t outbound_pkts;
};

// ============================================================================
// TABLE & PORT STRUCTURES
// ============================================================================

#define MAX_DST_IPS 1024

struct dst_ip_table {
    struct dst_ip_stats entries[MAX_DST_IPS];
};

struct port_stats {
    struct dst_ip_table dst_table;
};

extern struct port_stats *port_stats;

#define MONITORED_PORT 0

// ============================================================================
// PUBLIC API
// ============================================================================

void ddos_collector_init(void);
void ddos_collect_packet_stats(struct rte_mbuf *m, unsigned portid);
void ddos_log_and_reset_stats(void);

void     hll_init (struct hll_counter *hll, uint64_t seed);
void     hll_add  (struct hll_counter *hll, const void *data, size_t len);
uint64_t hll_count(const struct hll_counter *hll);

struct dst_ip_stats *dst_ip_table_get_or_create(struct dst_ip_table *table,
                                                  uint32_t dst_ip,
                                                  uint64_t timestamp,
                                                  uint16_t portid);

void   ewma_update(struct ewma_state *s, double x);
double ewma_mean  (const struct ewma_state *s);

void   burst_window_push (struct burst_window *bw, uint64_t value);
double burst_window_avg  (const struct burst_window *bw);

#endif /* __L2FWD_DDOS_COLLECTOR_H__ */