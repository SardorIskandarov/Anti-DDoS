#ifndef __L2FWD_DDOS_COLLECTOR_H__
#define __L2FWD_DDOS_COLLECTOR_H__

#include <stdint.h>
#include <rte_mbuf.h>

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

/**
 * HyperLogLog precision p = 14  →  2^14 = 16 384 registers (~16 KB each).
 * Used for: unique source IPs, unique destination ports, unique UDP flows,
 * and unique five-tuples (FPS estimation).
 */
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

/**
 * Short window = 1 s (one stats period).
 *
 * Long window for burst factor (tunable at compile time).
 *   BurstFactor(PPS) = PPS_1s / avg_PPS_over_BURST_LONG_WINDOW_SEC
 *   Same formula applies to BPS and FPS burst factors.
 *
 * Change BURST_LONG_WINDOW_SEC to adjust the long window without touching
 * any other code.  Must be ≤ BURST_WINDOW_MAX_SEC.
 */
#define BURST_LONG_WINDOW_SEC     5
#define BURST_WINDOW_MAX_SEC     60   /* maximum allowed long window */

// ============================================================================
// EWMA CONFIGURATION  (mean only — no variance)
// ============================================================================

/**
 * Per-tier smoothing factors.
 *
 *   Tier 0  (volume)       alpha = 0.15  — reacts quickly to volume spikes
 *   Tier 1.1 (TCP)         alpha = 0.08  — slower, behavioural patterns
 *   Tier 1.2 (UDP)         alpha = 0.08
 *   Tier 1.3 (ICMP)        alpha = 0.08
 *   Tier 1.4 (Distribution)alpha = 0.05  — very slow, long-term baseline
 *
 * EWMA update (mean only):
 *   mean_new = mean + alpha * (x - mean)
 */
#define EWMA_ALPHA_TIER0   0.15
#define EWMA_ALPHA_TIER1_1 0.08
#define EWMA_ALPHA_TIER1_2 0.08
#define EWMA_ALPHA_TIER1_3 0.08
#define EWMA_ALPHA_TIER1_4 0.05

/** Minimum observations before the EWMA mean is considered stable */
#define EWMA_WARMUP_PERIODS 10

/** Small epsilon to avoid division-by-zero in normalisation */
#define EWMA_EPSILON 1e-9

// ============================================================================
// EWMA STATE  (mean only)
// ============================================================================

/**
 * Lightweight EWMA state tracking only the mean.
 * Variance is not needed — anomaly scoring uses the Manhattan-distance
 * approach in the detection engine, not Z-scores.
 */
struct ewma_state {
    double   mean;   /* Current exponentially-weighted mean        */
    uint32_t n;      /* Number of updates (warm-up guard)          */
    double   alpha;  /* Per-state smoothing factor (tier-specific) */
};

// ============================================================================
// PER-TIER EWMA COLLECTIONS
// ============================================================================

/**
 * Tier 0 — Volume features (6 features, always ON)
 *   1. PPS
 *   2. BPS
 *   3. FPS   (unique five-tuples/s estimated by HLL)
 *   4. BurstFactor_PPS
 *   5. BurstFactor_BPS
 *   6. BurstFactor_FPS
 */
struct tier0_ewma {
    struct ewma_state pps;
    struct ewma_state bps;
    struct ewma_state fps;
    struct ewma_state burst_pps;
    struct ewma_state burst_bps;
    struct ewma_state burst_fps;
};

/**
 * Tier 1.1 — TCP behavioural features (7 features, passive)
 *   7.  SYN / TCP_pkts
 *   8.  SYN-ACK / TCP_pkts
 *   9.  FIN-ACK / TCP_pkts
 *   10. RST / TCP_pkts
 *   11. ACK-only (data) / TCP_pkts
 *   12. TCP_PPS / Total_PPS
 *   13. TCP_BPS / Total_BPS
 */
struct tier1_tcp_ewma {
    struct ewma_state syn_ratio;
    struct ewma_state synack_ratio;
    struct ewma_state finack_ratio;
    struct ewma_state rst_ratio;
    struct ewma_state ack_data_ratio;
    struct ewma_state tcp_pps_ratio;
    struct ewma_state tcp_bps_ratio;
};

/**
 * Tier 1.2 — UDP behavioural features (3 features, passive)
 *   14. UDP_BPS / Total_BPS
 *   15. UDP_PPS / Total_PPS
 *   16. UDP_flows / UDP_PPS   (flows via HLL)
 */
struct tier1_udp_ewma {
    struct ewma_state udp_bps_ratio;
    struct ewma_state udp_pps_ratio;
    struct ewma_state udp_flow_ratio;
};

/**
 * Tier 1.3 — ICMP behavioural features (2 features, passive)
 *   17. ICMP_echo_requests / Total_ICMP_PPS
 *   18. ICMP_PPS / Total_PPS
 */
struct tier1_icmp_ewma {
    struct ewma_state icmp_echo_ratio;
    struct ewma_state icmp_pps_ratio;
};

/**
 * Tier 1.4 — Distribution features (2 features, passive)
 *   19. Unique_src_IPs / PPS
 *   20. Unique_dst_ports / PPS
 */
struct tier1_dist_ewma {
    struct ewma_state src_ip_ratio;
    struct ewma_state dst_port_ratio;
};

// ============================================================================
// BURST WINDOW TRACKING (circular buffer per metric)
// ============================================================================

/**
 * One circular buffer that accumulates per-second totals for a single metric
 * (packets, bytes, or HLL-estimated flows).  Used to compute the long-window
 * average for the burst factor calculation.
 */
struct burst_window {
    uint64_t buckets[BURST_WINDOW_MAX_SEC]; /* Per-second totals            */
    uint8_t  index;                         /* Write index (wraps)          */
    uint64_t total;                         /* Running sum of active buckets */
    uint8_t  filled;                        /* Buckets currently in use      */
};

// ============================================================================
// PER-DESTINATION-IP STATISTICS
// ============================================================================

struct dst_ip_stats {
    uint32_t dst_ip;       /* Destination IP (host byte order)       */
    uint64_t last_update;  /* Timestamp of last packet (TSC cycles)  */

    /* ------------------------------------------------------------------
     * Current 1-second window counters (reset every STATS_PERIOD_US)
     * ------------------------------------------------------------------ */
    uint64_t total_pkts;
    uint64_t total_bytes;

    /* Protocol packet counts */
    uint64_t tcp_pkts;
    uint64_t udp_pkts;
    uint64_t icmp_pkts;
    uint64_t icmp_echo_pkts;    /* ICMP echo requests (ping) */

    /* TCP byte count (for TCP_BPS ratio) */
    uint64_t tcp_bytes;

    /* UDP byte count (for UDP_BPS ratio) */
    uint64_t udp_bytes;

    /* TCP flag counters */
    uint64_t syn_pkts;
    uint64_t syn_ack_pkts;
    uint64_t fin_ack_pkts;
    uint64_t rst_pkts;
    uint64_t ack_data_pkts;     /* ACK set, not SYN/FIN/RST — pure data */

    /* ------------------------------------------------------------------
     * HyperLogLog cardinality estimators (reset every second)
     * ------------------------------------------------------------------ */
    struct hll_counter unique_src_ips;    /* For Tier 1.4 */
    struct hll_counter unique_dst_ports;  /* For Tier 1.4 */
    struct hll_counter udp_flows;         /* For Tier 1.2: unique (src_ip,src_port) */
    struct hll_counter unique_flows;      /* For Tier 0 FPS: unique five-tuples */

    /* ------------------------------------------------------------------
     * Burst window circular buffers (one per metric)
     * ------------------------------------------------------------------ */
    struct burst_window bw_pps;   /* Per-second packet counts */
    struct burst_window bw_bps;   /* Per-second byte counts   */
    struct burst_window bw_fps;   /* Per-second HLL flow estimates */

    /* ------------------------------------------------------------------
     * EWMA baseline models (persist across windows, never reset)
     * ------------------------------------------------------------------ */
    struct tier0_ewma      ewma_t0;
    struct tier1_tcp_ewma  ewma_t1_tcp;
    struct tier1_udp_ewma  ewma_t1_udp;
    struct tier1_icmp_ewma ewma_t1_icmp;
    struct tier1_dist_ewma ewma_t1_dist;

    /* ------------------------------------------------------------------
     * Behavioural detection engine (heap-allocated, persists across windows)
     * ------------------------------------------------------------------ */
    struct detection_engine *detection;

    /* Active flag */
    uint8_t active;
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

/*
 * port_stats — heap-allocated in ddos_collector_init() via rte_zmalloc.
 * Declared as a pointer (not an array) because the full array (~2.1 GB)
 * would land in .bss and cause R_X86_64_PC32 relocation truncation at link
 * time on x86-64 when the section exceeds the ±2 GB PC-relative range.
 */
extern struct port_stats *port_stats;

#define MONITORED_PORT 0

// ============================================================================
// PUBLIC API
// ============================================================================

/* Lifecycle */
void ddos_collector_init(void);
void ddos_collect_packet_stats(struct rte_mbuf *m, unsigned portid);
void ddos_log_and_reset_stats(void);

/* HyperLogLog */
void     hll_init (struct hll_counter *hll, uint64_t seed);
void     hll_add  (struct hll_counter *hll, const void *data, size_t len);
uint64_t hll_count(const struct hll_counter *hll);

/* Destination IP table */
struct dst_ip_stats *dst_ip_table_get_or_create(struct dst_ip_table *table,
                                                  uint32_t dst_ip,
                                                  uint64_t timestamp,
                                                  uint16_t portid);

/* EWMA helpers */
void   ewma_update(struct ewma_state *s, double x);
double ewma_mean  (const struct ewma_state *s);

/* Burst window helpers */
void   burst_window_push (struct burst_window *bw, uint64_t value);
double burst_window_avg  (const struct burst_window *bw);

#endif /* __L2FWD_DDOS_COLLECTOR_H__ */