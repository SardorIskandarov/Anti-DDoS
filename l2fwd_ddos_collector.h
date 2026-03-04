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
#define EWMA_ALPHA_TIER0   0.01  /* Slower for stability */
#define EWMA_ALPHA_TIER1_1 0.05
#define EWMA_ALPHA_TIER1_2 0.05
#define EWMA_ALPHA_TIER1_3 0.05
#define EWMA_ALPHA_TIER1_4 0.05

/** Minimum observations before EWMA mean is stable */
#define EWMA_WARMUP_PERIODS 10

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
};

struct tier1_udp_ewma {
    struct ewma_state udp_bps_ratio;
    struct ewma_state udp_pps_ratio;
    struct ewma_state udp_flow_ratio;
};

struct tier1_icmp_ewma {
    struct ewma_state icmp_echo_ratio;
    struct ewma_state icmp_pps_ratio;
};

struct tier1_dist_ewma {
    struct ewma_state src_ip_ratio;
    struct ewma_state dst_port_ratio;
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

    /* HyperLogLog estimators */
    struct hll_counter unique_src_ips;
    struct hll_counter unique_dst_ports;
    struct hll_counter udp_flows;
    struct hll_counter unique_flows;

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

    /* Detection engine */
    struct detection_engine *detection;

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