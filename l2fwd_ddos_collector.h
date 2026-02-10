#ifndef __L2FWD_DDOS_COLLECTOR_H__
#define __L2FWD_DDOS_COLLECTOR_H__

#include <stdint.h>
#include <rte_mbuf.h>

// Time period over which statistics are collected (1 second)
#define STATS_PERIOD_US 1000000ULL

// Burst tracking window (10 seconds)
#define BURST_WINDOW_US 10000000ULL

// HyperLogLog parameters
#define HLL_PRECISION 14  // 2^14 = 16384 registers (uses ~16KB per HLL)
#define HLL_SIZE (1 << HLL_PRECISION)
#define HLL_ALPHA_16384 0.7213 / (1.0 + 1.079 / HLL_SIZE)

// Maximum destination IPs to track simultaneously
#define MAX_DST_IPS 1024

// ============================================================================
// EWMA CONFIGURATION
// ============================================================================

/**
 * EWMA smoothing factor (alpha).
 *
 * Controls how much weight the most recent observation gets:
 *   - Higher alpha (e.g. 0.3) = reacts faster to changes, less smoothing.
 *   - Lower  alpha (e.g. 0.05) = heavy smoothing, slower to react.
 *
 * Equivalent half-life: N ≈ 1 / alpha  periods.
 * At alpha = 0.1 the effective window is ~10 seconds, which matches the
 * burst_window already used in this code.
 */
#define EWMA_ALPHA 0.1

/**
 * Number of warm-up periods before Z-score output is considered reliable.
 * During warm-up the EWMA variance estimate is still settling; Z-scores are
 * set to 0.0 so downstream consumers can ignore them.
 */
#define EWMA_WARMUP_PERIODS 10

/**
 * Small epsilon added under the square-root when computing Z-scores to avoid
 * division-by-zero when variance is still near zero.
 */
#define EWMA_VAR_EPSILON 1e-9

// ============================================================================
// HYPERLOGLOG
// ============================================================================

/**
 * HyperLogLog structure for cardinality estimation.
 * Used to efficiently track unique IPs and ports.
 */
struct hll_counter {
    uint8_t registers[HLL_SIZE];
    uint64_t seed;
};

// ============================================================================
// EWMA STATE — one instance per tracked feature
// ============================================================================

/**
 * Exponentially-Weighted Moving Average state for a single scalar feature.
 *
 * Update equations (applied once per stats period):
 *
 *   delta    = x - mean
 *   mean_new = mean + alpha * delta
 *   var_new  = (1 - alpha) * (var + alpha * delta^2)
 *
 * This is the standard incremental EWMA variance estimator (analogous to
 * Welford's online algorithm but with exponential forgetting).
 *
 * Z-score:
 *   z = (x - mean) / sqrt(var + EWMA_VAR_EPSILON)
 */
struct ewma_state {
    double mean;        /* Current EWMA mean                          */
    double var;         /* Current EWMA variance                      */
    uint32_t n;         /* Number of updates applied (warm-up guard)  */
};

/**
 * Collection of EWMA states — one per exported feature.
 * Field names mirror the CSV column order used in ddos_log_and_reset_stats().
 */
struct ewma_feature_states {
    struct ewma_state pps;
    struct ewma_state bps;
    struct ewma_state fps;
    struct ewma_state burst_factor;
    struct ewma_state inbound_bits;
    struct ewma_state outbound_bits;
    struct ewma_state udp_ratio;
    struct ewma_state tcp_ratio;
    struct ewma_state icmp_ratio;
    struct ewma_state syn_ratio;
    struct ewma_state synack_ratio;
    struct ewma_state finack_ratio;
    struct ewma_state rst_ratio;
    struct ewma_state udp_flows;
    struct ewma_state unique_src_ips;
    struct ewma_state unique_dst_ports;
    struct ewma_state icmp_echo_rate;
};

// ============================================================================
// EWMA MEAN SNAPSHOT — smoothed baseline value for every feature
// ============================================================================

/**
 * EWMA mean (moving average) for every feature at the end of the most-recently
 * completed 1-second window.
 *
 * Each field is simply ewma_state.mean for the corresponding feature after
 * ewma_update() has been called for that period.  During the cold-start period
 * (n == 1) the mean equals the first observed value; from n == 2 onward it is
 * the exponentially-smoothed estimate of the long-run average for this
 * destination IP.
 *
 * These values are:
 *   - Emitted in the CSV so the Python side can plot the EWMA trend line
 *     alongside the raw measurement.
 *   - Cached here so other in-process consumers (e.g. a mitigation engine)
 *     can read the current baseline without recomputing.
 */
struct ewma_mean_snapshot {
    double pps;
    double bps;
    double fps;
    double burst_factor;
    double inbound_bits;
    double outbound_bits;
    double udp_ratio;
    double tcp_ratio;
    double icmp_ratio;
    double syn_ratio;
    double synack_ratio;
    double finack_ratio;
    double rst_ratio;
    double udp_flows;
    double unique_src_ips;
    double unique_dst_ports;
    double icmp_echo_rate;
};

// ============================================================================
// Z-SCORE SNAPSHOT — normalised values for the current period
// ============================================================================

/**
 * Z-score normalised values for every feature in the current 1-second window.
 *
 * A value of 0.0 means "perfectly average for this destination IP".
 * Large positive/negative values indicate anomalies.
 *
 * During the warm-up phase (ewma_state.n < EWMA_WARMUP_PERIODS) all fields
 * are set to 0.0.
 */
struct zscore_snapshot {
    double pps;
    double bps;
    double fps;
    double burst_factor;
    double inbound_bits;
    double outbound_bits;
    double udp_ratio;
    double tcp_ratio;
    double icmp_ratio;
    double syn_ratio;
    double synack_ratio;
    double finack_ratio;
    double rst_ratio;
    double udp_flows;
    double unique_src_ips;
    double unique_dst_ports;
    double icmp_echo_rate;
};

// ============================================================================
// PER-DESTINATION-IP STATISTICS
// ============================================================================

/**
 * Per-destination-IP statistics structure.
 */
struct dst_ip_stats {
    uint32_t dst_ip;                    /* Destination IP address            */
    uint64_t last_update;               /* Last update timestamp (TSC cycles) */

    /* ------------------------------------------------------------------ */
    /* Current window counters (reset every STATS_PERIOD_US = 1 second)   */
    /* ------------------------------------------------------------------ */
    uint64_t total_pkts;
    uint64_t total_bytes;
    uint64_t udp_pkts;
    uint64_t tcp_pkts;
    uint64_t icmp_pkts;
    uint64_t icmp_echo_pkts;

    /* TCP flag counters */
    uint64_t syn_pkts;
    uint64_t syn_ack_pkts;
    uint64_t fin_ack_pkts;
    uint64_t rst_pkts;

    /* Direction tracking */
    uint64_t inbound_bytes;
    uint64_t outbound_bytes;

    /* ------------------------------------------------------------------ */
    /* Burst window tracking — circular buffer of per-second packet counts */
    /* ------------------------------------------------------------------ */
    uint64_t burst_window_pkts[10];     /* Packet count per second, last 10 s */
    uint8_t  burst_window_index;        /* Current write index                */
    uint64_t burst_window_total;        /* Running sum of the circular buffer */

    /* ------------------------------------------------------------------ */
    /* HyperLogLog cardinality estimators                                  */
    /* ------------------------------------------------------------------ */
    struct hll_counter unique_src_ips;
    struct hll_counter unique_dst_ports;
    struct hll_counter udp_flows;       /* Track UDP flows (src_ip:src_port) */

    /* ------------------------------------------------------------------ */
    /* EWMA baseline models — updated every stats period                   */
    /* ------------------------------------------------------------------ */
    struct ewma_feature_states ewma;

    /* ------------------------------------------------------------------ */
    /* EWMA mean snapshot — smoothed moving-average value per feature,     */
    /* captured after ewma_update() for the most-recently-completed period.*/
    /* Emitted in the CSV so Python can plot the EWMA trend line alongside  */
    /* the raw measurement.                                                 */
    /* ------------------------------------------------------------------ */
    struct ewma_mean_snapshot ewma_mean;

    /* ------------------------------------------------------------------ */
    /* Z-score normalised snapshot for the most-recently-completed period  */
    /* Made available here so other components (e.g. ML inference) can     */
    /* read them without recomputing.                                      */
    /* ------------------------------------------------------------------ */
    struct zscore_snapshot zscore;

    /* Active flag */
    uint8_t active;
};

// ============================================================================
// DESTINATION IP HASH TABLE
// ============================================================================

/**
 * Destination IP hash table.
 */
struct dst_ip_table {
    struct dst_ip_stats entries[MAX_DST_IPS];
};

// ============================================================================
// PORT-LEVEL STATISTICS
// ============================================================================

/**
 * Port-level statistics (mainly for management).
 * Note: we only track statistics for port 0.
 */
struct port_stats {
    struct dst_ip_table dst_table;
};

extern struct port_stats port_stats[RTE_MAX_ETHPORTS];

/* Port to monitor (only port 0) */
#define MONITORED_PORT 0

// ============================================================================
// PUBLIC API
// ============================================================================

/* Core lifecycle */
void ddos_collector_init(void);
void ddos_collect_packet_stats(struct rte_mbuf *m, unsigned portid);
void ddos_log_and_reset_stats(void);

/* HyperLogLog */
void     hll_init  (struct hll_counter *hll, uint64_t seed);
void     hll_add   (struct hll_counter *hll, const void *data, size_t len);
uint64_t hll_count (const struct hll_counter *hll);

/* Destination IP table */
struct dst_ip_stats *dst_ip_table_get_or_create(struct dst_ip_table *table,
                                                 uint32_t dst_ip,
                                                 uint64_t timestamp,
                                                 uint16_t portid);

/* EWMA helpers */
void ewma_update  (struct ewma_state *s, double x);
double ewma_zscore(const struct ewma_state *s, double x);

#endif /* __L2FWD_DDOS_COLLECTOR_H__ */