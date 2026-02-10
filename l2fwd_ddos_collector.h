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

/**
 * HyperLogLog structure for cardinality estimation
 * Used to efficiently track unique IPs and ports
 */
struct hll_counter {
    uint8_t registers[HLL_SIZE];
    uint64_t seed;
};

/**
 * Per-destination-IP statistics structure
 */
struct dst_ip_stats {
    uint32_t dst_ip;                    // Destination IP address
    uint64_t last_update;               // Last update timestamp
    
    // Current window counters (1 second)
    uint64_t total_pkts;
    uint64_t total_bytes;
    uint64_t udp_pkts;
    uint64_t tcp_pkts;
    uint64_t icmp_pkts;
    uint64_t icmp_echo_pkts;
    
    // TCP flag counters
    uint64_t syn_pkts;
    uint64_t syn_ack_pkts;
    uint64_t fin_ack_pkts;
    uint64_t rst_pkts;
    
    // Direction tracking
    uint64_t inbound_bytes;
    uint64_t outbound_bytes;
    
    // Burst window tracking (10 seconds)
    uint64_t burst_window_pkts[10];     // Packet count per second for last 10 seconds
    uint8_t burst_window_index;         // Current index in circular buffer
    uint64_t burst_window_total;        // Sum of all packets in burst window
    
    // HyperLogLog cardinality estimators
    struct hll_counter unique_src_ips;
    struct hll_counter unique_dst_ports;
    struct hll_counter udp_flows;       // Track UDP flows (src_ip:src_port combinations)
    
    // Active flag
    uint8_t active;
};

/**
 * Destination IP hash table
 */
struct dst_ip_table {
    struct dst_ip_stats entries[MAX_DST_IPS];
};

/**
 * Port-level statistics (mainly for management)
 * Note: We only track statistics for port 0
 */
struct port_stats {
    struct dst_ip_table dst_table;
};

extern struct port_stats port_stats[RTE_MAX_ETHPORTS];

// Port to monitor (only port 0)
#define MONITORED_PORT 0

// Core functions
void ddos_collector_init(void);
void ddos_collect_packet_stats(struct rte_mbuf *m, unsigned portid);
void ddos_log_and_reset_stats(void);

// HyperLogLog functions
void hll_init(struct hll_counter *hll, uint64_t seed);
void hll_add(struct hll_counter *hll, const void *data, size_t len);
uint64_t hll_count(const struct hll_counter *hll);

// Destination IP table functions
struct dst_ip_stats* dst_ip_table_get_or_create(struct dst_ip_table *table, 
                                                 uint32_t dst_ip, 
                                                 uint64_t timestamp,
                                                 uint16_t portid);

#endif /* __L2FWD_DDOS_COLLECTOR_H__ */