#include "l2fwd_ddos_collector.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <errno.h>
#include <math.h>
#include <arpa/inet.h>

#include <rte_ethdev.h>
#include <rte_ether.h>
#include <rte_ip.h>
#include <rte_tcp.h>
#include <rte_udp.h>
#include <rte_icmp.h>
#include <rte_hash_crc.h>

// Global stats array
struct port_stats port_stats[RTE_MAX_ETHPORTS];

// Socket Configuration
#define SOCK_PATH "/tmp/ddos_stats_socket"
static int sock_fd = -1;
static struct sockaddr_un server_addr;

// ============================================================================
// HYPERLOGLOG IMPLEMENTATION
// ============================================================================

/**
 * Count leading zeros in a 32-bit integer
 */
static inline uint8_t clz32(uint32_t x) {
    if (x == 0) return 32;
    return __builtin_clz(x);
}

/**
 * Initialize HyperLogLog counter
 */
void hll_init(struct hll_counter *hll, uint64_t seed) {
    memset(hll->registers, 0, HLL_SIZE);
    hll->seed = seed;
}

/**
 * Add element to HyperLogLog
 */
void hll_add(struct hll_counter *hll, const void *data, size_t len) {
    // Hash the data
    uint32_t hash = rte_hash_crc(data, len, hll->seed);
    
    // Extract register index (first p bits)
    uint32_t index = hash >> (32 - HLL_PRECISION);
    
    // Extract remaining bits and count leading zeros + 1
    uint32_t w = hash << HLL_PRECISION;
    uint8_t leading_zeros = clz32(w) + 1;
    
    // Update register with maximum value
    if (leading_zeros > hll->registers[index]) {
        hll->registers[index] = leading_zeros;
    }
}

/**
 * Estimate cardinality from HyperLogLog
 */
uint64_t hll_count(const struct hll_counter *hll) {
    double raw_estimate = 0.0;
    uint32_t zero_count = 0;
    
    // Calculate harmonic mean
    for (uint32_t i = 0; i < HLL_SIZE; i++) {
        raw_estimate += 1.0 / (1ULL << hll->registers[i]);
        if (hll->registers[i] == 0) {
            zero_count++;
        }
    }
    
    double estimate = HLL_ALPHA_16384 * HLL_SIZE * HLL_SIZE / raw_estimate;
    
    // Small range correction
    if (estimate <= 5.0 * HLL_SIZE) {
        if (zero_count != 0) {
            estimate = HLL_SIZE * log((double)HLL_SIZE / zero_count);
        }
    }
    
    // Large range correction
    if (estimate > (1ULL << 32) / 30.0) {
        estimate = -(1ULL << 32) * log(1.0 - estimate / (1ULL << 32));
    }
    
    return (uint64_t)estimate;
}

// ============================================================================
// DESTINATION IP TABLE IMPLEMENTATION
// ============================================================================

/**
 * Simple hash function for destination IP lookup
 */
static uint32_t dst_ip_hash(uint32_t dst_ip) {
    return dst_ip % MAX_DST_IPS;
}

/**
 * Get or create destination IP stats entry
 */
struct dst_ip_stats* dst_ip_table_get_or_create(struct dst_ip_table *table, 
                                                 uint32_t dst_ip, 
                                                 uint64_t timestamp,
                                                 uint16_t portid) {
    uint32_t index = dst_ip_hash(dst_ip);
    uint32_t attempts = 0;
    
    // Linear probing to handle collisions
    while (attempts < MAX_DST_IPS) {
        struct dst_ip_stats *entry = &table->entries[index];
        
        // Found matching entry
        if (entry->active && entry->dst_ip == dst_ip) {
            return entry;
        }
        
        // Found empty slot - initialize new entry
        if (!entry->active) {
            memset(entry, 0, sizeof(struct dst_ip_stats));
            entry->dst_ip = dst_ip;
            entry->active = 1;
            entry->last_update = timestamp;
            
            // Initialize HyperLogLog counters with unique seeds
            hll_init(&entry->unique_src_ips, 0x12345678 + dst_ip);
            hll_init(&entry->unique_dst_ports, 0x87654321 + dst_ip);
            hll_init(&entry->udp_flows, 0xABCDEF00 + dst_ip);
            
            return entry;
        }
        
        // Try next slot
        index = (index + 1) % MAX_DST_IPS;
        attempts++;
    }
    
    // Table full - return NULL
    return NULL;
}

// ============================================================================
// COLLECTOR INITIALIZATION
// ============================================================================

/**
 * Initialize DDoS collector and socket structure
 */
void ddos_collector_init(void) {
    printf("DDoS Collector: Initializing per-destination-IP tracking...\n");

    // Clear all stats
    memset(port_stats, 0, sizeof(port_stats));

    // Setup the socket address structure
    memset(&server_addr, 0, sizeof(struct sockaddr_un));
    server_addr.sun_family = AF_UNIX;
    strncpy(server_addr.sun_path, SOCK_PATH, sizeof(server_addr.sun_path) - 1);

    printf("DDoS Collector: Initialization complete\n");
}

/**
 * Helper to manage socket connection (lazy connection)
 */
static void check_and_connect_socket(void) {
    if (sock_fd >= 0)
        return; // Already connected

    sock_fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (sock_fd < 0) {
        perror("DDoS Collector: Failed to create socket");
        return;
    }

    if (connect(sock_fd, (struct sockaddr *)&server_addr, sizeof(struct sockaddr_un)) < 0) {
        close(sock_fd);
        sock_fd = -1;
    } else {
        printf("DDoS Collector: Connected to Python receiver at %s\n", SOCK_PATH);
    }
}

// ============================================================================
// PACKET STATISTICS COLLECTION
// ============================================================================

/**
 * Determine if port is inbound (server) or outbound (client)
 * 
 * Inbound traffic: packets destined TO server ports (traffic coming IN to servers)
 * Outbound traffic: packets coming FROM server ports (traffic going OUT from servers)
 * 
 * This helps classify:
 * - Inbound attacks: flooding server ports (SYN flood, UDP flood to services)
 * - Outbound attacks: amplification attacks where servers respond with large data
 */
static inline int is_server_port(uint16_t port) {
    // Common server ports: 0-1023 (well-known), plus common services
    return (port < 1024) || (port == 3306) || (port == 5432) || 
           (port == 6379) || (port == 8080) || (port == 8443);
}

/**
 * Main packet statistics collection function
 * Only collects statistics for packets on port 0
 */
void ddos_collect_packet_stats(struct rte_mbuf *m, unsigned portid) {
    struct rte_ether_hdr *eth_hdr;
    struct rte_vlan_hdr *vlan_hdr;
    struct rte_ipv4_hdr *ipv4_hdr;
    struct rte_tcp_hdr *tcp_hdr;
    struct rte_udp_hdr *udp_hdr;
    struct rte_icmp_hdr *icmp_hdr;
    uint16_t ether_type;
    uint16_t offset = sizeof(struct rte_ether_hdr);
    uint64_t timestamp = rte_get_timer_cycles();

    // Only process packets from port 0
    if (unlikely(portid != MONITORED_PORT))
        return;

    if (unlikely(portid >= RTE_MAX_ETHPORTS))
        return;

    /* Parse Ethernet header */
    eth_hdr = rte_pktmbuf_mtod(m, struct rte_ether_hdr *);
    ether_type = rte_be_to_cpu_16(eth_hdr->ether_type);

    /* Handle VLAN tags */
    while (ether_type == RTE_ETHER_TYPE_VLAN || ether_type == RTE_ETHER_TYPE_QINQ) {
        vlan_hdr = rte_pktmbuf_mtod_offset(m, struct rte_vlan_hdr *, offset);
        ether_type = rte_be_to_cpu_16(vlan_hdr->eth_proto);
        offset += sizeof(struct rte_vlan_hdr);
    }

    /* Only process IPv4 */
    if (ether_type != RTE_ETHER_TYPE_IPV4) {
        return;
    }

    /* Parse IPv4 header */
    ipv4_hdr = rte_pktmbuf_mtod_offset(m, struct rte_ipv4_hdr *, offset);
    
    uint32_t src_ip = rte_be_to_cpu_32(ipv4_hdr->src_addr);
    uint32_t dst_ip = rte_be_to_cpu_32(ipv4_hdr->dst_addr);
    uint8_t protocol = ipv4_hdr->next_proto_id;
    
    // Get or create destination IP stats entry
    struct dst_ip_stats *dst_stats = dst_ip_table_get_or_create(
        &port_stats[portid].dst_table, dst_ip, timestamp, portid);
    
    if (dst_stats == NULL) {
        // Table full, drop this packet's stats
        return;
    }
    
    // Update basic counters
    dst_stats->total_pkts++;
    dst_stats->total_bytes += m->pkt_len;
    dst_stats->last_update = timestamp;
    
    // Add source IP to HyperLogLog
    hll_add(&dst_stats->unique_src_ips, &src_ip, sizeof(src_ip));

    // Process based on protocol
    switch (protocol) {
    case IPPROTO_UDP:
        dst_stats->udp_pkts++;
        
        udp_hdr = (struct rte_udp_hdr *)((char *)ipv4_hdr + (ipv4_hdr->ihl * 4));
        uint16_t udp_src_port = rte_be_to_cpu_16(udp_hdr->src_port);
        uint16_t udp_dst_port = rte_be_to_cpu_16(udp_hdr->dst_port);
        
        // Track destination ports in HyperLogLog
        hll_add(&dst_stats->unique_dst_ports, &udp_dst_port, sizeof(udp_dst_port));
        
        // Track UDP flows (combination of src_ip and src_port)
        struct {
            uint32_t src_ip;
            uint16_t src_port;
        } udp_flow_key = {src_ip, udp_src_port};
        hll_add(&dst_stats->udp_flows, &udp_flow_key, sizeof(udp_flow_key));
        
        // Inbound/Outbound classification
        if (is_server_port(udp_dst_port)) {
            dst_stats->inbound_bytes += m->pkt_len;
        } else if (is_server_port(udp_src_port)) {
            dst_stats->outbound_bytes += m->pkt_len;
        }
        break;

    case IPPROTO_TCP:
        dst_stats->tcp_pkts++;
        
        tcp_hdr = (struct rte_tcp_hdr *)((char *)ipv4_hdr + (ipv4_hdr->ihl * 4));
        uint16_t tcp_src_port = rte_be_to_cpu_16(tcp_hdr->src_port);
        uint16_t tcp_dst_port = rte_be_to_cpu_16(tcp_hdr->dst_port);
        uint8_t tcp_flags = tcp_hdr->tcp_flags;
        
        // Track destination ports in HyperLogLog
        hll_add(&dst_stats->unique_dst_ports, &tcp_dst_port, sizeof(tcp_dst_port));
        
        // Count TCP flags
        if (tcp_flags & RTE_TCP_SYN_FLAG) {
            dst_stats->syn_pkts++;
            if (tcp_flags & RTE_TCP_ACK_FLAG) {
                dst_stats->syn_ack_pkts++;
            }
        }
        if (tcp_flags & RTE_TCP_FIN_FLAG) {
            if (tcp_flags & RTE_TCP_ACK_FLAG) {
                dst_stats->fin_ack_pkts++;
            }
        }
        if (tcp_flags & RTE_TCP_RST_FLAG) {
            dst_stats->rst_pkts++;
        }
        
        // Inbound/Outbound classification
        if (is_server_port(tcp_dst_port)) {
            dst_stats->inbound_bytes += m->pkt_len;
        } else if (is_server_port(tcp_src_port)) {
            dst_stats->outbound_bytes += m->pkt_len;
        }
        break;

    case IPPROTO_ICMP:
        dst_stats->icmp_pkts++;
        
        icmp_hdr = (struct rte_icmp_hdr *)((char *)ipv4_hdr + (ipv4_hdr->ihl * 4));
        
        // Track ICMP Echo requests specifically
        if (icmp_hdr->icmp_type == RTE_IP_ICMP_ECHO_REQUEST) {
            dst_stats->icmp_echo_pkts++;
        }
        break;

    default:
        break;
    }
}

// ============================================================================
// STATISTICS LOGGING AND EXPORT
// ============================================================================

/**
 * Main logging and statistics export function
 * Only exports statistics for port 0
 */
void ddos_log_and_reset_stats(void) {
    struct timespec ts;
    long long timestamp_ms;
    char buffer[1024];
    int len;
    uint64_t current_time = rte_get_timer_cycles();

    check_and_connect_socket();
    
    clock_gettime(0, &ts);
    timestamp_ms = (long long)ts.tv_sec * 1000LL + (long long)ts.tv_nsec / 1000000LL;

    // Only process port 0
    unsigned portid = MONITORED_PORT;
    struct dst_ip_table *table = &port_stats[portid].dst_table;
        
    // Iterate through all destination IPs
    for (uint32_t i = 0; i < MAX_DST_IPS; i++) {
        struct dst_ip_stats *stats = &table->entries[i];
            
            if (!stats->active || stats->total_pkts == 0) {
                continue;
            }
            
            double time_sec = (double)STATS_PERIOD_US / 1000000.0;
            
            // === CALCULATE FEATURES ===
            
            // pps - packets per second
            double pps = (double)stats->total_pkts / time_sec;
            
            // bps - bits per second
            double bps = (double)stats->total_bytes * 8.0 / time_sec;
            
            // fps - flows per second (current packets per second)
            double fps = pps;
            
            // burst_factor - current PPS / average PPS over last 10 seconds
            double avg_pps_10s = (double)stats->burst_window_total / 10.0;
            double burst_factor = (avg_pps_10s > 0) ? pps / avg_pps_10s : 1.0;
            
            // inbound_bits and outbound_bits
            double inbound_bits = (double)stats->inbound_bytes * 8.0;
            double outbound_bits = (double)stats->outbound_bytes * 8.0;
            
            // Protocol ratios
            double total_safe = (stats->total_pkts > 0) ? (double)stats->total_pkts : 1.0;
            double udp = (double)stats->udp_pkts / total_safe;
            double tcp = (double)stats->tcp_pkts / total_safe;
            double icmp = (double)stats->icmp_pkts / total_safe;
            
            // TCP flag ratios
            double tcp_total = (stats->tcp_pkts > 0) ? (double)stats->tcp_pkts : 1.0;
            double syn_pps = (double)stats->syn_pkts / tcp_total;
            double synack_pps = (double)stats->syn_ack_pkts / tcp_total;
            double finack_pps = (double)stats->fin_ack_pkts / tcp_total;
            double rst_pps = (double)stats->rst_pkts / tcp_total;
            
            // Cardinality estimates from HyperLogLog
            uint64_t udp_flows = hll_count(&stats->udp_flows);
            uint64_t unique_src_ips = hll_count(&stats->unique_src_ips);
            uint64_t unique_dst_ports = hll_count(&stats->unique_dst_ports);
            
            // icmp_echo_rate
            double icmp_echo_rate = (stats->icmp_pkts > 0) ?
                                   (double)stats->icmp_echo_pkts / (double)stats->icmp_pkts : 0.0;
            
            // Convert dst_ip to readable format
            struct in_addr addr;
            addr.s_addr = htonl(stats->dst_ip);
            char dst_ip_str[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &addr, dst_ip_str, INET_ADDRSTRLEN);
            
            // === FORMAT OUTPUT ===
            // CSV: timestamp,port,dst_ip,pps,bps,fps,burst_factor,inbound_bits,outbound_bits,
            //      udp,tcp,icmp,syn_pps,synack_pps,finack_pps,rst_pps,udp_flows,
            //      unique_src_ips,unique_dst_ports,icmp_echo_rate
            
            len = snprintf(buffer, sizeof(buffer),
                          "%lld,%u,%s,%.2f,%.2f,%.2f,%.4f,%.2f,%.2f,%.4f,%.4f,%.4f,"
                          "%.4f,%.4f,%.4f,%.4f,%lu,%lu,%lu,%.4f\n",
                          timestamp_ms, portid, dst_ip_str,
                          pps, bps, fps, burst_factor, inbound_bits, outbound_bits,
                          udp, tcp, icmp, syn_pps, synack_pps, finack_pps, rst_pps,
                          udp_flows, unique_src_ips, unique_dst_ports, icmp_echo_rate);

            // Send to Python
            if (sock_fd >= 0) {
                if (send(sock_fd, buffer, len, MSG_NOSIGNAL) < 0) {
                    perror("DDoS Collector: Failed to send data");
                    close(sock_fd);
                    sock_fd = -1;
                }
            }

            // Update burst window (circular buffer of last 10 seconds)
            stats->burst_window_total -= stats->burst_window_pkts[stats->burst_window_index];
            stats->burst_window_pkts[stats->burst_window_index] = stats->total_pkts;
            stats->burst_window_total += stats->total_pkts;
            stats->burst_window_index = (stats->burst_window_index + 1) % 10;
            
            // Reset counters for next period
            stats->total_pkts = 0;
            stats->total_bytes = 0;
            stats->udp_pkts = 0;
            stats->tcp_pkts = 0;
            stats->icmp_pkts = 0;
            stats->icmp_echo_pkts = 0;
            stats->syn_pkts = 0;
            stats->syn_ack_pkts = 0;
            stats->fin_ack_pkts = 0;
            stats->rst_pkts = 0;
            stats->inbound_bytes = 0;
            stats->outbound_bytes = 0;
            
            // Reset HyperLogLog counters for next period
            hll_init(&stats->unique_src_ips, 0x12345678 + stats->dst_ip);
            hll_init(&stats->unique_dst_ports, 0x87654321 + stats->dst_ip);
            hll_init(&stats->udp_flows, 0xABCDEF00 + stats->dst_ip);
        }
}