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
 * Count leading zeros in a 32-bit integer.
 */
static inline uint8_t clz32(uint32_t x) {
    if (x == 0) return 32;
    return __builtin_clz(x);
}

/**
 * Initialize HyperLogLog counter.
 */
void hll_init(struct hll_counter *hll, uint64_t seed) {
    memset(hll->registers, 0, HLL_SIZE);
    hll->seed = seed;
}

/**
 * Add element to HyperLogLog.
 */
void hll_add(struct hll_counter *hll, const void *data, size_t len) {
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
 * Estimate cardinality from HyperLogLog.
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
// EWMA IMPLEMENTATION
// ============================================================================

/**
 * ewma_update() — incorporate one new observation into an EWMA state.
 *
 * The update uses the standard incremental EWMA variance estimator:
 *
 *   delta    = x - mean          (deviation before the update)
 *   mean    += alpha * delta
 *   var      = (1 - alpha) * (var + alpha * delta^2)
 *
 * This is analogous to Welford's online algorithm but with exponential
 * forgetting controlled by EWMA_ALPHA, so old observations gradually
 * lose influence.
 *
 * On the very first call (n == 0) the mean is seeded directly with x and
 * variance is left at 0; this avoids a large spurious spike on startup.
 *
 * @param s  Pointer to the EWMA state to update.
 * @param x  The new observed value for this period.
 */
void ewma_update(struct ewma_state *s, double x) {
    if (s->n == 0) {
        /* Cold start: seed mean directly, variance stays 0. */
        s->mean = x;
        s->var  = 0.0;
    } else {
        double delta = x - s->mean;
        s->mean += EWMA_ALPHA * delta;
        s->var   = (1.0 - EWMA_ALPHA) * (s->var + EWMA_ALPHA * delta * delta);
    }

    /* Cap counter so it doesn't overflow on long-running deployments. */
    if (s->n < UINT32_MAX)
        s->n++;
}

/**
 * ewma_zscore() — compute the Z-score of x given the current EWMA baseline.
 *
 *   z = (x - mean) / sqrt(var + EWMA_VAR_EPSILON)
 *
 * Returns 0.0 during the warm-up phase (n < EWMA_WARMUP_PERIODS) so that
 * downstream consumers can treat early periods as "no anomaly signal yet".
 *
 * @param s  Pointer to the (already-updated) EWMA state.
 * @param x  The observed value for this period.
 * @return   Z-score (dimensionless; values beyond ±3 are typically anomalous).
 */
double ewma_zscore(const struct ewma_state *s, double x) {
    if (s->n < EWMA_WARMUP_PERIODS)
        return 0.0;
    return (x - s->mean) / sqrt(s->var + EWMA_VAR_EPSILON);
}

/**
 * Internal helper: update one EWMA state and immediately return its Z-score.
 *
 * Note: ewma_update() must be called BEFORE ewma_zscore() so the Z-score
 * is computed against the already-updated baseline (i.e. "how far is x
 * from the smoothed history including x itself").  For anomaly detection
 * it is equally valid to compute the Z-score *before* the update (i.e.
 * "how far is x from the history excluding x"); choose whichever your
 * downstream model expects.  Here we update first for consistency with
 * the common convention used in streaming anomaly detectors.
 */
static inline double ewma_update_and_zscore(struct ewma_state *s, double x) {
    ewma_update(s, x);
    return ewma_zscore(s, x);
}

// ============================================================================
// DESTINATION IP TABLE IMPLEMENTATION
// ============================================================================

/**
 * Simple hash function for destination IP lookup.
 */
static uint32_t dst_ip_hash(uint32_t dst_ip) {
    return dst_ip % MAX_DST_IPS;
}

/**
 * Get or create destination IP stats entry.
 */
struct dst_ip_stats *dst_ip_table_get_or_create(struct dst_ip_table *table,
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
            entry->dst_ip    = dst_ip;
            entry->active    = 1;
            entry->last_update = timestamp;

            // Initialize HyperLogLog counters with unique seeds
            hll_init(&entry->unique_src_ips,  0x12345678 + dst_ip);
            hll_init(&entry->unique_dst_ports, 0x87654321 + dst_ip);
            hll_init(&entry->udp_flows,        0xABCDEF00 + dst_ip);

            /*
             * EWMA states are already zeroed by memset above.
             * ewma_state.n == 0 triggers the cold-start seed on first update.
             */

            return entry;
        }

        // Try next slot
        index = (index + 1) % MAX_DST_IPS;
        attempts++;
    }

    // Table full
    return NULL;
}

// ============================================================================
// COLLECTOR INITIALIZATION
// ============================================================================

/**
 * Initialize DDoS collector and socket structure.
 */
void ddos_collector_init(void) {
    printf("DDoS Collector: Initializing per-destination-IP tracking...\n");

    memset(port_stats, 0, sizeof(port_stats));

    memset(&server_addr, 0, sizeof(struct sockaddr_un));
    server_addr.sun_family = AF_UNIX;
    strncpy(server_addr.sun_path, SOCK_PATH, sizeof(server_addr.sun_path) - 1);

    printf("DDoS Collector: Initialization complete\n");
}

/**
 * Helper to manage socket connection (lazy connection).
 */
static void check_and_connect_socket(void) {
    if (sock_fd >= 0)
        return;

    sock_fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (sock_fd < 0) {
        perror("DDoS Collector: Failed to create socket");
        return;
    }

    if (connect(sock_fd, (struct sockaddr *)&server_addr,
                sizeof(struct sockaddr_un)) < 0) {
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
 * Determine if port is inbound (server) or outbound (client).
 *
 * Inbound traffic : packets destined TO server ports (traffic coming IN).
 * Outbound traffic: packets coming FROM server ports (traffic going OUT).
 */
static inline int is_server_port(uint16_t port) {
    return (port < 1024) || (port == 3306) || (port == 5432) ||
           (port == 6379) || (port == 8080) || (port == 8443);
}

/**
 * Main packet statistics collection function.
 * Only collects statistics for packets on port 0.
 */
void ddos_collect_packet_stats(struct rte_mbuf *m, unsigned portid) {
    struct rte_ether_hdr *eth_hdr;
    struct rte_vlan_hdr  *vlan_hdr;
    struct rte_ipv4_hdr  *ipv4_hdr;
    struct rte_tcp_hdr   *tcp_hdr;
    struct rte_udp_hdr   *udp_hdr;
    struct rte_icmp_hdr  *icmp_hdr;
    uint16_t ether_type;
    uint16_t offset    = sizeof(struct rte_ether_hdr);
    uint64_t timestamp = rte_get_timer_cycles();

    if (unlikely(portid != MONITORED_PORT))
        return;
    if (unlikely(portid >= RTE_MAX_ETHPORTS))
        return;

    /* Parse Ethernet header */
    eth_hdr    = rte_pktmbuf_mtod(m, struct rte_ether_hdr *);
    ether_type = rte_be_to_cpu_16(eth_hdr->ether_type);

    /* Handle VLAN tags */
    while (ether_type == RTE_ETHER_TYPE_VLAN || ether_type == RTE_ETHER_TYPE_QINQ) {
        vlan_hdr   = rte_pktmbuf_mtod_offset(m, struct rte_vlan_hdr *, offset);
        ether_type = rte_be_to_cpu_16(vlan_hdr->eth_proto);
        offset    += sizeof(struct rte_vlan_hdr);
    }

    /* Only process IPv4 */
    if (ether_type != RTE_ETHER_TYPE_IPV4)
        return;

    /* Parse IPv4 header */
    ipv4_hdr = rte_pktmbuf_mtod_offset(m, struct rte_ipv4_hdr *, offset);

    uint32_t src_ip   = rte_be_to_cpu_32(ipv4_hdr->src_addr);
    uint32_t dst_ip   = rte_be_to_cpu_32(ipv4_hdr->dst_addr);
    uint8_t  protocol = ipv4_hdr->next_proto_id;

    struct dst_ip_stats *dst_stats = dst_ip_table_get_or_create(
        &port_stats[portid].dst_table, dst_ip, timestamp, portid);
    if (dst_stats == NULL)
        return;

    dst_stats->total_pkts++;
    dst_stats->total_bytes += m->pkt_len;
    dst_stats->last_update  = timestamp;

    hll_add(&dst_stats->unique_src_ips, &src_ip, sizeof(src_ip));

    switch (protocol) {
    case IPPROTO_UDP: {
        dst_stats->udp_pkts++;

        udp_hdr = (struct rte_udp_hdr *)((char *)ipv4_hdr + (ipv4_hdr->ihl * 4));
        uint16_t udp_src_port = rte_be_to_cpu_16(udp_hdr->src_port);
        uint16_t udp_dst_port = rte_be_to_cpu_16(udp_hdr->dst_port);

        hll_add(&dst_stats->unique_dst_ports, &udp_dst_port, sizeof(udp_dst_port));

        struct {
            uint32_t src_ip;
            uint16_t src_port;
        } udp_flow_key = {src_ip, udp_src_port};
        hll_add(&dst_stats->udp_flows, &udp_flow_key, sizeof(udp_flow_key));

        if (is_server_port(udp_dst_port))
            dst_stats->inbound_bytes += m->pkt_len;
        else if (is_server_port(udp_src_port))
            dst_stats->outbound_bytes += m->pkt_len;
        break;
    }
    case IPPROTO_TCP: {
        dst_stats->tcp_pkts++;

        tcp_hdr = (struct rte_tcp_hdr *)((char *)ipv4_hdr + (ipv4_hdr->ihl * 4));
        uint16_t tcp_src_port = rte_be_to_cpu_16(tcp_hdr->src_port);
        uint16_t tcp_dst_port = rte_be_to_cpu_16(tcp_hdr->dst_port);
        uint8_t  tcp_flags    = tcp_hdr->tcp_flags;

        hll_add(&dst_stats->unique_dst_ports, &tcp_dst_port, sizeof(tcp_dst_port));

        if (tcp_flags & RTE_TCP_SYN_FLAG) {
            dst_stats->syn_pkts++;
            if (tcp_flags & RTE_TCP_ACK_FLAG)
                dst_stats->syn_ack_pkts++;
        }
        if (tcp_flags & RTE_TCP_FIN_FLAG) {
            if (tcp_flags & RTE_TCP_ACK_FLAG)
                dst_stats->fin_ack_pkts++;
        }
        if (tcp_flags & RTE_TCP_RST_FLAG)
            dst_stats->rst_pkts++;

        if (is_server_port(tcp_dst_port))
            dst_stats->inbound_bytes += m->pkt_len;
        else if (is_server_port(tcp_src_port))
            dst_stats->outbound_bytes += m->pkt_len;
        break;
    }
    case IPPROTO_ICMP: {
        dst_stats->icmp_pkts++;

        icmp_hdr = (struct rte_icmp_hdr *)((char *)ipv4_hdr + (ipv4_hdr->ihl * 4));
        if (icmp_hdr->icmp_type == RTE_IP_ICMP_ECHO_REQUEST)
            dst_stats->icmp_echo_pkts++;
        break;
    }
    default:
        break;
    }
}

// ============================================================================
// STATISTICS LOGGING AND EXPORT
// ============================================================================

/**
 * Main logging and statistics export function.
 * Only exports statistics for port 0.
 *
 * For every active destination IP the function:
 *   1. Computes the 17 traffic features for the current 1-second window.
 *   2. Updates the per-feature EWMA baseline (mean + variance).
 *   3. Derives a Z-score for each feature using the updated baseline.
 *   4. Emits a CSV line containing raw features AND their Z-scores.
 *   5. Resets the per-window counters and HLL estimators.
 *
 * CSV column order:
 *   timestamp, port, dst_ip,
 *   pps, bps, fps, burst_factor, inbound_bits, outbound_bits,
 *   udp, tcp, icmp,
 *   syn_ratio, synack_ratio, finack_ratio, rst_ratio,
 *   udp_flows, unique_src_ips, unique_dst_ports, icmp_echo_rate,
 *   z_pps, z_bps, z_fps, z_burst_factor, z_inbound_bits, z_outbound_bits,
 *   z_udp, z_tcp, z_icmp,
 *   z_syn_ratio, z_synack_ratio, z_finack_ratio, z_rst_ratio,
 *   z_udp_flows, z_unique_src_ips, z_unique_dst_ports, z_icmp_echo_rate
 */
void ddos_log_and_reset_stats(void) {
    struct timespec ts;
    long long  timestamp_ms;

    /*
     * Buffer sized for 3 header + 17 raw + 17 EWMA-mean + 17 Z-score fields
     * plus the IP string and formatting overhead.
     * 54 fields × ~12 chars each + separators ≈ 700 bytes; 1024 is safe.
     */
    char buffer[1024];
    int  len;

    check_and_connect_socket();

    clock_gettime(0, &ts);
    timestamp_ms = (long long)ts.tv_sec * 1000LL +
                   (long long)ts.tv_nsec / 1000000LL;

    unsigned portid = MONITORED_PORT;
    struct dst_ip_table *table = &port_stats[portid].dst_table;

    for (uint32_t i = 0; i < MAX_DST_IPS; i++) {
        struct dst_ip_stats *stats = &table->entries[i];

        if (!stats->active || stats->total_pkts == 0)
            continue;

        double time_sec = (double)STATS_PERIOD_US / 1000000.0;

        // ----------------------------------------------------------------
        // STEP 1: COMPUTE RAW FEATURES
        // ----------------------------------------------------------------

        /* pps — packets per second */
        double pps = (double)stats->total_pkts / time_sec;

        /* bps — bits per second */
        double bps = (double)stats->total_bytes * 8.0 / time_sec;

        /* fps — flows per second (approximated as pps here) */
        double fps = pps;

        /* burst_factor — ratio of current PPS to 10-second rolling average */
        double avg_pps_10s  = (double)stats->burst_window_total / 10.0;
        double burst_factor = (avg_pps_10s > 0) ? pps / avg_pps_10s : 1.0;

        /* inbound / outbound bits this period */
        double inbound_bits  = (double)stats->inbound_bytes  * 8.0;
        double outbound_bits = (double)stats->outbound_bytes * 8.0;

        /* Protocol mix ratios */
        double total_safe  = (stats->total_pkts > 0) ? (double)stats->total_pkts : 1.0;
        double udp_ratio   = (double)stats->udp_pkts  / total_safe;
        double tcp_ratio   = (double)stats->tcp_pkts  / total_safe;
        double icmp_ratio  = (double)stats->icmp_pkts / total_safe;

        /* TCP flag ratios (denominator = TCP packets) */
        double tcp_total    = (stats->tcp_pkts > 0) ? (double)stats->tcp_pkts : 1.0;
        double syn_ratio    = (double)stats->syn_pkts     / tcp_total;
        double synack_ratio = (double)stats->syn_ack_pkts / tcp_total;
        double finack_ratio = (double)stats->fin_ack_pkts / tcp_total;
        double rst_ratio    = (double)stats->rst_pkts     / tcp_total;

        /* HyperLogLog cardinality estimates */
        double udp_flows_f       = (double)hll_count(&stats->udp_flows);
        double unique_src_ips_f  = (double)hll_count(&stats->unique_src_ips);
        double unique_dst_ports_f= (double)hll_count(&stats->unique_dst_ports);

        /* ICMP echo request rate */
        double icmp_echo_rate = (stats->icmp_pkts > 0)
            ? (double)stats->icmp_echo_pkts / (double)stats->icmp_pkts
            : 0.0;

        // ----------------------------------------------------------------
        // STEP 2: UPDATE EWMA BASELINES AND DERIVE Z-SCORES
        //
        // ewma_update_and_zscore() first incorporates x into the EWMA
        // model, then returns how many standard deviations x sits from
        // the newly-updated mean.  During the warm-up phase
        // (ewma_state.n < EWMA_WARMUP_PERIODS) the helper returns 0.0
        // so early anomaly scores stay quiet while the model stabilises.
        // ----------------------------------------------------------------

        double z_pps         = ewma_update_and_zscore(&stats->ewma.pps,         pps);
        double z_bps         = ewma_update_and_zscore(&stats->ewma.bps,         bps);
        double z_fps         = ewma_update_and_zscore(&stats->ewma.fps,         fps);
        double z_burst       = ewma_update_and_zscore(&stats->ewma.burst_factor, burst_factor);
        double z_inbound     = ewma_update_and_zscore(&stats->ewma.inbound_bits,  inbound_bits);
        double z_outbound    = ewma_update_and_zscore(&stats->ewma.outbound_bits, outbound_bits);
        double z_udp         = ewma_update_and_zscore(&stats->ewma.udp_ratio,    udp_ratio);
        double z_tcp         = ewma_update_and_zscore(&stats->ewma.tcp_ratio,    tcp_ratio);
        double z_icmp        = ewma_update_and_zscore(&stats->ewma.icmp_ratio,   icmp_ratio);
        double z_syn         = ewma_update_and_zscore(&stats->ewma.syn_ratio,    syn_ratio);
        double z_synack      = ewma_update_and_zscore(&stats->ewma.synack_ratio, synack_ratio);
        double z_finack      = ewma_update_and_zscore(&stats->ewma.finack_ratio, finack_ratio);
        double z_rst         = ewma_update_and_zscore(&stats->ewma.rst_ratio,    rst_ratio);
        double z_udp_flows   = ewma_update_and_zscore(&stats->ewma.udp_flows,    udp_flows_f);
        double z_src_ips     = ewma_update_and_zscore(&stats->ewma.unique_src_ips,  unique_src_ips_f);
        double z_dst_ports   = ewma_update_and_zscore(&stats->ewma.unique_dst_ports, unique_dst_ports_f);
        double z_icmp_echo   = ewma_update_and_zscore(&stats->ewma.icmp_echo_rate,  icmp_echo_rate);

        /* Cache the Z-score snapshot on the stats struct for other consumers */
        stats->zscore.pps             = z_pps;
        stats->zscore.bps             = z_bps;
        stats->zscore.fps             = z_fps;
        stats->zscore.burst_factor    = z_burst;
        stats->zscore.inbound_bits    = z_inbound;
        stats->zscore.outbound_bits   = z_outbound;
        stats->zscore.udp_ratio       = z_udp;
        stats->zscore.tcp_ratio       = z_tcp;
        stats->zscore.icmp_ratio      = z_icmp;
        stats->zscore.syn_ratio       = z_syn;
        stats->zscore.synack_ratio    = z_synack;
        stats->zscore.finack_ratio    = z_finack;
        stats->zscore.rst_ratio       = z_rst;
        stats->zscore.udp_flows       = z_udp_flows;
        stats->zscore.unique_src_ips  = z_src_ips;
        stats->zscore.unique_dst_ports= z_dst_ports;
        stats->zscore.icmp_echo_rate  = z_icmp_echo;

        // ----------------------------------------------------------------
        // STEP 2b: CAPTURE EWMA MEAN (moving-average baseline) VALUES
        //
        // ewma_update() has already run for every feature above, so
        // ewma_state.mean now holds the post-update exponentially-smoothed
        // average.  We copy each mean into a local variable for use in
        // the snprintf call below, and also persist it in the snapshot
        // struct so other in-process consumers can read the current
        // baseline without touching the ewma_state directly.
        // ----------------------------------------------------------------

        double em_pps        = stats->ewma.pps.mean;
        double em_bps        = stats->ewma.bps.mean;
        double em_fps        = stats->ewma.fps.mean;
        double em_burst      = stats->ewma.burst_factor.mean;
        double em_inbound    = stats->ewma.inbound_bits.mean;
        double em_outbound   = stats->ewma.outbound_bits.mean;
        double em_udp        = stats->ewma.udp_ratio.mean;
        double em_tcp        = stats->ewma.tcp_ratio.mean;
        double em_icmp       = stats->ewma.icmp_ratio.mean;
        double em_syn        = stats->ewma.syn_ratio.mean;
        double em_synack     = stats->ewma.synack_ratio.mean;
        double em_finack     = stats->ewma.finack_ratio.mean;
        double em_rst        = stats->ewma.rst_ratio.mean;
        double em_udp_flows  = stats->ewma.udp_flows.mean;
        double em_src_ips    = stats->ewma.unique_src_ips.mean;
        double em_dst_ports  = stats->ewma.unique_dst_ports.mean;
        double em_icmp_echo  = stats->ewma.icmp_echo_rate.mean;

        /* Persist in snapshot struct for other consumers */
        stats->ewma_mean.pps             = em_pps;
        stats->ewma_mean.bps             = em_bps;
        stats->ewma_mean.fps             = em_fps;
        stats->ewma_mean.burst_factor    = em_burst;
        stats->ewma_mean.inbound_bits    = em_inbound;
        stats->ewma_mean.outbound_bits   = em_outbound;
        stats->ewma_mean.udp_ratio       = em_udp;
        stats->ewma_mean.tcp_ratio       = em_tcp;
        stats->ewma_mean.icmp_ratio      = em_icmp;
        stats->ewma_mean.syn_ratio       = em_syn;
        stats->ewma_mean.synack_ratio    = em_synack;
        stats->ewma_mean.finack_ratio    = em_finack;
        stats->ewma_mean.rst_ratio       = em_rst;
        stats->ewma_mean.udp_flows       = em_udp_flows;
        stats->ewma_mean.unique_src_ips  = em_src_ips;
        stats->ewma_mean.unique_dst_ports= em_dst_ports;
        stats->ewma_mean.icmp_echo_rate  = em_icmp_echo;

        // ----------------------------------------------------------------
        // STEP 3: FORMAT AND EMIT CSV LINE
        // ----------------------------------------------------------------

        /* Convert dst_ip to dotted-decimal string */
        struct in_addr addr;
        addr.s_addr = htonl(stats->dst_ip);
        char dst_ip_str[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &addr, dst_ip_str, INET_ADDRSTRLEN);

        /*
         * CSV format (54 data columns total):
         *   timestamp, port, dst_ip,
         *
         *   --- 17 raw features ---
         *   pps, bps, fps, burst_factor, inbound_bits, outbound_bits,
         *   udp, tcp, icmp,
         *   syn_ratio, synack_ratio, finack_ratio, rst_ratio,
         *   udp_flows, unique_src_ips, unique_dst_ports, icmp_echo_rate,
         *
         *   --- 17 EWMA mean values (prefixed "em_") ---
         *   em_pps, em_bps, em_fps, em_burst_factor,
         *   em_inbound_bits, em_outbound_bits,
         *   em_udp, em_tcp, em_icmp,
         *   em_syn_ratio, em_synack_ratio, em_finack_ratio, em_rst_ratio,
         *   em_udp_flows, em_unique_src_ips, em_unique_dst_ports,
         *   em_icmp_echo_rate,
         *
         *   --- 17 Z-scores (prefixed "z_") ---
         *   z_pps, z_bps, z_fps, z_burst_factor,
         *   z_inbound_bits, z_outbound_bits,
         *   z_udp, z_tcp, z_icmp,
         *   z_syn_ratio, z_synack_ratio, z_finack_ratio, z_rst_ratio,
         *   z_udp_flows, z_unique_src_ips, z_unique_dst_ports,
         *   z_icmp_echo_rate
         */
        len = snprintf(buffer, sizeof(buffer),
            /* header */
            "%lld,%u,%s,"
            /* raw features */
            "%.2f,%.2f,%.2f,%.4f,%.2f,%.2f,"
            "%.4f,%.4f,%.4f,"
            "%.4f,%.4f,%.4f,%.4f,"
            "%.0f,%.0f,%.0f,%.4f,"
            /* EWMA mean values */
            "%.2f,%.2f,%.2f,%.4f,%.2f,%.2f,"
            "%.4f,%.4f,%.4f,"
            "%.4f,%.4f,%.4f,%.4f,"
            "%.2f,%.2f,%.2f,%.4f,"
            /* Z-scores */
            "%.4f,%.4f,%.4f,%.4f,%.4f,%.4f,"
            "%.4f,%.4f,%.4f,"
            "%.4f,%.4f,%.4f,%.4f,"
            "%.4f,%.4f,%.4f,%.4f\n",
            /* header */
            timestamp_ms, portid, dst_ip_str,
            /* raw features */
            pps, bps, fps, burst_factor, inbound_bits, outbound_bits,
            udp_ratio, tcp_ratio, icmp_ratio,
            syn_ratio, synack_ratio, finack_ratio, rst_ratio,
            udp_flows_f, unique_src_ips_f, unique_dst_ports_f, icmp_echo_rate,
            /* EWMA mean values */
            em_pps, em_bps, em_fps, em_burst, em_inbound, em_outbound,
            em_udp, em_tcp, em_icmp,
            em_syn, em_synack, em_finack, em_rst,
            em_udp_flows, em_src_ips, em_dst_ports, em_icmp_echo,
            /* Z-scores */
            z_pps, z_bps, z_fps, z_burst, z_inbound, z_outbound,
            z_udp, z_tcp, z_icmp,
            z_syn, z_synack, z_finack, z_rst,
            z_udp_flows, z_src_ips, z_dst_ports, z_icmp_echo);

        /* Send to Python receiver */
        if (sock_fd >= 0) {
            if (send(sock_fd, buffer, len, MSG_NOSIGNAL) < 0) {
                perror("DDoS Collector: Failed to send data");
                close(sock_fd);
                sock_fd = -1;
            }
        }

        // ----------------------------------------------------------------
        // STEP 4: UPDATE BURST WINDOW (circular buffer) AND RESET COUNTERS
        // ----------------------------------------------------------------

        stats->burst_window_total -= stats->burst_window_pkts[stats->burst_window_index];
        stats->burst_window_pkts[stats->burst_window_index] = stats->total_pkts;
        stats->burst_window_total += stats->total_pkts;
        stats->burst_window_index  = (stats->burst_window_index + 1) % 10;

        /* Reset per-period counters */
        stats->total_pkts     = 0;
        stats->total_bytes    = 0;
        stats->udp_pkts       = 0;
        stats->tcp_pkts       = 0;
        stats->icmp_pkts      = 0;
        stats->icmp_echo_pkts = 0;
        stats->syn_pkts       = 0;
        stats->syn_ack_pkts   = 0;
        stats->fin_ack_pkts   = 0;
        stats->rst_pkts       = 0;
        stats->inbound_bytes  = 0;
        stats->outbound_bytes = 0;

        /* Reset HyperLogLog counters (fresh sketch every second) */
        hll_init(&stats->unique_src_ips,   0x12345678 + stats->dst_ip);
        hll_init(&stats->unique_dst_ports, 0x87654321 + stats->dst_ip);
        hll_init(&stats->udp_flows,        0xABCDEF00 + stats->dst_ip);

        /*
         * NOTE: EWMA states (stats->ewma) are intentionally NOT reset here.
         * They accumulate across periods to build up the long-running
         * baseline model for each destination IP.
         */
    }
}