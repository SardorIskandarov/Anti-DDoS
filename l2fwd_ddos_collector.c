#include "l2fwd_ddos_collector.h"
#include "l2fwd_detection_engine.h"
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
#include <rte_cycles.h>
#include <rte_malloc.h>

/*
 * port_stats — allocated on the heap at startup via rte_zmalloc.
 *
 * A static array of struct port_stats is ~2.1 GB (RTE_MAX_ETHPORTS=32 ×
 * 1024 dst_ip entries × ~66 KB each), which exceeds the ±2 GB signed
 * 32-bit PC-relative addressing range and causes R_X86_64_PC32 relocation
 * truncation errors at link time.  Heap allocation places the object in a
 * region reachable via a 64-bit absolute pointer, bypassing the constraint.
 */
struct port_stats *port_stats = NULL;

/* Socket */
#define SOCK_PATH "/tmp/ddos_stats_socket"
static int sock_fd = -1;
static struct sockaddr_un server_addr;

/* CSV file for raw features logging */
static FILE *csv_file = NULL;
static bool csv_header_written = false;
#define CSV_PATH "/tmp/ddos_raw_features.csv"

// ============================================================================
// HYPERLOGLOG IMPLEMENTATION
// ============================================================================

static inline uint8_t clz32(uint32_t x) {
    if (x == 0) return 32;
    return __builtin_clz(x);
}

void hll_init(struct hll_counter *hll, uint64_t seed) {
    memset(hll->registers, 0, HLL_SIZE);
    hll->seed = seed;
}

void hll_add(struct hll_counter *hll, const void *data, size_t len) {
    uint32_t hash  = rte_hash_crc(data, len, hll->seed);
    uint32_t index = hash >> (32 - HLL_PRECISION);
    uint32_t w     = hash << HLL_PRECISION;
    uint8_t  lz    = clz32(w) + 1;
    if (lz > hll->registers[index])
        hll->registers[index] = lz;
}

uint64_t hll_count(const struct hll_counter *hll) {
    double   raw   = 0.0;
    uint32_t zeros = 0;
    for (uint32_t i = 0; i < HLL_SIZE; i++) {
        raw += 1.0 / (1ULL << hll->registers[i]);
        if (hll->registers[i] == 0) zeros++;
    }
    double est = HLL_ALPHA_16384 * HLL_SIZE * HLL_SIZE / raw;
    if (est <= 5.0 * HLL_SIZE && zeros != 0)
        est = HLL_SIZE * log((double)HLL_SIZE / zeros);
    if (est > (double)((uint64_t)1 << 32) / 30.0)
        est = -((double)((uint64_t)1 << 32)) * log(1.0 - est / ((uint64_t)1 << 32));
    return (uint64_t)est;
}

// ============================================================================
// EWMA IMPLEMENTATION  (with variance ceiling - IMPROVEMENT 1)
// ============================================================================

void ewma_update(struct ewma_state *s, double x) {
    if (s->n == 0) {
        s->mean = x;
        s->variance = 0.0;
    } else {
        // Update mean
        s->mean += s->alpha * (x - s->mean);
        
        // Update variance (EWMA on squared residuals)
        double residual = x - s->mean;
        double new_variance = s->variance + s->alpha * (residual * residual - s->variance);
        
        // IMPROVEMENT 1: Initialize variance ceiling at warmup completion
        if (s->n == EWMA_WARMUP_PERIODS - 1 && !s->ceiling_initialized) {
            s->initial_std = sqrt(s->variance);
            if (s->initial_std > EWMA_EPSILON) {
                s->variance_max = (3.0 * s->initial_std) * (3.0 * s->initial_std);
                s->ceiling_initialized = true;
            }
        }
        
        // IMPROVEMENT 1: Apply variance ceiling (3× initial variance)
        if (s->ceiling_initialized && new_variance > s->variance_max) {
            new_variance = s->variance_max;
        }
        
        s->variance = new_variance;
    }
    if (s->n < UINT32_MAX) s->n++;
}

double ewma_mean(const struct ewma_state *s) {
    return s->mean;
}

// ============================================================================
// BURST WINDOW IMPLEMENTATION
// ============================================================================

void burst_window_push(struct burst_window *bw, uint64_t value) {
    bw->total -= bw->buckets[bw->index];
    bw->buckets[bw->index] = value;
    bw->total += value;
    bw->index = (bw->index + 1) % BURST_WINDOW_MAX_SEC;
    if (bw->filled < BURST_WINDOW_MAX_SEC) bw->filled++;
}

double burst_window_avg(const struct burst_window *bw) {
    uint8_t n = (bw->filled < BURST_LONG_WINDOW_SEC)
                    ? bw->filled : BURST_LONG_WINDOW_SEC;
    if (n == 0) return 0.0;
    if (bw->filled <= BURST_LONG_WINDOW_SEC)
        return (double)bw->total / n;
    /* Re-sum most recent BURST_LONG_WINDOW_SEC buckets */
    uint64_t sum  = 0;
    int      start = (int)bw->index - BURST_LONG_WINDOW_SEC;
    for (int k = 0; k < BURST_LONG_WINDOW_SEC; k++) {
        int idx = (start + k + BURST_WINDOW_MAX_SEC) % BURST_WINDOW_MAX_SEC;
        sum += bw->buckets[idx];
    }
    return (double)sum / BURST_LONG_WINDOW_SEC;
}

// ============================================================================
// ALPHA INITIALISATION HELPERS
// ============================================================================

static void init_tier0_alpha(struct tier0_ewma *e) {
    e->pps.alpha       = EWMA_ALPHA_TIER0;
    e->bps.alpha       = EWMA_ALPHA_TIER0;
    e->fps.alpha       = EWMA_ALPHA_TIER0;
    e->burst_pps.alpha = EWMA_ALPHA_TIER0;
    e->burst_bps.alpha = EWMA_ALPHA_TIER0;
    e->burst_fps.alpha = EWMA_ALPHA_TIER0;
}
static void init_tier1_tcp_alpha(struct tier1_tcp_ewma *e) {
    e->syn_ratio.alpha      = EWMA_ALPHA_TIER1_1;
    e->synack_ratio.alpha   = EWMA_ALPHA_TIER1_1;
    e->finack_ratio.alpha   = EWMA_ALPHA_TIER1_1;
    e->rst_ratio.alpha      = EWMA_ALPHA_TIER1_1;
    e->ack_data_ratio.alpha = EWMA_ALPHA_TIER1_1;
    e->tcp_pps_ratio.alpha  = EWMA_ALPHA_TIER1_1;
    e->tcp_bps_ratio.alpha  = EWMA_ALPHA_TIER1_1;
}
static void init_tier1_udp_alpha(struct tier1_udp_ewma *e) {
    e->udp_bps_ratio.alpha  = EWMA_ALPHA_TIER1_2;
    e->udp_pps_ratio.alpha  = EWMA_ALPHA_TIER1_2;
    e->udp_flow_ratio.alpha = EWMA_ALPHA_TIER1_2;
}
static void init_tier1_icmp_alpha(struct tier1_icmp_ewma *e) {
    e->icmp_echo_ratio.alpha = EWMA_ALPHA_TIER1_3;
    e->icmp_pps_ratio.alpha  = EWMA_ALPHA_TIER1_3;
}
static void init_tier1_dist_alpha(struct tier1_dist_ewma *e) {
    e->src_ip_ratio.alpha   = EWMA_ALPHA_TIER1_4;
    e->dst_port_ratio.alpha = EWMA_ALPHA_TIER1_4;
}

// ============================================================================
// DESTINATION IP TABLE
// ============================================================================

static uint32_t dst_ip_hash(uint32_t ip) { return ip % MAX_DST_IPS; }

struct dst_ip_stats *dst_ip_table_get_or_create(struct dst_ip_table *table,
                                                  uint32_t dst_ip,
                                                  uint64_t timestamp,
                                                  uint16_t portid) {
    uint32_t index    = dst_ip_hash(dst_ip);
    uint32_t attempts = 0;

    while (attempts < MAX_DST_IPS) {
        struct dst_ip_stats *e = &table->entries[index];

        if (e->active && e->dst_ip == dst_ip)
            return e;

        if (!e->active) {
            memset(e, 0, sizeof(*e));
            e->dst_ip      = dst_ip;
            e->active      = 1;
            e->last_update = timestamp;

            /* HLL seeds — use different constants per estimator */
            hll_init(&e->unique_src_ips,  0x11111111 + dst_ip);
            hll_init(&e->unique_dst_ports,0x22222222 + dst_ip);
            hll_init(&e->udp_flows,       0x33333333 + dst_ip);
            hll_init(&e->unique_flows,    0x44444444 + dst_ip);

            /* Set per-tier EWMA alphas */
            init_tier0_alpha    (&e->ewma_t0);
            init_tier1_tcp_alpha(&e->ewma_t1_tcp);
            init_tier1_udp_alpha(&e->ewma_t1_udp);
            init_tier1_icmp_alpha(&e->ewma_t1_icmp);
            init_tier1_dist_alpha(&e->ewma_t1_dist);

            /* Allocate and initialise detection engine */
            e->detection = (struct detection_engine *)
                            malloc(sizeof(struct detection_engine));
            if (e->detection) {
                detection_engine_init(e->detection, timestamp);
            } else {
                printf("[Collector] ERROR: malloc failed for detection engine\n");
            }

            return e;
        }

        index = (index + 1) % MAX_DST_IPS;
        attempts++;
    }
    return NULL;
}

// ============================================================================
// COLLECTOR INIT
// ============================================================================

void ddos_collector_init(void) {
    printf("[Collector] Initialising per-dst-IP tracking (MAX_DST_IPS=%d)\n",
           MAX_DST_IPS);

    port_stats = rte_zmalloc("port_stats",
                             sizeof(struct port_stats) * RTE_MAX_ETHPORTS,
                             RTE_CACHE_LINE_SIZE);
    if (port_stats == NULL) {
        rte_exit(EXIT_FAILURE,
                 "[Collector] FATAL: rte_zmalloc failed for port_stats "
                 "(%zu bytes)\n",
                 sizeof(struct port_stats) * RTE_MAX_ETHPORTS);
    }

    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sun_family = AF_UNIX;
    strncpy(server_addr.sun_path, SOCK_PATH,
            sizeof(server_addr.sun_path) - 1);
    
    /* Remove old CSV file if exists */
    remove(CSV_PATH);
    
    /* ★ ADD THESE LINES TO CREATE FILE IMMEDIATELY ★ */
    csv_file = fopen(CSV_PATH, "w");
    if (csv_file != NULL) {
        printf("[Collector] CSV file pre-created at %s\n", CSV_PATH);
        fclose(csv_file);
        csv_file = NULL;  /* Will be reopened on first write */
    }
    
    printf("[Collector] Initialisation complete\n");
}

static void check_and_connect_socket(void) {
    if (sock_fd >= 0) return;
    sock_fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (sock_fd < 0) { perror("[Collector] socket()"); return; }
    if (connect(sock_fd, (struct sockaddr *)&server_addr,
                sizeof(server_addr)) < 0) {
        close(sock_fd);
        sock_fd = -1;
    } else {
        printf("[Collector] Connected to Python receiver at %s\n", SOCK_PATH);
    }
}

// ============================================================================
// PACKET STATISTICS COLLECTION
// ============================================================================

void ddos_collect_packet_stats(struct rte_mbuf *m, unsigned portid) {
    struct rte_ether_hdr *eth_hdr;
    struct rte_vlan_hdr  *vlan_hdr;
    struct rte_ipv4_hdr  *ipv4_hdr;
    struct rte_tcp_hdr   *tcp_hdr;
    struct rte_udp_hdr   *udp_hdr;
    struct rte_icmp_hdr  *icmp_hdr;
    uint16_t etype;
    uint16_t offset    = sizeof(struct rte_ether_hdr);
    uint64_t timestamp = rte_get_timer_cycles();

    // if (unlikely(portid != MONITORED_PORT)) return;
    if (unlikely(portid >= RTE_MAX_ETHPORTS)) return;
    if (unlikely(port_stats == NULL)) return;

    eth_hdr = rte_pktmbuf_mtod(m, struct rte_ether_hdr *);
    etype   = rte_be_to_cpu_16(eth_hdr->ether_type);

    /* Strip VLAN tags */
    while (etype == RTE_ETHER_TYPE_VLAN || etype == RTE_ETHER_TYPE_QINQ) {
        vlan_hdr = rte_pktmbuf_mtod_offset(m, struct rte_vlan_hdr *, offset);
        etype    = rte_be_to_cpu_16(vlan_hdr->eth_proto);
        offset  += sizeof(struct rte_vlan_hdr);
    }
    if (etype != RTE_ETHER_TYPE_IPV4) return;

    ipv4_hdr = rte_pktmbuf_mtod_offset(m, struct rte_ipv4_hdr *, offset);
    uint32_t src_ip   = rte_be_to_cpu_32(ipv4_hdr->src_addr);
    uint32_t dst_ip   = rte_be_to_cpu_32(ipv4_hdr->dst_addr);
    uint8_t  protocol = ipv4_hdr->next_proto_id;
    uint16_t ip_hl    = ipv4_hdr->ihl * 4;

    struct dst_ip_stats *s = dst_ip_table_get_or_create(
        &port_stats[portid].dst_table, dst_ip, timestamp, portid);
    if (!s) return;

    s->total_pkts++;
    s->total_bytes += m->pkt_len;
    s->last_update  = timestamp;

    /* Track unique source IPs (Tier 1.4) */
    hll_add(&s->unique_src_ips, &src_ip, sizeof(src_ip));

    switch (protocol) {

    case IPPROTO_TCP: {
        tcp_hdr = (struct rte_tcp_hdr *)((char *)ipv4_hdr + ip_hl);
        uint16_t src_port = rte_be_to_cpu_16(tcp_hdr->src_port);
        uint16_t dst_port = rte_be_to_cpu_16(tcp_hdr->dst_port);
        uint8_t  flags    = tcp_hdr->tcp_flags;

        s->tcp_pkts++;
        s->tcp_bytes += m->pkt_len;

        hll_add(&s->unique_dst_ports, &dst_port, sizeof(dst_port));

        /* Five-tuple for FPS: (src_ip, src_port, dst_port, proto=TCP) */
        struct { uint32_t sip; uint16_t sp; uint16_t dp; uint8_t proto; }
            flow_key = { src_ip, src_port, dst_port, IPPROTO_TCP };
        hll_add(&s->unique_flows, &flow_key, sizeof(flow_key));

        /* Classify TCP flags */
        uint8_t syn = !!(flags & RTE_TCP_SYN_FLAG);
        uint8_t ack = !!(flags & RTE_TCP_ACK_FLAG);
        uint8_t fin = !!(flags & RTE_TCP_FIN_FLAG);
        uint8_t rst = !!(flags & RTE_TCP_RST_FLAG);

        if (syn && !ack)          s->syn_pkts++;
        if (syn &&  ack)          s->syn_ack_pkts++;
        if (fin &&  ack)          s->fin_ack_pkts++;
        if (rst)                  s->rst_pkts++;
        /* ACK-only data packet: ACK set, no SYN / FIN / RST */
        if (ack && !syn && !fin && !rst) s->ack_data_pkts++;

        break;
    }

    case IPPROTO_UDP: {
        udp_hdr = (struct rte_udp_hdr *)((char *)ipv4_hdr + ip_hl);
        uint16_t src_port = rte_be_to_cpu_16(udp_hdr->src_port);
        uint16_t dst_port = rte_be_to_cpu_16(udp_hdr->dst_port);

        s->udp_pkts++;
        s->udp_bytes += m->pkt_len;

        hll_add(&s->unique_dst_ports, &dst_port, sizeof(dst_port));

        /* UDP flow key: (src_ip, src_port) */
        struct { uint32_t sip; uint16_t sp; } udp_key = { src_ip, src_port };
        hll_add(&s->udp_flows, &udp_key, sizeof(udp_key));

        /* Five-tuple for FPS */
        struct { uint32_t sip; uint16_t sp; uint16_t dp; uint8_t proto; }
            flow_key = { src_ip, src_port, dst_port, IPPROTO_UDP };
        hll_add(&s->unique_flows, &flow_key, sizeof(flow_key));

        break;
    }

    case IPPROTO_ICMP: {
        icmp_hdr = (struct rte_icmp_hdr *)((char *)ipv4_hdr + ip_hl);
        s->icmp_pkts++;
        if (icmp_hdr->icmp_type == RTE_IP_ICMP_ECHO_REQUEST)
            s->icmp_echo_pkts++;

        /* Five-tuple for FPS (ICMP has no ports; use type/code as proxy) */
        struct { uint32_t sip; uint8_t type; uint8_t code; uint8_t proto; }
            flow_key = { src_ip, icmp_hdr->icmp_type,
                         icmp_hdr->icmp_code, IPPROTO_ICMP };
        hll_add(&s->unique_flows, &flow_key, sizeof(flow_key));
        break;
    }

    default:
        break;
    }
}

// ============================================================================
// CSV RAW FEATURES LOGGING
// ============================================================================

// ============================================================================
// CSV RAW FEATURES LOGGING (HUMAN-READABLE FORMAT)
// ============================================================================

// ============================================================================
// CSV RAW FEATURES LOGGING (HUMAN-READABLE FORMAT - FILTERED TO SINGLE IP)
// ============================================================================

static void log_raw_features_to_csv(long long timestamp_ms,
                                      uint32_t dst_ip,
                                      const struct tier0_features *t0,
                                      const struct tier1_tcp_features *t1_tcp,
                                      const struct tier1_udp_features *t1_udp,
                                      const struct tier1_icmp_features *t1_icmp,
                                      const struct tier1_dist_features *t1_dist) {
    
    /* ★ FILTER: Only log data for IP 93.188.85.234 ★ */
    if (dst_ip != DEBUG_IP) return;  /* 93.188.85.234 in host byte order */
    
    /* Open CSV file on first call */
    if (csv_file == NULL) {
        csv_file = fopen(CSV_PATH, "w");
        if (csv_file == NULL) {
            perror("[Collector] Failed to open CSV file");
            return;
        }
        printf("[Collector] CSV raw features log created at %s (filtering IP: 93.188.85.34)\n", CSV_PATH);
    }

    /* Write CSV header on first write with clear, descriptive names */
    if (!csv_header_written) {
        fprintf(csv_file,
                /* Basic Info */
                "timestamp_ms,dst_ip,"
                
                /* Volume Metrics (easy to spot floods) */
                "pps_packets_per_sec,bps_bits_per_sec,fps_flows_per_sec,"
                
                /* TCP Behavior (spot SYN/ACK/RST floods) */
                "tcp_syn_ratio,tcp_synack_ratio,tcp_finack_ratio,tcp_rst_ratio,tcp_ack_data_ratio,"
                "tcp_pps_dominance,tcp_bps_dominance,"
                
                /* UDP Behavior (spot UDP floods) */
                "udp_bps_dominance,udp_pps_dominance,udp_flow_diversity,"
                
                /* ICMP Behavior (spot ping floods) */
                "icmp_echo_ratio,icmp_pps_dominance,"
                
                /* Distribution (spot botnets) */
                "unique_sources_ratio,unique_ports_ratio,"
                
                /* Quick Analysis Columns (ADDED FOR CLARITY) */
                "dominant_protocol,attack_indicators\n");
        csv_header_written = true;
    }

    /* Convert IP to string */
    struct in_addr addr;
    addr.s_addr = htonl(dst_ip);
    char dst_ip_str[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &addr, dst_ip_str, sizeof(dst_ip_str));

    // /* Determine dominant protocol */
    // const char *dominant_proto = "MIXED";
    // if (t1_tcp->tcp_pps_ratio > 0.80) dominant_proto = "TCP";
    // else if (t1_udp->udp_pps_ratio > 0.80) dominant_proto = "UDP";
    // else if (t1_icmp->icmp_pps_ratio > 0.80) dominant_proto = "ICMP";

    // /* Build attack indicators string (visual flags) */
    // char indicators[128] = "";
    // int suspicious = 0;
    
    // if (t0->pps > 10000) { strcat(indicators, "HIGH_PPS "); suspicious++; }
    // if (t0->bps > 100000000) { strcat(indicators, "HIGH_BPS "); suspicious++; }
    // if (t1_tcp->syn_ratio > 0.80) { strcat(indicators, "SYN_FLOOD? "); suspicious++; }
    // if (t1_tcp->rst_ratio > 0.50) { strcat(indicators, "RST_FLOOD? "); suspicious++; }
    // if (t1_udp->udp_pps_ratio > 0.90) { strcat(indicators, "UDP_FLOOD? "); suspicious++; }
    // if (t1_icmp->icmp_pps_ratio > 0.80) { strcat(indicators, "ICMP_FLOOD? "); suspicious++; }
    // if (t1_dist->src_ip_ratio > 0.50) { strcat(indicators, "BOTNET? "); suspicious++; }
    // if (t1_dist->dst_port_ratio > 0.80) { strcat(indicators, "PORT_SCAN? "); suspicious++; }
    
    // if (suspicious == 0) strcpy(indicators, "CLEAN");

    /* Write data with better formatting */
    fprintf(csv_file,
            /* Basic Info */
            "%lld,%s,"
            
            /* Volume (formatted for readability) */
            "%.0f,%.0f,%.0f,"
            
            /* TCP Behavior (0.0000 = 0%, 1.0000 = 100%) */
            "%.2f%%,%.2f%%,%.2f%%,%.2f%%,%.2f%%,"
            "%.2f%%,%.2f%%,"
            
            /* UDP Behavior */
            "%.2f%%,%.2f%%,%.2f%%,"
            
            /* ICMP Behavior */
            "%.2f%%,%.2f%%,"
            
            /* Distribution */
            "%.2f%%,%.2f%%,"
            
            /* Quick Analysis */
            "%s,%s\n",
            
            /* Values */
            timestamp_ms, dst_ip_str,
            
            /* Volume */
            t0->pps, t0->bps, t0->fps,
            
            /* TCP (multiply by 100 for percentage) */
            t1_tcp->syn_ratio * 100.0,
            t1_tcp->synack_ratio * 100.0,
            t1_tcp->finack_ratio * 100.0,
            t1_tcp->rst_ratio * 100.0,
            t1_tcp->ack_data_ratio * 100.0,
            t1_tcp->tcp_pps_ratio * 100.0,
            t1_tcp->tcp_bps_ratio * 100.0,
            
            /* UDP */
            t1_udp->udp_bps_ratio * 100.0,
            t1_udp->udp_pps_ratio * 100.0,
            t1_udp->udp_flow_ratio * 100.0,
            
            /* ICMP */
            t1_icmp->icmp_echo_ratio * 100.0,
            t1_icmp->icmp_pps_ratio * 100.0,
            
            /* Distribution */
            t1_dist->src_ip_ratio * 100.0,
            t1_dist->dst_port_ratio * 100.0);
            
            // /* Quick Analysis */
            // dominant_proto,
            // indicators

    /* Flush immediately for real-time visibility */
    fflush(csv_file);
}

// ============================================================================
// STATISTICS LOGGING, DETECTION & CSV EXPORT
// ============================================================================

/**
 * CSV schema  (60 columns total):
 *
 *  Header (3):
 *    timestamp_ms, port, dst_ip
 *
 *  Tier 0 raw features (6):
 *    pps, bps, fps, burst_pps, burst_bps, burst_fps
 *
 *  Tier 1.1 raw features (7):
 *    tcp_syn_ratio, tcp_synack_ratio, tcp_finack_ratio, tcp_rst_ratio,
 *    tcp_ack_data_ratio, tcp_pps_ratio, tcp_bps_ratio
 *
 *  Tier 1.2 raw features (3):
 *    udp_bps_ratio, udp_pps_ratio, udp_flow_ratio
 *
 *  Tier 1.3 raw features (2):
 *    icmp_echo_ratio, icmp_pps_ratio
 *
 *  Tier 1.4 raw features (2):
 *    src_ip_ratio, dst_port_ratio
 *
 *  Tier 0 EWMA means (6):
 *    em_pps, em_bps, em_fps, em_burst_pps, em_burst_bps, em_burst_fps
 *
 *  Tier 1.1 EWMA means (7):
 *    em_tcp_syn_ratio .. em_tcp_bps_ratio
 *
 *  Tier 1.2 EWMA means (3):
 *    em_udp_bps_ratio, em_udp_pps_ratio, em_udp_flow_ratio
 *
 *  Tier 1.3 EWMA means (2):
 *    em_icmp_echo_ratio, em_icmp_pps_ratio
 *
 *  Tier 1.4 EWMA means (2):
 *    em_src_ip_ratio, em_dst_port_ratio
 *
 *  Detection fields (15):
 *    detection_state,
 *    tier0_global_risk,
 *    tier0_risk_pps, tier0_risk_bps, tier0_risk_fps,
 *    tier0_risk_burst_pps, tier0_risk_burst_bps, tier0_risk_burst_fps,
 *    tier1_tcp_score, tier1_udp_score, tier1_icmp_score, tier1_dist_score,
 *    tier1_final_score,
 *    tier1_evaluated,
 *    warmup_remaining
 *
 *  HLL observability fields (2):
 *    unique_src_ips,
 *    unique_dst_ports
 */
void ddos_log_and_reset_stats(void) {
    struct timespec ts;
    long long timestamp_ms;

    /*
     * 60 fields × ~12 chars + separators still fits comfortably in 1536 bytes.
     */
    char buffer[1536];
    int  len;

    check_and_connect_socket();

    if (unlikely(port_stats == NULL)) return;

    clock_gettime(0, &ts);
    timestamp_ms = (long long)ts.tv_sec * 1000LL +
                   (long long)ts.tv_nsec / 1000000LL;

    for (uint16_t port = 0; port < RTE_MAX_ETHPORTS; port++) {
        struct dst_ip_table *table = &port_stats[port].dst_table;

        for (uint32_t i = 0; i < MAX_DST_IPS; i++) {
            struct dst_ip_stats *s = &table->entries[i];
            if (!s->active) continue;
            if (s->total_pkts == 0) continue;

            struct in_addr addr;
            addr.s_addr = htonl(s->dst_ip);
            char dst_ip_str[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &addr, dst_ip_str, sizeof(dst_ip_str));

            // you should remove it later
            if (s->dst_ip == DEBUG_IP) {
                printf("[DEBUG] Processing port=%u dst_ip=%s (0x%08x), pkts=%llu\n",
                    port,
                    dst_ip_str,
                    s->dst_ip,
                    (unsigned long long)s->total_pkts);
            }

            uint64_t now       = rte_get_timer_cycles();
            double   time_sec  = (double)STATS_PERIOD_US / 1000000.0;

            /* ----------------------------------------------------------------
             * STEP 1: Push current window into burst circular buffers.
             *         (Must happen before feature extraction so burst factors
             *          incorporate the current second's counts.)
             * -------------------------------------------------------------- */
            burst_window_push(&s->bw_pps, s->total_pkts);
            burst_window_push(&s->bw_bps, s->total_bytes * 8);
            burst_window_push(&s->bw_fps, hll_count(&s->unique_flows));

            /* ----------------------------------------------------------------
             * STEP 2: Extract raw feature vectors for all tiers.
             * -------------------------------------------------------------- */
            struct tier0_features      t0;
            struct tier1_tcp_features  t1_tcp;
            struct tier1_udp_features  t1_udp;
            struct tier1_icmp_features t1_icmp;
            struct tier1_dist_features t1_dist;

            extract_tier0_features     (s, &t0,     time_sec);
            extract_tier1_tcp_features (s, &t1_tcp,  time_sec);
            extract_tier1_udp_features (s, &t1_udp,  time_sec);
            extract_tier1_icmp_features(s, &t1_icmp, time_sec);
            extract_tier1_dist_features(s, &t1_dist, time_sec);

            /* Log raw features to CSV file */
            log_raw_features_to_csv(timestamp_ms, s->dst_ip, &t0, &t1_tcp, &t1_udp, &t1_icmp, &t1_dist);

            /* ----------------------------------------------------------------
             * STEP 3: Run the detection engine (updates EWMA baselines too).
             * -------------------------------------------------------------- */
            struct detection_result det;
            memset(&det, 0, sizeof(det));
            if (s->detection) {
                det = detection_engine_process(s->detection, s, now, s->dst_ip);
            }

            /* ----------------------------------------------------------------
             * STEP 4: Snapshot EWMA means for CSV output.
             * -------------------------------------------------------------- */
            /* Tier 0 */
            double em_pps       = s->ewma_t0.pps.mean;
            double em_bps       = s->ewma_t0.bps.mean;
            double em_fps       = s->ewma_t0.fps.mean;
            double em_burst_pps = s->ewma_t0.burst_pps.mean;
            double em_burst_bps = s->ewma_t0.burst_bps.mean;
            double em_burst_fps = s->ewma_t0.burst_fps.mean;

            /* Tier 1.1 */
            double em_syn       = s->ewma_t1_tcp.syn_ratio.mean;
            double em_synack    = s->ewma_t1_tcp.synack_ratio.mean;
            double em_finack    = s->ewma_t1_tcp.finack_ratio.mean;
            double em_rst       = s->ewma_t1_tcp.rst_ratio.mean;
            double em_ack_data  = s->ewma_t1_tcp.ack_data_ratio.mean;
            double em_tcp_pps_r = s->ewma_t1_tcp.tcp_pps_ratio.mean;
            double em_tcp_bps_r = s->ewma_t1_tcp.tcp_bps_ratio.mean;

            /* Tier 1.2 */
            double em_udp_bps_r  = s->ewma_t1_udp.udp_bps_ratio.mean;
            double em_udp_pps_r  = s->ewma_t1_udp.udp_pps_ratio.mean;
            double em_udp_flow_r = s->ewma_t1_udp.udp_flow_ratio.mean;

            /* Tier 1.3 */
            double em_icmp_echo  = s->ewma_t1_icmp.icmp_echo_ratio.mean;
            double em_icmp_pps_r = s->ewma_t1_icmp.icmp_pps_ratio.mean;

            /* Tier 1.4 */
            double em_src_ip_r  = s->ewma_t1_dist.src_ip_ratio.mean;
            double em_dst_port_r = s->ewma_t1_dist.dst_port_ratio.mean;

            /* ----------------------------------------------------------------
             * STEP 5: Format and emit CSV.
             * -------------------------------------------------------------- */
            uint32_t warmup_rem = 0;
            uint64_t unique_src_ips = hll_count(&s->unique_src_ips);
            uint64_t unique_dst_ports = hll_count(&s->unique_dst_ports);
            if (s->detection && s->detection->state == DETECTION_STATE_WARMUP) {
                uint32_t wc = s->detection->warmup_counter;
                warmup_rem  = (wc < DETECTION_WARMUP_WINDOWS)
                                ? (DETECTION_WARMUP_WINDOWS - wc) : 0;
            }

            len = snprintf(buffer, sizeof(buffer),
                /* Header */
                "%lld,%u,%s,"
                /* Tier 0 raw (6) */
                "%.2f,%.2f,%.2f,%.4f,%.4f,%.4f,"
                /* Tier 1.1 raw (7) */
                "%.4f,%.4f,%.4f,%.4f,%.4f,%.4f,%.4f,"
                /* Tier 1.2 raw (3) */
                "%.4f,%.4f,%.4f,"
                /* Tier 1.3 raw (2) */
                "%.4f,%.4f,"
                /* Tier 1.4 raw (2) */
                "%.4f,%.4f,"
                /* Tier 0 EWMA means (6) */
                "%.2f,%.2f,%.2f,%.4f,%.4f,%.4f,"
                /* Tier 1.1 EWMA means (7) */
                "%.4f,%.4f,%.4f,%.4f,%.4f,%.4f,%.4f,"
                /* Tier 1.2 EWMA means (3) */
                "%.4f,%.4f,%.4f,"
                /* Tier 1.3 EWMA means (2) */
                "%.4f,%.4f,"
                /* Tier 1.4 EWMA means (2) */
                "%.4f,%.4f,"
                /* Detection (15) */
                "%s,%.4f,%.4f,%.4f,%.4f,%.4f,%.4f,%.4f,%.4f,%.4f,%.4f,%.4f,%.4f,%d,%u,"
                /* HLL observability (2) */
                "%llu,%llu\n",

                /* Header values */
                timestamp_ms, (unsigned)port, dst_ip_str,
                /* Tier 0 raw */
                t0.pps, t0.bps, t0.fps,
                t0.burst_pps, t0.burst_bps, t0.burst_fps,

                /* Tier 1.1 raw */
                t1_tcp.syn_ratio, t1_tcp.synack_ratio,
                t1_tcp.finack_ratio, t1_tcp.rst_ratio,
                t1_tcp.ack_data_ratio,
                t1_tcp.tcp_pps_ratio, t1_tcp.tcp_bps_ratio,

                /* Tier 1.2 raw */
                t1_udp.udp_bps_ratio, t1_udp.udp_pps_ratio, t1_udp.udp_flow_ratio,

                /* Tier 1.3 raw */
                t1_icmp.icmp_echo_ratio, t1_icmp.icmp_pps_ratio,

                /* Tier 1.4 raw */
                t1_dist.src_ip_ratio, t1_dist.dst_port_ratio,

                /* Tier 0 EWMA means */
                em_pps, em_bps, em_fps,
                em_burst_pps, em_burst_bps, em_burst_fps,

                /* Tier 1.1 EWMA means */
                em_syn, em_synack, em_finack, em_rst, em_ack_data,
                em_tcp_pps_r, em_tcp_bps_r,

                /* Tier 1.2 EWMA means */
                em_udp_bps_r, em_udp_pps_r, em_udp_flow_r,

                /* Tier 1.3 EWMA means */
                em_icmp_echo, em_icmp_pps_r,

                /* Tier 1.4 EWMA means */
                em_src_ip_r, em_dst_port_r,

                /* Detection fields */
                detection_state_str(det.state),
                det.tier0_global_risk,
                det.tier0_risk_pps, det.tier0_risk_bps, det.tier0_risk_fps,
                det.tier0_risk_burst_pps, det.tier0_risk_burst_bps, det.tier0_risk_burst_fps,
                det.tier1_tcp_score,  det.tier1_udp_score,
                det.tier1_icmp_score, det.tier1_dist_score,
                det.tier1_final_score,
                (int)det.tier1_evaluated,
                warmup_rem,

                /* HLL observability */
                (unsigned long long)unique_src_ips,
                (unsigned long long)unique_dst_ports);

            if (sock_fd >= 0) {
                if (send(sock_fd, buffer, len, MSG_NOSIGNAL) < 0) {
                    perror("[Collector] send()");
                    close(sock_fd);
                    sock_fd = -1;
                }
            }

            /* ----------------------------------------------------------------
             * STEP 6: Reset per-window counters and HLL sketches.
             *         EWMA states and burst window buffers are NOT reset.
             * -------------------------------------------------------------- */
            s->total_pkts     = 0;
            s->total_bytes    = 0;
            s->tcp_pkts       = 0;
            s->tcp_bytes      = 0;
            s->udp_pkts       = 0;
            s->udp_bytes      = 0;
            s->icmp_pkts      = 0;
            s->icmp_echo_pkts = 0;
            s->syn_pkts       = 0;
            s->syn_ack_pkts   = 0;
            s->fin_ack_pkts   = 0;
            s->rst_pkts       = 0;
            s->ack_data_pkts  = 0;

            hll_init(&s->unique_src_ips,  0x11111111 + s->dst_ip);
            hll_init(&s->unique_dst_ports,0x22222222 + s->dst_ip);
            hll_init(&s->udp_flows,       0x33333333 + s->dst_ip);
            hll_init(&s->unique_flows,    0x44444444 + s->dst_ip);
        }
    }
}
