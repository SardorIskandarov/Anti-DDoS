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
 * A static array of struct port_stats is ~2.1 GB (RTE_MAX_ETHPORTS=32 ×
 * 1024 dst_ip entries × ~66 KB each), which exceeds the ±2 GB signed
 * 32-bit PC-relative addressing range and causes R_X86_64_PC32 relocation
 * truncation errors at link time.  Heap allocation places the object in a
 * region reachable via a 64-bit absolute pointer, bypassing the constraint.
 */
struct port_stats *port_stats = NULL;

/* Socket — existing 1-second 62-column IP record stream. Only the IP
 * line emitted in ddos_log_and_reset_stats() may be sent on this fd. */
#define SOCK_PATH "/tmp/ddos_stats_socket"
static int sock_fd = -1;
static struct sockaddr_un server_addr;

/* Temporal socket — separate Unix-domain stream dedicated to the 79-field
 * TEMP records produced by l2fwd_temporal.c. This fd is plumbed into
 * l2_temporal_update_1s() and used by send_temporal_record() exclusively;
 * the existing 62-column IP path never touches it. Drop / reconnect /
 * send-failure handling mirrors the IP path 1:1 but is independent so a
 * temporal hiccup cannot cascade into IP-record loss. */
#define TEMPORAL_SOCK_PATH "/tmp/ddos_temporal_socket"
static int temporal_sock_fd = -1;
static struct sockaddr_un temporal_server_addr;

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

    /* Lock-free monotone-max update on the register byte.
     * Packet-processing lcores may call hll_add concurrently on the same
     * dst_ip entry; a CAS loop keeps the "max leading-zeros" invariant
     * without spinlocks. RELAXED ordering is sufficient — HLL registers
     * have no ordering dependency on other counters. */
    uint8_t cur = __atomic_load_n(&hll->registers[index], __ATOMIC_RELAXED);
    while (lz > cur) {
        if (__atomic_compare_exchange_n(&hll->registers[index], &cur, lz,
                                        false,
                                        __ATOMIC_RELAXED,
                                        __ATOMIC_RELAXED))
            break;
    }
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
// COUNT-MIN SKETCH IMPLEMENTATION  (V3.1)
// ============================================================================

/* ============================================================
 * V3.1: Count-min sketch update inlines.
 *
 * 4 hashes via multiplicative hashing with 4 distinct primes.
 * Update increments one counter per row; estimated count for a
 * key is the minimum across all 4 row counters.
 *
 * Top-K maintained as unsorted array. When an updated estimate
 * exceeds the array's current minimum entry, the key replaces
 * the minimum.
 *
 * NOTE: This is single-writer per dst_ip (the RX core for that
 * dst_ip), so no atomics or locks are needed on the sketch
 * itself. If we ever go multi-RX-core per dst_ip, this MUST
 * change.
 * ============================================================ */

static const uint32_t CM_HASH_PRIMES[4] = {
    2654435761u, 2246822519u, 3266489917u, 668265263u
};

static inline uint32_t cm_hash(uint32_t key, int row, uint32_t cols) {
    uint32_t h = key * CM_HASH_PRIMES[row];
    h ^= h >> 16;
    return h & (cols - 1);  /* cols must be power of 2 */
}

/* Update an unsorted top-K array with a key/count pair.
 * If key is already present, refresh its count. Else if the
 * array minimum is less than the new count, replace the min. */
static inline void cm_topk_update(struct cm_topk_entry *topk,
                                   uint32_t key, uint32_t count) {
    int min_idx = 0;
    uint32_t min_count = topk[0].count;
    for (int i = 0; i < L3_TOPK; i++) {
        if (topk[i].key == key) {
            topk[i].count = count;
            return;
        }
        if (topk[i].count < min_count) {
            min_count = topk[i].count;
            min_idx = i;
        }
    }
    if (count > min_count) {
        topk[min_idx].key   = key;
        topk[min_idx].count = count;
    }
}

/* Update sketch for src_port (16-bit key). */
static inline void cm_update_src_port(struct cm_sketch_src_port *s,
                                       uint16_t src_port) {
    uint32_t key = (uint32_t)src_port;
    uint32_t est = UINT32_MAX;
    for (int r = 0; r < 4; r++) {
        uint32_t c = cm_hash(key, r, 16);
        s->counters[r][c]++;
        if (s->counters[r][c] < est) est = s->counters[r][c];
    }
    cm_topk_update(s->topk, key, est);
}

/* Update sketch for /24 prefix (32-bit key, top 24 bits of src_ip).
 * src_ip is big-endian from the IP header; convert and mask. */
static inline void cm_update_src_24(struct cm_sketch_src_24 *s,
                                     uint32_t src_ip_be) {
    uint32_t key = rte_be_to_cpu_32(src_ip_be) & 0xFFFFFF00u;
    uint32_t est = UINT32_MAX;
    for (int r = 0; r < 4; r++) {
        uint32_t c = cm_hash(key, r, 32);
        s->counters[r][c]++;
        if (s->counters[r][c] < est) est = s->counters[r][c];
    }
    cm_topk_update(s->topk, key, est);
}

// ============================================================================
// ALPHA INITIALISATION HELPERS
// ============================================================================

static void init_tier0_alpha(struct tier0_ewma *e,
                              const struct l2_profile *p) {
    e->pps.alpha       = p->alpha_tier0;
    e->bps.alpha       = p->alpha_tier0;
    e->fps.alpha       = p->alpha_tier0;
    e->burst_pps.alpha = p->alpha_tier0;
    e->burst_bps.alpha = p->alpha_tier0;
    e->burst_fps.alpha = p->alpha_tier0;
}
static void init_tier1_tcp_alpha(struct tier1_tcp_ewma *e,
                                  const struct l2_profile *p) {
    e->syn_ratio.alpha      = p->alpha_tier1_tcp;
    e->synack_ratio.alpha   = p->alpha_tier1_tcp;
    e->finack_ratio.alpha   = p->alpha_tier1_tcp;
    e->rst_ratio.alpha      = p->alpha_tier1_tcp;
    e->ack_data_ratio.alpha = p->alpha_tier1_tcp;
    e->tcp_pps_ratio.alpha  = p->alpha_tier1_tcp;
    e->tcp_bps_ratio.alpha  = p->alpha_tier1_tcp;
    /* V2 features — same alpha as the rest of TCP tier */
    e->empty_ack_ratio.alpha       = p->alpha_tier1_tcp;
    e->zero_window_ratio.alpha     = p->alpha_tier1_tcp;
    e->small_window_ratio.alpha    = p->alpha_tier1_tcp;
    e->new_flow_ratio.alpha        = p->alpha_tier1_tcp;
    e->syn_fin_ratio.alpha         = p->alpha_tier1_tcp;
    e->syn_to_synack_ratio.alpha   = p->alpha_tier1_tcp;
    e->tcp_pkt_size_cov.alpha      = p->alpha_tier1_tcp;
    e->tcp_mean_pkt_size.alpha     = p->alpha_tier1_tcp;
}
static void init_tier1_udp_alpha(struct tier1_udp_ewma *e,
                                  const struct l2_profile *p) {
    e->udp_bps_ratio.alpha  = p->alpha_tier1_udp;
    e->udp_pps_ratio.alpha  = p->alpha_tier1_udp;
    e->udp_flow_ratio.alpha = p->alpha_tier1_udp;
    /* V2 features */
    e->udp_pkt_size_cov.alpha   = p->alpha_tier1_udp;
    e->udp_mean_pkt_size.alpha  = p->alpha_tier1_udp;
}
static void init_tier1_icmp_alpha(struct tier1_icmp_ewma *e,
                                   const struct l2_profile *p) {
    e->icmp_echo_ratio.alpha = p->alpha_tier1_icmp;
    e->icmp_pps_ratio.alpha  = p->alpha_tier1_icmp;
}
static void init_tier1_dist_alpha(struct tier1_dist_ewma *e,
                                   const struct l2_profile *p) {
    e->src_ip_ratio.alpha   = p->alpha_tier1_dist;
    e->dst_port_ratio.alpha = p->alpha_tier1_dist;
}
static inline void init_tier1_l3_alpha(struct dst_ip_stats *e,
                                        const struct l2_profile *p) {
    /* L3 channel uses alpha_tier1_dist cadence — same time-scale
     * as distribution features (slow EWMA, suited to features
     * that move on minute scales not second scales) */
    e->ewma_t1_l3.ttl_stddev.alpha = p->alpha_tier1_dist;
    /* V3.1: sketch-derived features track on the same cadence */
    e->ewma_t1_l3.src_port_top1_share.alpha = p->alpha_tier1_dist;
    e->ewma_t1_l3.src_24_top1_share.alpha   = p->alpha_tier1_dist;
    e->ewma_t1_l3.src_24_entropy.alpha      = p->alpha_tier1_dist;
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

            /* Resolve the Layer-2 profile for this destination IP.
             * Returns the default profile unless an entry exists in
             * the static assignment table in l2fwd_l2_profile.c. */
            e->profile = l2_profile_for_ip(dst_ip);

            /* Multi-timescale temporal observability state. memset above
             * already zeroed every byte; l2_temporal_init re-seeds the
             * per-bucket min sentinels and sets the result phase to
             * L2_TEMPORAL_WARMUP. No reader yet — wired in a later commit. */
            l2_temporal_init(&e->temporal);

            /* HLL seeds — use different constants per estimator */
            hll_init(&e->unique_src_ips,  0x11111111 + dst_ip);
            hll_init(&e->unique_dst_ports,0x22222222 + dst_ip);
            hll_init(&e->udp_flows,       0x33333333 + dst_ip);
            hll_init(&e->unique_flows,    0x44444444 + dst_ip);
            /* V2 */
            hll_init(&e->unique_new_flows, 0x55555555 + dst_ip);

            /* Set per-tier EWMA alphas from the attached profile */
            init_tier0_alpha    (&e->ewma_t0,      e->profile);
            init_tier1_tcp_alpha(&e->ewma_t1_tcp,  e->profile);
            init_tier1_udp_alpha(&e->ewma_t1_udp,  e->profile);
            init_tier1_icmp_alpha(&e->ewma_t1_icmp, e->profile);
            init_tier1_dist_alpha(&e->ewma_t1_dist, e->profile);
            init_tier1_l3_alpha(e, e->profile);

            /* Allocate and initialise detection engine */
            e->detection = (struct detection_engine *)
                            malloc(sizeof(struct detection_engine));
            if (e->detection) {
                detection_engine_init(e->detection, timestamp, e->profile);
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

    /* Independent socket address for TEMP records. Mirrors the IP
     * server_addr setup above but targets TEMPORAL_SOCK_PATH so the
     * temporal stream can connect / disconnect without disturbing the
     * existing 62-column IP path. */
    memset(&temporal_server_addr, 0, sizeof(temporal_server_addr));
    temporal_server_addr.sun_family = AF_UNIX;
    strncpy(temporal_server_addr.sun_path, TEMPORAL_SOCK_PATH,
            sizeof(temporal_server_addr.sun_path) - 1);

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

/* Mirrors check_and_connect_socket() but for the dedicated temporal
 * stream. Independent state (`temporal_sock_fd` / `temporal_server_addr`)
 * means a temporal connect-failure can never affect the IP path's
 * `sock_fd`, and vice versa. send() failures inside the temporal module
 * are swallowed; the next 1Hz tick reopens the socket here. */
static void check_and_connect_temporal_socket(void) {
    if (temporal_sock_fd >= 0) return;
    temporal_sock_fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (temporal_sock_fd < 0) {
        perror("[Collector] temporal socket()");
        return;
    }
    if (connect(temporal_sock_fd,
                (struct sockaddr *)&temporal_server_addr,
                sizeof(temporal_server_addr)) < 0) {
        close(temporal_sock_fd);
        temporal_sock_fd = -1;
    } else {
        printf("[Collector] Connected to temporal receiver at %s\n",
               TEMPORAL_SOCK_PATH);
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

    /* DIRECTIONALITY_EXPERIMENT: increment inbound count for dst_ip.
     * The packet was destined for this IP, so it's inbound from the
     * IP's perspective. */
    __atomic_fetch_add(&s->inbound_pkts, 1, __ATOMIC_RELAXED);

    /* DIRECTIONALITY_EXPERIMENT: also look up src_ip and increment
     * outbound count on its slot. The packet was sent FROM that IP,
     * so it's outbound from that IP's perspective.
     * Note: src_ip lookup may fail (NULL) if the hash table is full
     * with other IPs. That's acceptable — we still get the inbound
     * count, and if the table fills, the diagnostic will reveal it. */
    struct dst_ip_stats *s_src = dst_ip_table_get_or_create(
        &port_stats[portid].dst_table, src_ip, timestamp, portid);
    if (s_src) {
        __atomic_fetch_add(&s_src->outbound_pkts, 1, __ATOMIC_RELAXED);
    }

    /* Hot path: RELAXED atomics keep counter updates lock-free and
     * cache-friendly when multiple lcores touch the same dst_ip entry. */
    __atomic_fetch_add(&s->total_pkts,  1,            __ATOMIC_RELAXED);
    __atomic_fetch_add(&s->total_bytes, m->pkt_len,   __ATOMIC_RELAXED);
    __atomic_store_n  (&s->last_update, timestamp,    __ATOMIC_RELAXED);

    /* Track unique source IPs (Tier 1.4) */
    hll_add(&s->unique_src_ips, &src_ip, sizeof(src_ip));

    /* V3.0: accumulate TTL for stddev computation.
     * Single byte field, no endian conversion needed. */
    uint8_t ttl = ipv4_hdr->time_to_live;
    __atomic_fetch_add(&s->ttl_sum,    (uint64_t)ttl,        __ATOMIC_RELAXED);
    __atomic_fetch_add(&s->ttl_sum_sq, (uint64_t)ttl * ttl,  __ATOMIC_RELAXED);

    /* V3.0: detect IP fragments.
     * Fragment iff (MF flag set) OR (offset != 0).
     * Mask 0x3FFF = MF bit + 13 offset bits; ignores DF bit. */
    uint16_t frag_field = rte_be_to_cpu_16(ipv4_hdr->fragment_offset);
    if ((frag_field & 0x3FFF) != 0) {
        __atomic_fetch_add(&s->ip_frag_pkts, 1, __ATOMIC_RELAXED);
    }

    /* V3.1: update /24 sketch on every IPv4 packet */
    cm_update_src_24(&s->cm_src_24, ipv4_hdr->src_addr);

    switch (protocol) {

    case IPPROTO_TCP: {
        tcp_hdr = (struct rte_tcp_hdr *)((char *)ipv4_hdr + ip_hl);
        uint16_t src_port = rte_be_to_cpu_16(tcp_hdr->src_port);
        uint16_t dst_port = rte_be_to_cpu_16(tcp_hdr->dst_port);
        uint8_t  flags    = tcp_hdr->tcp_flags;

        /* V3.1: update src_port sketch (TCP path) */
        cm_update_src_port(&s->cm_src_port,
                           rte_be_to_cpu_16(tcp_hdr->src_port));

        /* V2: Compute TCP payload length and receive window for behavioral
         * signatures (empty ACK, zero/small window, packet-size CoV). */
        uint16_t tcp_hdr_len = ((tcp_hdr->data_off & 0xf0) >> 4) * 4;
        uint16_t ip_total_len = rte_be_to_cpu_16(ipv4_hdr->total_length);
        int32_t  tcp_payload_len = (int32_t)ip_total_len - ip_hl - tcp_hdr_len;
        if (tcp_payload_len < 0) tcp_payload_len = 0;
        uint16_t rx_win = rte_be_to_cpu_16(tcp_hdr->rx_win);

        __atomic_fetch_add(&s->tcp_pkts,  1,           __ATOMIC_RELAXED);
        __atomic_fetch_add(&s->tcp_bytes, m->pkt_len,  __ATOMIC_RELAXED);

        /* V2: TCP packet-size sum-of-squares (for CoV computation) */
        __atomic_fetch_add(&s->tcp_pkt_size_sum_sq,
                           (uint64_t)m->pkt_len * (uint64_t)m->pkt_len,
                           __ATOMIC_RELAXED);

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

        if (syn && !ack) {
            __atomic_fetch_add(&s->syn_pkts, 1, __ATOMIC_RELAXED);
            /* V2: track unique flows that contained a SYN-only packet */
            hll_add(&s->unique_new_flows, &flow_key, sizeof(flow_key));
        }
        if (syn &&  ack) __atomic_fetch_add(&s->syn_ack_pkts,  1, __ATOMIC_RELAXED);
        if (fin &&  ack) __atomic_fetch_add(&s->fin_ack_pkts,  1, __ATOMIC_RELAXED);
        if (rst)         __atomic_fetch_add(&s->rst_pkts,      1, __ATOMIC_RELAXED);
        /* ACK-only data packet: ACK set, no SYN / FIN / RST */
        if (ack && !syn && !fin && !rst) {
            __atomic_fetch_add(&s->ack_data_pkts, 1, __ATOMIC_RELAXED);
            /* V2: empty ACK = ACK-only with no payload */
            if (tcp_payload_len == 0) {
                __atomic_fetch_add(&s->empty_ack_pkts, 1, __ATOMIC_RELAXED);
            }
        }

        /* V2: TCP receive window signatures.
         * Zero window: receiver advertised 0 (state-exhaustion signature).
         * Small window: 0 < rx_win < SMALL_WINDOW_THRESHOLD. Mutually
         * exclusive with zero window so each packet contributes to at most
         * one of these counters. */
        if (rx_win == 0) {
            __atomic_fetch_add(&s->zero_window_pkts, 1, __ATOMIC_RELAXED);
        } else if (rx_win < SMALL_WINDOW_THRESHOLD) {
            __atomic_fetch_add(&s->small_window_pkts, 1, __ATOMIC_RELAXED);
        }

        break;
    }

    case IPPROTO_UDP: {
        udp_hdr = (struct rte_udp_hdr *)((char *)ipv4_hdr + ip_hl);
        uint16_t src_port = rte_be_to_cpu_16(udp_hdr->src_port);
        uint16_t dst_port = rte_be_to_cpu_16(udp_hdr->dst_port);

        /* V3.1: update src_port sketch (UDP path) */
        cm_update_src_port(&s->cm_src_port,
                           rte_be_to_cpu_16(udp_hdr->src_port));

        __atomic_fetch_add(&s->udp_pkts,  1,          __ATOMIC_RELAXED);
        __atomic_fetch_add(&s->udp_bytes, m->pkt_len, __ATOMIC_RELAXED);

        /* V2: UDP packet-size sum-of-squares (for CoV computation) */
        __atomic_fetch_add(&s->udp_pkt_size_sum_sq,
                           (uint64_t)m->pkt_len * (uint64_t)m->pkt_len,
                           __ATOMIC_RELAXED);

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
        __atomic_fetch_add(&s->icmp_pkts, 1, __ATOMIC_RELAXED);
        if (icmp_hdr->icmp_type == RTE_IP_ICMP_ECHO_REQUEST)
            __atomic_fetch_add(&s->icmp_echo_pkts, 1, __ATOMIC_RELAXED);

        /* Five-tuple for FPS (ICMP has no ports; use type/code as proxy) */
        struct { uint32_t sip; uint8_t type; uint8_t code; uint8_t proto; }
            flow_key = { src_ip, icmp_hdr->icmp_type,
                         icmp_hdr->icmp_code, IPPROTO_ICMP };
        hll_add(&s->unique_flows, &flow_key, sizeof(flow_key));
        break;
    }

    default:
        /* V3.0: catch GRE (47), ESP (50), IP-in-IP (4), and any
         * other non-TCP/UDP/ICMP traffic. */
        __atomic_fetch_add(&s->other_proto_pkts, 1, __ATOMIC_RELAXED);
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
    
    /* Open CSV file on first call */
    if (csv_file == NULL) {
        csv_file = fopen(CSV_PATH, "w");
        if (csv_file == NULL) {
            perror("[Collector] Failed to open CSV file");
            return;
        }
        printf("[Collector] CSV raw features log created at %s\n", CSV_PATH);
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
            "%.2f%%,%.2f%%\n",

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
 * CSV schema  (94 columns total):
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
 *
 *  Layer-2 profile identity (2, appended):
 *    profile_name, profile_version
 *
 *  V2 EXTENSIONS (added after Layer-2 profile identity columns):
 *
 *  Tier 1.1 raw V2 (8 fields, appended after existing 7 raw):
 *    empty_ack_ratio, zero_window_ratio, small_window_ratio,
 *    new_flow_ratio, syn_fin_ratio, syn_to_synack_ratio,
 *    tcp_pkt_size_cov, tcp_mean_pkt_size
 *
 *  Tier 1.2 raw V2 (2 fields, appended after existing 3 raw):
 *    udp_pkt_size_cov, udp_mean_pkt_size
 *
 *  Tier 1.1 EWMA V2 (8 fields, appended after existing 7 EWMA):
 *    em_empty_ack_ratio, em_zero_window_ratio, em_small_window_ratio,
 *    em_new_flow_ratio, em_syn_fin_ratio, em_syn_to_synack_ratio,
 *    em_tcp_pkt_size_cov, em_tcp_mean_pkt_size
 *
 *  Tier 1.2 EWMA V2 (2 fields, appended after existing 3 EWMA):
 *    em_udp_pkt_size_cov, em_udp_mean_pkt_size
 *
 *  Total V2 column delta: +20 columns (10 raw + 10 EWMA).
 *  Total IP CSV column count after V2: 82.
 *
 *  V3.0 EXTENSIONS (appended after Layer-2 profile identity columns
 *  but before any future schema version field):
 *
 *  L3-channel raw (3 fields):
 *    ttl_stddev, ip_frag_ratio, other_proto_ratio
 *
 *  L3-channel derived (3 fields):
 *    em_ttl_stddev, tier1_l3_score, attack_evidence
 *
 *  Total V3.0 column delta: +6 columns.
 *  Total IP CSV column count after V3.0: 88.
 *
 *  V3.1 EXTENSIONS:
 *
 *  L3-channel raw v3.1 (3 fields):
 *    src_port_top1_share, src_24_top1_share, src_24_entropy
 *
 *  L3-channel EWMA companions v3.1 (3 fields):
 *    em_src_port_top1_share, em_src_24_top1_share, em_src_24_entropy
 *
 *  Total V3.1 column delta: +6 columns.
 *  Total IP CSV column count after V3.1: 94.
 *
 *  DIRECTIONALITY_EXPERIMENT (TEMPORARY — REMOVE WHEN DONE):
 *
 *  Diagnostic counters (2 fields, appended at the very end):
 *    inbound_pkts, outbound_pkts
 *
 *  These count, per 1-second window, how many packets had this
 *  dst_ip as the destination vs the source. Pure observability;
 *  does not feed into any scoring or detection path.
 *
 *  Total V3.1+DIAGNOSTIC column count: 96.
 */
void ddos_log_and_reset_stats(void) {
    struct timespec ts;
    long long timestamp_ms;

    /*
     * 60 fields × ~12 chars + separators still fits comfortably in 1536 bytes.
     */
    char buffer[2880];  /* DIRECTIONALITY_EXPERIMENT: +2 columns */
    int  len;

    check_and_connect_socket();
    /* Connect / reconnect the temporal stream every tick on the same
     * cadence as the IP stream. Independent fd: a temporal connect
     * failure must not perturb sock_fd. */
    check_and_connect_temporal_socket();

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

            /* V2 TCP EWMA snapshots */
            double em_empty_ack       = s->ewma_t1_tcp.empty_ack_ratio.mean;
            double em_zero_window     = s->ewma_t1_tcp.zero_window_ratio.mean;
            double em_small_window    = s->ewma_t1_tcp.small_window_ratio.mean;
            double em_new_flow        = s->ewma_t1_tcp.new_flow_ratio.mean;
            double em_syn_fin         = s->ewma_t1_tcp.syn_fin_ratio.mean;
            double em_syn_to_synack   = s->ewma_t1_tcp.syn_to_synack_ratio.mean;
            double em_tcp_pkt_size_cov  = s->ewma_t1_tcp.tcp_pkt_size_cov.mean;
            double em_tcp_mean_pkt_size = s->ewma_t1_tcp.tcp_mean_pkt_size.mean;

            /* Tier 1.2 */
            double em_udp_bps_r  = s->ewma_t1_udp.udp_bps_ratio.mean;
            double em_udp_pps_r  = s->ewma_t1_udp.udp_pps_ratio.mean;
            double em_udp_flow_r = s->ewma_t1_udp.udp_flow_ratio.mean;

            /* V2 UDP EWMA snapshots */
            double em_udp_pkt_size_cov  = s->ewma_t1_udp.udp_pkt_size_cov.mean;
            double em_udp_mean_pkt_size = s->ewma_t1_udp.udp_mean_pkt_size.mean;

            /* V3.0: L3-channel snapshot values */
            struct tier1_l3_features t1_l3_snap;
            extract_tier1_l3_features(s, &t1_l3_snap);

            double em_ttl_stddev = s->ewma_t1_l3.ttl_stddev.mean;

            /* V3.1 L3 EWMA snapshots */
            double em_src_port_top1   = s->ewma_t1_l3.src_port_top1_share.mean;
            double em_src_24_top1     = s->ewma_t1_l3.src_24_top1_share.mean;
            double em_src_24_entropy  = s->ewma_t1_l3.src_24_entropy.mean;

            /* tier1_l3_score: re-derived from snapshots for emission.
             * This mirrors how tier1_*_score variables are derived for the
             * existing CSV row. */
            double tier1_l3_score_emit =
                compute_tier1_l3_score(s->profile, &t1_l3_snap, &s->ewma_t1_l3);

            /* Tier 1.3 */
            double em_icmp_echo  = s->ewma_t1_icmp.icmp_echo_ratio.mean;
            double em_icmp_pps_r = s->ewma_t1_icmp.icmp_pps_ratio.mean;

            /* Tier 1.4 */
            double em_src_ip_r  = s->ewma_t1_dist.src_ip_ratio.mean;
            double em_dst_port_r = s->ewma_t1_dist.dst_port_ratio.mean;

            /* DIRECTIONALITY_EXPERIMENT: snapshot inbound/outbound counts */
            uint64_t exp_inbound  = s->inbound_pkts;
            uint64_t exp_outbound = s->outbound_pkts;

            /* ----------------------------------------------------------------
             * STEP 5: Format and emit CSV.
             * -------------------------------------------------------------- */
            uint32_t warmup_rem = 0;
            uint64_t unique_src_ips = hll_count(&s->unique_src_ips);
            uint64_t unique_dst_ports = hll_count(&s->unique_dst_ports);
            if (s->detection && s->detection->state == DETECTION_STATE_WARMUP) {
                uint32_t wc = s->detection->warmup_counter;
                uint32_t wmax = s->profile->warmup_windows;
                warmup_rem   = (wc < wmax) ? (wmax - wc) : 0;
            }

            len = snprintf(buffer, sizeof(buffer),
                /* Header */
                "%lld,%u,%s,"
                /* Tier 0 raw (6) */
                "%.2f,%.2f,%.2f,%.4f,%.4f,%.4f,"
                /* Tier 1.1 raw (15) — was 7 */
                "%.4f,%.4f,%.4f,%.4f,%.4f,%.4f,%.4f,"
                "%.4f,%.4f,%.4f,%.4f,%.4f,%.4f,%.4f,%.2f,"
                /* Tier 1.2 raw (5) — was 3 */
                "%.4f,%.4f,%.4f,"
                "%.4f,%.2f,"
                /* Tier 1.3 raw (2) */
                "%.4f,%.4f,"
                /* Tier 1.4 raw (2) */
                "%.4f,%.4f,"
                /* Tier 0 EWMA means (6) */
                "%.2f,%.2f,%.2f,%.4f,%.4f,%.4f,"
                /* Tier 1.1 EWMA means (15) — was 7 */
                "%.4f,%.4f,%.4f,%.4f,%.4f,%.4f,%.4f,"
                "%.4f,%.4f,%.4f,%.4f,%.4f,%.4f,%.4f,%.2f,"
                /* Tier 1.2 EWMA means (5) — was 3 */
                "%.4f,%.4f,%.4f,"
                "%.4f,%.2f,"
                /* Tier 1.3 EWMA means (2) */
                "%.4f,%.4f,"
                /* Tier 1.4 EWMA means (2) */
                "%.4f,%.4f,"
                /* Detection (15) */
                "%s,%.4f,%.4f,%.4f,%.4f,%.4f,%.4f,%.4f,%.4f,%.4f,%.4f,%.4f,%.4f,%d,%u,"
                /* HLL observability (2) */
                "%llu,%llu,"
                /* Layer-2 profile identity (2) */
                "%s,%s,"
                /* V3.0: ttl_stddev, ip_frag_ratio, other_proto_ratio,
                 *       em_ttl_stddev, tier1_l3_score, attack_evidence */
                "%.4f,%.4f,%.4f,%.4f,%.4f,%.4f"
                /* V3.1: src_port_top1_share, src_24_top1_share, src_24_entropy,
                   em_src_port_top1, em_src_24_top1, em_src_24_entropy */
                ",%.4f,%.4f,%.4f,%.4f,%.4f,%.4f"
                /* DIRECTIONALITY_EXPERIMENT: inbound_pkts, outbound_pkts */
                ",%lu,%lu\n",

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

                /* Tier 1.1 raw V2 */
                t1_tcp.empty_ack_ratio,
                t1_tcp.zero_window_ratio,
                t1_tcp.small_window_ratio,
                t1_tcp.new_flow_ratio,
                t1_tcp.syn_fin_ratio,
                t1_tcp.syn_to_synack_ratio,
                t1_tcp.tcp_pkt_size_cov,
                t1_tcp.tcp_mean_pkt_size,

                /* Tier 1.2 raw */
                t1_udp.udp_bps_ratio, t1_udp.udp_pps_ratio, t1_udp.udp_flow_ratio,

                /* Tier 1.2 raw V2 */
                t1_udp.udp_pkt_size_cov,
                t1_udp.udp_mean_pkt_size,

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

                /* Tier 1.1 EWMA means V2 */
                em_empty_ack,
                em_zero_window,
                em_small_window,
                em_new_flow,
                em_syn_fin,
                em_syn_to_synack,
                em_tcp_pkt_size_cov,
                em_tcp_mean_pkt_size,

                /* Tier 1.2 EWMA means */
                em_udp_bps_r, em_udp_pps_r, em_udp_flow_r,

                /* Tier 1.2 EWMA means V2 */
                em_udp_pkt_size_cov,
                em_udp_mean_pkt_size,

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
                (unsigned long long)unique_dst_ports,

                /* Layer-2 profile identity (names are controlled in-code
                 * and comma-free; no quoting required). Fall back to "-"
                 * if a resolver somehow returned NULL so the CSV line
                 * still has the expected column count. */
                (s->profile && s->profile->name)    ? s->profile->name    : "-",
                (s->profile && s->profile->version) ? s->profile->version : "-",

                /* V3.0 L3-channel */
                t1_l3_snap.ttl_stddev,
                t1_l3_snap.ip_frag_ratio,
                t1_l3_snap.other_proto_ratio,
                em_ttl_stddev,
                tier1_l3_score_emit,
                /* attack_evidence emitted for observability of OR-combination */
                (det.tier1_final_score > tier1_l3_score_emit
                    ? det.tier1_final_score
                    : tier1_l3_score_emit),

                /* V3.1 L3-channel */
                t1_l3_snap.src_port_top1_share,
                t1_l3_snap.src_24_top1_share,
                t1_l3_snap.src_24_entropy,
                em_src_port_top1,
                em_src_24_top1,
                em_src_24_entropy,

                /* DIRECTIONALITY_EXPERIMENT */
                (unsigned long)exp_inbound,
                (unsigned long)exp_outbound);

            if (sock_fd >= 0) {
                if (send(sock_fd, buffer, len, MSG_NOSIGNAL) < 0) {
                    perror("[Collector] send()");
                    close(sock_fd);
                    sock_fd = -1;
                }
            }

            /* ----------------------------------------------------------------
             * STEP 5b: Multi-timescale temporal observability (shadow only).
             *         Folds the just-finished 1-second values into the per-IP
             *         temporal state, rotates the 10s ring when full,
             *         derives 10s / 60s / 300s window_stats locally, runs
             *         shadow scoring + (gated) baseline updates, and best-
             *         effort emits one "TEMP,..." line per finalised scale
             *         on the existing IP socket. Existing 62-column IP CSV
             *         lines are unchanged. Must run AFTER
             *         detection_engine_process() so det carries this
             *         second's verdict, and BEFORE STEP 6 zeroes the
             *         per-window counters this fold reads from. TEMP send
             *         failures are swallowed inside the temporal module
             *         and never affect the IP path.
             * -------------------------------------------------------------- */
            (void)l2_temporal_update_1s(&s->temporal, s,
                                        port, dst_ip_str,
                                        &t0, &t1_tcp, &t1_udp,
                                        &t1_icmp, &t1_dist,
                                        &det, (uint64_t)timestamp_ms,
                                        temporal_sock_fd);

            /* ----------------------------------------------------------------
             * STEP 6: Reset per-window counters and HLL sketches.
             *         EWMA states and burst window buffers are NOT reset.
             * -------------------------------------------------------------- */
            /* RELAXED atomic stores pair with the fetch_add() increments in
             * ddos_collect_packet_stats(). A tiny window (<1us) may lose a
             * handful of increments concurrent with the reset — acceptable
             * at the 1Hz window boundary and avoids per-packet locking. */
            __atomic_store_n(&s->total_pkts,     0, __ATOMIC_RELAXED);
            __atomic_store_n(&s->total_bytes,    0, __ATOMIC_RELAXED);
            __atomic_store_n(&s->tcp_pkts,       0, __ATOMIC_RELAXED);
            __atomic_store_n(&s->tcp_bytes,      0, __ATOMIC_RELAXED);
            __atomic_store_n(&s->udp_pkts,       0, __ATOMIC_RELAXED);
            __atomic_store_n(&s->udp_bytes,      0, __ATOMIC_RELAXED);
            __atomic_store_n(&s->icmp_pkts,      0, __ATOMIC_RELAXED);
            __atomic_store_n(&s->icmp_echo_pkts, 0, __ATOMIC_RELAXED);
            __atomic_store_n(&s->syn_pkts,       0, __ATOMIC_RELAXED);
            __atomic_store_n(&s->syn_ack_pkts,   0, __ATOMIC_RELAXED);
            __atomic_store_n(&s->fin_ack_pkts,   0, __ATOMIC_RELAXED);
            __atomic_store_n(&s->rst_pkts,       0, __ATOMIC_RELAXED);
            __atomic_store_n(&s->ack_data_pkts,  0, __ATOMIC_RELAXED);

            /* V2: reset new behavioral counters at window boundary */
            __atomic_store_n(&s->empty_ack_pkts,       0, __ATOMIC_RELAXED);
            __atomic_store_n(&s->zero_window_pkts,     0, __ATOMIC_RELAXED);
            __atomic_store_n(&s->small_window_pkts,    0, __ATOMIC_RELAXED);
            __atomic_store_n(&s->tcp_pkt_size_sum_sq,  0, __ATOMIC_RELAXED);
            __atomic_store_n(&s->udp_pkt_size_sum_sq,  0, __ATOMIC_RELAXED);

            /* V3.0 resets */
            __atomic_store_n(&s->ttl_sum,          0, __ATOMIC_RELAXED);
            __atomic_store_n(&s->ttl_sum_sq,       0, __ATOMIC_RELAXED);
            __atomic_store_n(&s->ip_frag_pkts,     0, __ATOMIC_RELAXED);
            __atomic_store_n(&s->other_proto_pkts, 0, __ATOMIC_RELAXED);

            /* V3.1 resets: zero both sketches in-place.
             * memset is fine — sketch dimensions are stable, and resetting
             * counters AND topk together preserves invariants. */
            memset(&s->cm_src_port, 0, sizeof(s->cm_src_port));
            memset(&s->cm_src_24,   0, sizeof(s->cm_src_24));

            /* DIRECTIONALITY_EXPERIMENT: reset window counters */
            __atomic_store_n(&s->inbound_pkts,  0, __ATOMIC_RELAXED);
            __atomic_store_n(&s->outbound_pkts, 0, __ATOMIC_RELAXED);

            /* HLL reset: hll_init() memsets register bytes back to zero.
             * Concurrent hll_add() CAS updates on the same registers may
             * race with this memset, but any lost updates are bounded to
             * the reset window and fall well within HLL's intrinsic error
             * (~0.8% for precision 14). No lock required. */
            hll_init(&s->unique_src_ips,  0x11111111 + s->dst_ip);
            hll_init(&s->unique_dst_ports,0x22222222 + s->dst_ip);
            hll_init(&s->udp_flows,       0x33333333 + s->dst_ip);
            hll_init(&s->unique_flows,    0x44444444 + s->dst_ip);
            /* V2 */
            hll_init(&s->unique_new_flows, 0x55555555 + s->dst_ip);
        }
    }
}
