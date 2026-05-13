/**
 * @file   l2fwd_service_hotpath.c
 * @brief  Per-service packet hot path — P7 implementation.
 *
 * See l2fwd_service_hotpath.h for the public-API contract.
 *
 * P7 ships raw counters only. No feature ratios (P8), no detection
 * scoring (P9). The intent of P7 is to wire packets through the new
 * per-service data model end-to-end so that future prompts have a
 * working hot path to extend.
 */

#include "l2fwd_service_hotpath.h"
#include "l2fwd_service_registry.h"
#include "l2fwd_service_stats.h"
#include "l2fwd_service_features.h"      /* P8: HLL/CM/EWMA primitives + compute_all */
#include "l2fwd_service_scoring.h"       /* P9: detection scoring + phase machine */
#include "l2fwd_service_wire.h"          /* P10: binary wire protocol v1 */
#include "l2fwd_service_detection.h"     /* P8: phase enum used in temporal push */
#include "l2fwd_service_temporal_state.h"/* P8: per-slot temporal ring buffer  */

#include <rte_mbuf.h>
#include <rte_ether.h>
#include <rte_ip.h>
#include <rte_tcp.h>
#include <rte_udp.h>
#include <rte_icmp.h>
#include <rte_byteorder.h>

#include <netinet/in.h>          /* IPPROTO_TCP / UDP / ICMP */

#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <time.h>                /* P8: per-tick timestamp */
#include <stdatomic.h>

/* -------------------------------------------------------------------------
 * P8: fast per-packet hash for sketch updates
 *
 * Multiplicative finalizer (Murmur3-style). Cheap (a few mul + xor +
 * shift), good enough decorrelation for HLL / CM sketches. NOT
 * cryptographic. Inline so the compiler folds it into the call site. */
static inline uint32_t hp_hash32(uint32_t k) {
    k ^= k >> 16;
    k *= 0x85ebca6bu;
    k ^= k >> 13;
    k *= 0xc2b2ae35u;
    k ^= k >> 16;
    return k;
}

static inline uint32_t hp_hash_flow(uint32_t sip, uint16_t sp, uint16_t dp) {
    return hp_hash32(sip ^ ((uint32_t)sp << 16) ^ (uint32_t)dp);
}

/* -------------------------------------------------------------------------
 * Cached state, set once at init()
 * ------------------------------------------------------------------------- */
static struct service_registry    *g_reg = NULL;
static struct service_stats_array *g_arr = NULL;

/* -------------------------------------------------------------------------
 * Atomic diagnostic counters
 * ------------------------------------------------------------------------- */
static _Atomic uint64_t g_pkts_processed              = 0;
static _Atomic uint64_t g_pkts_dropped_non_protected  = 0;
static _Atomic uint64_t g_lookups_tier1_exact         = 0;
static _Atomic uint64_t g_lookups_tier2_per_proto_ca  = 0;
static _Atomic uint64_t g_lookups_tier3_other_ca      = 0;
static _Atomic uint64_t g_lookups_miss                = 0;
static _Atomic uint64_t g_off_proto_counts            = 0;

/* -------------------------------------------------------------------------
 * Unix socket connection to the Python collector
 * ------------------------------------------------------------------------- */
static int g_stats_sock_fd = -1;
#define STATS_SOCKET_PATH "/tmp/ddos_stats_socket"

/* P10: monotonic sequence number stamped into every wire message.
 * Atomic only because the wire emit happens on a single lcore (main),
 * but keeping it atomic costs nothing and documents the intent. */
static _Atomic uint64_t g_wire_sequence = 0;

/* -------------------------------------------------------------------------
 * Lifecycle
 * ------------------------------------------------------------------------- */

int service_hotpath_init(struct service_registry    *reg,
                         struct service_stats_array *arr)
{
    if (!reg || !arr) return -1;
    g_reg = reg;
    g_arr = arr;

    g_stats_sock_fd = socket(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK, 0);
    if (g_stats_sock_fd >= 0) {
        struct sockaddr_un addr;
        memset(&addr, 0, sizeof(addr));
        addr.sun_family = AF_UNIX;
        strncpy(addr.sun_path, STATS_SOCKET_PATH, sizeof(addr.sun_path) - 1);
        if (connect(g_stats_sock_fd, (struct sockaddr *)&addr,
                    sizeof(addr)) < 0) {
            if (errno != EINPROGRESS && errno != EAGAIN) {
                fprintf(stderr,
                        "[hotpath] socket connect to %s failed: %s "
                        "(will operate without telemetry)\n",
                        STATS_SOCKET_PATH, strerror(errno));
                close(g_stats_sock_fd);
                g_stats_sock_fd = -1;
            }
        }
    }

    fprintf(stderr,
            "[hotpath] initialized: registry=%p stats_array=%p socket_fd=%d\n",
            (void *)g_reg, (void *)g_arr, g_stats_sock_fd);

    /* P9: scoring subsystem init (currently a log line + reserved hook). */
    (void)service_scoring_init();
    return 0;
}

void service_hotpath_destroy(void) {
    /* P9: tear down scoring before releasing the stats array. Idempotent. */
    service_scoring_destroy();

    if (g_stats_sock_fd >= 0) {
        close(g_stats_sock_fd);
        g_stats_sock_fd = -1;
    }
    g_reg = NULL;
    g_arr = NULL;
}

/* -------------------------------------------------------------------------
 * Three-tier registry lookup
 *
 * Cost is O(1) average per tier via the registry's open-addressed hash.
 * In the worst case (an OTHER catchall on every packet), tier 1 is
 * skipped, tier 2 lookups the per-proto catchall, and tier 3 doesn't
 * fire — so two probes max.
 * ------------------------------------------------------------------------- */
static struct service_hotpath_lookup_result
do_three_tier_lookup(uint32_t target_ip, uint16_t port, uint8_t l4_proto)
{
    struct service_hotpath_lookup_result r = { NULL, 0, false };
    if (!g_reg || !g_arr || !g_arr->slots) return r;

    /* Map IP-level protocol to the canonical service_proto_kind pair. */
    uint8_t pk_specific;
    uint8_t pk_catchall;
    switch (l4_proto) {
        case IPPROTO_TCP:
            pk_specific = SERVICE_PROTO_TCP;
            pk_catchall = SERVICE_PROTO_CATCHALL_TCP;
            break;
        case IPPROTO_UDP:
            pk_specific = SERVICE_PROTO_UDP;
            pk_catchall = SERVICE_PROTO_CATCHALL_UDP;
            break;
        case IPPROTO_ICMP:
            pk_specific = SERVICE_PROTO_ICMP;
            pk_catchall = SERVICE_PROTO_CATCHALL_ICMP;
            break;
        default:
            /* GRE / ESP / IP-in-IP / etc. — goes straight to OTHER. */
            pk_specific = 0;                              /* sentinel — no exact */
            pk_catchall = SERVICE_PROTO_CATCHALL_OTHER;
            break;
    }

    /* Tier 1: exact (IP, port, proto). Only viable for TCP / UDP. */
    if (pk_specific != 0 && port != 0) {
        const struct service_descriptor *desc =
            service_registry_lookup_exact(g_reg, target_ip, port, pk_specific);
        if (desc) {
            size_t idx = (size_t)(desc - g_reg->slots);
            if (idx < g_arr->capacity) {
                r.slot = &g_arr->slots[idx];
                r.tier = 1;
                return r;
            }
        }
    }

    /* Tier 2: per-protocol catchall (IP, *, pk_catchall).
     * If the packet's proto is "other," pk_catchall is OTHER, and a hit
     * here is technically tier 3 from a semantic standpoint. */
    {
        const struct service_descriptor *desc =
            service_registry_lookup_catchall(g_reg, target_ip, pk_catchall);
        if (desc) {
            size_t idx = (size_t)(desc - g_reg->slots);
            if (idx < g_arr->capacity) {
                r.slot = &g_arr->slots[idx];
                r.tier = (pk_catchall == SERVICE_PROTO_CATCHALL_OTHER) ? 3 : 2;
                return r;
            }
        }
    }

    /* Tier 3: OTHER catchall fallback. Only run if we haven't tried OTHER
     * already (i.e. the packet is TCP/UDP/ICMP and no per-proto catchall
     * existed for this IP — unusual but possible). */
    if (pk_catchall != SERVICE_PROTO_CATCHALL_OTHER) {
        const struct service_descriptor *desc =
            service_registry_lookup_catchall(g_reg, target_ip,
                                              SERVICE_PROTO_CATCHALL_OTHER);
        if (desc) {
            size_t idx = (size_t)(desc - g_reg->slots);
            if (idx < g_arr->capacity) {
                r.slot      = &g_arr->slots[idx];
                r.tier      = 3;
                r.off_proto = true;
                return r;
            }
        }
    }

    return r;
}

/* -------------------------------------------------------------------------
 * Increment helpers — inlined into process_packet but factored here for
 * readability. The increments use plain ++ on uint64_t: safe ONLY as
 * long as a single lcore owns each slot's writes (see header note).
 * ------------------------------------------------------------------------- */

static inline void
account_inbound_common(struct service_stats *s,
                       uint16_t total_len, uint8_t ttl,
                       bool is_frag, bool off_proto)
{
    s->common.inbound_pkts++;
    s->common.inbound_bytes += total_len;
    s->common.ttl_sum       += ttl;
    s->common.ttl_sum_sq    += (uint64_t)ttl * ttl;
    if (is_frag)   s->common.ip_frag_pkts++;
    if (off_proto) s->common.off_proto_pkts++;
}

static inline void
account_inbound_tcp(struct service_tcp_stats *t, uint16_t total_len,
                    bool tcp_syn, bool tcp_syn_ack, bool tcp_fin_ack,
                    bool tcp_rst, bool tcp_ack,
                    bool tcp_empty_ack, bool tcp_zero_window)
{
    t->tcp_pkts++;
    t->tcp_bytes           += total_len;
    t->tcp_pkt_size_sum    += total_len;
    t->tcp_pkt_size_sum_sq += (uint64_t)total_len * total_len;
    if (tcp_syn)         t->syn_pkts++;
    if (tcp_syn_ack)     t->syn_ack_pkts++;
    if (tcp_fin_ack)     t->fin_ack_pkts++;
    if (tcp_rst)         t->rst_pkts++;
    if (tcp_ack && !tcp_syn && !tcp_fin_ack && !tcp_rst)
                         t->ack_data_pkts++;
    if (tcp_empty_ack)   t->empty_ack_pkts++;
    if (tcp_zero_window) t->zero_window_pkts++;
}

static inline void
account_inbound_udp(struct service_udp_stats *u, uint16_t total_len)
{
    u->udp_pkts++;
    u->udp_bytes           += total_len;
    u->udp_pkt_size_sum    += total_len;
    u->udp_pkt_size_sum_sq += (uint64_t)total_len * total_len;
}

/* ICMP type 8 = Echo Request (RFC 792). DPDK exposes the symbolic
 * constant under RTE_IP_ICMP_ECHO_REQUEST, which is marked deprecated in
 * the current DPDK release; using the literal here avoids the warning in
 * new P7 code. The legacy collector compiled with this warning. */
#define HOTPATH_ICMP_ECHO_REQUEST 8

static inline void
account_inbound_icmp(struct service_icmp_stats *ic,
                     uint16_t total_len, uint8_t icmp_type)
{
    ic->icmp_pkts++;
    ic->icmp_bytes += total_len;
    if (icmp_type == HOTPATH_ICMP_ECHO_REQUEST) ic->icmp_echo_pkts++;
}

/* -------------------------------------------------------------------------
 * The hot-path entrypoint
 *
 * Concurrency: see header note. Plain ++ on uint64_t fields is safe under
 * the current "one RX queue per port, one lcore per port" arrangement.
 * If RX is ever sharded across multiple lcores per slot, swap to atomic
 * fetch_adds or per-lcore arrays + fold.
 * ------------------------------------------------------------------------- */
int service_hotpath_process_packet(struct rte_mbuf *m, unsigned int port_id)
{
    (void)port_id;  /* P7 does not yet split stats by port. */

    if (!m || !g_reg || !g_arr) return -1;

    atomic_fetch_add_explicit(&g_pkts_processed, 1, memory_order_relaxed);

    /* --- Ethernet header --- */
    struct rte_ether_hdr *eth =
        rte_pktmbuf_mtod(m, struct rte_ether_hdr *);
    uint16_t ether_type = rte_be_to_cpu_16(eth->ether_type);
    if (ether_type != RTE_ETHER_TYPE_IPV4) {
        /* IPv6 / VLAN / MPLS dropped silently in P7. */
        return -1;
    }

    /* --- IPv4 header --- */
    struct rte_ipv4_hdr *ip4 =
        (struct rte_ipv4_hdr *)((char *)eth + sizeof(struct rte_ether_hdr));
    uint8_t  l4_proto  = ip4->next_proto_id;
    uint32_t src_ip    = rte_be_to_cpu_32(ip4->src_addr);
    uint32_t dst_ip    = rte_be_to_cpu_32(ip4->dst_addr);
    uint16_t total_len = rte_be_to_cpu_16(ip4->total_length);
    uint8_t  ttl       = ip4->time_to_live;
    /* Fragment if MF flag set OR fragment offset is non-zero. The DF
     * bit (0x4000) is masked out. */
    bool     is_frag   = (rte_be_to_cpu_16(ip4->fragment_offset) & 0x3FFF) != 0;

    uint8_t ihl_bytes  = (ip4->version_ihl & 0x0F) * 4;
    char   *l4_ptr     = (char *)ip4 + ihl_bytes;

    /* --- L4 header (TCP / UDP / ICMP) --- */
    uint16_t src_port = 0, dst_port = 0;
    bool     tcp_syn = false, tcp_syn_ack = false, tcp_fin_ack = false;
    bool     tcp_rst = false, tcp_ack = false;
    bool     tcp_empty_ack = false, tcp_zero_window = false;
    uint8_t  icmp_type = 0;

    if (l4_proto == IPPROTO_TCP) {
        struct rte_tcp_hdr *tcp = (struct rte_tcp_hdr *)l4_ptr;
        src_port = rte_be_to_cpu_16(tcp->src_port);
        dst_port = rte_be_to_cpu_16(tcp->dst_port);
        uint8_t flags    = tcp->tcp_flags;
        tcp_syn          = (flags & RTE_TCP_SYN_FLAG) && !(flags & RTE_TCP_ACK_FLAG);
        tcp_syn_ack      = (flags & RTE_TCP_SYN_FLAG) &&  (flags & RTE_TCP_ACK_FLAG);
        tcp_fin_ack      = (flags & RTE_TCP_FIN_FLAG) &&  (flags & RTE_TCP_ACK_FLAG);
        tcp_rst          = !!(flags & RTE_TCP_RST_FLAG);
        tcp_ack          = !!(flags & RTE_TCP_ACK_FLAG);

        uint8_t  data_off_bytes = ((tcp->data_off >> 4) & 0x0F) * 4;
        int      payload_len    = (int)total_len - (int)ihl_bytes - (int)data_off_bytes;
        if (payload_len < 0) payload_len = 0;
        tcp_empty_ack    = tcp_ack && (payload_len == 0) &&
                           !tcp_syn && !tcp_fin_ack && !tcp_rst;
        tcp_zero_window  = (rte_be_to_cpu_16(tcp->rx_win) == 0);
    } else if (l4_proto == IPPROTO_UDP) {
        struct rte_udp_hdr *udp = (struct rte_udp_hdr *)l4_ptr;
        src_port = rte_be_to_cpu_16(udp->src_port);
        dst_port = rte_be_to_cpu_16(udp->dst_port);
    } else if (l4_proto == IPPROTO_ICMP) {
        struct rte_icmp_hdr *icmp = (struct rte_icmp_hdr *)l4_ptr;
        icmp_type = icmp->icmp_type;
    }

    /* --- Direction classification --- */
    bool dst_protected = service_registry_is_protected_ip(g_reg, dst_ip);
    bool src_protected = service_registry_is_protected_ip(g_reg, src_ip);

    if (!dst_protected && !src_protected) {
        atomic_fetch_add_explicit(&g_pkts_dropped_non_protected, 1,
                                   memory_order_relaxed);
        return -1;
    }

    /* --- Inbound path --- */
    if (dst_protected) {
        struct service_hotpath_lookup_result r =
            do_three_tier_lookup(dst_ip, dst_port, l4_proto);
        if (!r.slot) {
            atomic_fetch_add_explicit(&g_lookups_miss, 1, memory_order_relaxed);
            return -1;
        }

        switch (r.tier) {
            case 1:
                atomic_fetch_add_explicit(&g_lookups_tier1_exact,
                                           1, memory_order_relaxed);
                break;
            case 2:
                atomic_fetch_add_explicit(&g_lookups_tier2_per_proto_ca,
                                           1, memory_order_relaxed);
                break;
            case 3:
                atomic_fetch_add_explicit(&g_lookups_tier3_other_ca,
                                           1, memory_order_relaxed);
                break;
            default: break;
        }
        if (r.off_proto) {
            atomic_fetch_add_explicit(&g_off_proto_counts,
                                       1, memory_order_relaxed);
        }

        struct service_stats *s = r.slot;
        account_inbound_common(s, total_len, ttl, is_frag, r.off_proto);

        /* P8: per-packet sketch updates that feed P9 detection.
         * Always-on for every inbound: src-IP HLL + flow HLL + /24 CM.
         * Proto-specific sketches added inside the switch below. */
        service_hll_insert(&s->common.unique_src_ips, hp_hash32(src_ip));
        service_hll_insert(&s->common.unique_flows,
                           hp_hash_flow(src_ip, src_port, dst_port));
        service_cm_src_24_insert(&s->common.cm_src_24, src_ip);

        switch (s->proto_kind) {
        case SERVICE_PROTO_TCP:
        case SERVICE_PROTO_CATCHALL_TCP:
            if (l4_proto == IPPROTO_TCP) {
                account_inbound_tcp(&s->proto.tcp.stats, total_len,
                                     tcp_syn, tcp_syn_ack, tcp_fin_ack,
                                     tcp_rst, tcp_ack,
                                     tcp_empty_ack, tcp_zero_window);
                /* P8: TCP flow HLL + source-port CM. */
                service_hll_insert(&s->proto.tcp.stats.unique_new_flows,
                                   hp_hash_flow(src_ip, src_port, dst_port));
                service_cm_src_port_insert(&s->proto.tcp.stats.cm_src_port,
                                            src_port);
            }
            break;
        case SERVICE_PROTO_UDP:
        case SERVICE_PROTO_CATCHALL_UDP:
            if (l4_proto == IPPROTO_UDP) {
                account_inbound_udp(&s->proto.udp.stats, total_len);
                /* P8: UDP flow HLL + source-port CM. */
                service_hll_insert(&s->proto.udp.stats.udp_flows,
                                   hp_hash_flow(src_ip, src_port, dst_port));
                service_cm_src_port_insert(&s->proto.udp.stats.cm_src_port,
                                            src_port);
            }
            break;
        case SERVICE_PROTO_ICMP:
        case SERVICE_PROTO_CATCHALL_ICMP:
            if (l4_proto == IPPROTO_ICMP) {
                account_inbound_icmp(&s->proto.icmp.stats, total_len,
                                      icmp_type);
                /* ICMP has no proto-specific HLL/CM in the data model. */
            }
            break;
        case SERVICE_PROTO_CATCHALL_OTHER:
            /* OTHER catchall carries all four arms; route by l4_proto. */
            if (l4_proto == IPPROTO_TCP) {
                account_inbound_tcp(&s->proto.other_catchall.tcp_stats,
                                     total_len,
                                     tcp_syn, tcp_syn_ack, tcp_fin_ack,
                                     tcp_rst, tcp_ack,
                                     tcp_empty_ack, tcp_zero_window);
                service_hll_insert(
                    &s->proto.other_catchall.tcp_stats.unique_new_flows,
                    hp_hash_flow(src_ip, src_port, dst_port));
                service_cm_src_port_insert(
                    &s->proto.other_catchall.tcp_stats.cm_src_port,
                    src_port);
            } else if (l4_proto == IPPROTO_UDP) {
                account_inbound_udp(&s->proto.other_catchall.udp_stats,
                                     total_len);
                service_hll_insert(
                    &s->proto.other_catchall.udp_stats.udp_flows,
                    hp_hash_flow(src_ip, src_port, dst_port));
                service_cm_src_port_insert(
                    &s->proto.other_catchall.udp_stats.cm_src_port,
                    src_port);
            } else if (l4_proto == IPPROTO_ICMP) {
                account_inbound_icmp(&s->proto.other_catchall.icmp_stats,
                                      total_len, icmp_type);
            } else {
                /* True "other" IP proto: GRE/ESP/IP-in-IP/etc. */
                struct service_other_stats *o =
                    &s->proto.other_catchall.other_stats;
                o->other_pkts++;
                o->other_bytes += total_len;
                o->proto_counts[l4_proto]++;
            }
            /* OTHER catchall always tracks dst-port distribution
             * (separately from the per-arm src-port CM above). */
            service_hll_insert(&s->proto.other_catchall.unique_dst_ports,
                               hp_hash32((uint32_t)dst_port));
            break;
        default:
            break;
        }

        (void)src_port;
        return 0;
    }

    /* --- Outbound path --- */
    if (src_protected) {
        struct service_hotpath_lookup_result r =
            do_three_tier_lookup(src_ip, src_port, l4_proto);
        if (!r.slot) {
            atomic_fetch_add_explicit(&g_lookups_miss, 1, memory_order_relaxed);
            return -1;
        }

        struct service_stats *s = r.slot;
        s->outbound.out_pkts++;
        s->outbound.out_bytes += total_len;
        if      (l4_proto == IPPROTO_TCP)  s->outbound.out_tcp_pkts++;
        else if (l4_proto == IPPROTO_UDP)  s->outbound.out_udp_pkts++;
        else if (l4_proto == IPPROTO_ICMP) s->outbound.out_icmp_pkts++;

        /* P8: outbound HLL sketches for dst-IP/dst-port cardinality. */
        service_hll_insert(&s->outbound.unique_dst_ips,
                           hp_hash32(dst_ip));
        if (dst_port != 0) {
            service_hll_insert(&s->outbound.unique_dst_ports,
                               hp_hash32((uint32_t)dst_port));
        }
        return 0;
    }

    return -1;
}

/* -------------------------------------------------------------------------
 * Per-1Hz tick
 * ------------------------------------------------------------------------- */
void service_hotpath_tick(void)
{
    if (!g_arr || !g_arr->slots) return;

    /* P8 step 1: derive features from this window's raw counters.
     * MUST run before the per-window reset below — the raw counters
     * disappear once service_stats_reset_window_all() fires.
     *
     * P9: compute_all reads the freeze flag from each slot's
     * detection_state and skips EWMA updates when frozen, so this call
     * is safe to invoke before the scoring evaluate_all below. */
    service_features_compute_all(g_arr);

    /* P9 step 1b: scoring — Tier-0 CUSUM, Tier-1 multi-feature combine,
     * phase machine. Must run BEFORE the per-window reset (uses the
     * raw counters and just-updated EWMA state). Updates each slot's
     * detection_state in place; subsequent calls to
     * service_scoring_is_frozen() see the new freeze status. */
    service_scoring_evaluate_all(g_arr);

    /* P8 step 2: push one 1Hz temporal sample per active slot.
     * pkts/bytes come from the just-computed window; flows is the HLL
     * cardinality estimate at end-of-window; phase comes from the
     * slot's detection_state if wired (P9 will populate the phase
     * transitions). Using time(NULL) is good enough for 1Hz cadence;
     * P10 may swap in rte_get_timer_cycles for sub-second precision. */
    uint64_t now_ns = (uint64_t)time(NULL) * 1000000000ULL;
    for (size_t i = 0; i < g_arr->capacity; i++) {
        struct service_stats *s = &g_arr->slots[i];
        if (!s->active || !s->temporal_state) continue;

        uint8_t phase = 0;  /* WARMUP default */
        if (s->detection_state) {
            const struct service_detection_state *det =
                (const struct service_detection_state *)s->detection_state;
            phase = det->phase;
        }
        double flows_est = service_features_unique_flows(s);
        uint64_t flows   = (flows_est > 0.0) ? (uint64_t)flows_est : 0u;

        service_temporal_push_sample(
            (struct service_temporal_state *)s->temporal_state,
            now_ns,
            s->common.inbound_pkts,
            s->common.inbound_bytes,
            flows,
            phase);
    }

    /* P10 step 3 (revised P10.5): binary wire-protocol emit.
     *
     * One 416-byte message per active slot per tick, framed with
     * magic + version + length + CRC32. Emit unconditionally — every
     * active slot reports its state every second, including WARMUP
     * slots with zero traffic. The dashboard relies on this cadence
     * to confirm slot liveness.
     *
     * The Python collector (P12) consumes this exact format. */
    if (g_stats_sock_fd >= 0) {
        uint8_t buf[L2FWD_WIRE_MSG_SIZE];
        for (size_t i = 0; i < g_arr->capacity; i++) {
            struct service_stats *s = &g_arr->slots[i];
            if (!s->active) continue;

            /* P10.5: emit heartbeat for every active slot regardless of
             * phase or traffic. The dashboard relies on per-slot tick
             * cadence to confirm liveness. The previous "skip if WARMUP
             * AND idle" filter suppressed emission for the entire
             * warmup window (default 400s), blocking early operator
             * visibility. At 44 slots × 416 B × 1 Hz the bandwidth cost
             * is ~18 KB/sec — negligible. The Python collector (P12)
             * can apply downstream filters if persistence cost
             * matters. */

            uint64_t seq = atomic_fetch_add_explicit(
                &g_wire_sequence, 1, memory_order_relaxed);

            int rc = service_wire_serialize_slot(s, (uint16_t)i,
                                                  now_ns, seq, buf);
            if (rc != 0) continue;

            ssize_t sent = write(g_stats_sock_fd, buf,
                                  L2FWD_WIRE_MSG_SIZE);
            (void)sent;   /* best-effort; EAGAIN / EPIPE swallowed */
        }
    }

    /* P8 step 4: reset per-window raw counters.
     * HLL / CM / EWMA / burst-window history is preserved by design —
     * see service_stats_reset_window() docs. */
    service_stats_reset_window_all(g_arr);
}

/* -------------------------------------------------------------------------
 * Diagnostics
 * ------------------------------------------------------------------------- */
void service_hotpath_get_diag(struct service_hotpath_diag *out)
{
    if (!out) return;
    out->pkts_processed                   =
        atomic_load_explicit(&g_pkts_processed,             memory_order_relaxed);
    out->pkts_dropped_non_protected       =
        atomic_load_explicit(&g_pkts_dropped_non_protected, memory_order_relaxed);
    out->lookups_tier1_exact              =
        atomic_load_explicit(&g_lookups_tier1_exact,        memory_order_relaxed);
    out->lookups_tier2_per_proto_catchall =
        atomic_load_explicit(&g_lookups_tier2_per_proto_ca, memory_order_relaxed);
    out->lookups_tier3_other_catchall     =
        atomic_load_explicit(&g_lookups_tier3_other_ca,     memory_order_relaxed);
    out->lookups_miss                     =
        atomic_load_explicit(&g_lookups_miss,               memory_order_relaxed);
    out->off_proto_counts                 =
        atomic_load_explicit(&g_off_proto_counts,           memory_order_relaxed);
}
