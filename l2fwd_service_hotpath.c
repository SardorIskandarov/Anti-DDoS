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
#include <stdatomic.h>

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
    return 0;
}

void service_hotpath_destroy(void) {
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

        switch (s->proto_kind) {
        case SERVICE_PROTO_TCP:
        case SERVICE_PROTO_CATCHALL_TCP:
            if (l4_proto == IPPROTO_TCP) {
                account_inbound_tcp(&s->proto.tcp.stats, total_len,
                                     tcp_syn, tcp_syn_ack, tcp_fin_ack,
                                     tcp_rst, tcp_ack,
                                     tcp_empty_ack, tcp_zero_window);
            }
            break;
        case SERVICE_PROTO_UDP:
        case SERVICE_PROTO_CATCHALL_UDP:
            if (l4_proto == IPPROTO_UDP) {
                account_inbound_udp(&s->proto.udp.stats, total_len);
            }
            break;
        case SERVICE_PROTO_ICMP:
        case SERVICE_PROTO_CATCHALL_ICMP:
            if (l4_proto == IPPROTO_ICMP) {
                account_inbound_icmp(&s->proto.icmp.stats, total_len,
                                      icmp_type);
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
            } else if (l4_proto == IPPROTO_UDP) {
                account_inbound_udp(&s->proto.other_catchall.udp_stats,
                                     total_len);
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

    /* Emit one debug line per active+non-idle slot to the Unix socket.
     * P7 uses key=value text for early visibility; P10 will define the
     * binary protocol. The Python collector will NOT understand this
     * format — that's an accepted blackout until P12 rewrites the
     * collector. */
    if (g_stats_sock_fd >= 0) {
        char buf[512];
        for (size_t i = 0; i < g_arr->capacity; i++) {
            struct service_stats *s = &g_arr->slots[i];
            if (!s->active) continue;
            if (s->common.inbound_pkts == 0 && s->outbound.out_pkts == 0)
                continue;

            int n = snprintf(buf, sizeof(buf),
                             "slot=%zu ip=%u port=%u kind=%u "
                             "in_pkts=%llu in_bytes=%llu out_pkts=%llu\n",
                             i,
                             (unsigned)s->key.target_ip,
                             (unsigned)s->key.port,
                             (unsigned)s->proto_kind,
                             (unsigned long long)s->common.inbound_pkts,
                             (unsigned long long)s->common.inbound_bytes,
                             (unsigned long long)s->outbound.out_pkts);
            if (n > 0 && n < (int)sizeof(buf)) {
                ssize_t sent = write(g_stats_sock_fd, buf, (size_t)n);
                (void)sent;  /* best-effort; EAGAIN / EPIPE swallowed */
            }
        }
    }

    /* Reset per-window raw counters on every active slot.
     * HLL / CM / EWMA / burst-window history is preserved by design — see
     * service_stats_reset_window() docs. */
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
