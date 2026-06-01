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
#include "l2fwd_service_features.h"      /* HLL / CM sketch primitives (per-packet) */
#include "l2fwd_service_snapshot.h"      /* C->Python raw-telemetry shm producer */

#include <rte_mbuf.h>
#include <rte_ether.h>
#include <rte_ip.h>
#include <rte_tcp.h>
#include <rte_udp.h>
#include <rte_icmp.h>
#include <rte_byteorder.h>
#include <rte_cycles.h>          /* rte_delay_us_block — bank-flip settle */

#include <netinet/in.h>          /* IPPROTO_TCP / UDP / ICMP */

#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <time.h>                /* per-tick timestamp */
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

/* Double-buffered accumulation banks. RX lcores write the bank g_active points
 * at; the 1 Hz tick flips g_active to the other bank, drains in-flight writers,
 * then publishes + resets the now-frozen bank. g_active is an atomic pointer:
 * each packet loads it ONCE so a flip mid-packet can't split a packet's writes
 * across banks. */
static struct service_stats_array *g_bank[2] = { NULL, NULL };
static _Atomic(struct service_stats_array *) g_active = NULL;

/* Microseconds the tick waits after flipping g_active before it reads/resets
 * the frozen bank — long enough for any RX lcore that loaded the old pointer to
 * finish its current process_packet (poll cycles are sub-µs). Negligible at
 * 1 Hz. */
#define SERVICE_HOTPATH_FLIP_SETTLE_US 100

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

/* Registry generation, surfaced to the Python detector in every snapshot so
 * it can re-align per-slot state by identity after a SIGHUP reload. Starts
 * at 1; reload wiring bumps it in a later step. */
static uint64_t g_registry_epoch = 1;

/* -------------------------------------------------------------------------
 * Lifecycle
 * ------------------------------------------------------------------------- */

int service_hotpath_init(struct service_registry    *reg,
                         struct service_stats_array *bank0,
                         struct service_stats_array *bank1)
{
    if (!reg || !bank0 || !bank1) return -1;
    g_reg     = reg;
    g_bank[0] = bank0;
    g_bank[1] = bank1;
    atomic_store_explicit(&g_active, bank0, memory_order_release);

    fprintf(stderr,
            "[hotpath] initialized: registry=%p banks=%p,%p\n",
            (void *)g_reg, (void *)bank0, (void *)bank1);

    /* Raw-telemetry snapshot producer (C->Python contract). Best-effort: a
     * failure here disables the shm path but must not take down the engine. */
    if (service_snapshot_producer_init() != 0) {
        fprintf(stderr, "[hotpath] snapshot producer disabled "
                        "(see error above); engine continues\n");
    }
    return 0;
}

void service_hotpath_reset_active_bank(void)
{
    /* Main lcore, post-reload: both banks were reinitialised from the new
     * registry; resume accumulation on bank0. */
    atomic_store_explicit(&g_active, g_bank[0], memory_order_release);
}

void service_hotpath_destroy(void) {
    /* Unmap + unlink the snapshot shm region. Idempotent. */
    service_snapshot_producer_destroy();

    g_reg     = NULL;
    g_bank[0] = NULL;
    g_bank[1] = NULL;
    atomic_store_explicit(&g_active, NULL, memory_order_release);
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
do_three_tier_lookup(struct service_stats_array *arr,
                     uint32_t target_ip, uint16_t port, uint8_t l4_proto)
{
    struct service_hotpath_lookup_result r = { NULL, 0, false };
    if (!g_reg || !arr || !arr->slots) return r;

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
            if (idx < arr->capacity) {
                r.slot = &arr->slots[idx];
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
            if (idx < arr->capacity) {
                r.slot = &arr->slots[idx];
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
            if (idx < arr->capacity) {
                r.slot      = &arr->slots[idx];
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

/* Welford online update on (mean, M2) given that n has just been incremented
 * to n_new. Three FLOPs + one division per packet, no catastrophic cancellation
 * at high Gbps. */
#define WELFORD_UPDATE(MEAN, M2, X, N_NEW) do {                       \
    double _w_delta  = (double)(X) - (MEAN);                          \
    (MEAN)          += _w_delta / (double)(N_NEW);                    \
    (M2)            += _w_delta * ((double)(X) - (MEAN));             \
} while (0)

static inline void
account_inbound_common(struct service_stats *s,
                       uint16_t total_len, uint8_t ttl,
                       bool is_frag, bool off_proto)
{
    s->common.inbound_pkts++;
    s->common.inbound_bytes += total_len;
    WELFORD_UPDATE(s->common.ttl_mean, s->common.ttl_M2,
                   ttl, s->common.inbound_pkts);
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
    t->tcp_bytes += total_len;
    WELFORD_UPDATE(t->tcp_pkt_size_mean, t->tcp_pkt_size_M2,
                   total_len, t->tcp_pkts);
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
    u->udp_bytes += total_len;
    WELFORD_UPDATE(u->udp_pkt_size_mean, u->udp_pkt_size_M2,
                   total_len, u->udp_pkts);
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

    if (!m || !g_reg) return -1;

    /* Load the active accumulation bank ONCE for the whole packet, so a
     * concurrent tick flip cannot split this packet's writes across banks. */
    struct service_stats_array *arr =
        atomic_load_explicit(&g_active, memory_order_acquire);
    if (!arr || !arr->slots) return -1;

    atomic_fetch_add_explicit(&g_pkts_processed, 1, memory_order_relaxed);

    /* --- Ethernet header --- */
    struct rte_ether_hdr *eth =
        rte_pktmbuf_mtod(m, struct rte_ether_hdr *);
    uint16_t ether_type = rte_be_to_cpu_16(eth->ether_type);
    /* --- VLAN unwrap (802.1Q, ether_type 0x8100) ---
     * Mirrored traffic from a trunk port arrives with a VLAN tag wrapping
     * the inner IPv4 frame. We skip the 4-byte tag and re-read the inner
     * ether_type. P7-original assumed untagged frames. */
    size_t l2_hdr_bytes = sizeof(struct rte_ether_hdr);
    if (ether_type == 0x8100) {
        /* The VLAN TCI is 2 bytes (PCP|DEI|VID); inner ether_type is the
         * next 2 bytes. The whole shim is 4 bytes total. */
        struct rte_vlan_hdr {
            uint16_t vlan_tci;
            uint16_t inner_type;
        } __attribute__((packed));
        struct rte_vlan_hdr *vh =
            (struct rte_vlan_hdr *)((char *)eth + sizeof(struct rte_ether_hdr));
        ether_type   = rte_be_to_cpu_16(vh->inner_type);
        l2_hdr_bytes += 4;
    }

    if (ether_type != RTE_ETHER_TYPE_IPV4) {
        /* IPv6 / MPLS / unknown dropped silently. */
        return -1;
    }

    /* --- IPv4 header --- */
    struct rte_ipv4_hdr *ip4 =
        (struct rte_ipv4_hdr *)((char *)eth + l2_hdr_bytes);
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
            do_three_tier_lookup(arr, dst_ip, dst_port, l4_proto);
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
            do_three_tier_lookup(arr, src_ip, src_port, l4_proto);
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
    struct service_stats_array *cur =
        atomic_load_explicit(&g_active, memory_order_relaxed);
    if (!cur || !cur->slots) return;

    /* 1. Flip the active bank. New packets accumulate into `nxt` (which was
     *    published + reset on the previous tick, so it is clean); `cur` becomes
     *    the frozen window we are about to read. The release store pairs with
     *    the acquire load in process_packet. */
    struct service_stats_array *nxt = (cur == g_bank[0]) ? g_bank[1] : g_bank[0];
    atomic_store_explicit(&g_active, nxt, memory_order_release);

    /* 2. Let any RX lcore that loaded the OLD pointer just before the flip
     *    finish its in-flight process_packet. After this short settle, `cur`
     *    has no concurrent writers — the snapshot sees a clean window. */
    rte_delay_us_block(SERVICE_HOTPATH_FLIP_SETTLE_US);

    /* 3. Publish the frozen window's RAW telemetry to shared memory for the
     *    Python detection brain (the abs-floor fail-safe is computed inside),
     *    then reset its scalar counters so it is clean for the next flip. HLL /
     *    CM sketches persist by design (see service_stats_reset_window). */
    uint64_t now_ns = (uint64_t)time(NULL) * 1000000000ULL;
    service_snapshot_publish(cur, now_ns, g_registry_epoch);
    service_stats_reset_window_all(cur);
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
