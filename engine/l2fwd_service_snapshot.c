/**
 * @file   l2fwd_service_snapshot.c
 * @brief  Per-service raw-telemetry snapshot producer (C side of the
 *         C↔Python detection contract). See l2fwd_service_snapshot.h.
 *
 * Responsibilities:
 *   - Create + map the double-buffered POSIX shared-memory region.
 *   - Once per 1 Hz tick, fill the inactive bank with one RAW record per
 *     active slot (raw counters + sketch ESTIMATES + the absolute-floor
 *     fail-safe flag), then publish by flipping active_bank.
 *
 * What this module does NOT do: feature derivation, EWMA, CUSUM, scoring,
 * or the phase machine. Those move to the Python detector. This producer
 * ships only raw numbers + scalars.
 *
 * Concurrency: called from the 1 Hz tick on the main lcore (single writer).
 * The active_bank flip is a release store; Python reads it as an acquire
 * load (a plain aligned 4-byte load on x86-64). Because the producer always
 * fills the INACTIVE bank and only flips when done, the bank a reader sees
 * is never being written for the ~1 s until the next publish.
 *
 * MIGRATION NOTE (P1): during the transition this runs ALONGSIDE the legacy
 * C P8/P9 + wire emit. It reads the live stats array at the same tick point
 * as those do — i.e. it inherits the same (tolerated, sub-microsecond)
 * boundary race with the RX lcores, and adds no new one. Double-buffered
 * ACCUMULATION banks land at cutover (P5), once persistent EWMA/detection
 * state has left C and service_stats holds per-window data only.
 */

#include "l2fwd_service_snapshot.h"
#include "l2fwd_service_stats.h"
#include "l2fwd_service_features.h"   /* service_hll_estimate / cm helpers */
#include "l2fwd_l2_profile.h"

#include <sys/mman.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdatomic.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>

/* -------------------------------------------------------------------------
 * Layout-hash field table — MUST mirror RECORD_FIELDS in
 * ddos_monitor/detection/snapshot.py exactly (same order, offsets, sizes, kinds).
 * The FNV-1a hash over this table is checked at init against both the
 * baked-in SERVICE_SNAPSHOT_LAYOUT_HASH and (implicitly) the Python mirror.
 * ------------------------------------------------------------------------- */

enum { SNAP_K_U64 = 1, SNAP_K_U32 = 2, SNAP_K_U16 = 3,
       SNAP_K_U8 = 4, SNAP_K_F64 = 5, SNAP_K_BYTES = 6 };

struct snap_field { uint16_t off; uint16_t size; uint8_t kind; };

static const struct snap_field k_field_table[] = {
    {  0, 8, SNAP_K_U64}, {  8, 8, SNAP_K_U64}, { 16, 8, SNAP_K_U64},
    { 24, 8, SNAP_K_U64}, { 32, 8, SNAP_K_F64}, { 40, 8, SNAP_K_F64},  /* ttl_mean, ttl_M2 */
    { 48, 8, SNAP_K_U64}, { 56, 8, SNAP_K_U64}, { 64, 8, SNAP_K_U64},
    { 72, 8, SNAP_K_U64}, { 80, 8, SNAP_K_U64}, { 88, 8, SNAP_K_U64},
    { 96, 8, SNAP_K_U64}, {104, 8, SNAP_K_U64}, {112, 8, SNAP_K_U64},
    {120, 8, SNAP_K_U64}, {128, 8, SNAP_K_U64}, {136, 8, SNAP_K_U64},
    {144, 8, SNAP_K_U64}, {152, 8, SNAP_K_U64}, {160, 8, SNAP_K_U64},
    {168, 8, SNAP_K_F64}, {176, 8, SNAP_K_F64}, {184, 8, SNAP_K_U64},  /* tcp_pkt_size_mean/M2 */
    {192, 8, SNAP_K_U64}, {200, 8, SNAP_K_U64}, {208, 8, SNAP_K_U64},
    {216, 8, SNAP_K_F64}, {224, 8, SNAP_K_F64}, {232, 8, SNAP_K_U64},  /* udp_pkt_size_mean/M2 */
    {240, 8, SNAP_K_U64}, {248, 8, SNAP_K_U64}, {256, 8, SNAP_K_U64},
    {264, 8, SNAP_K_U64}, {272, 8, SNAP_K_U64}, {280, 8, SNAP_K_U64},
    {288, 8, SNAP_K_F64}, {296, 8, SNAP_K_F64}, {304, 8, SNAP_K_F64},
    {312, 8, SNAP_K_F64}, {320, 8, SNAP_K_F64}, {328, 8, SNAP_K_F64},
    {336, 8, SNAP_K_F64},
    {344, 4, SNAP_K_U32}, {348, 4, SNAP_K_U32},
    {352, 2, SNAP_K_U16},
    {354, 1, SNAP_K_U8}, {355, 1, SNAP_K_U8}, {356, 1, SNAP_K_U8},
    {357, 8, SNAP_K_BYTES},
};

uint32_t service_snapshot_compute_layout_hash(void)
{
    /* FNV-1a 32-bit. Per field, feed off(u16-LE), size(u16-LE), kind(u8) —
     * byte-identical to compute_layout_hash() in snapshot.py. */
    uint32_t h = 0x811C9DC5u;
    const size_t n = sizeof(k_field_table) / sizeof(k_field_table[0]);
    for (size_t i = 0; i < n; i++) {
        uint8_t bytes[5] = {
            (uint8_t)(k_field_table[i].off  & 0xFF),
            (uint8_t)(k_field_table[i].off  >> 8),
            (uint8_t)(k_field_table[i].size & 0xFF),
            (uint8_t)(k_field_table[i].size >> 8),
            k_field_table[i].kind,
        };
        for (int b = 0; b < 5; b++) {
            h ^= bytes[b];
            h *= 0x01000193u;
        }
    }
    return h;
}

/* -------------------------------------------------------------------------
 * Mapped-region state (single producer)
 * ------------------------------------------------------------------------- */
static void                              *g_shm_base = MAP_FAILED;
static size_t                             g_shm_size = 0;
static struct service_snapshot_shm_header *g_header   = NULL;
static struct service_snapshot_record     *g_bank[2]  = { NULL, NULL };
static uint64_t                           g_seq       = 0;

static struct service_snapshot_record *bank_ptr(unsigned which)
{
    uint8_t *base = (uint8_t *)g_shm_base + SERVICE_SNAPSHOT_HEADER_SIZE;
    return (struct service_snapshot_record *)
        (base + (size_t)which * SERVICE_SNAPSHOT_CAPACITY *
                SERVICE_SNAPSHOT_RECORD_SIZE);
}

/* -------------------------------------------------------------------------
 * Lifecycle
 * ------------------------------------------------------------------------- */

int service_snapshot_producer_init(void)
{
    uint32_t local_hash = service_snapshot_compute_layout_hash();
    if (local_hash != SERVICE_SNAPSHOT_LAYOUT_HASH) {
        fprintf(stderr,
                "[snapshot] FATAL: layout hash 0x%08X != baked 0x%08X "
                "(field table drifted from the header/Python mirror)\n",
                local_hash, (unsigned)SERVICE_SNAPSHOT_LAYOUT_HASH);
        return -1;
    }

    /* Clear any stale region from a previous run, then create fresh. */
    shm_unlink(SERVICE_SNAPSHOT_SHM_NAME);   /* ignore ENOENT */

    int fd = shm_open(SERVICE_SNAPSHOT_SHM_NAME, O_CREAT | O_RDWR, 0644);
    if (fd < 0) {
        fprintf(stderr, "[snapshot] shm_open(%s) failed: %s\n",
                SERVICE_SNAPSHOT_SHM_NAME, strerror(errno));
        return -1;
    }

    g_shm_size = SERVICE_SNAPSHOT_HEADER_SIZE +
                 (size_t)2 * SERVICE_SNAPSHOT_CAPACITY *
                 SERVICE_SNAPSHOT_RECORD_SIZE;

    if (ftruncate(fd, (off_t)g_shm_size) != 0) {
        fprintf(stderr, "[snapshot] ftruncate(%zu) failed: %s\n",
                g_shm_size, strerror(errno));
        close(fd);
        shm_unlink(SERVICE_SNAPSHOT_SHM_NAME);
        return -1;
    }

    g_shm_base = mmap(NULL, g_shm_size, PROT_READ | PROT_WRITE,
                      MAP_SHARED, fd, 0);
    close(fd);   /* mapping survives the fd */
    if (g_shm_base == MAP_FAILED) {
        fprintf(stderr, "[snapshot] mmap(%zu) failed: %s\n",
                g_shm_size, strerror(errno));
        g_shm_size = 0;
        shm_unlink(SERVICE_SNAPSHOT_SHM_NAME);
        return -1;
    }

    memset(g_shm_base, 0, g_shm_size);
    g_header  = (struct service_snapshot_shm_header *)g_shm_base;
    g_bank[0] = bank_ptr(0);
    g_bank[1] = bank_ptr(1);

    g_header->magic[0]       = SERVICE_SNAPSHOT_MAGIC_0;
    g_header->magic[1]       = SERVICE_SNAPSHOT_MAGIC_1;
    g_header->magic[2]       = SERVICE_SNAPSHOT_MAGIC_2;
    g_header->magic[3]       = SERVICE_SNAPSHOT_MAGIC_3;
    g_header->format_version = SERVICE_SNAPSHOT_FORMAT_VERSION;
    g_header->record_version = SERVICE_SNAPSHOT_RECORD_VERSION;
    g_header->record_size    = SERVICE_SNAPSHOT_RECORD_SIZE;
    g_header->layout_hash    = local_hash;
    g_header->capacity       = SERVICE_SNAPSHOT_CAPACITY;
    g_header->n_active       = 0;
    g_header->active_bank    = 0;
    g_header->registry_epoch = 0;
    g_header->seq_bank0      = 0;
    g_header->seq_bank1      = 0;
    g_header->produced_ts_ns = 0;

    fprintf(stderr,
            "[snapshot] producer ready: %s size=%zu capacity=%u "
            "record=%uB hash=0x%08X\n",
            SERVICE_SNAPSHOT_SHM_PATH, g_shm_size,
            (unsigned)SERVICE_SNAPSHOT_CAPACITY,
            (unsigned)SERVICE_SNAPSHOT_RECORD_SIZE, local_hash);
    return 0;
}

void service_snapshot_producer_destroy(void)
{
    if (g_shm_base != MAP_FAILED && g_shm_base != NULL) {
        munmap(g_shm_base, g_shm_size);
    }
    g_shm_base = MAP_FAILED;
    g_shm_size = 0;
    g_header   = NULL;
    g_bank[0]  = NULL;
    g_bank[1]  = NULL;
    shm_unlink(SERVICE_SNAPSHOT_SHM_NAME);
}

/* -------------------------------------------------------------------------
 * Per-slot record fill
 * ------------------------------------------------------------------------- */

/* Absolute-floor fail-safe: raw volume past a hard per-profile ceiling.
 * Reads the SAME raw window inputs the (legacy) Tier-0 floor used; a
 * threshold of 0.0 disables that channel. Self-contained so it survives the
 * deletion of the C scoring path at P5. */
static uint8_t snapshot_absolute_floor(const struct service_stats *s,
                                       double fps_est)
{
    const struct l2_profile *p = s->profile;
    if (!p) return 0;
    double pps = (double)s->common.inbound_pkts;
    double bps = (double)s->common.inbound_bytes * 8.0;
    if (p->absolute_pps_threshold > 0.0 && pps >= p->absolute_pps_threshold)
        return 1;
    if (p->absolute_bps_threshold > 0.0 && bps >= p->absolute_bps_threshold)
        return 1;
    if (p->absolute_fps_threshold > 0.0 && fps_est >= p->absolute_fps_threshold)
        return 1;
    return 0;
}

static void fill_record(const struct service_stats *s,
                        struct service_snapshot_record *r)
{
    memset(r, 0, sizeof(*r));

    /* Identity. */
    r->target_ip    = s->key.target_ip;
    r->port         = s->key.port;
    r->proto_kind   = s->proto_kind;
    r->is_catchall  = s->is_catchall ? 1u : 0u;
    r->window_count = s->window_count;
    if (s->profile && s->profile->name) {
        strncpy(r->profile_name, s->profile->name,
                SERVICE_SNAPSHOT_PROFILE_NAME_LEN);   /* truncates; no NUL needed */
    }

    /* Common inbound raw. */
    r->inbound_pkts   = s->common.inbound_pkts;
    r->inbound_bytes  = s->common.inbound_bytes;
    r->off_proto_pkts = s->common.off_proto_pkts;
    r->ip_frag_pkts   = s->common.ip_frag_pkts;
    r->ttl_mean       = s->common.ttl_mean;
    r->ttl_M2         = s->common.ttl_M2;

    /* Outbound raw. */
    r->out_pkts      = s->outbound.out_pkts;
    r->out_bytes     = s->outbound.out_bytes;
    r->out_tcp_pkts  = s->outbound.out_tcp_pkts;
    r->out_udp_pkts  = s->outbound.out_udp_pkts;
    r->out_icmp_pkts = s->outbound.out_icmp_pkts;

    /* Common sketch estimates. */
    r->est_unique_src_ips = service_hll_estimate(&s->common.unique_src_ips);
    r->est_unique_flows   = service_hll_estimate(&s->common.unique_flows);
    r->src_24_top1_share  = service_cm_top1_share(
        (uint64_t)s->common.cm_src_24.top_count, s->common.cm_src_24.total);
    r->src_24_entropy     = service_cm_src_24_entropy(&s->common.cm_src_24);

    /* Proto-arm raw counters + per-arm estimates. Resolve the active arm
     * from proto_kind, exactly like the scoring/feature dispatch. */
    const struct service_tcp_stats  *t  = NULL;
    const struct service_udp_stats  *u  = NULL;
    const struct service_icmp_stats *ic = NULL;
    const struct service_other_stats *o = NULL;
    const struct service_hll *other_dstports = NULL;

    switch (s->proto_kind) {
    case SERVICE_PROTO_TCP:
    case SERVICE_PROTO_CATCHALL_TCP:
        t = &s->proto.tcp.stats;
        break;
    case SERVICE_PROTO_UDP:
    case SERVICE_PROTO_CATCHALL_UDP:
        u = &s->proto.udp.stats;
        break;
    case SERVICE_PROTO_ICMP:
    case SERVICE_PROTO_CATCHALL_ICMP:
        ic = &s->proto.icmp.stats;
        break;
    case SERVICE_PROTO_CATCHALL_OTHER:
        t  = &s->proto.other_catchall.tcp_stats;
        u  = &s->proto.other_catchall.udp_stats;
        ic = &s->proto.other_catchall.icmp_stats;
        o  = &s->proto.other_catchall.other_stats;
        other_dstports = &s->proto.other_catchall.unique_dst_ports;
        break;
    default:
        break;
    }

    if (t) {
        r->tcp_pkts            = t->tcp_pkts;
        r->tcp_bytes           = t->tcp_bytes;
        r->syn_pkts            = t->syn_pkts;
        r->syn_ack_pkts        = t->syn_ack_pkts;
        r->fin_ack_pkts        = t->fin_ack_pkts;
        r->rst_pkts            = t->rst_pkts;
        r->ack_data_pkts       = t->ack_data_pkts;
        r->empty_ack_pkts      = t->empty_ack_pkts;
        r->zero_window_pkts    = t->zero_window_pkts;
        r->small_window_pkts   = t->small_window_pkts;
        r->tcp_pkt_size_mean   = t->tcp_pkt_size_mean;
        r->tcp_pkt_size_M2     = t->tcp_pkt_size_M2;
        r->tcp_cm_src_port_top_count = t->cm_src_port.top_count;
        r->tcp_cm_src_port_total     = t->cm_src_port.total;
        r->est_tcp_new_flows   = service_hll_estimate(&t->unique_new_flows);
    }
    if (u) {
        r->udp_pkts            = u->udp_pkts;
        r->udp_bytes           = u->udp_bytes;
        r->udp_pkt_size_mean   = u->udp_pkt_size_mean;
        r->udp_pkt_size_M2     = u->udp_pkt_size_M2;
        r->udp_cm_src_port_top_count = u->cm_src_port.top_count;
        r->udp_cm_src_port_total     = u->cm_src_port.total;
        r->est_udp_flows       = service_hll_estimate(&u->udp_flows);
    }
    if (ic) {
        r->icmp_pkts      = ic->icmp_pkts;
        r->icmp_echo_pkts = ic->icmp_echo_pkts;
        r->icmp_bytes     = ic->icmp_bytes;
    }
    if (o) {
        r->other_pkts  = o->other_pkts;
        r->other_bytes = o->other_bytes;
    }
    if (other_dstports) {
        r->est_other_dst_ports = service_hll_estimate(other_dstports);
    }

    /* Absolute-floor fail-safe (uses the just-computed common flow estimate). */
    r->absolute_floor_fired = snapshot_absolute_floor(s, r->est_unique_flows);
}

/* -------------------------------------------------------------------------
 * Publish
 * ------------------------------------------------------------------------- */

void service_snapshot_publish(const struct service_stats_array *arr,
                              uint64_t now_ns,
                              uint64_t registry_epoch)
{
    if (!g_header || !arr || !arr->slots) return;

    /* Fill the bank NOT currently published. */
    unsigned active = atomic_load_explicit(
        (const _Atomic uint32_t *)&g_header->active_bank,
        memory_order_relaxed) & 1u;
    unsigned target = active ^ 1u;
    struct service_snapshot_record *bank = g_bank[target];

    uint32_t n_active = 0;
    size_t cap = arr->capacity < SERVICE_SNAPSHOT_CAPACITY
               ? arr->capacity : SERVICE_SNAPSHOT_CAPACITY;

    for (size_t i = 0; i < cap; i++) {
        struct service_snapshot_record *r = &bank[i];
        const struct service_stats *s = &arr->slots[i];
        if (!s->active) {
            /* Slot index is the implicit slot_id; keep the slot empty so the
             * reader (proto_kind == 0) skips it. */
            memset(r, 0, sizeof(*r));
            continue;
        }
        fill_record(s, r);
        n_active++;
    }

    /* Metadata for this publish, then flip with release ordering so the
     * reader's acquire-load of active_bank sees all the writes above. */
    g_header->n_active       = n_active;
    g_header->registry_epoch = registry_epoch;
    g_header->produced_ts_ns = now_ns;
    uint64_t seq = ++g_seq;
    if (target == 0) g_header->seq_bank0 = seq;
    else             g_header->seq_bank1 = seq;

    atomic_store_explicit((_Atomic uint32_t *)&g_header->active_bank,
                          target, memory_order_release);
}
