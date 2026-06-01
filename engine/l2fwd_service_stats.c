/**
 * @file   l2fwd_service_stats.c
 * @brief  Per-service runtime stats implementation (P4 — storage + lifecycle).
 *
 * All real implementations of the public API declared in
 * l2fwd_service_stats.h. No detection logic, no feature extraction, no
 * EWMA updates — those land in P8/P9. P4 owns:
 *
 *   - Allocation:   service_stats_array_init()
 *   - Init:         service_stats_init_slot(), _init_from_registry()
 *   - Window reset: service_stats_reset_window(), _reset_window_all()
 *   - Destroy:      service_stats_array_destroy()
 *   - Diagnostics:  service_stats_get_proto_arm/ewma(), _log_slot()
 *
 * Memory model: plain calloc-backed heap allocation. The stats array is
 * created at startup (when P5 wires it in) and lives for the process
 * lifetime, with one in-place reset every 1Hz tick.
 */

#include "l2fwd_service_stats.h"
#include "l2fwd_l2_profile.h"           /* full struct l2_profile */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

/* -------------------------------------------------------------------------
 * Lifecycle
 * ------------------------------------------------------------------------- */

int service_stats_array_init(struct service_stats_array *arr) {
    if (!arr) return -1;
    memset(arr, 0, sizeof(*arr));
    arr->slots = calloc(SERVICE_REGISTRY_MAX_TOTAL_SLOTS,
                         sizeof(struct service_stats));
    if (!arr->slots) {
        fprintf(stderr,
                "[service_stats] [ERROR] allocation of %zu slots "
                "(%zu bytes each = %zu KB) failed\n",
                (size_t)SERVICE_REGISTRY_MAX_TOTAL_SLOTS,
                sizeof(struct service_stats),
                (SERVICE_REGISTRY_MAX_TOTAL_SLOTS *
                 sizeof(struct service_stats)) / 1024);
        return -2;
    }
    arr->capacity = SERVICE_REGISTRY_MAX_TOTAL_SLOTS;
    arr->n_active = 0;
    return 0;
}

int service_stats_init_slot(struct service_stats *slot,
                             const struct service_descriptor *desc)
{
    if (!slot || !desc) return -1;

    /* Zero everything: raw counters + sketches. Zero is a valid initial
     * state for every union arm. */
    memset(slot, 0, sizeof(*slot));

    /* Cache identity from the registry descriptor. */
    slot->key         = desc->key;
    slot->proto_kind  = desc->key.proto_kind;
    slot->is_catchall = desc->is_catchall;
    slot->profile     = desc->profile;
    slot->active      = true;

    return 0;
}

int service_stats_init_from_registry(struct service_stats_array *arr,
                                      const struct service_registry *reg)
{
    if (!arr || !reg) return -1;
    if (!arr->slots)  return -2;  /* array not initialised */

    if (reg->n_slots > arr->capacity) {
        fprintf(stderr,
                "[service_stats] [ERROR] registry has %zu slots but stats "
                "array capacity is %zu\n",
                reg->n_slots, arr->capacity);
        return -3;
    }

    size_t initialized = 0;
    for (size_t i = 0; i < reg->n_slots; i++) {
        int rc = service_stats_init_slot(&arr->slots[i], &reg->slots[i]);
        if (rc != 0) {
            fprintf(stderr,
                    "[service_stats] [ERROR] init_slot %zu failed: rc=%d\n",
                    i, rc);
            return rc;
        }
        initialized++;
    }
    arr->n_active = initialized;

    fprintf(stderr,
            "[service_stats] initialized %zu/%zu slots from registry "
            "(capacity %zu)\n",
            initialized, reg->n_slots, arr->capacity);
    return 0;
}

void service_stats_array_destroy(struct service_stats_array *arr) {
    if (!arr) return;
    if (arr->slots) {
        free(arr->slots);
        arr->slots = NULL;
    }
    arr->capacity = 0;
    arr->n_active = 0;
}

/* -------------------------------------------------------------------------
 * Window reset
 *
 * Zeros the per-window raw counters but PRESERVES:
 *   - identity (key, proto_kind, is_catchall, profile, active)
 *   - EWMA state (mean, variance, sample_count) on every channel
 *   - HLL register arrays (history is what makes them useful)
 *   - CM sketch tables (likewise)
 *   - burst window samples (rolling 3-second buffer)
 *
 * Note on HLL/CM preservation: this is a deliberate choice — the
 * feature-extraction step (P8) will read these *before* the reset, then
 * the reset clears the raw 1Hz counters. HLL and CM are computed over
 * longer windows than 1 second, so they accumulate across ticks.
 *
 * Possible future revision: P8 may decide HLL should reset per-window
 * (matches what the legacy hot path does for unique_src_ips). If so,
 * add the memset calls here and update this comment.
 * ------------------------------------------------------------------------- */
void service_stats_reset_window(struct service_stats *slot) {
    if (!slot || !slot->active) return;

    /* --- Common inbound counters --- */
    slot->common.inbound_pkts   = 0;
    slot->common.inbound_bytes  = 0;
    slot->common.off_proto_pkts = 0;
    slot->common.ttl_mean       = 0.0;
    slot->common.ttl_M2         = 0.0;
    slot->common.ip_frag_pkts   = 0;
    /* HLL / CM / burst-window history preserved (see comment above). */

    /* --- Protocol-specific raw counters --- */
    switch (slot->proto_kind) {
    case SERVICE_PROTO_TCP:
    case SERVICE_PROTO_CATCHALL_TCP: {
        struct service_tcp_stats *t = &slot->proto.tcp.stats;
        t->tcp_pkts          = 0;
        t->tcp_bytes         = 0;
        t->syn_pkts          = 0;
        t->syn_ack_pkts      = 0;
        t->fin_ack_pkts      = 0;
        t->rst_pkts          = 0;
        t->ack_data_pkts     = 0;
        t->empty_ack_pkts    = 0;
        t->zero_window_pkts  = 0;
        t->small_window_pkts = 0;
        t->tcp_pkt_size_mean   = 0.0;
        t->tcp_pkt_size_M2     = 0.0;
        /* HLL unique_new_flows / CM cm_src_port preserved. */
        break;
    }
    case SERVICE_PROTO_UDP:
    case SERVICE_PROTO_CATCHALL_UDP: {
        struct service_udp_stats *u = &slot->proto.udp.stats;
        u->udp_pkts            = 0;
        u->udp_bytes           = 0;
        u->udp_pkt_size_mean   = 0.0;
        u->udp_pkt_size_M2     = 0.0;
        /* HLL / CM preserved. */
        break;
    }
    case SERVICE_PROTO_ICMP:
    case SERVICE_PROTO_CATCHALL_ICMP: {
        struct service_icmp_stats *ic = &slot->proto.icmp.stats;
        ic->icmp_pkts      = 0;
        ic->icmp_echo_pkts = 0;
        ic->icmp_bytes     = 0;
        break;
    }
    case SERVICE_PROTO_CATCHALL_OTHER: {
        struct service_tcp_stats   *t  = &slot->proto.other_catchall.tcp_stats;
        struct service_udp_stats   *u  = &slot->proto.other_catchall.udp_stats;
        struct service_icmp_stats  *ic = &slot->proto.other_catchall.icmp_stats;
        struct service_other_stats *o  = &slot->proto.other_catchall.other_stats;

        t->tcp_pkts          = 0;
        t->tcp_bytes         = 0;
        t->syn_pkts          = 0;
        t->syn_ack_pkts      = 0;
        t->fin_ack_pkts      = 0;
        t->rst_pkts          = 0;
        t->ack_data_pkts     = 0;
        t->empty_ack_pkts    = 0;
        t->zero_window_pkts  = 0;
        t->small_window_pkts = 0;
        t->tcp_pkt_size_mean   = 0.0;
        t->tcp_pkt_size_M2     = 0.0;
        u->udp_pkts            = 0;
        u->udp_bytes           = 0;
        u->udp_pkt_size_mean   = 0.0;
        u->udp_pkt_size_M2     = 0.0;
        ic->icmp_pkts      = 0;
        ic->icmp_echo_pkts = 0;
        ic->icmp_bytes     = 0;
        o->other_pkts  = 0;
        o->other_bytes = 0;
        memset(o->proto_counts, 0, sizeof(o->proto_counts));
        /* HLL / CM in all three arms preserved; unique_dst_ports preserved. */
        break;
    }
    default:
        /* Programmer error if we get here — log once but don't touch the
         * union (which would risk wandering into wrong memory). */
        fprintf(stderr,
                "[service_stats] [WARN] reset_window: unknown proto_kind=%u "
                "for slot at %p\n",
                slot->proto_kind, (const void *)slot);
        break;
    }

    /* --- Outbound counters --- */
    slot->outbound.out_pkts      = 0;
    slot->outbound.out_bytes     = 0;
    slot->outbound.out_tcp_pkts  = 0;
    slot->outbound.out_udp_pkts  = 0;
    slot->outbound.out_icmp_pkts = 0;
    /* HLL unique_dst_ips / unique_dst_ports preserved. */

    slot->window_count++;
}

void service_stats_reset_window_all(struct service_stats_array *arr) {
    if (!arr || !arr->slots) return;
    for (size_t i = 0; i < arr->capacity; i++) {
        if (arr->slots[i].active) {
            service_stats_reset_window(&arr->slots[i]);
        }
    }
}

/* -------------------------------------------------------------------------
 * Helpers / diagnostics
 * ------------------------------------------------------------------------- */

void *service_stats_get_proto_arm(struct service_stats *slot) {
    if (!slot) return NULL;
    switch (slot->proto_kind) {
    case SERVICE_PROTO_TCP:
    case SERVICE_PROTO_CATCHALL_TCP:
        return &slot->proto.tcp.stats;
    case SERVICE_PROTO_UDP:
    case SERVICE_PROTO_CATCHALL_UDP:
        return &slot->proto.udp.stats;
    case SERVICE_PROTO_ICMP:
    case SERVICE_PROTO_CATCHALL_ICMP:
        return &slot->proto.icmp.stats;
    case SERVICE_PROTO_CATCHALL_OTHER:
        return &slot->proto.other_catchall;
    default:
        return NULL;
    }
}

void service_stats_log_slot(const struct service_stats *slot) {
    if (!slot) return;
    char ip_str[16];
    uint32_t ip = slot->key.target_ip;
    snprintf(ip_str, sizeof(ip_str), "%u.%u.%u.%u",
             (ip >> 24) & 0xFFu, (ip >> 16) & 0xFFu,
             (ip >>  8) & 0xFFu,  ip        & 0xFFu);
    fprintf(stderr,
            "[service_stats] slot: ip=%s port=%u proto_kind=%u%s "
            "inbound_pkts=%llu out_pkts=%llu profile=%s active=%d\n",
            ip_str,
            (unsigned)slot->key.port,
            (unsigned)slot->proto_kind,
            slot->is_catchall ? " (catchall)" : "",
            (unsigned long long)slot->common.inbound_pkts,
            (unsigned long long)slot->outbound.out_pkts,
            slot->profile ? "[set]" : "[null]",
            (int)slot->active);
}

size_t service_stats_sizeof(void) {
    return sizeof(struct service_stats);
}
