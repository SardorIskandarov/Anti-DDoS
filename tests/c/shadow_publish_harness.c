/*
 * shadow_publish_harness.c — publish a known snapshot bank to the real
 * /dev/shm/anti_ddos_snapshot, then exit WITHOUT unlinking, so a Python
 * ShadowRunner can attach via SnapshotReader and process it. Used by
 * tests/python/test_shadow_e2e.py to validate the live transport path
 * (producer -> shm -> reader -> pipeline).
 *
 * Two sparse active slots (indices 2 and 6) so the test confirms slot_id ==
 * record index and that inactive slots are skipped.
 */

#include "l2fwd_service_snapshot.h"
#include "l2fwd_service_stats.h"
#include "l2fwd_service_features.h"
#include "l2fwd_service_registry.h"
#include "l2fwd_l2_profile.h"

#include <stdio.h>
#include <string.h>
#include <stdbool.h>

/* features.c references these (scoring TU not linked here). */
bool service_scoring_is_frozen(const struct service_stats *s) { (void)s; return false; }
bool service_scoring_cusum_is_frozen(const struct service_stats *s) { (void)s; return false; }

static uint32_t h32(uint32_t k) {
    k ^= k >> 16; k *= 0x85ebca6bu; k ^= k >> 13;
    k *= 0xc2b2ae35u; k ^= k >> 16; return k;
}

int main(void) {
    static struct l2_profile prof; memset(&prof, 0, sizeof(prof));
    prof.name = "shadowp";
    prof.absolute_pps_threshold = 100000.0;   /* high; floor won't fire here */

    static struct service_stats slots[8];
    memset(slots, 0, sizeof(slots));
    struct service_stats_array arr = { .slots = slots, .capacity = 8, .n_active = 2 };

    /* slot index 2: TCP :443 */
    struct service_stats *s = &slots[2];
    s->active = true; s->proto_kind = SERVICE_PROTO_TCP; s->profile = &prof;
    s->window_count = 9;
    s->key.target_ip = 0x01020304u; s->key.port = 443; s->key.proto_kind = SERVICE_PROTO_TCP;
    s->common.inbound_pkts = 1234; s->common.inbound_bytes = 78976;
    s->proto.tcp.stats.tcp_pkts = 1200; s->proto.tcp.stats.syn_pkts = 1100;
    for (uint32_t i = 0; i < 200; i++) {
        service_hll_insert(&s->common.unique_src_ips, h32(i));
        service_hll_insert(&s->common.unique_flows, h32(i * 7u + 1u));
        service_hll_insert(&s->proto.tcp.stats.unique_new_flows, h32(i * 13u + 2u));
    }

    /* slot index 6: UDP :53 */
    s = &slots[6];
    s->active = true; s->proto_kind = SERVICE_PROTO_UDP; s->profile = &prof;
    s->window_count = 9;
    s->key.target_ip = 0x05060708u; s->key.port = 53; s->key.proto_kind = SERVICE_PROTO_UDP;
    s->common.inbound_pkts = 500; s->common.inbound_bytes = 80000;
    s->proto.udp.stats.udp_pkts = 500; s->proto.udp.stats.udp_bytes = 80000;
    for (uint32_t i = 0; i < 40; i++)
        service_hll_insert(&s->proto.udp.stats.udp_flows, h32(i * 131u));

    if (service_snapshot_producer_init() != 0) { fprintf(stderr, "init failed\n"); return 1; }
    service_snapshot_publish(&arr, 555000000000ull, 1);
    printf("published 2 sparse slots (idx 2 TCP:443, idx 6 UDP:53)\n");
    /* leave shm in place for the Python reader */
    return 0;
}
