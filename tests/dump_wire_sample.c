/**
 * @file   tests/dump_wire_sample.c
 * @brief  Emit one canonical v2 wire message to stdout for C->Python
 *         equivalence checking. TEST-ONLY: not part of the engine build.
 *
 * Constructs the SAME known slot + detection_state as the positive
 * roundtrip case in tests/test_service_wire.c (test_full_slot_roundtrip),
 * serializes it with service_wire_serialize_slot(), and writes the raw
 * L2FWD_WIRE_MSG_SIZE bytes to stdout — nothing else. Any human-readable
 * note goes to stderr so stdout stays a pure binary message.
 *
 * KEEP IN SYNC: the field values below mirror test_full_slot_roundtrip so a
 * Python decoder can be checked against the C serializer on identical input.
 * If that test's fixture changes, change this too.
 */

#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>

#include "l2fwd_service_wire.h"
#include "l2fwd_service_stats.h"
#include "l2fwd_service_detection.h"
#include "l2fwd_service_temporal_state.h"
#include "l2fwd_service_registry.h"   /* SERVICE_PROTO_CATCHALL_TCP */
#include "l2fwd_service_scoring.h"    /* DOMINANT_BPS */

int main(void) {
    static struct service_stats slot;
    static struct service_detection_state det;
    static struct service_temporal_state tmp;
    memset(&slot, 0, sizeof(slot));
    memset(&det,  0, sizeof(det));
    memset(&tmp,  0, sizeof(tmp));

    /* Identity. */
    slot.active            = true;
    slot.proto_kind        = SERVICE_PROTO_CATCHALL_TCP;
    slot.is_catchall       = true;
    slot.key.target_ip     = 0x0A0B0C0Du;        /* 10.11.12.13 */
    slot.key.port          = 443;
    slot.detection_state   = &det;
    slot.temporal_state    = &tmp;

    /* Phase state. */
    det.phase                       = 2;            /* SUSPICIOUS */
    det.prev_phase                  = 1;            /* NORMAL    */
    det.warmup_remaining            = 17;
    det.consecutive_attack_windows  =  4;
    det.baseline_freeze_remaining   = 30;
    det.thaw_cooldown_remaining     =  5;
    det.windows_seen                = 12345;
    det.last_tier0_score            = 0.42;
    det.last_tier1_tcp_score        = 0.50;
    det.last_tier1_udp_score        = 0.10;
    det.last_tier1_icmp_score       = 0.05;
    det.last_tier1_dist_score       = 0.65;
    det.last_tier1_l3_score         = 0.30;
    det.last_tier1_offproto_score   = 0.20;
    det.last_tier1_final_score      = 0.65;

    /* v2 Tier-0 risk vector + dominant channel. */
    det.last_tier0_risk_pps         = 0.11;
    det.last_tier0_risk_bps         = 0.22;
    det.last_tier0_risk_fps         = 0.33;
    det.last_tier0_risk_burst_pps   = 0.44;
    det.last_tier0_risk_burst_bps   = 0.55;
    det.last_tier0_risk_burst_fps   = 0.66;
    det.last_dominant_channel       = DOMINANT_BPS;

    /* Raw counters. */
    slot.common.inbound_pkts   = 1000;
    slot.common.inbound_bytes  = 1500u * 1000u;
    slot.common.off_proto_pkts =  3;
    slot.common.ip_frag_pkts   =  1;
    slot.common.ttl_sum        = 64u * 1000u;
    slot.common.ttl_sum_sq     = 64u * 64u * 1000u;
    slot.outbound.out_pkts     =  50;
    slot.outbound.out_bytes    = 1500u * 50u;
    slot.outbound.out_tcp_pkts =  40;
    slot.outbound.out_udp_pkts =   8;
    slot.outbound.out_icmp_pkts=   2;

    /* TCP arm raw counters. */
    slot.proto.tcp.stats.tcp_pkts         = 1000;
    slot.proto.tcp.stats.tcp_bytes        = 1500u * 1000u;
    slot.proto.tcp.stats.syn_pkts         = 200;
    slot.proto.tcp.stats.syn_ack_pkts     =  10;
    slot.proto.tcp.stats.fin_ack_pkts     =   8;
    slot.proto.tcp.stats.rst_pkts         =   5;
    slot.proto.tcp.stats.ack_data_pkts    = 700;
    slot.proto.tcp.stats.empty_ack_pkts   =  70;
    slot.proto.tcp.stats.zero_window_pkts =   0;

    /* Temporal windows. */
    tmp.windows[0].size_seconds   = 10;
    tmp.windows[0].total_pkts     = 10000;
    tmp.windows[0].peak_pps       = 1200.0;
    tmp.windows[0].attack_seconds = 2;
    tmp.windows[1].size_seconds   = 60;
    tmp.windows[1].total_pkts     = 50000;
    tmp.windows[1].peak_pps       = 1200.0;
    tmp.windows[1].attack_seconds = 7;
    tmp.windows[2].size_seconds   = 300;
    tmp.windows[2].total_pkts     = 200000;
    tmp.windows[2].peak_pps       = 1200.0;
    tmp.windows[2].attack_seconds = 12;

    uint8_t buf[L2FWD_WIRE_MSG_SIZE];
    int rc = service_wire_serialize_slot(&slot,
                                         /* slot_id      = */ 42,
                                         /* timestamp_ns = */ 1700000000000000000ULL,
                                         /* sequence_num = */ 9001,
                                         buf);
    if (rc != 0) {
        fprintf(stderr, "dump_wire_sample: serialize failed (rc=%d)\n", rc);
        return 1;
    }

    size_t n = fwrite(buf, 1, L2FWD_WIRE_MSG_SIZE, stdout);
    if (n != (size_t)L2FWD_WIRE_MSG_SIZE) {
        fprintf(stderr, "dump_wire_sample: short write (%zu of %d)\n",
                n, L2FWD_WIRE_MSG_SIZE);
        return 1;
    }
    return 0;
}
