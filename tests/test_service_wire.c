/**
 * @file   tests/test_service_wire.c
 * @brief  Standalone test harness for the P10 wire protocol.
 *
 * Exercises:
 *   1. CRC32 against canonical vectors ("", "123456789", "fox sentence")
 *   2. Big-endian round-trips on u16 / u32 / u64 / double (NaN, ±0.0, ∞)
 *   3. Endianness check: write_u32(0x12345678) lands as 0x12 0x34 0x56 0x78
 *   4. Full slot serialize + verify + parse-back
 *   5. Verify rejects: wrong-size, bad magic, wrong version, CRC mismatch
 *   6. All 44 registry slots serialize cleanly
 *   7. Performance probe (informational): per-slot serialize cost
 *   8. NULL handling
 *   9. Size constants self-consistency
 *  10. Reserved bytes are zero in a fresh serialisation
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <math.h>
#include <time.h>

#include "l2fwd_service_wire.h"
#include "l2fwd_service_stats.h"
#include "l2fwd_service_detection.h"
#include "l2fwd_service_temporal_state.h"
#include "l2fwd_service_registry.h"

#define SERVICES_JSON_PATH \
    "/home/user_1/Music/Anti-DDoS/service_registry/services.json"

static int g_pass = 0;
static int g_fail = 0;

#define CHECK(cond, fmt, ...) do {                                       \
    if (cond) {                                                           \
        g_pass++;                                                         \
        fprintf(stderr, "  [PASS] " fmt "\n", ##__VA_ARGS__);             \
    } else {                                                              \
        g_fail++;                                                         \
        fprintf(stderr, "  [FAIL] " fmt "  (%s:%d)\n",                    \
                ##__VA_ARGS__, __FILE__, __LINE__);                       \
    }                                                                     \
} while (0)

/* -------------------------------------------------------------------------
 * 1. CRC32 canonical vectors
 * ------------------------------------------------------------------------- */
static void test_crc32_vectors(void) {
    fprintf(stderr, "\n=== POSITIVE: CRC32 known vectors ===\n");
    const char *s = "";
    uint32_t c0 = service_wire_crc32((const uint8_t *)s, 0);
    fprintf(stderr, "  crc32(\"\")           = 0x%08X (expect 0x00000000)\n", c0);
    CHECK(c0 == 0x00000000u, "crc32(\"\") = 0x00000000");

    const char *s1 = "123456789";
    uint32_t c1 = service_wire_crc32((const uint8_t *)s1, 9);
    fprintf(stderr, "  crc32(\"123456789\") = 0x%08X (expect 0xCBF43926)\n", c1);
    CHECK(c1 == 0xCBF43926u, "crc32(\"123456789\") = 0xCBF43926");

    const char *s2 = "The quick brown fox jumps over the lazy dog";
    uint32_t c2 = service_wire_crc32((const uint8_t *)s2, strlen(s2));
    fprintf(stderr, "  crc32(fox sentence)  = 0x%08X (expect 0x414FA339)\n", c2);
    CHECK(c2 == 0x414FA339u, "crc32(\"The quick brown fox...\") = 0x414FA339");
}

/* -------------------------------------------------------------------------
 * 2. Big-endian round-trips
 * ------------------------------------------------------------------------- */
static void test_be_roundtrips(void) {
    fprintf(stderr, "\n=== POSITIVE: BE round-trips for u16/u32/u64/double ===\n");
    uint8_t buf[16];

    service_wire_write_u16(buf, 0x1234);
    CHECK(service_wire_read_u16(buf) == 0x1234u, "u16 0x1234 roundtrip");

    service_wire_write_u32(buf, 0xDEADBEEFu);
    CHECK(service_wire_read_u32(buf) == 0xDEADBEEFu, "u32 0xDEADBEEF roundtrip");

    service_wire_write_u64(buf, 0xCAFEBABE12345678ULL);
    CHECK(service_wire_read_u64(buf) == 0xCAFEBABE12345678ULL,
          "u64 0xCAFEBABE12345678 roundtrip");

    /* Doubles: ordinary, ±0.0, NaN, ±inf. */
    double d_in = 3.141592653589793;
    service_wire_write_double(buf, d_in);
    double d_out = service_wire_read_double(buf);
    CHECK(d_in == d_out, "double 3.14159... roundtrip (bit-exact)");

    service_wire_write_double(buf, -0.0);
    d_out = service_wire_read_double(buf);
    uint64_t bits_neg0 = 0;
    memcpy(&bits_neg0, &d_out, 8);
    CHECK(bits_neg0 == 0x8000000000000000ULL, "double -0.0 preserves sign bit");

    double nan_in = (double)NAN;
    service_wire_write_double(buf, nan_in);
    d_out = service_wire_read_double(buf);
    CHECK(isnan(d_out), "double NaN roundtrip");

    service_wire_write_double(buf, INFINITY);
    d_out = service_wire_read_double(buf);
    CHECK(isinf(d_out) && d_out > 0.0, "double +inf roundtrip");

    service_wire_write_double(buf, -INFINITY);
    d_out = service_wire_read_double(buf);
    CHECK(isinf(d_out) && d_out < 0.0, "double -inf roundtrip");
}

/* -------------------------------------------------------------------------
 * 3. Endianness verification
 * ------------------------------------------------------------------------- */
static void test_endianness(void) {
    fprintf(stderr, "\n=== POSITIVE: byte order on the wire is big-endian ===\n");
    uint8_t buf[4];
    service_wire_write_u32(buf, 0x12345678u);
    CHECK(buf[0] == 0x12 && buf[1] == 0x34 && buf[2] == 0x56 && buf[3] == 0x78,
          "u32 0x12345678 -> bytes [12 34 56 78] (got [%02x %02x %02x %02x])",
          buf[0], buf[1], buf[2], buf[3]);

    uint8_t b2[2];
    service_wire_write_u16(b2, 0xABCDu);
    CHECK(b2[0] == 0xAB && b2[1] == 0xCD,
          "u16 0xABCD -> bytes [AB CD] (got [%02x %02x])", b2[0], b2[1]);
}

/* -------------------------------------------------------------------------
 * 4. Full slot serialize -> verify -> parse-back
 * ------------------------------------------------------------------------- */
static void test_full_slot_roundtrip(void) {
    fprintf(stderr, "\n=== POSITIVE: full slot serialize -> verify -> parse-back ===\n");

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
    slot.proto.tcp.stats.tcp_pkts       = 1000;
    slot.proto.tcp.stats.tcp_bytes      = 1500u * 1000u;
    slot.proto.tcp.stats.syn_pkts       = 200;
    slot.proto.tcp.stats.syn_ack_pkts   =  10;
    slot.proto.tcp.stats.fin_ack_pkts   =   8;
    slot.proto.tcp.stats.rst_pkts       =   5;
    slot.proto.tcp.stats.ack_data_pkts  = 700;
    slot.proto.tcp.stats.empty_ack_pkts =  70;
    slot.proto.tcp.stats.zero_window_pkts =  0;

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
                                          /* slot_id = */ 42,
                                          /* timestamp_ns = */ 1700000000000000000ULL,
                                          /* sequence_num = */ 9001,
                                          buf);
    CHECK(rc == 0, "serialize returned 0 (rc=%d)", rc);

    int vrc = service_wire_verify(buf, sizeof(buf));
    CHECK(vrc == L2FWD_WIRE_OK,
          "verify returned OK (rc=%d)", vrc);

    /* --- Parse back and compare --- */

    /* Header. */
    CHECK(buf[0]=='L' && buf[1]=='2' && buf[2]=='F' && buf[3]=='W',
          "magic = 'L2FW'");
    CHECK(buf[4] == L2FWD_WIRE_VERSION,        "version = 0x01");
    CHECK(buf[5] == L2FWD_WIRE_MSGTYPE_SNAP,   "msg_type = 0x01");
    CHECK(service_wire_read_u64(buf + 8) == 1700000000000000000ULL,
          "timestamp_ns roundtripped");
    CHECK(service_wire_read_u16(buf + 16) == 42, "slot_id roundtripped");
    CHECK(service_wire_read_u16(buf + 18) == L2FWD_WIRE_PAYLOAD_SIZE,
          "payload_len = 380");
    CHECK(service_wire_read_u64(buf + 20) == 9001ULL,
          "sequence_num roundtripped");

    /* Payload — identity. */
    const uint8_t *pl = buf + L2FWD_WIRE_HEADER_SIZE;
    const uint8_t *id = pl + L2FWD_WIRE_PL_IDENTITY_OFF;
    CHECK(service_wire_read_u32(id + 0) == 0x0A0B0C0Du,
          "target_ip = 10.11.12.13");
    CHECK(service_wire_read_u16(id + 4) == 443, "port = 443");
    CHECK(id[6] == SERVICE_PROTO_CATCHALL_TCP, "proto_kind preserved");
    CHECK(id[7] == 1, "is_catchall = 1");

    /* Phase state. */
    const uint8_t *ph = pl + L2FWD_WIRE_PL_PHASE_OFF;
    CHECK(ph[0] == 2, "phase = SUSPICIOUS");
    CHECK(ph[1] == 1, "prev_phase = NORMAL");
    CHECK(service_wire_read_u32(ph +  4) == 17, "warmup_remaining = 17");
    CHECK(service_wire_read_u32(ph +  8) ==  4, "consecutive_attack = 4");
    CHECK(service_wire_read_u32(ph + 12) == 30, "freeze_remaining = 30");
    CHECK(service_wire_read_u32(ph + 16) ==  5, "thaw_remaining = 5");
    CHECK(service_wire_read_u32(ph + 20) == 12345, "windows_seen = 12345");

    /* Counters. */
    const uint8_t *c = pl + L2FWD_WIRE_PL_COUNTERS_OFF;
    CHECK(service_wire_read_u64(c +  0) == 1000,        "inbound_pkts = 1000");
    CHECK(service_wire_read_u64(c +  8) == 1500*1000u,  "inbound_bytes = 1.5M");
    CHECK(service_wire_read_u64(c + 16) ==  3,          "off_proto_pkts = 3");
    CHECK(service_wire_read_u64(c + 24) ==  1,          "ip_frag_pkts = 1");
    CHECK(service_wire_read_u64(c + 48) ==  50,         "out_pkts = 50");
    CHECK(service_wire_read_u32(c + 64) ==  40,         "out_tcp_pkts = 40");
    CHECK(service_wire_read_u32(c + 68) ==   8,         "out_udp_pkts = 8");
    CHECK(service_wire_read_u32(c + 72) ==   2,         "out_icmp_pkts = 2");

    /* Proto section. */
    const uint8_t *p = pl + L2FWD_WIRE_PL_PROTO_OFF;
    CHECK(service_wire_read_u64(p +  0) == 1000, "tcp_pkts = 1000");
    CHECK(service_wire_read_u64(p + 16) ==  200, "syn_pkts = 200");
    CHECK(service_wire_read_u64(p + 24) ==   10, "syn_ack_pkts = 10");
    CHECK(service_wire_read_u64(p + 56) ==   70, "empty_ack_pkts = 70");
    CHECK(service_wire_read_u64(p + 72) ==    0, "udp_pkts = 0 (TCP-only slot)");
    CHECK(service_wire_read_u64(p + 88) ==    0, "icmp_pkts = 0");

    /* Scores. */
    const uint8_t *s = pl + L2FWD_WIRE_PL_SCORES_OFF;
    double t0 = service_wire_read_double(s + 0);
    double t1_final = service_wire_read_double(s + 56);
    double t1_dist  = service_wire_read_double(s + 32);
    CHECK(t0 == 0.42, "last_tier0_score = 0.42 (got %.4f)", t0);
    CHECK(t1_dist == 0.65, "last_tier1_dist_score = 0.65 (got %.4f)", t1_dist);
    CHECK(t1_final == 0.65, "last_tier1_final_score = 0.65 (got %.4f)", t1_final);

    /* Temporal windows. */
    const uint8_t *tw = pl + L2FWD_WIRE_PL_TEMPORAL_OFF;
    CHECK(service_wire_read_u32(tw +  0) == 10000,
          "windows[0].total_pkts = 10000");
    CHECK(service_wire_read_u32(tw +  4) == 1200,
          "windows[0].peak_pps = 1200 (truncated from double)");
    CHECK(service_wire_read_u32(tw +  8) ==     2,
          "windows[0].attack_seconds = 2");
    CHECK(service_wire_read_u32(tw + 16) == 1200,
          "windows[1].peak_pps = 1200");
    CHECK(service_wire_read_u32(tw + 20) ==     7,
          "windows[1].attack_seconds = 7");
    CHECK(service_wire_read_u32(tw + 32) ==    12,
          "windows[2].attack_seconds = 12");
}

/* -------------------------------------------------------------------------
 * 5. Verify rejects malformed messages
 * ------------------------------------------------------------------------- */
static void test_verify_rejects(void) {
    fprintf(stderr, "\n=== NEGATIVE: verify rejects malformed messages ===\n");
    static struct service_stats slot;
    static struct service_detection_state det;
    memset(&slot, 0, sizeof(slot));
    memset(&det,  0, sizeof(det));
    slot.active          = true;
    slot.proto_kind      = SERVICE_PROTO_TCP;
    slot.detection_state = &det;
    slot.common.inbound_pkts = 1;

    uint8_t buf[L2FWD_WIRE_MSG_SIZE];
    int rc = service_wire_serialize_slot(&slot, 0, 1, 1, buf);
    CHECK(rc == 0, "baseline serialize OK");
    CHECK(service_wire_verify(buf, sizeof(buf)) == L2FWD_WIRE_OK,
          "baseline verify OK");

    /* Wrong size. */
    CHECK(service_wire_verify(buf, 400) == L2FWD_WIRE_ERR_SIZE,
          "size=400 -> ERR_SIZE");
    CHECK(service_wire_verify(NULL, L2FWD_WIRE_MSG_SIZE)
          == L2FWD_WIRE_ERR_SIZE,
          "NULL buffer -> ERR_SIZE");

    /* Bad magic. */
    uint8_t bad[L2FWD_WIRE_MSG_SIZE];
    memcpy(bad, buf, L2FWD_WIRE_MSG_SIZE);
    bad[0] = 'X';
    CHECK(service_wire_verify(bad, sizeof(bad)) == L2FWD_WIRE_ERR_MAGIC,
          "bad magic[0] -> ERR_MAGIC");

    /* Wrong version. */
    memcpy(bad, buf, L2FWD_WIRE_MSG_SIZE);
    bad[4] = 99;
    CHECK(service_wire_verify(bad, sizeof(bad)) == L2FWD_WIRE_ERR_VERSION,
          "version=99 -> ERR_VERSION");

    /* Wrong msg_type. */
    memcpy(bad, buf, L2FWD_WIRE_MSG_SIZE);
    bad[5] = 0x77;
    CHECK(service_wire_verify(bad, sizeof(bad)) == L2FWD_WIRE_ERR_MSGTYPE,
          "msg_type=0x77 -> ERR_MSGTYPE");

    /* Wrong payload_len. */
    memcpy(bad, buf, L2FWD_WIRE_MSG_SIZE);
    service_wire_write_u16(bad + 18, 379);
    CHECK(service_wire_verify(bad, sizeof(bad)) == L2FWD_WIRE_ERR_PAYLOAD,
          "payload_len=379 -> ERR_PAYLOAD");

    /* CRC mismatch — corrupt a byte deep in the payload but leave the
     * CRC unchanged. */
    memcpy(bad, buf, L2FWD_WIRE_MSG_SIZE);
    bad[200] ^= 0x01;
    CHECK(service_wire_verify(bad, sizeof(bad)) == L2FWD_WIRE_ERR_CRC,
          "single-byte corruption -> ERR_CRC");
}

/* -------------------------------------------------------------------------
 * 6. All 44 registry slots serialize cleanly
 * ------------------------------------------------------------------------- */
static void test_all_registry_slots(void) {
    fprintf(stderr, "\n=== POSITIVE: all registry slots serialize + verify ===\n");

    static struct service_registry    reg;
    static struct service_stats_array arr;

    int rc = service_registry_init(&reg);
    CHECK(rc == 0, "registry_init OK");
    rc = service_registry_load(&reg, SERVICES_JSON_PATH);
    CHECK(rc == 0, "registry_load OK (rc=%d)", rc);

    rc = service_stats_array_init(&arr);
    CHECK(rc == 0, "stats_array_init OK");
    rc = service_stats_init_from_registry(&arr, &reg);
    CHECK(rc == 0, "init_from_registry OK");
    rc = service_stats_wire_all(&arr);
    CHECK(rc == 0, "stats_wire_all OK");

    int serialized = 0, verified = 0;
    uint8_t buf[L2FWD_WIRE_MSG_SIZE];
    for (size_t i = 0; i < arr.capacity; i++) {
        struct service_stats *s = &arr.slots[i];
        if (!s->active) continue;
        int srz = service_wire_serialize_slot(s, (uint16_t)i,
                                               1700000000000000000ULL,
                                               (uint64_t)i, buf);
        if (srz == 0) serialized++;
        if (service_wire_verify(buf, sizeof(buf)) == L2FWD_WIRE_OK) verified++;
    }
    fprintf(stderr, "  serialized=%d verified=%d (active=%zu)\n",
            serialized, verified, arr.n_active);
    CHECK(serialized == (int)arr.n_active,
          "serialize succeeded on all %zu active slots", arr.n_active);
    CHECK(verified   == (int)arr.n_active,
          "verify succeeded on all %zu active slots",     arr.n_active);

    service_stats_unwire_all(&arr);
    service_stats_array_destroy(&arr);
    service_registry_destroy(&reg);
}

/* -------------------------------------------------------------------------
 * 7. Performance probe
 * ------------------------------------------------------------------------- */
static void test_performance(void) {
    fprintf(stderr, "\n=== INFORMATIONAL: serialize throughput ===\n");
    static struct service_stats slot;
    static struct service_detection_state det;
    memset(&slot, 0, sizeof(slot));
    memset(&det,  0, sizeof(det));
    slot.active            = true;
    slot.proto_kind        = SERVICE_PROTO_CATCHALL_TCP;
    slot.is_catchall       = true;
    slot.detection_state   = &det;
    slot.common.inbound_pkts = 1000;
    det.phase = 1;

    uint8_t buf[L2FWD_WIRE_MSG_SIZE];
    const int N = 10000;
    struct timespec t0, t1;
    clock_gettime(CLOCK_MONOTONIC, &t0);
    for (int i = 0; i < N; i++) {
        service_wire_serialize_slot(&slot, (uint16_t)(i & 0xFFFF),
                                     1700000000000000000ULL + i,
                                     (uint64_t)i, buf);
    }
    clock_gettime(CLOCK_MONOTONIC, &t1);
    double elapsed_ns = (double)(t1.tv_sec  - t0.tv_sec ) * 1e9
                      + (double)(t1.tv_nsec - t0.tv_nsec);
    double per_slot_us = elapsed_ns / (double)N / 1000.0;
    fprintf(stderr,
        "  serialized %d messages in %.3f ms (%.3f µs per slot)\n",
        N, elapsed_ns / 1e6, per_slot_us);
    /* Not a hard failure — informational. ~ a few µs per slot easily
     * keeps us well below the 1Hz tick budget at 328 slots. */
    CHECK(per_slot_us < 50.0,
          "serialize cost under 50µs per slot (got %.3f)", per_slot_us);
}

/* -------------------------------------------------------------------------
 * 8. NULL handling
 * ------------------------------------------------------------------------- */
static void test_null_handling(void) {
    fprintf(stderr, "\n=== NEGATIVE: NULL handling ===\n");
    uint8_t buf[L2FWD_WIRE_MSG_SIZE];

    CHECK(service_wire_serialize_slot(NULL, 0, 0, 0, buf) < 0,
          "serialize(NULL slot) returns negative");

    static struct service_stats slot;
    memset(&slot, 0, sizeof(slot));
    slot.active = true;
    CHECK(service_wire_serialize_slot(&slot, 0, 0, 0, NULL) < 0,
          "serialize(NULL buffer) returns negative");

    slot.active = false;
    CHECK(service_wire_serialize_slot(&slot, 0, 0, 0, buf) < 0,
          "serialize(inactive slot) returns negative");

    /* CRC on NULL/0 bytes — return 0 by definition. */
    CHECK(service_wire_crc32(NULL, 0) == 0x00000000u,
          "crc32(NULL, 0) = 0");
}

/* -------------------------------------------------------------------------
 * 9. Size constants self-consistency
 * ------------------------------------------------------------------------- */
static void test_size_constants(void) {
    fprintf(stderr, "\n=== POSITIVE: size constants self-consistent ===\n");
    CHECK(L2FWD_WIRE_HEADER_SIZE + L2FWD_WIRE_PAYLOAD_SIZE +
          L2FWD_WIRE_FOOTER_SIZE == L2FWD_WIRE_MSG_SIZE,
          "header + payload + footer = MSG_SIZE (%d)",
          L2FWD_WIRE_MSG_SIZE);
    int sum_payload = L2FWD_WIRE_PL_IDENTITY_SIZE
                    + L2FWD_WIRE_PL_PHASE_SIZE
                    + L2FWD_WIRE_PL_COUNTERS_SIZE
                    + L2FWD_WIRE_PL_PROTO_SIZE
                    + L2FWD_WIRE_PL_FEATURES_SIZE
                    + L2FWD_WIRE_PL_SCORES_SIZE
                    + L2FWD_WIRE_PL_TEMPORAL_SIZE;
    CHECK(sum_payload == L2FWD_WIRE_PAYLOAD_SIZE,
          "payload sections sum to PAYLOAD_SIZE (%d, got %d)",
          L2FWD_WIRE_PAYLOAD_SIZE, sum_payload);

    /* Section offsets are consecutive. */
    CHECK(L2FWD_WIRE_PL_IDENTITY_OFF == 0,                    "identity off=0");
    CHECK(L2FWD_WIRE_PL_PHASE_OFF    ==   L2FWD_WIRE_PL_IDENTITY_OFF
                                       + L2FWD_WIRE_PL_IDENTITY_SIZE,
          "phase off follows identity");
    CHECK(L2FWD_WIRE_PL_COUNTERS_OFF ==   L2FWD_WIRE_PL_PHASE_OFF
                                       + L2FWD_WIRE_PL_PHASE_SIZE,
          "counters off follows phase");
    CHECK(L2FWD_WIRE_PL_PROTO_OFF    ==   L2FWD_WIRE_PL_COUNTERS_OFF
                                       + L2FWD_WIRE_PL_COUNTERS_SIZE,
          "proto off follows counters");
    CHECK(L2FWD_WIRE_PL_FEATURES_OFF ==   L2FWD_WIRE_PL_PROTO_OFF
                                       + L2FWD_WIRE_PL_PROTO_SIZE,
          "features off follows proto");
    CHECK(L2FWD_WIRE_PL_SCORES_OFF   ==   L2FWD_WIRE_PL_FEATURES_OFF
                                       + L2FWD_WIRE_PL_FEATURES_SIZE,
          "scores off follows features");
    CHECK(L2FWD_WIRE_PL_TEMPORAL_OFF ==   L2FWD_WIRE_PL_SCORES_OFF
                                       + L2FWD_WIRE_PL_SCORES_SIZE,
          "temporal off follows scores");
}

/* -------------------------------------------------------------------------
 * 10. Reserved bytes are zero
 * ------------------------------------------------------------------------- */
static void test_reserved_zero(void) {
    fprintf(stderr, "\n=== POSITIVE: reserved bytes are zero in fresh msg ===\n");
    static struct service_stats slot;
    static struct service_detection_state det;
    memset(&slot, 0, sizeof(slot));
    memset(&det,  0, sizeof(det));
    slot.active          = true;
    slot.detection_state = &det;
    slot.common.inbound_pkts = 1;

    uint8_t buf[L2FWD_WIRE_MSG_SIZE];
    int rc = service_wire_serialize_slot(&slot, 0, 1, 1, buf);
    CHECK(rc == 0, "serialize OK");

    /* Header reserved at offsets 6..7 and 28..31. */
    CHECK(buf[6]  == 0 && buf[7]  == 0, "header reserved [6..7] = 0");
    CHECK(buf[28] == 0 && buf[29] == 0 && buf[30] == 0 && buf[31] == 0,
          "header reserved [28..31] = 0");

    /* Phase reserved at payload offset 18..19 (= buffer offset 50..51). */
    const uint8_t *pl = buf + L2FWD_WIRE_HEADER_SIZE;
    const uint8_t *ph = pl + L2FWD_WIRE_PL_PHASE_OFF;
    CHECK(ph[2] == 0 && ph[3] == 0, "phase reserved [2..3] = 0");

    /* Counters reserved at offset 76..79 (= buffer offset 116..119). */
    const uint8_t *c = pl + L2FWD_WIRE_PL_COUNTERS_OFF;
    CHECK(c[76] == 0 && c[77] == 0 && c[78] == 0 && c[79] == 0,
          "counters reserved [76..79] = 0");
}

/* -------------------------------------------------------------------------
 * main
 * ------------------------------------------------------------------------- */
int main(void) {
    fprintf(stderr, "\n*** service_wire P10 test harness ***\n");
    test_crc32_vectors();
    test_be_roundtrips();
    test_endianness();
    test_full_slot_roundtrip();
    test_verify_rejects();
    test_all_registry_slots();
    test_performance();
    test_null_handling();
    test_size_constants();
    test_reserved_zero();

    fprintf(stderr, "\n=== SUMMARY: %d PASS, %d FAIL ===\n", g_pass, g_fail);
    return (g_fail == 0) ? 0 : 1;
}
