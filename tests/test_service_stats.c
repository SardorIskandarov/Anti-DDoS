/**
 * @file   tests/test_service_stats.c
 * @brief  Standalone test harness for the P4 service_stats data model.
 *
 * Exercises:
 *   - array_init / array_destroy lifecycle
 *   - init_from_registry against the real services.json
 *   - Per-slot identity caching
 *   - Window simulation + reset semantics
 *   - OTHER catchall reset (all three protocol arms + proto_counts)
 *   - Memory budget (sizeof + array footprint ≤ 16 MB)
 *   - Idempotency on cleanup + re-init
 *   - NULL-input safety
 *
 * Build:  ninja -C build test_service_stats
 * Run:    ./build/test_service_stats
 * Returns 0 on full pass, 1 on any FAIL.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

#include "l2fwd_service_registry.h"
#include "l2fwd_service_stats.h"

#define SERVICES_JSON_PATH \
    "/home/user_1/Music/Anti-DDoS/service_registry/services.json"

/* -------------------------------------------------------------------------
 * Tiny assertion framework
 * ------------------------------------------------------------------------- */
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

static uint32_t mk_ip(uint8_t a, uint8_t b, uint8_t c, uint8_t d) {
    return ((uint32_t)a << 24) | ((uint32_t)b << 16) |
           ((uint32_t)c << 8)  |  (uint32_t)d;
}

/* Locate the slot in `arr` matching (ip, port, proto_kind). */
static struct service_stats *
find_slot(struct service_stats_array *arr,
          uint32_t ip, uint16_t port, uint8_t kind)
{
    if (!arr || !arr->slots) return NULL;
    for (size_t i = 0; i < arr->capacity; i++) {
        struct service_stats *s = &arr->slots[i];
        if (!s->active) continue;
        if (s->key.target_ip == ip &&
            s->key.port      == port &&
            s->key.proto_kind == kind) {
            return s;
        }
    }
    return NULL;
}

/* -------------------------------------------------------------------------
 * Tests
 * ------------------------------------------------------------------------- */

static int test_array_init(struct service_stats_array *arr) {
    fprintf(stderr, "\n=== POSITIVE: array_init ===\n");
    int rc = service_stats_array_init(arr);
    CHECK(rc == 0, "array_init returned 0 (rc=%d)", rc);
    CHECK(arr->slots != NULL, "arr->slots is non-NULL");
    CHECK(arr->capacity == SERVICE_REGISTRY_MAX_TOTAL_SLOTS,
          "capacity=%zu == SERVICE_REGISTRY_MAX_TOTAL_SLOTS=%d",
          arr->capacity, SERVICE_REGISTRY_MAX_TOTAL_SLOTS);
    CHECK(arr->n_active == 0, "n_active=%zu (expect 0)", arr->n_active);
    return rc;
}

static int test_init_from_registry(struct service_stats_array *arr,
                                    struct service_registry *reg) {
    fprintf(stderr, "\n=== POSITIVE: registry load → init_from_registry ===\n");
    int rc = service_registry_load(reg, SERVICES_JSON_PATH);
    CHECK(rc == 0, "registry_load returned 0 (rc=%d)", rc);
    CHECK(reg->n_slots == 44, "registry n_slots=%zu (expect 44)", reg->n_slots);

    rc = service_stats_init_from_registry(arr, reg);
    CHECK(rc == 0, "init_from_registry returned 0 (rc=%d)", rc);
    CHECK(arr->n_active == 44, "arr->n_active=%zu (expect 44)", arr->n_active);
    return rc;
}

static int test_slots_initialized_correctly(const struct service_stats_array *arr) {
    fprintf(stderr, "\n=== POSITIVE: 44/44 slots correctly initialized ===\n");
    int n_active = 0, n_profile_set = 0, n_catchall = 0;
    int n_kind_ok = 0, n_counters_zero = 0, n_ewma_zero = 0;

    for (size_t i = 0; i < arr->capacity; i++) {
        const struct service_stats *s = &arr->slots[i];
        if (!s->active) continue;
        n_active++;

        if (s->profile != NULL)                    n_profile_set++;
        if (s->is_catchall)                        n_catchall++;
        uint8_t k = s->proto_kind;
        if (k == SERVICE_PROTO_CATCHALL_TCP   ||
            k == SERVICE_PROTO_CATCHALL_UDP   ||
            k == SERVICE_PROTO_CATCHALL_ICMP  ||
            k == SERVICE_PROTO_CATCHALL_OTHER) n_kind_ok++;

        /* Spot-check several counter fields are zero. */
        if (s->common.inbound_pkts == 0 &&
            s->common.inbound_bytes == 0 &&
            s->common.ttl_sum == 0 &&
            s->outbound.out_pkts == 0 &&
            s->outbound.out_tcp_pkts == 0 &&
            s->window_count == 0 &&
            s->detection_state == NULL &&
            s->temporal_state == NULL) {
            n_counters_zero++;
        }

        /* EWMA spot-check: pps + bps both uninitialised and zero. */
        if (!s->common_ewma.pps.initialized &&
            s->common_ewma.pps.mean == 0.0 &&
            !s->common_ewma.bps.initialized &&
            s->common_ewma.bps.mean == 0.0) {
            n_ewma_zero++;
        }
    }

    CHECK(n_active == 44,       "44/%d slots active",       n_active);
    CHECK(n_profile_set == 44,  "44/%d slots have profile", n_profile_set);
    CHECK(n_catchall == 44,     "44/%d slots is_catchall",  n_catchall);
    CHECK(n_kind_ok == 44,
          "44/%d slots have a recognized CATCHALL_* kind", n_kind_ok);
    CHECK(n_counters_zero == 44,
          "44/%d slots have zero raw counters + NULL placeholders",
          n_counters_zero);
    CHECK(n_ewma_zero == 44,
          "44/%d slots have uninitialised+zero EWMA state", n_ewma_zero);
    return 0;
}

static int test_simulated_window_and_reset(struct service_stats_array *arr) {
    fprintf(stderr, "\n=== POSITIVE: simulated window + reset (TCP catchall) ===\n");
    uint32_t ip50 = mk_ip(213, 230, 125, 50);
    struct service_stats *s =
        find_slot(arr, ip50, 0, SERVICE_PROTO_CATCHALL_TCP);
    CHECK(s != NULL, "found TCP catchall slot for 213.230.125.50");
    if (!s) return -1;

    /* Cache identity for the comparison after reset. */
    service_key_t  saved_key       = s->key;
    uint8_t        saved_kind      = s->proto_kind;
    bool           saved_catchall  = s->is_catchall;
    const struct l2_profile *saved_profile = s->profile;

    /* Populate counters. */
    s->common.inbound_pkts        = 1000;
    s->common.inbound_bytes       = 1500000;
    s->proto.tcp.stats.syn_pkts   = 200;
    s->proto.tcp.stats.tcp_pkts   = 1000;
    s->proto.tcp.stats.tcp_bytes  = 1450000;
    s->outbound.out_pkts          = 50;
    s->outbound.out_tcp_pkts      = 50;

    CHECK(s->common.inbound_pkts    == 1000, "inbound_pkts stored (1000)");
    CHECK(s->proto.tcp.stats.syn_pkts == 200, "syn_pkts stored (200)");
    CHECK(s->outbound.out_pkts      == 50,   "out_pkts stored (50)");

    /* Reset. */
    uint32_t prev_count = s->window_count;
    service_stats_reset_window(s);

    CHECK(s->common.inbound_pkts == 0,     "inbound_pkts cleared");
    CHECK(s->common.inbound_bytes == 0,    "inbound_bytes cleared");
    CHECK(s->proto.tcp.stats.syn_pkts == 0, "syn_pkts cleared");
    CHECK(s->proto.tcp.stats.tcp_pkts == 0, "tcp_pkts cleared");
    CHECK(s->outbound.out_pkts == 0,       "outbound.out_pkts cleared");
    CHECK(s->outbound.out_tcp_pkts == 0,   "outbound.out_tcp_pkts cleared");

    CHECK(s->window_count == prev_count + 1,
          "window_count incremented to %u", (unsigned)s->window_count);

    CHECK(memcmp(&saved_key, &s->key, sizeof(saved_key)) == 0,
          "key preserved across reset");
    CHECK(s->proto_kind == saved_kind,
          "proto_kind preserved (%u)", (unsigned)s->proto_kind);
    CHECK(s->is_catchall == saved_catchall, "is_catchall preserved");
    CHECK(s->profile == saved_profile, "profile pointer preserved");
    CHECK(s->active == true, "active preserved");
    return 0;
}

static int test_other_catchall_reset(struct service_stats_array *arr) {
    fprintf(stderr, "\n=== POSITIVE: other_catchall reset (all 3 proto arms + proto_counts) ===\n");
    uint32_t ip50 = mk_ip(213, 230, 125, 50);
    struct service_stats *s =
        find_slot(arr, ip50, 0, SERVICE_PROTO_CATCHALL_OTHER);
    CHECK(s != NULL, "found OTHER catchall slot for 213.230.125.50");
    if (!s) return -1;

    /* Populate every arm. */
    s->proto.other_catchall.tcp_stats.syn_pkts            = 100;
    s->proto.other_catchall.tcp_stats.tcp_pkts            = 300;
    s->proto.other_catchall.udp_stats.udp_pkts            = 200;
    s->proto.other_catchall.icmp_stats.icmp_pkts          = 50;
    s->proto.other_catchall.icmp_stats.icmp_echo_pkts     = 30;
    s->proto.other_catchall.other_stats.other_pkts        = 25;
    s->proto.other_catchall.other_stats.proto_counts[47]  = 10;  /* GRE */
    s->proto.other_catchall.other_stats.proto_counts[50]  = 7;   /* ESP */
    s->common.inbound_pkts = 575;

    /* Reset. */
    service_stats_reset_window(s);

    CHECK(s->proto.other_catchall.tcp_stats.syn_pkts == 0,   "tcp_stats.syn_pkts cleared");
    CHECK(s->proto.other_catchall.tcp_stats.tcp_pkts == 0,   "tcp_stats.tcp_pkts cleared");
    CHECK(s->proto.other_catchall.udp_stats.udp_pkts == 0,   "udp_stats.udp_pkts cleared");
    CHECK(s->proto.other_catchall.icmp_stats.icmp_pkts == 0, "icmp_stats.icmp_pkts cleared");
    CHECK(s->proto.other_catchall.icmp_stats.icmp_echo_pkts == 0,
          "icmp_stats.icmp_echo_pkts cleared");
    CHECK(s->proto.other_catchall.other_stats.other_pkts == 0,
          "other_stats.other_pkts cleared");
    CHECK(s->proto.other_catchall.other_stats.proto_counts[47] == 0,
          "proto_counts[47] (GRE) cleared");
    CHECK(s->proto.other_catchall.other_stats.proto_counts[50] == 0,
          "proto_counts[50] (ESP) cleared");
    CHECK(s->common.inbound_pkts == 0, "common.inbound_pkts cleared");
    CHECK(s->active == true, "active still true after reset");
    CHECK(s->proto_kind == SERVICE_PROTO_CATCHALL_OTHER,
          "proto_kind still CATCHALL_OTHER");
    return 0;
}

static int test_memory_budget(const struct service_stats_array *arr) {
    fprintf(stderr, "\n=== POSITIVE: memory budget ===\n");
    size_t per_slot = service_stats_sizeof();
    size_t total    = per_slot * arr->capacity;
    double total_mb = (double)total / (1024.0 * 1024.0);
    fprintf(stderr, "  sizeof(struct service_stats) = %zu bytes\n", per_slot);
    fprintf(stderr, "  total array size = %zu bytes = %.2f MB (%zu slots)\n",
            total, total_mb, arr->capacity);
    /* 16 MB ceiling per spec. */
    CHECK(total <= (size_t)16 * 1024 * 1024,
          "total %.2f MB ≤ 16 MB ceiling", total_mb);
    return 0;
}

static int test_idempotency(void) {
    fprintf(stderr, "\n=== POSITIVE: cleanup + re-init idempotent ===\n");
    static struct service_registry reg;
    static struct service_stats_array arr;

    /* Init twice in a row: second call should reset cleanly. */
    int rc = service_stats_array_init(&arr);
    CHECK(rc == 0, "first init OK");
    /* Destroy then re-init. */
    service_stats_array_destroy(&arr);
    rc = service_stats_array_init(&arr);
    CHECK(rc == 0, "re-init after destroy OK");

    /* Load registry + init from it twice; both should succeed. */
    rc = service_registry_load(&reg, SERVICES_JSON_PATH);
    CHECK(rc == 0, "registry_load (1st) OK");
    rc = service_stats_init_from_registry(&arr, &reg);
    CHECK(rc == 0, "init_from_registry (1st) OK");

    /* Reload registry, re-init stats — simulates a P6 SIGHUP reload. */
    rc = service_registry_load(&reg, SERVICES_JSON_PATH);
    CHECK(rc == 0, "registry_load (2nd, reload) OK");
    rc = service_stats_init_from_registry(&arr, &reg);
    CHECK(rc == 0, "init_from_registry (2nd) OK");

    /* Final clean up. Calling destroy twice is also fine. */
    service_stats_array_destroy(&arr);
    service_stats_array_destroy(&arr);   /* idempotent */
    service_registry_destroy(&reg);
    return 0;
}

static int test_null_inputs(void) {
    fprintf(stderr, "\n=== NEGATIVE: NULL inputs handled ===\n");

    int rc = service_stats_init_slot(NULL, NULL);
    CHECK(rc < 0, "init_slot(NULL, NULL) returned negative (rc=%d)", rc);

    rc = service_stats_init_from_registry(NULL, NULL);
    CHECK(rc < 0, "init_from_registry(NULL, NULL) returned negative (rc=%d)",
          rc);

    /* Non-NULL arr but NULL registry. */
    static struct service_stats_array arr;
    service_stats_array_init(&arr);
    rc = service_stats_init_from_registry(&arr, NULL);
    CHECK(rc < 0, "init_from_registry(arr, NULL) returned negative (rc=%d)",
          rc);
    service_stats_array_destroy(&arr);

    /* reset_window on a NULL pointer is a no-op (does not crash). */
    service_stats_reset_window(NULL);
    CHECK(true, "reset_window(NULL) did not crash");

    /* reset_window on an inactive slot is a no-op. */
    static struct service_stats inactive_slot;   /* zero-initialised */
    service_stats_reset_window(&inactive_slot);
    CHECK(inactive_slot.window_count == 0,
          "reset_window(inactive slot) is a no-op (window_count still 0)");

    /* array_destroy on NULL is a no-op. */
    service_stats_array_destroy(NULL);
    CHECK(true, "array_destroy(NULL) did not crash");

    /* get_proto_arm / get_proto_ewma on NULL slot return NULL. */
    CHECK(service_stats_get_proto_arm(NULL) == NULL,
          "get_proto_arm(NULL) returns NULL");
    CHECK(service_stats_get_proto_ewma(NULL) == NULL,
          "get_proto_ewma(NULL) returns NULL");
    return 0;
}

/* -------------------------------------------------------------------------
 * Main
 * ------------------------------------------------------------------------- */

int main(void) {
    static struct service_registry    reg;
    static struct service_stats_array arr;

    fprintf(stderr, "\n*** service_stats P4 test harness ***\n");

    test_array_init(&arr);
    test_init_from_registry(&arr, &reg);
    test_slots_initialized_correctly(&arr);
    test_simulated_window_and_reset(&arr);
    test_other_catchall_reset(&arr);
    test_memory_budget(&arr);

    /* One sample log line so we can eyeball the diagnostic helper. */
    fprintf(stderr, "\n=== diagnostic: service_stats_log_slot on a TCP catchall ===\n");
    uint32_t ip50 = mk_ip(213, 230, 125, 50);
    struct service_stats *s = find_slot(&arr, ip50, 0, SERVICE_PROTO_CATCHALL_TCP);
    if (s) service_stats_log_slot(s);

    /* Clean up the primary fixture, then run idempotency on a fresh one. */
    service_stats_array_destroy(&arr);
    service_registry_destroy(&reg);

    test_idempotency();
    test_null_inputs();

    fprintf(stderr, "\n=== SUMMARY: %d PASS, %d FAIL ===\n", g_pass, g_fail);
    return (g_fail == 0) ? 0 : 1;
}
