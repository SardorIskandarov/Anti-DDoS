/**
 * @file   tests/test_service_registry_load.c
 * @brief  Standalone test harness for service_registry load + lookup + validate.
 *
 * Exercises:
 *   - Positive load of the real service_registry/services.json
 *   - Lookup correctness (catchalls hit, non-protected miss, no specific svc)
 *   - Profile pointer resolution
 *   - Full validator pass
 *   - Six negative tests via on-the-fly cJSON mutations
 *
 * Build:    ninja -C build test_service_registry_load
 * Run:      ./build/test_service_registry_load
 * Returns:  0 if every test passes, 1 otherwise.
 *
 * No DPDK dependency — this binary stands alone.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include <unistd.h>

#include "l2fwd_service_registry.h"
#include "cJSON.h"

/* Stable known-good fixture: the preserved 11-IP / 44-slot / 12-profile
 * phase-0 registry. Deliberately decoupled from the live operational
 * service_registry/services.json, which changes with production config. */
#define SERVICES_JSON_PATH \
    "/home/user_1/Music/Anti-DDoS/service_registry/services_v1_phase0_backup.json"

/* --------------------------------------------------------------- */
/* Tiny assertion framework                                          */
/* --------------------------------------------------------------- */
static int g_pass = 0;
static int g_fail = 0;

#define CHECK(cond, fmt, ...) do {                                          \
    if (cond) {                                                              \
        g_pass++;                                                            \
        fprintf(stderr, "  [PASS] " fmt "\n", ##__VA_ARGS__);                \
    } else {                                                                 \
        g_fail++;                                                            \
        fprintf(stderr, "  [FAIL] " fmt "  (%s:%d)\n",                       \
                ##__VA_ARGS__, __FILE__, __LINE__);                          \
    }                                                                        \
} while (0)

static uint32_t mk_ip(uint8_t a, uint8_t b, uint8_t c, uint8_t d) {
    return ((uint32_t)a << 24) | ((uint32_t)b << 16) |
           ((uint32_t)c << 8)  |  (uint32_t)d;
}

/* --------------------------------------------------------------- */
/* Mutate the canonical services.json in memory, write to /tmp,     */
/* and reload. The mutator returns 0 on success (or panics).        */
/* --------------------------------------------------------------- */
static int write_mutated_json(const char *src_path, const char *dst_path,
                               void (*mutate)(cJSON *root))
{
    FILE *fp = fopen(src_path, "rb");
    if (!fp) { perror(src_path); return -1; }
    fseek(fp, 0, SEEK_END);
    long sz = ftell(fp);
    rewind(fp);
    char *buf = malloc((size_t)sz + 1);
    if (!buf) { fclose(fp); return -1; }
    if (fread(buf, 1, (size_t)sz, fp) != (size_t)sz) {
        fclose(fp); free(buf); return -1;
    }
    fclose(fp);
    buf[sz] = '\0';

    cJSON *root = cJSON_Parse(buf);
    free(buf);
    if (!root) return -1;

    mutate(root);

    char *out = cJSON_Print(root);
    cJSON_Delete(root);
    if (!out) return -1;

    FILE *of = fopen(dst_path, "wb");
    if (!of) { free(out); return -1; }
    fputs(out, of);
    fclose(of);
    free(out);
    return 0;
}

/* --------------------------------------------------------------- */
/* Mutators                                                          */
/* --------------------------------------------------------------- */
static void mut_bad_version(cJSON *root) {
    cJSON *v = cJSON_GetObjectItem(root, "version");
    cJSON_SetNumberValue(v, 99);
}

/* Sparse catchall_assignments: drop ONLY the TCP catchall key for
 * 213.230.125.50 (udp/icmp/other stay). Used by the POSITIVE
 * sparse_remove_one_catchall_test below — under the relaxed engine
 * contract this is a valid config, not a load error. */
static void mut_remove_one_catchall(cJSON *root) {
    cJSON *ca = cJSON_GetObjectItem(root, "catchall_assignments");
    cJSON *entry = cJSON_GetObjectItem(ca, "213.230.125.50");
    cJSON_DeleteItemFromObject(entry, "tcp");
}

static void mut_duplicate_service(cJSON *root) {
    cJSON *services = cJSON_GetObjectItem(root, "services");
    /* Insert two identical (target_ip, port, proto) services. */
    cJSON *a = cJSON_CreateObject();
    cJSON_AddStringToObject(a, "name", "test-dup-a");
    cJSON_AddStringToObject(a, "target_ip", "213.230.125.50");
    cJSON_AddNumberToObject(a, "port", 443);
    cJSON_AddStringToObject(a, "proto", "TCP");
    cJSON_AddStringToObject(a, "profile", "catchall_213_230_125_50_v1");
    cJSON_AddBoolToObject(a, "detection_enabled", 1);
    cJSON *b = cJSON_Duplicate(a, 1);
    cJSON_ReplaceItemInObjectCaseSensitive(b, "name", cJSON_CreateString("test-dup-b"));
    cJSON_AddItemToArray(services, a);
    cJSON_AddItemToArray(services, b);
}

static void mut_unknown_profile_in_catchall(cJSON *root) {
    cJSON *ca = cJSON_GetObjectItem(root, "catchall_assignments");
    cJSON *entry = cJSON_GetObjectItem(ca, "213.230.125.50");
    cJSON_ReplaceItemInObjectCaseSensitive(entry, "tcp",
        cJSON_CreateString("no_such_profile"));
}

static void mut_remove_tier0(cJSON *root) {
    cJSON *profiles = cJSON_GetObjectItem(root, "profiles");
    cJSON *p = cJSON_GetObjectItem(profiles, "catchall_213_230_125_50_v1");
    cJSON_DeleteItemFromObject(p, "tier0");
}

static void mut_empty_services_noop(cJSON *root) {
    /* services[] is already empty in services.json; just confirm we
     * can round-trip the file untouched. */
    (void)root;
}

/* --------------------------------------------------------------- */
/* Tests                                                             */
/* --------------------------------------------------------------- */
static int positive_test(struct service_registry *reg) {
    fprintf(stderr, "\n=== POSITIVE: load real services.json ===\n");
    int rc = service_registry_load(reg, SERVICES_JSON_PATH);
    CHECK(rc == SERVICE_REGISTRY_OK, "load returned OK (rc=%d)", rc);
    if (rc != SERVICE_REGISTRY_OK) return 1;

    CHECK(reg->n_protected_ips == 11, "n_protected_ips=%zu (expect 11)",
          reg->n_protected_ips);
    CHECK(reg->n_profiles == 12, "n_profiles=%zu (expect 12)", reg->n_profiles);
    CHECK(reg->n_catchalls == 44, "n_catchalls=%zu (expect 44)",
          reg->n_catchalls);
    CHECK(reg->n_services == 0, "n_services=%zu (expect 0)", reg->n_services);
    CHECK(reg->n_slots == 44, "n_slots=%zu (expect 44)", reg->n_slots);

    service_registry_log_summary(reg);

    fprintf(stderr, "\n=== POSITIVE: lookup correctness ===\n");
    uint32_t ip50 = mk_ip(213, 230, 125, 50);

    const struct service_descriptor *d;
    d = service_registry_lookup_catchall(reg, ip50, SERVICE_PROTO_CATCHALL_TCP);
    CHECK(d != NULL, "lookup_catchall(213.230.125.50, TCP) non-NULL");
    if (d) {
        CHECK(strcmp(d->profile_name, "catchall_213_230_125_50_v1") == 0,
              "profile_name='%s'", d->profile_name);
        CHECK(d->profile != NULL, "profile pointer non-NULL");
        CHECK(d->is_catchall, "is_catchall=true");
    }
    d = service_registry_lookup_catchall(reg, ip50, SERVICE_PROTO_CATCHALL_UDP);
    CHECK(d != NULL, "lookup_catchall(213.230.125.50, UDP) non-NULL");
    d = service_registry_lookup_catchall(reg, ip50, SERVICE_PROTO_CATCHALL_ICMP);
    CHECK(d != NULL, "lookup_catchall(213.230.125.50, ICMP) non-NULL");
    d = service_registry_lookup_catchall(reg, ip50, SERVICE_PROTO_CATCHALL_OTHER);
    CHECK(d != NULL, "lookup_catchall(213.230.125.50, OTHER) non-NULL");

    /* Specific service lookup: no specific services registered, so miss. */
    d = service_registry_lookup_exact(reg, ip50, 443, SERVICE_PROTO_TCP);
    CHECK(d == NULL, "lookup_exact(213.230.125.50, 443, TCP) NULL "
                     "(no specific service registered)");

    /* Non-protected IP miss. */
    uint32_t bad_ip = mk_ip(10, 10, 10, 10);
    d = service_registry_lookup_catchall(reg, bad_ip, SERVICE_PROTO_CATCHALL_TCP);
    CHECK(d == NULL, "lookup_catchall(10.10.10.10, TCP) NULL (not protected)");

    fprintf(stderr, "\n=== POSITIVE: validate again on loaded registry ===\n");
    char err[512] = {0};
    rc = service_registry_validate(reg, err, sizeof(err));
    CHECK(rc == SERVICE_REGISTRY_OK,
          "validate returned OK (rc=%d, err='%s')", rc, err);

    fprintf(stderr, "\n=== POSITIVE: every catchall slot resolves to a profile ===\n");
    int slots_with_profile = 0;
    for (size_t i = 0; i < reg->n_slots; i++) {
        if (reg->slots[i].is_catchall && reg->slots[i].profile != NULL) {
            slots_with_profile++;
        }
    }
    CHECK(slots_with_profile == 44, "%d/44 catchall slots resolve to a profile",
          slots_with_profile);

    fprintf(stderr, "\n=== POSITIVE: profile names match catchall_<ip>_v1 pattern ===\n");
    int slots_with_expected_name = 0;
    for (size_t i = 0; i < reg->n_slots; i++) {
        if (!reg->slots[i].is_catchall) continue;
        uint32_t ip = reg->slots[i].key.target_ip;
        char want[80];
        snprintf(want, sizeof(want), "catchall_%u_%u_%u_%u_v1",
                 (ip >> 24) & 0xff, (ip >> 16) & 0xff,
                 (ip >> 8) & 0xff, ip & 0xff);
        if (strcmp(reg->slots[i].profile_name, want) == 0) {
            slots_with_expected_name++;
        } else {
            fprintf(stderr, "  unexpected name: '%s' (wanted '%s')\n",
                    reg->slots[i].profile_name, want);
        }
    }
    CHECK(slots_with_expected_name == 44,
          "%d/44 catchall profile names match expected pattern",
          slots_with_expected_name);

    return 0;
}

static int negative_test(const char *label,
                          void (*mutator)(cJSON *root),
                          bool expect_load_failure)
{
    fprintf(stderr, "\n=== NEGATIVE: %s ===\n", label);
    char path[64];
    snprintf(path, sizeof(path), "/tmp/test_registry_%d.json", (int)getpid());
    if (write_mutated_json(SERVICES_JSON_PATH, path, mutator) != 0) {
        fprintf(stderr, "  [FAIL] could not write mutated JSON\n");
        g_fail++;
        return 1;
    }

    struct service_registry reg;
    service_registry_init(&reg);
    int rc = service_registry_load(&reg, path);

    if (expect_load_failure) {
        CHECK(rc != SERVICE_REGISTRY_OK,
              "load FAILED as expected (rc=%d)", rc);
    } else {
        CHECK(rc == SERVICE_REGISTRY_OK,
              "load SUCCEEDED as expected (rc=%d)", rc);
    }
    unlink(path);
    return 0;
}

/* --------------------------------------------------------------- */
/* Sparse catchall_assignments contract (relaxed validation).        */
/*                                                                   */
/* The engine no longer requires every protected IP to carry all     */
/* four {tcp,udp,icmp,other} catchalls. catchall_assignments[ip] may  */
/* hold any subset — or the IP may have no entry at all if it only    */
/* has named services. These two positive tests pin that contract.   */
/* --------------------------------------------------------------- */

/* Write a cJSON tree to disk; returns 0 on success. */
static int write_json_root(const char *dst_path, cJSON *root) {
    char *out = cJSON_Print(root);
    if (!out) return -1;
    FILE *of = fopen(dst_path, "wb");
    if (!of) { free(out); return -1; }
    fputs(out, of);
    fclose(of);
    free(out);
    return 0;
}

/* Sparse catchall_assignments: removing ONE catchall key from an IP's
 * entry must SUCCEED and produce baseline-1 slots. The removed
 * (ip, proto) catchall no longer resolves; the IP's sibling catchalls
 * are unaffected. (Before the relaxation this was a hard load error.) */
static int sparse_remove_one_catchall_test(size_t baseline_n_slots) {
    fprintf(stderr,
        "\n=== POSITIVE: sparse catchall — drop one (ip,proto), expect N-1 ===\n");
    char path[64];
    snprintf(path, sizeof(path), "/tmp/test_registry_sparse1_%d.json", (int)getpid());
    if (write_mutated_json(SERVICES_JSON_PATH, path, mut_remove_one_catchall) != 0) {
        fprintf(stderr, "  [FAIL] could not write mutated JSON\n");
        g_fail++;
        return 1;
    }

    static struct service_registry reg;
    service_registry_init(&reg);
    int rc = service_registry_load(&reg, path);
    CHECK(rc == SERVICE_REGISTRY_OK,
          "load SUCCEEDED with a sparse catchall entry (rc=%d)", rc);
    if (rc == SERVICE_REGISTRY_OK) {
        CHECK(reg.n_slots == baseline_n_slots - 1,
              "n_slots=%zu (expect baseline-1 = %zu)",
              reg.n_slots, baseline_n_slots - 1);

        uint32_t ip50 = mk_ip(213, 230, 125, 50);
        const struct service_descriptor *d;
        d = service_registry_lookup_catchall(&reg, ip50, SERVICE_PROTO_CATCHALL_TCP);
        CHECK(d == NULL,
              "lookup_catchall(213.230.125.50, TCP) NULL — removed catchall is gone");
        d = service_registry_lookup_catchall(&reg, ip50, SERVICE_PROTO_CATCHALL_UDP);
        CHECK(d != NULL,
              "lookup_catchall(213.230.125.50, UDP) non-NULL — sibling catchall intact");
        d = service_registry_lookup_catchall(&reg, ip50, SERVICE_PROTO_CATCHALL_ICMP);
        CHECK(d != NULL,
              "lookup_catchall(213.230.125.50, ICMP) non-NULL — sibling catchall intact");
        d = service_registry_lookup_catchall(&reg, ip50, SERVICE_PROTO_CATCHALL_OTHER);
        CHECK(d != NULL,
              "lookup_catchall(213.230.125.50, OTHER) non-NULL — sibling catchall intact");
    }
    service_registry_destroy(&reg);
    unlink(path);
    return 0;
}

/* Most-extreme sparse case: a protected IP with NO catchall_assignments
 * entry at all, only a named service. Load must succeed with exactly the
 * one named-service slot and zero catchalls. The profile is lifted
 * verbatim from the backup fixture so we don't hand-roll one. */
static int sparse_no_catchall_test(void) {
    fprintf(stderr,
        "\n=== POSITIVE: sparse catchall — IP with only a named service ===\n");

    /* Read the backup fixture and copy out a known-good profile. */
    FILE *fp = fopen(SERVICES_JSON_PATH, "rb");
    if (!fp) { fprintf(stderr, "  [FAIL] open backup fixture\n"); g_fail++; return 1; }
    fseek(fp, 0, SEEK_END);
    long sz = ftell(fp);
    rewind(fp);
    char *buf = malloc((size_t)sz + 1);
    if (!buf || fread(buf, 1, (size_t)sz, fp) != (size_t)sz) {
        fclose(fp); free(buf);
        fprintf(stderr, "  [FAIL] read backup fixture\n"); g_fail++; return 1;
    }
    fclose(fp);
    buf[sz] = '\0';
    cJSON *backup = cJSON_Parse(buf);
    free(buf);
    if (!backup) { fprintf(stderr, "  [FAIL] parse backup fixture\n"); g_fail++; return 1; }
    cJSON *generic = cJSON_GetObjectItem(
        cJSON_GetObjectItem(backup, "profiles"), "catchall_generic_default");
    cJSON *profile_copy = cJSON_Duplicate(generic, 1);
    cJSON_Delete(backup);
    if (!profile_copy) {
        fprintf(stderr, "  [FAIL] copy profile from backup\n"); g_fail++; return 1;
    }

    /* Build a synthetic registry: 1 protected IP, empty
     * catchall_assignments{}, and a single named TCP service. */
    cJSON *root = cJSON_CreateObject();
    cJSON_AddNumberToObject(root, "version", 1);
    cJSON *meta = cJSON_CreateObject();
    cJSON_AddStringToObject(meta, "comment", "synthetic sparse-catchall test fixture");
    cJSON_AddItemToObject(root, "metadata", meta);
    cJSON *pips = cJSON_CreateArray();
    cJSON_AddItemToArray(pips, cJSON_CreateString("1.2.3.4"));
    cJSON_AddItemToObject(root, "protected_ips", pips);
    cJSON *profiles = cJSON_CreateObject();
    cJSON_AddItemToObject(profiles, "default", profile_copy);
    cJSON_AddItemToObject(root, "profiles", profiles);
    cJSON_AddItemToObject(root, "catchall_assignments", cJSON_CreateObject()); /* {} */
    cJSON *svcs = cJSON_CreateArray();
    cJSON *svc = cJSON_CreateObject();
    cJSON_AddStringToObject(svc, "name", "svc_1.2.3.4_tcp443");
    cJSON_AddStringToObject(svc, "target_ip", "1.2.3.4");
    cJSON_AddStringToObject(svc, "proto", "TCP");
    cJSON_AddNumberToObject(svc, "port", 443);
    cJSON_AddStringToObject(svc, "profile", "default");
    cJSON_AddBoolToObject(svc, "detection_enabled", 0);
    cJSON_AddItemToArray(svcs, svc);
    cJSON_AddItemToObject(root, "services", svcs);

    char path[64];
    snprintf(path, sizeof(path), "/tmp/test_registry_sparse0_%d.json", (int)getpid());
    int wrc = write_json_root(path, root);
    cJSON_Delete(root);
    if (wrc != 0) {
        fprintf(stderr, "  [FAIL] write synthetic JSON\n"); g_fail++; return 1;
    }

    static struct service_registry reg;
    service_registry_init(&reg);
    int rc = service_registry_load(&reg, path);
    CHECK(rc == SERVICE_REGISTRY_OK,
          "load SUCCEEDED for an IP with no catchall entry (rc=%d)", rc);
    if (rc == SERVICE_REGISTRY_OK) {
        CHECK(reg.n_slots == 1,     "n_slots=%zu (expect 1)", reg.n_slots);
        CHECK(reg.n_catchalls == 0, "n_catchalls=%zu (expect 0)", reg.n_catchalls);
        CHECK(reg.n_services == 1,  "n_services=%zu (expect 1)", reg.n_services);

        uint32_t ip = mk_ip(1, 2, 3, 4);
        const struct service_descriptor *d =
            service_registry_lookup_exact(&reg, ip, 443, SERVICE_PROTO_TCP);
        CHECK(d != NULL,
              "lookup_exact(1.2.3.4, 443, TCP) non-NULL — named service slot exists");
        d = service_registry_lookup_catchall(&reg, ip, SERVICE_PROTO_CATCHALL_TCP);
        CHECK(d == NULL,
              "lookup_catchall(1.2.3.4, TCP) NULL — no catchall was configured");
    }
    service_registry_destroy(&reg);
    unlink(path);
    return 0;
}

int main(void) {
    static struct service_registry reg;  /* ~250 KB; use static to avoid stack */

    fprintf(stderr, "\n*** service_registry P2 test harness ***\n");

    positive_test(&reg);
    size_t baseline_n_slots = reg.n_slots;   /* 44 for the phase-0 backup */

    negative_test("bad_version (version=99)",            mut_bad_version,             true);
    negative_test("duplicate (target_ip, port, proto)",  mut_duplicate_service,       true);
    negative_test("unknown profile in catchall",         mut_unknown_profile_in_catchall, true);
    negative_test("profile missing tier0 section",       mut_remove_tier0,            true);
    negative_test("untouched services.json (round-trip)", mut_empty_services_noop,    false);

    /* Sparse catchall_assignments contract — see comment block above. */
    sparse_remove_one_catchall_test(baseline_n_slots);
    sparse_no_catchall_test();

    fprintf(stderr, "\n=== SUMMARY: %d PASS, %d FAIL ===\n", g_pass, g_fail);
    return (g_fail == 0) ? 0 : 1;
}
