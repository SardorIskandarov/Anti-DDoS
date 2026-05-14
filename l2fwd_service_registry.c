/**
 * @file   l2fwd_service_registry.c
 * @brief  JSON-driven service registry: loader, validator, and hot-path
 *         lookup implementation.
 *
 * P2 deliverable: every stub from P1 is now real. The registry can be
 * loaded from disk, validated against the 12 schema rules, and queried
 * via two hot-path lookup functions. Nothing in main.c, the collector,
 * or the detection engine calls these yet — wiring happens in P5/P7.
 *
 * Layout of this file (top-down for readability):
 *   1. Static invariants (compile-time)
 *   2. Logging helper
 *   3. Low-level utility helpers (file I/O, IP parse, hashing, JSON
 *      accessors)
 *   4. Profile object parser
 *   5. Hash-table insert / lookup primitives
 *   6. Public API: lifecycle (init, load, validate, destroy)
 *   7. Public API: hot-path lookups
 *   8. Public API: diagnostics
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdarg.h>
#include <time.h>
#include <ctype.h>
#include <errno.h>
#include <limits.h>
#include <stdatomic.h>

#include "l2fwd_service_registry.h"
#include "l2fwd_l2_profile.h"
#include "cJSON.h"

/* -------------------------------------------------------------------------
 * 1. Static invariants — checked at compile time
 * ------------------------------------------------------------------------- */
_Static_assert(sizeof(service_key_t) == 8,
               "service_key_t must be exactly 8 bytes packed");
_Static_assert((SERVICE_REGISTRY_HASH_SIZE & (SERVICE_REGISTRY_HASH_SIZE - 1)) == 0,
               "SERVICE_REGISTRY_HASH_SIZE must be a power of two");
_Static_assert(SERVICE_REGISTRY_MAX_TOTAL_SLOTS <= SERVICE_REGISTRY_HASH_SIZE,
               "SERVICE_REGISTRY_MAX_TOTAL_SLOTS must fit in the hash table");
_Static_assert(SERVICE_REGISTRY_MAX_PROFILES > 0, "MAX_PROFILES > 0");

/* -------------------------------------------------------------------------
 * 2. Logging
 * ------------------------------------------------------------------------- */
static void registry_log(const char *level, const char *fmt, ...)
    __attribute__((format(printf, 2, 3)));

static void registry_log(const char *level, const char *fmt, ...) {
    char ts[32];
    time_t now = time(NULL);
    struct tm tm_buf;
    if (gmtime_r(&now, &tm_buf) == NULL ||
        strftime(ts, sizeof(ts), "%Y-%m-%dT%H:%M:%SZ", &tm_buf) == 0) {
        snprintf(ts, sizeof(ts), "?");
    }
    fprintf(stderr, "[service_registry] [%s] %s ", level, ts);
    va_list ap;
    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
    fputc('\n', stderr);
}

/* -------------------------------------------------------------------------
 * 3. Low-level utility helpers
 * ------------------------------------------------------------------------- */

/**
 * Read a file fully into a heap buffer. NUL-terminates the buffer
 * (allocates len+1 bytes). Caller must free(*out_buf).
 */
static int read_file_to_buffer(const char *path, char **out_buf, size_t *out_len) {
    *out_buf = NULL;
    *out_len = 0;

    FILE *fp = fopen(path, "rb");
    if (fp == NULL) {
        registry_log("ERROR", "open(%s) failed: %s", path, strerror(errno));
        return SERVICE_REGISTRY_ERR_IO;
    }
    if (fseek(fp, 0, SEEK_END) != 0) {
        registry_log("ERROR", "fseek(end) on %s failed", path);
        fclose(fp);
        return SERVICE_REGISTRY_ERR_IO;
    }
    long sz = ftell(fp);
    if (sz < 0) {
        registry_log("ERROR", "ftell on %s failed", path);
        fclose(fp);
        return SERVICE_REGISTRY_ERR_IO;
    }
    rewind(fp);

    char *buf = malloc((size_t)sz + 1);
    if (buf == NULL) {
        registry_log("ERROR", "malloc(%ld) failed for %s", sz + 1, path);
        fclose(fp);
        return SERVICE_REGISTRY_ERR_IO;
    }
    size_t got = fread(buf, 1, (size_t)sz, fp);
    fclose(fp);
    if (got != (size_t)sz) {
        registry_log("ERROR", "fread short on %s: got %zu of %ld bytes",
                     path, got, sz);
        free(buf);
        return SERVICE_REGISTRY_ERR_IO;
    }
    buf[sz] = '\0';
    *out_buf = buf;
    *out_len = (size_t)sz;
    return SERVICE_REGISTRY_OK;
}

/**
 * Parse "A.B.C.D" to uint32_t in host byte order
 * (matching the convention used by RTE_IPV4() and the existing
 * collector hot path).
 *
 * Rejects: leading zeros (except "0" itself), out-of-range octets,
 * trailing garbage, embedded whitespace, signs.
 */
static uint32_t parse_ipv4_string(const char *str, bool *ok) {
    *ok = false;
    if (str == NULL) return 0;

    uint32_t out = 0;
    int oct_index = 0;
    const char *p = str;

    for (; oct_index < 4; oct_index++) {
        if (!isdigit((unsigned char)*p)) return 0;
        /* Reject leading zero in multi-digit octet ("01" is invalid). */
        if (p[0] == '0' && isdigit((unsigned char)p[1])) return 0;

        int v = 0;
        int digits = 0;
        while (isdigit((unsigned char)*p)) {
            v = v * 10 + (*p - '0');
            if (v > 255) return 0;
            p++;
            digits++;
            if (digits > 3) return 0;
        }
        if (digits == 0) return 0;
        out = (out << 8) | (uint32_t)v;

        if (oct_index < 3) {
            if (*p != '.') return 0;
            p++;
        }
    }
    if (*p != '\0') return 0;
    *ok = true;
    return out;
}

/**
 * Map "TCP"/"UDP"/"ICMP" → SERVICE_PROTO_* kind.
 */
static int parse_proto_string(const char *str, uint8_t *out_kind) {
    if (str == NULL || out_kind == NULL) return SERVICE_REGISTRY_ERR_VALIDATE;
    if (strcmp(str, "TCP") == 0)  { *out_kind = SERVICE_PROTO_TCP;  return SERVICE_REGISTRY_OK; }
    if (strcmp(str, "UDP") == 0)  { *out_kind = SERVICE_PROTO_UDP;  return SERVICE_REGISTRY_OK; }
    if (strcmp(str, "ICMP") == 0) { *out_kind = SERVICE_PROTO_ICMP; return SERVICE_REGISTRY_OK; }
    return SERVICE_REGISTRY_ERR_VALIDATE;
}

/**
 * FNV-1a 64-bit hash. Used for hashing service_key_t (always 8 bytes).
 */
static uint64_t fnv1a_64(const void *data, size_t len) {
    uint64_t h = 0xCBF29CE484222325ULL;
    const uint8_t *p = (const uint8_t *)data;
    for (size_t i = 0; i < len; i++) {
        h ^= p[i];
        h *= 0x100000001B3ULL;
    }
    return h;
}

/**
 * Strict JSON accessors. Each logs a precise context line on failure.
 */
static int json_get_string(const cJSON *obj, const char *key,
                            char *out, size_t out_size, const char *ctx) {
    const cJSON *v = cJSON_GetObjectItemCaseSensitive(obj, key);
    if (!cJSON_IsString(v) || v->valuestring == NULL) {
        registry_log("ERROR", "[parse] %s: missing or non-string field '%s'", ctx, key);
        return SERVICE_REGISTRY_ERR_PARSE;
    }
    size_t n = strlen(v->valuestring);
    if (n >= out_size) {
        registry_log("ERROR", "[parse] %s: field '%s' length %zu exceeds %zu",
                     ctx, key, n, out_size - 1);
        return SERVICE_REGISTRY_ERR_PARSE;
    }
    memcpy(out, v->valuestring, n);
    out[n] = '\0';
    return SERVICE_REGISTRY_OK;
}

static int json_get_int(const cJSON *obj, const char *key,
                         int *out, const char *ctx) {
    const cJSON *v = cJSON_GetObjectItemCaseSensitive(obj, key);
    if (!cJSON_IsNumber(v)) {
        registry_log("ERROR", "[parse] %s: missing or non-numeric field '%s'", ctx, key);
        return SERVICE_REGISTRY_ERR_PARSE;
    }
    double d = v->valuedouble;
    if (d < (double)INT_MIN || d > (double)INT_MAX) {
        registry_log("ERROR", "[parse] %s: field '%s' = %g out of int range", ctx, key, d);
        return SERVICE_REGISTRY_ERR_PARSE;
    }
    *out = (int)d;
    return SERVICE_REGISTRY_OK;
}

static int json_get_object(const cJSON *obj, const char *key,
                            const cJSON **out, const char *ctx) {
    const cJSON *v = cJSON_GetObjectItemCaseSensitive(obj, key);
    if (!cJSON_IsObject(v)) {
        registry_log("ERROR", "[parse] %s: missing or non-object field '%s'", ctx, key);
        return SERVICE_REGISTRY_ERR_PARSE;
    }
    *out = v;
    return SERVICE_REGISTRY_OK;
}

/* Forgiving variant: returns 0.0 when absent, fails only on wrong type. */
static int json_get_double_optional(const cJSON *obj, const char *key,
                                     double *out, const char *ctx) {
    *out = 0.0;
    const cJSON *v = cJSON_GetObjectItemCaseSensitive(obj, key);
    if (v == NULL) return SERVICE_REGISTRY_OK;
    if (!cJSON_IsNumber(v)) {
        registry_log("ERROR", "[parse] %s: field '%s' present but not numeric", ctx, key);
        return SERVICE_REGISTRY_ERR_PARSE;
    }
    *out = v->valuedouble;
    return SERVICE_REGISTRY_OK;
}

static int json_get_int_optional(const cJSON *obj, const char *key,
                                  uint32_t *out, const char *ctx) {
    *out = 0;
    const cJSON *v = cJSON_GetObjectItemCaseSensitive(obj, key);
    if (v == NULL) return SERVICE_REGISTRY_OK;
    if (!cJSON_IsNumber(v)) {
        registry_log("ERROR", "[parse] %s: field '%s' present but not numeric", ctx, key);
        return SERVICE_REGISTRY_ERR_PARSE;
    }
    double d = v->valuedouble;
    if (d < 0.0 || d > (double)UINT32_MAX) {
        registry_log("ERROR", "[parse] %s: field '%s' = %g out of uint32 range", ctx, key, d);
        return SERVICE_REGISTRY_ERR_PARSE;
    }
    *out = (uint32_t)d;
    return SERVICE_REGISTRY_OK;
}

/* -------------------------------------------------------------------------
 * 4. Profile parser
 *
 * Sections we walk:
 *   tier0  { … weights{ … } … }
 *   tier1  { … fusion_weights{ … } … }
 *   tier1_l3 { … weights{ … } noise_floor_overrides{ … } … }
 *   tier1_offproto { suspicious_threshold, attack_threshold }
 *   v2_feature_weights { … }
 *
 * Sub-fields that are missing default to 0 / 0.0 (matches C designated-
 * initialiser behaviour). The five section keys themselves are REQUIRED
 * — their absence is a parse error.
 * ------------------------------------------------------------------------- */
static int parse_profile_object(const cJSON *prof_obj,
                                 const char *profile_name,
                                 struct l2_profile *out,
                                 struct service_offproto_config *offproto)
{
    char ctx[128];
    snprintf(ctx, sizeof(ctx), "profile '%s'", profile_name);
    memset(out, 0, sizeof(*out));

    const cJSON *t0  = NULL;
    const cJSON *t1  = NULL;
    const cJSON *t1l = NULL;
    const cJSON *t1o = NULL;
    const cJSON *v2  = NULL;
    if (json_get_object(prof_obj, "tier0",              &t0,  ctx) != SERVICE_REGISTRY_OK ||
        json_get_object(prof_obj, "tier1",              &t1,  ctx) != SERVICE_REGISTRY_OK ||
        json_get_object(prof_obj, "tier1_l3",           &t1l, ctx) != SERVICE_REGISTRY_OK ||
        json_get_object(prof_obj, "tier1_offproto",     &t1o, ctx) != SERVICE_REGISTRY_OK ||
        json_get_object(prof_obj, "v2_feature_weights", &v2,  ctx) != SERVICE_REGISTRY_OK) {
        return SERVICE_REGISTRY_ERR_PARSE;
    }

    /* Sub-objects we'll need. */
    const cJSON *t0w   = cJSON_GetObjectItemCaseSensitive(t0,  "weights");
    const cJSON *t1f   = cJSON_GetObjectItemCaseSensitive(t1,  "fusion_weights");
    const cJSON *t1lw  = cJSON_GetObjectItemCaseSensitive(t1l, "weights");
    const cJSON *t1ln  = cJSON_GetObjectItemCaseSensitive(t1l, "noise_floor_overrides");
    /* These are optional containers (their absence means their fields
     * absent — the field-level helpers tolerate NULL parents safely
     * via cJSON_GetObjectItemCaseSensitive(NULL, ...) → NULL). */
    (void)t0w; (void)t1f; (void)t1lw; (void)t1ln;

    /* Helper macro: read a double from container (cJSON*) or 0.0 if
     * the container is NULL / the field is missing. */
    #define GD(parent, key, dst) \
        do { \
            double _d = 0.0; \
            if ((parent) != NULL) { \
                if (json_get_double_optional((parent), (key), &_d, ctx) != SERVICE_REGISTRY_OK) \
                    return SERVICE_REGISTRY_ERR_PARSE; \
            } \
            (dst) = _d; \
        } while (0)

    #define GU(parent, key, dst) \
        do { \
            uint32_t _u = 0; \
            if ((parent) != NULL) { \
                if (json_get_int_optional((parent), (key), &_u, ctx) != SERVICE_REGISTRY_OK) \
                    return SERVICE_REGISTRY_ERR_PARSE; \
            } \
            (dst) = _u; \
        } while (0)

    /* --- Tier-0 --- */
    GD(t0,  "alpha",                    out->alpha_tier0);
    GD(t0,  "cusum_k_pps",              out->cusum_k_pps);
    GD(t0,  "cusum_h_pps",              out->cusum_h_pps);
    GD(t0,  "cusum_k_bps",              out->cusum_k_bps);
    GD(t0,  "cusum_h_bps",              out->cusum_h_bps);
    GD(t0,  "cusum_k_fps",              out->cusum_k_fps);
    GD(t0,  "cusum_h_fps",              out->cusum_h_fps);
    GD(t0,  "burst_z_threshold",        out->burst_z_threshold);
    GD(t0,  "variance_ceiling_factor",  out->variance_ceiling_factor);
    GD(t0w, "pps",                      out->t0_w_pps);
    GD(t0w, "bps",                      out->t0_w_bps);
    GD(t0w, "fps",                      out->t0_w_fps);
    GD(t0w, "burst_pps",                out->t0_w_burst_pps);
    GD(t0w, "burst_bps",                out->t0_w_burst_bps);
    GD(t0w, "burst_fps",                out->t0_w_burst_fps);
    GD(t0,  "suspicious_threshold",     out->t0_suspicious_risk_threshold);
    GD(t0,  "attack_threshold",         out->t0_risk_threshold);
    GD(t0,  "absolute_pps_threshold",   out->absolute_pps_threshold);
    GD(t0,  "absolute_bps_threshold",   out->absolute_bps_threshold);
    GD(t0,  "absolute_fps_threshold",   out->absolute_fps_threshold);

    /* --- Tier-1 --- */
    GD(t1,  "sigmoid_k",                out->sigmoid_k);
    GD(t1,  "sigmoid_d0",               out->sigmoid_d0);
    GD(t1,  "normal_threshold",         out->threshold_normal);
    GD(t1,  "suspicious_threshold",     out->threshold_suspicious);
    GD(t1f, "tcp",                      out->w_tcp);
    GD(t1f, "udp",                      out->w_udp);
    GD(t1f, "icmp",                     out->w_icmp);
    GD(t1f, "dist",                     out->w_dist);
    GD(t1,  "alpha_tcp",                out->alpha_tier1_tcp);
    GD(t1,  "alpha_udp",                out->alpha_tier1_udp);
    GD(t1,  "alpha_icmp",               out->alpha_tier1_icmp);
    GD(t1,  "alpha_dist",               out->alpha_tier1_dist);
    GU(t1,  "warmup_windows",             out->warmup_windows);
    GU(t1,  "consecutive_attack_windows", out->consecutive_attack_windows);
    GU(t1,  "baseline_freeze_windows",    out->baseline_freeze_windows);
    GU(t1,  "thaw_cooldown_windows",      out->thaw_cooldown_windows);

    /* --- Tier-1.5 L3 --- */
    GD(t1l,  "sigmoid_k",                  out->sigmoid_k_l3);
    GD(t1l,  "sigmoid_d0",                 out->sigmoid_d0_l3);
    GD(t1lw, "ttl_stddev",                 out->w_feat_ttl_stddev);
    GD(t1lw, "ip_frag_ratio",              out->w_feat_ip_frag);
    GD(t1lw, "other_proto_ratio",          out->w_feat_other_proto);
    GD(t1lw, "src_port_top1_share",        out->w_feat_src_port_top1);
    GD(t1lw, "src_24_top1_share",          out->w_feat_src_24_top1);
    GD(t1lw, "src_24_entropy",             out->w_feat_src_24_entropy);
    GD(t1ln, "ip_frag_ratio",              out->frag_noise_floor_override);
    GD(t1ln, "other_proto_ratio",          out->other_proto_noise_floor_override);

    /* --- Tier-1 off-protocol (parallel array, not in struct l2_profile) --- */
    if (offproto != NULL) {
        memset(offproto, 0, sizeof(*offproto));
        GD(t1o, "suspicious_threshold", offproto->suspicious_threshold);
        GD(t1o, "attack_threshold",     offproto->attack_threshold);
    }

    /* --- V2 feature weights --- */
    GD(v2, "empty_ack_ratio",     out->w_feat_empty_ack);
    GD(v2, "zero_window_ratio",   out->w_feat_zero_window);
    GD(v2, "small_window_ratio",  out->w_feat_small_window);
    GD(v2, "new_flow_ratio",      out->w_feat_new_flow);
    GD(v2, "syn_fin_ratio",       out->w_feat_syn_fin);
    GD(v2, "syn_to_synack_ratio", out->w_feat_syn_to_synack);
    GD(v2, "tcp_pkt_size_cov",    out->w_feat_tcp_pkt_size_cov);
    GD(v2, "tcp_mean_pkt_size",   out->w_feat_tcp_mean_pkt_size);
    GD(v2, "udp_pkt_size_cov",    out->w_feat_udp_pkt_size_cov);
    GD(v2, "udp_mean_pkt_size",   out->w_feat_udp_mean_pkt_size);

    #undef GD
    #undef GU

    return SERVICE_REGISTRY_OK;
}

/* Resolve a profile name string to an index in reg->profile_names[].
 * Returns -1 if not found. */
static int find_profile_index(const struct service_registry *reg, const char *name) {
    for (size_t i = 0; i < reg->n_profiles; i++) {
        if (strcmp(reg->profile_names[i], name) == 0) return (int)i;
    }
    return -1;
}

/* Locate an IP in protected_ips[]. Returns -1 if not present. */
static int find_protected_ip_index(const struct service_registry *reg, uint32_t ip) {
    for (size_t i = 0; i < reg->n_protected_ips; i++) {
        if (reg->protected_ips[i] == ip) return (int)i;
    }
    return -1;
}

/* -------------------------------------------------------------------------
 * 5. Hash table primitives
 * ------------------------------------------------------------------------- */
static int registry_hash_insert(struct service_registry *reg, int32_t slot_idx) {
    if (slot_idx < 0 || (size_t)slot_idx >= reg->n_slots) {
        return SERVICE_REGISTRY_ERR_INTERNAL;
    }
    const service_key_t *k = &reg->slots[slot_idx].key;
    uint64_t h = fnv1a_64(k, sizeof(*k));
    uint32_t mask = SERVICE_REGISTRY_HASH_SIZE - 1;
    uint32_t idx = (uint32_t)(h & mask);
    for (uint32_t i = 0; i < SERVICE_REGISTRY_HASH_SIZE; i++) {
        uint32_t probe = (idx + i) & mask;
        if (reg->hash_table[probe] == -1) {
            reg->hash_table[probe] = slot_idx;
            return SERVICE_REGISTRY_OK;
        }
        /* Duplicate-key check: should never happen — caller guarantees
         * uniqueness — but defend against it. */
        int32_t existing = reg->hash_table[probe];
        if (existing >= 0 &&
            memcmp(&reg->slots[existing].key, k, sizeof(*k)) == 0) {
            return SERVICE_REGISTRY_ERR_INTERNAL;
        }
    }
    return SERVICE_REGISTRY_ERR_CAPACITY;
}

/* Shared lookup helper for the two public hot-path functions. */
static const struct service_descriptor *
hash_lookup(const struct service_registry *reg, const service_key_t *k) {
    if (reg == NULL) return NULL;
    uint64_t h = fnv1a_64(k, sizeof(*k));
    uint32_t mask = SERVICE_REGISTRY_HASH_SIZE - 1;
    uint32_t idx = (uint32_t)(h & mask);
    for (uint32_t i = 0; i < SERVICE_REGISTRY_HASH_SIZE; i++) {
        int32_t slot = reg->hash_table[(idx + i) & mask];
        if (slot == -1) return NULL;
        if (memcmp(&reg->slots[slot].key, k, sizeof(*k)) == 0) {
            return &reg->slots[slot];
        }
    }
    return NULL;
}

/* Create + insert a single slot. Owns the slot index it consumes. */
static int registry_add_slot(struct service_registry *reg,
                              const service_key_t *key,
                              const char *name,
                              const char *profile_name,
                              bool is_catchall,
                              bool detection_enabled,
                              uint64_t added_at_unix)
{
    if (reg->n_slots >= SERVICE_REGISTRY_MAX_TOTAL_SLOTS) {
        return SERVICE_REGISTRY_ERR_CAPACITY;
    }
    int p_idx = find_profile_index(reg, profile_name);
    if (p_idx < 0) {
        registry_log("ERROR", "profile '%s' referenced but not defined", profile_name);
        return SERVICE_REGISTRY_ERR_VALIDATE;
    }
    size_t i = reg->n_slots;
    struct service_descriptor *s = &reg->slots[i];
    s->key = *key;
    s->key._pad = 0;  /* defensive: hash relies on _pad == 0 */
    strncpy(s->name, name, sizeof(s->name) - 1);
    s->name[sizeof(s->name) - 1] = '\0';
    strncpy(s->profile_name, profile_name, sizeof(s->profile_name) - 1);
    s->profile_name[sizeof(s->profile_name) - 1] = '\0';
    s->profile = &reg->profiles[p_idx];
    s->detection_enabled = detection_enabled;
    s->is_catchall = is_catchall;
    s->added_at_unix = added_at_unix;

    reg->n_slots++;
    int rc = registry_hash_insert(reg, (int32_t)i);
    if (rc != SERVICE_REGISTRY_OK) {
        /* Roll back the slot bump so the array stays consistent. */
        reg->n_slots--;
        memset(s, 0, sizeof(*s));
        return rc;
    }
    return SERVICE_REGISTRY_OK;
}

/* -------------------------------------------------------------------------
 * 6. Public API — Lifecycle
 * ------------------------------------------------------------------------- */

int service_registry_init(struct service_registry *reg) {
    if (reg == NULL) {
        registry_log("ERROR", "service_registry_init: reg is NULL");
        return SERVICE_REGISTRY_ERR_INTERNAL;
    }
    memset(reg, 0, sizeof(*reg));
    for (size_t i = 0; i < SERVICE_REGISTRY_HASH_SIZE; i++) {
        reg->hash_table[i] = -1;
    }
    return SERVICE_REGISTRY_OK;
}

void service_registry_destroy(struct service_registry *reg) {
    if (reg == NULL) return;
    memset(reg, 0, sizeof(*reg));
}

int service_registry_load(struct service_registry *reg, const char *path) {
    if (reg == NULL || path == NULL) {
        registry_log("ERROR", "service_registry_load: NULL argument");
        return SERVICE_REGISTRY_ERR_INTERNAL;
    }

    /* Preserve previous reload_count across re-load (incremented at end). */
    uint32_t prior_reload_count = reg->reload_count;

    service_registry_init(reg);

    char *buf = NULL;
    size_t len = 0;
    int rc = read_file_to_buffer(path, &buf, &len);
    if (rc != SERVICE_REGISTRY_OK) return rc;

    cJSON *root = cJSON_ParseWithLength(buf, len);
    if (root == NULL) {
        const char *err = cJSON_GetErrorPtr();
        size_t at = (err != NULL) ? (size_t)(err - buf) : 0;
        registry_log("ERROR", "JSON parse failed in %s near byte %zu", path, at);
        free(buf);
        return SERVICE_REGISTRY_ERR_PARSE;
    }
    if (!cJSON_IsObject(root)) {
        registry_log("ERROR", "%s: top-level value must be a JSON object", path);
        cJSON_Delete(root);
        free(buf);
        return SERVICE_REGISTRY_ERR_PARSE;
    }

    /* --- 1. version --- */
    int version = -1;
    if (json_get_int(root, "version", &version, path) != SERVICE_REGISTRY_OK) {
        cJSON_Delete(root); free(buf); return SERVICE_REGISTRY_ERR_PARSE;
    }
    if (version != 1) {
        registry_log("ERROR", "%s: unsupported version %d (expected 1)", path, version);
        cJSON_Delete(root); free(buf); return SERVICE_REGISTRY_ERR_VALIDATE;
    }

    /* --- 1b. learning_mode (optional top-level flag) --- */
    const cJSON *lm = cJSON_GetObjectItemCaseSensitive(root, "learning_mode");
    if (lm == NULL) {
        reg->learning_mode = false;  /* default = production mode */
    } else if (cJSON_IsBool(lm)) {
        reg->learning_mode = cJSON_IsTrue(lm) ? true : false;
    } else {
        registry_log("ERROR", "%s: 'learning_mode' must be boolean if present", path);
        cJSON_Delete(root); free(buf); return SERVICE_REGISTRY_ERR_PARSE;
    }

    /* --- 2. protected_ips --- */
    const cJSON *pips = cJSON_GetObjectItemCaseSensitive(root, "protected_ips");
    if (!cJSON_IsArray(pips)) {
        registry_log("ERROR", "%s: missing or non-array 'protected_ips'", path);
        cJSON_Delete(root); free(buf); return SERVICE_REGISTRY_ERR_PARSE;
    }
    {
        const cJSON *item = NULL;
        cJSON_ArrayForEach(item, pips) {
            if (reg->n_protected_ips >= SERVICE_REGISTRY_MAX_PROTECTED_IPS) {
                registry_log("ERROR", "%s: protected_ips exceeds max %d",
                             path, SERVICE_REGISTRY_MAX_PROTECTED_IPS);
                cJSON_Delete(root); free(buf); return SERVICE_REGISTRY_ERR_CAPACITY;
            }
            if (!cJSON_IsString(item) || item->valuestring == NULL) {
                registry_log("ERROR", "%s: protected_ips[%zu] not a string",
                             path, reg->n_protected_ips);
                cJSON_Delete(root); free(buf); return SERVICE_REGISTRY_ERR_PARSE;
            }
            bool ip_ok = false;
            uint32_t ip = parse_ipv4_string(item->valuestring, &ip_ok);
            if (!ip_ok) {
                registry_log("ERROR", "%s: protected_ips[%zu] = '%s' is not a valid IPv4",
                             path, reg->n_protected_ips, item->valuestring);
                cJSON_Delete(root); free(buf); return SERVICE_REGISTRY_ERR_PARSE;
            }
            reg->protected_ips[reg->n_protected_ips++] = ip;
        }
    }

    /* --- 3. profiles --- */
    const cJSON *profs = cJSON_GetObjectItemCaseSensitive(root, "profiles");
    if (!cJSON_IsObject(profs)) {
        registry_log("ERROR", "%s: missing or non-object 'profiles'", path);
        cJSON_Delete(root); free(buf); return SERVICE_REGISTRY_ERR_PARSE;
    }
    {
        const cJSON *prof = NULL;
        cJSON_ArrayForEach(prof, profs) {
            const char *pname = prof->string;
            if (pname == NULL) {
                registry_log("ERROR", "%s: profiles{} has unnamed child", path);
                cJSON_Delete(root); free(buf); return SERVICE_REGISTRY_ERR_PARSE;
            }
            if (strlen(pname) >= SERVICE_REGISTRY_PROFILE_NAME_MAX) {
                registry_log("ERROR", "%s: profile name '%s' exceeds %d chars",
                             path, pname, SERVICE_REGISTRY_PROFILE_NAME_MAX - 1);
                cJSON_Delete(root); free(buf); return SERVICE_REGISTRY_ERR_VALIDATE;
            }
            if (reg->n_profiles >= SERVICE_REGISTRY_MAX_PROFILES) {
                registry_log("ERROR", "%s: profiles exceeds max %d",
                             path, SERVICE_REGISTRY_MAX_PROFILES);
                cJSON_Delete(root); free(buf); return SERVICE_REGISTRY_ERR_CAPACITY;
            }
            if (find_profile_index(reg, pname) >= 0) {
                registry_log("ERROR", "%s: duplicate profile name '%s'", path, pname);
                cJSON_Delete(root); free(buf); return SERVICE_REGISTRY_ERR_VALIDATE;
            }
            size_t i = reg->n_profiles;
            int rc2 = parse_profile_object(prof, pname,
                                            &reg->profiles[i],
                                            &reg->offproto[i]);
            if (rc2 != SERVICE_REGISTRY_OK) {
                cJSON_Delete(root); free(buf); return rc2;
            }
            strncpy(reg->profile_names[i], pname,
                    SERVICE_REGISTRY_PROFILE_NAME_MAX - 1);
            reg->profile_names[i][SERVICE_REGISTRY_PROFILE_NAME_MAX - 1] = '\0';
            /* struct l2_profile carries const char *name/version; point
             * them at the registry's own stable storage. */
            reg->profiles[i].name = reg->profile_names[i];
            reg->profiles[i].version = "v1";
            reg->n_profiles++;
        }
    }

    /* --- 4. catchall_assignments --- */
    const cJSON *ca = cJSON_GetObjectItemCaseSensitive(root, "catchall_assignments");
    if (!cJSON_IsObject(ca)) {
        registry_log("ERROR", "%s: missing or non-object 'catchall_assignments'", path);
        cJSON_Delete(root); free(buf); return SERVICE_REGISTRY_ERR_PARSE;
    }
    uint64_t now = (uint64_t)time(NULL);
    {
        /* Track which protected_ips got a catchall assignment, for rule 4. */
        bool seen[SERVICE_REGISTRY_MAX_PROTECTED_IPS] = {false};

        const cJSON *entry = NULL;
        cJSON_ArrayForEach(entry, ca) {
            const char *ip_str = entry->string;
            if (ip_str == NULL) {
                registry_log("ERROR", "%s: catchall_assignments has unnamed child", path);
                cJSON_Delete(root); free(buf); return SERVICE_REGISTRY_ERR_PARSE;
            }
            bool ip_ok = false;
            uint32_t ip = parse_ipv4_string(ip_str, &ip_ok);
            if (!ip_ok) {
                registry_log("ERROR", "%s: catchall_assignments key '%s' not valid IPv4",
                             path, ip_str);
                cJSON_Delete(root); free(buf); return SERVICE_REGISTRY_ERR_PARSE;
            }
            int p_idx_ip = find_protected_ip_index(reg, ip);
            if (p_idx_ip < 0) {
                registry_log("ERROR",
                             "%s: catchall_assignments has IP '%s' not in protected_ips",
                             path, ip_str);
                cJSON_Delete(root); free(buf); return SERVICE_REGISTRY_ERR_VALIDATE;
            }
            seen[p_idx_ip] = true;

            if (!cJSON_IsObject(entry)) {
                registry_log("ERROR", "%s: catchall_assignments[%s] not an object",
                             path, ip_str);
                cJSON_Delete(root); free(buf); return SERVICE_REGISTRY_ERR_PARSE;
            }
            const struct {
                const char *key;
                uint8_t     kind;
            } cmap[] = {
                {"tcp",   SERVICE_PROTO_CATCHALL_TCP},
                {"udp",   SERVICE_PROTO_CATCHALL_UDP},
                {"icmp",  SERVICE_PROTO_CATCHALL_ICMP},
                {"other", SERVICE_PROTO_CATCHALL_OTHER},
            };
            for (size_t ci = 0; ci < sizeof(cmap)/sizeof(cmap[0]); ci++) {
                char pname[SERVICE_REGISTRY_PROFILE_NAME_MAX];
                char ctx[80];
                snprintf(ctx, sizeof(ctx), "catchall_assignments[%s]", ip_str);
                if (json_get_string(entry, cmap[ci].key, pname, sizeof(pname), ctx)
                    != SERVICE_REGISTRY_OK) {
                    cJSON_Delete(root); free(buf); return SERVICE_REGISTRY_ERR_PARSE;
                }
                service_key_t k = {
                    .target_ip = ip,
                    .port = 0,
                    .proto_kind = cmap[ci].kind,
                    ._pad = 0,
                };
                char slot_name[SERVICE_REGISTRY_SERVICE_NAME_MAX];
                snprintf(slot_name, sizeof(slot_name),
                         "catchall_%s_%s", cmap[ci].key, ip_str);
                int rc3 = registry_add_slot(reg, &k, slot_name, pname,
                                             /*is_catchall=*/true,
                                             /*detection_enabled=*/true,
                                             now);
                if (rc3 != SERVICE_REGISTRY_OK) {
                    cJSON_Delete(root); free(buf); return rc3;
                }
                reg->n_catchalls++;
            }
        }
        /* Rule 4: every protected IP must have an entry. */
        for (size_t i = 0; i < reg->n_protected_ips; i++) {
            if (!seen[i]) {
                /* Format the IP back for the error message. */
                uint32_t ip = reg->protected_ips[i];
                registry_log("ERROR",
                             "%s: protected_ip %u.%u.%u.%u has no catchall_assignments",
                             path, (ip >> 24) & 0xff, (ip >> 16) & 0xff,
                             (ip >> 8) & 0xff, ip & 0xff);
                cJSON_Delete(root); free(buf); return SERVICE_REGISTRY_ERR_VALIDATE;
            }
        }
    }

    /* --- 5. services --- */
    const cJSON *svcs = cJSON_GetObjectItemCaseSensitive(root, "services");
    if (!cJSON_IsArray(svcs)) {
        registry_log("ERROR", "%s: missing or non-array 'services'", path);
        cJSON_Delete(root); free(buf); return SERVICE_REGISTRY_ERR_PARSE;
    }
    {
        size_t svc_idx = 0;
        const cJSON *svc = NULL;
        cJSON_ArrayForEach(svc, svcs) {
            char ctx[64];
            snprintf(ctx, sizeof(ctx), "services[%zu]", svc_idx);
            svc_idx++;
            if (!cJSON_IsObject(svc)) {
                registry_log("ERROR", "%s: %s is not an object", path, ctx);
                cJSON_Delete(root); free(buf); return SERVICE_REGISTRY_ERR_PARSE;
            }
            char name[SERVICE_REGISTRY_SERVICE_NAME_MAX];
            char target_ip_s[16];
            char proto_s[8];
            char prof_s[SERVICE_REGISTRY_PROFILE_NAME_MAX];
            if (json_get_string(svc, "name",       name,         sizeof(name),         ctx) ||
                json_get_string(svc, "target_ip",  target_ip_s,  sizeof(target_ip_s),  ctx) ||
                json_get_string(svc, "proto",      proto_s,      sizeof(proto_s),      ctx) ||
                json_get_string(svc, "profile",    prof_s,       sizeof(prof_s),       ctx)) {
                cJSON_Delete(root); free(buf); return SERVICE_REGISTRY_ERR_PARSE;
            }
            bool ip_ok = false;
            uint32_t ip = parse_ipv4_string(target_ip_s, &ip_ok);
            if (!ip_ok) {
                registry_log("ERROR", "%s: %s.target_ip not valid IPv4", path, ctx);
                cJSON_Delete(root); free(buf); return SERVICE_REGISTRY_ERR_PARSE;
            }
            if (find_protected_ip_index(reg, ip) < 0) {
                registry_log("ERROR", "%s: %s.target_ip not in protected_ips", path, ctx);
                cJSON_Delete(root); free(buf); return SERVICE_REGISTRY_ERR_VALIDATE;
            }
            uint8_t proto_kind = 0;
            if (parse_proto_string(proto_s, &proto_kind) != SERVICE_REGISTRY_OK) {
                registry_log("ERROR", "%s: %s.proto = '%s' not in {TCP, UDP, ICMP}",
                             path, ctx, proto_s);
                cJSON_Delete(root); free(buf); return SERVICE_REGISTRY_ERR_VALIDATE;
            }
            const cJSON *de = cJSON_GetObjectItemCaseSensitive(svc, "detection_enabled");
            if (!cJSON_IsBool(de)) {
                registry_log("ERROR", "%s: %s.detection_enabled must be boolean", path, ctx);
                cJSON_Delete(root); free(buf); return SERVICE_REGISTRY_ERR_PARSE;
            }
            bool detection_enabled = cJSON_IsTrue(de) ? true : false;

            /* port / port_range — exactly one is required. */
            const cJSON *p_port  = cJSON_GetObjectItemCaseSensitive(svc, "port");
            const cJSON *p_range = cJSON_GetObjectItemCaseSensitive(svc, "port_range");
            bool has_port = (p_port != NULL);
            bool has_range = (p_range != NULL);
            if (has_port == has_range) {
                registry_log("ERROR",
                             "%s: %s must have exactly one of 'port' / 'port_range'",
                             path, ctx);
                cJSON_Delete(root); free(buf); return SERVICE_REGISTRY_ERR_VALIDATE;
            }

            int low = -1, high = -1;
            if (has_port) {
                if (!cJSON_IsNumber(p_port)) {
                    registry_log("ERROR", "%s: %s.port not numeric", path, ctx);
                    cJSON_Delete(root); free(buf); return SERVICE_REGISTRY_ERR_PARSE;
                }
                low = high = (int)p_port->valuedouble;
            } else {
                if (proto_kind == SERVICE_PROTO_ICMP) {
                    registry_log("ERROR", "%s: %s is ICMP, may not use port_range", path, ctx);
                    cJSON_Delete(root); free(buf); return SERVICE_REGISTRY_ERR_VALIDATE;
                }
                if (!cJSON_IsString(p_range) || p_range->valuestring == NULL) {
                    registry_log("ERROR", "%s: %s.port_range must be a string", path, ctx);
                    cJSON_Delete(root); free(buf); return SERVICE_REGISTRY_ERR_PARSE;
                }
                const char *rs = p_range->valuestring;
                int matched = sscanf(rs, "%d-%d", &low, &high);
                if (matched != 2) {
                    registry_log("ERROR", "%s: %s.port_range '%s' not 'LOW-HIGH'", path, ctx, rs);
                    cJSON_Delete(root); free(buf); return SERVICE_REGISTRY_ERR_PARSE;
                }
                if (low > high) {
                    registry_log("ERROR", "%s: %s.port_range '%s' has LOW > HIGH",
                                 path, ctx, rs);
                    cJSON_Delete(root); free(buf); return SERVICE_REGISTRY_ERR_VALIDATE;
                }
            }
            if (low < 0 || high > 65535) {
                registry_log("ERROR", "%s: %s port(s) out of [0, 65535]", path, ctx);
                cJSON_Delete(root); free(buf); return SERVICE_REGISTRY_ERR_VALIDATE;
            }
            if (proto_kind == SERVICE_PROTO_ICMP && (low != 0 || high != 0)) {
                registry_log("ERROR", "%s: %s is ICMP, port must be 0", path, ctx);
                cJSON_Delete(root); free(buf); return SERVICE_REGISTRY_ERR_VALIDATE;
            }

            for (int port = low; port <= high; port++) {
                service_key_t k = {
                    .target_ip = ip,
                    .port = (uint16_t)port,
                    .proto_kind = proto_kind,
                    ._pad = 0,
                };
                /* Rule 7: uniqueness check via hash table BEFORE adding. */
                if (hash_lookup(reg, &k) != NULL) {
                    registry_log("ERROR",
                                 "%s: %s duplicates (target_ip=%s, port=%d, proto=%s)",
                                 path, ctx, target_ip_s, port, proto_s);
                    cJSON_Delete(root); free(buf); return SERVICE_REGISTRY_ERR_VALIDATE;
                }
                int rc4 = registry_add_slot(reg, &k, name, prof_s,
                                             /*is_catchall=*/false,
                                             detection_enabled, now);
                if (rc4 != SERVICE_REGISTRY_OK) {
                    cJSON_Delete(root); free(buf); return rc4;
                }
                reg->n_services++;
            }
        }
    }

    /* --- 6. Cross-validation --- */
    {
        char errbuf[256] = {0};
        int rc5 = service_registry_validate(reg, errbuf, sizeof(errbuf));
        if (rc5 != SERVICE_REGISTRY_OK) {
            registry_log("ERROR", "%s: validate failed: %s", path, errbuf);
            cJSON_Delete(root); free(buf); return rc5;
        }
    }

    /* --- 7. Finalise metadata --- */
    reg->loaded_at_unix = now;
    reg->reload_count = prior_reload_count + 1;
    strncpy(reg->source_path, path, SERVICE_REGISTRY_PATH_MAX - 1);
    reg->source_path[SERVICE_REGISTRY_PATH_MAX - 1] = '\0';

    cJSON_Delete(root);
    free(buf);

    registry_log("INFO", "loaded %s: %zu protected_ips, %zu profiles, %zu slots",
                 path, reg->n_protected_ips, reg->n_profiles, reg->n_slots);
    return SERVICE_REGISTRY_OK;
}

/* -------------------------------------------------------------------------
 * Validation
 *
 * Each rule appends to the err buffer (snprintf semantics, respect
 * errlen). Accumulates ALL violations rather than short-circuiting.
 *
 * Helper: append a formatted string to err, advancing the internal
 * cursor. Subsequent calls are NUL-safe; if err is full, additional
 * messages are dropped but the rule violation is still reflected in the
 * eventual return value.
 * ------------------------------------------------------------------------- */
struct err_buf {
    char  *buf;
    size_t cap;
    size_t used;
    int    n_violations;
};

static void err_append(struct err_buf *e, const char *fmt, ...)
    __attribute__((format(printf, 2, 3)));

static void err_append(struct err_buf *e, const char *fmt, ...) {
    e->n_violations++;
    if (e->buf == NULL || e->cap == 0 || e->used >= e->cap - 1) return;
    if (e->used > 0 && e->used < e->cap - 1) {
        e->buf[e->used++] = '\n';
        e->buf[e->used] = '\0';
    }
    size_t avail = e->cap - e->used;
    va_list ap;
    va_start(ap, fmt);
    int n = vsnprintf(e->buf + e->used, avail, fmt, ap);
    va_end(ap);
    if (n > 0) {
        e->used += ((size_t)n < avail) ? (size_t)n : (avail - 1);
        e->buf[e->cap - 1] = '\0';
    }
}

int service_registry_validate(const struct service_registry *reg,
                              char *err, size_t errlen) {
    if (reg == NULL) {
        if (err != NULL && errlen > 0) snprintf(err, errlen, "reg is NULL");
        return SERVICE_REGISTRY_ERR_INTERNAL;
    }
    struct err_buf e = { .buf = err, .cap = errlen, .used = 0, .n_violations = 0 };
    if (err != NULL && errlen > 0) err[0] = '\0';

    /* Rule 11: protected_ip count. */
    if (reg->n_protected_ips > SERVICE_REGISTRY_MAX_PROTECTED_IPS) {
        err_append(&e, "[rule 11] n_protected_ips=%zu > max %d",
                   reg->n_protected_ips, SERVICE_REGISTRY_MAX_PROTECTED_IPS);
    }
    /* Rule 10: total slots cap. */
    if (reg->n_slots > SERVICE_REGISTRY_MAX_TOTAL_SLOTS) {
        err_append(&e, "[rule 10] n_slots=%zu > max %d",
                   reg->n_slots, SERVICE_REGISTRY_MAX_TOTAL_SLOTS);
    }

    /* Per-slot checks for rules 2, 3, 6, 7, 8, 9. */
    for (size_t i = 0; i < reg->n_slots; i++) {
        const struct service_descriptor *s = &reg->slots[i];

        /* Rule 8: proto_kind in valid enum range. */
        if (s->key.proto_kind < SERVICE_PROTO_TCP ||
            s->key.proto_kind >= SERVICE_PROTO_KIND_MAX) {
            err_append(&e, "[rule 8] slots[%zu] proto_kind=%u out of range",
                       i, s->key.proto_kind);
        }

        /* Rule 2: target_ip in protected_ips. */
        if (find_protected_ip_index(reg, s->key.target_ip) < 0) {
            uint32_t ip = s->key.target_ip;
            err_append(&e,
                       "[rule 2] slots[%zu].target_ip %u.%u.%u.%u not in protected_ips",
                       i, (ip >> 24) & 0xff, (ip >> 16) & 0xff,
                       (ip >> 8) & 0xff, ip & 0xff);
        }

        /* Rules 3 / 6: profile reference resolves. */
        int p_idx = find_profile_index(reg, s->profile_name);
        if (p_idx < 0) {
            err_append(&e, "[rule 3/6] slots[%zu] profile '%s' not defined",
                       i, s->profile_name);
        } else if (s->profile != &reg->profiles[p_idx]) {
            err_append(&e, "[rule 6] slots[%zu] profile pointer mismatch", i);
        }

        /* Rule 9: port shape vs proto_kind. */
        bool is_specific = service_proto_kind_is_specific(s->key.proto_kind);
        bool is_catchall = service_proto_kind_is_catchall(s->key.proto_kind);
        if (is_specific) {
            if (s->key.proto_kind == SERVICE_PROTO_ICMP && s->key.port != 0) {
                err_append(&e, "[rule 9] slots[%zu] ICMP service has port=%u (must be 0)",
                           i, s->key.port);
            }
        } else if (is_catchall) {
            if (s->key.port != 0) {
                err_append(&e, "[rule 9] slots[%zu] catchall has port=%u (must be 0)",
                           i, s->key.port);
            }
        }

        /* Rule 7: duplicate (ip, port, proto_kind). O(n²) — fine at 328. */
        for (size_t j = i + 1; j < reg->n_slots; j++) {
            if (memcmp(&reg->slots[i].key, &reg->slots[j].key,
                       sizeof(service_key_t)) == 0) {
                err_append(&e,
                           "[rule 7] slots[%zu] and slots[%zu] share "
                           "(target_ip, port, proto_kind)", i, j);
            }
        }
    }

    /* Rules 4 + 5: every protected IP has exactly the 4 catchall kinds. */
    for (size_t i = 0; i < reg->n_protected_ips; i++) {
        uint32_t ip = reg->protected_ips[i];
        bool present[4] = {false, false, false, false};
        for (size_t s = 0; s < reg->n_slots; s++) {
            if (reg->slots[s].key.target_ip != ip) continue;
            uint8_t k = reg->slots[s].key.proto_kind;
            if (k == SERVICE_PROTO_CATCHALL_TCP)   present[0] = true;
            if (k == SERVICE_PROTO_CATCHALL_UDP)   present[1] = true;
            if (k == SERVICE_PROTO_CATCHALL_ICMP)  present[2] = true;
            if (k == SERVICE_PROTO_CATCHALL_OTHER) present[3] = true;
        }
        const char *names[4] = {"TCP", "UDP", "ICMP", "OTHER"};
        for (int kk = 0; kk < 4; kk++) {
            if (!present[kk]) {
                err_append(&e,
                           "[rule 4/5] protected_ip %u.%u.%u.%u missing "
                           "catchall '%s'",
                           (ip >> 24) & 0xff, (ip >> 16) & 0xff,
                           (ip >> 8) & 0xff, ip & 0xff, names[kk]);
            }
        }
    }

    /* Rule 12: weight non-negativity + probability bounds per profile. */
    for (size_t i = 0; i < reg->n_profiles; i++) {
        const struct l2_profile *p = &reg->profiles[i];
        const char *n = reg->profile_names[i];
        const struct service_offproto_config *op = &reg->offproto[i];

        const struct {
            const char *label;
            double v;
        } weights[] = {
            {"tier0.weights.pps",       p->t0_w_pps},
            {"tier0.weights.bps",       p->t0_w_bps},
            {"tier0.weights.fps",       p->t0_w_fps},
            {"tier0.weights.burst_pps", p->t0_w_burst_pps},
            {"tier0.weights.burst_bps", p->t0_w_burst_bps},
            {"tier0.weights.burst_fps", p->t0_w_burst_fps},
            {"tier1.fusion_weights.tcp",  p->w_tcp},
            {"tier1.fusion_weights.udp",  p->w_udp},
            {"tier1.fusion_weights.icmp", p->w_icmp},
            {"tier1.fusion_weights.dist", p->w_dist},
            {"tier1_l3.weights.ttl_stddev",          p->w_feat_ttl_stddev},
            {"tier1_l3.weights.ip_frag_ratio",       p->w_feat_ip_frag},
            {"tier1_l3.weights.other_proto_ratio",   p->w_feat_other_proto},
            {"tier1_l3.weights.src_port_top1_share", p->w_feat_src_port_top1},
            {"tier1_l3.weights.src_24_top1_share",   p->w_feat_src_24_top1},
            {"tier1_l3.weights.src_24_entropy",      p->w_feat_src_24_entropy},
            {"v2_feature_weights.empty_ack_ratio",      p->w_feat_empty_ack},
            {"v2_feature_weights.zero_window_ratio",    p->w_feat_zero_window},
            {"v2_feature_weights.small_window_ratio",   p->w_feat_small_window},
            {"v2_feature_weights.new_flow_ratio",       p->w_feat_new_flow},
            {"v2_feature_weights.syn_fin_ratio",        p->w_feat_syn_fin},
            {"v2_feature_weights.syn_to_synack_ratio",  p->w_feat_syn_to_synack},
            {"v2_feature_weights.tcp_pkt_size_cov",     p->w_feat_tcp_pkt_size_cov},
            {"v2_feature_weights.tcp_mean_pkt_size",    p->w_feat_tcp_mean_pkt_size},
            {"v2_feature_weights.udp_pkt_size_cov",     p->w_feat_udp_pkt_size_cov},
            {"v2_feature_weights.udp_mean_pkt_size",    p->w_feat_udp_mean_pkt_size},
        };
        for (size_t w = 0; w < sizeof(weights)/sizeof(weights[0]); w++) {
            if (weights[w].v < 0.0) {
                err_append(&e,
                           "[rule 12] profiles['%s'].%s = %g must be >= 0.0",
                           n, weights[w].label, weights[w].v);
            }
        }

        const struct {
            const char *label;
            double v;
        } probs[] = {
            {"tier1.normal_threshold",         p->threshold_normal},
            {"tier1.suspicious_threshold",     p->threshold_suspicious},
            {"tier1_offproto.suspicious_threshold", op->suspicious_threshold},
            {"tier1_offproto.attack_threshold",     op->attack_threshold},
        };
        for (size_t w = 0; w < sizeof(probs)/sizeof(probs[0]); w++) {
            if (probs[w].v < 0.0 || probs[w].v > 1.0) {
                err_append(&e,
                           "[rule 12] profiles['%s'].%s = %g must be in [0, 1]",
                           n, probs[w].label, probs[w].v);
            }
        }
    }

    /* Rule 1: load completed (loaded_at_unix > 0). Skipped here because
     * we call this both during and after load; the load path sets the
     * timestamp at the very end. */

    return (e.n_violations == 0) ? SERVICE_REGISTRY_OK
                                  : SERVICE_REGISTRY_ERR_VALIDATE;
}

/* -------------------------------------------------------------------------
 * 7. Public API — Hot-path lookups
 * ------------------------------------------------------------------------- */

const struct service_descriptor *service_registry_lookup_exact(
    const struct service_registry *reg,
    uint32_t target_ip, uint16_t port, uint8_t proto_kind)
{
    service_key_t k = {
        .target_ip = target_ip,
        .port = port,
        .proto_kind = proto_kind,
        ._pad = 0,
    };
    return hash_lookup(reg, &k);
}

const struct service_descriptor *service_registry_lookup_catchall(
    const struct service_registry *reg,
    uint32_t target_ip, uint8_t catchall_kind)
{
    service_key_t k = {
        .target_ip = target_ip,
        .port = 0,
        .proto_kind = catchall_kind,
        ._pad = 0,
    };
    return hash_lookup(reg, &k);
}

int service_registry_slot_index(const struct service_registry *reg,
                                uint32_t target_ip, uint16_t port,
                                uint8_t proto_kind)
{
    const struct service_descriptor *d =
        service_registry_lookup_exact(reg, target_ip, port, proto_kind);
    if (d == NULL || reg == NULL) return -1;
    return (int)(d - reg->slots);
}

/* P7: per-service hot path needs to classify packet direction (inbound vs
 * outbound) based on whether dst_ip / src_ip is one of the registry's
 * protected IPs. Linear scan over <= MAX_PROTECTED_IPS (32) entries — small
 * enough that any O(1) hash structure would cost more in cache pollution
 * than the scan itself. */
bool service_registry_is_protected_ip(const struct service_registry *reg,
                                      uint32_t ip)
{
    if (reg == NULL) return false;
    for (size_t i = 0; i < reg->n_protected_ips; i++) {
        if (reg->protected_ips[i] == ip) return true;
    }
    return false;
}

/* -------------------------------------------------------------------------
 * 8. Public API — Diagnostics
 * ------------------------------------------------------------------------- */

void service_registry_log_summary(const struct service_registry *reg) {
    if (reg == NULL) {
        fprintf(stderr, "[service_registry] <null registry>\n");
        return;
    }
    char ts[32] = "(unloaded)";
    if (reg->loaded_at_unix > 0) {
        time_t t = (time_t)reg->loaded_at_unix;
        struct tm tm_buf;
        if (gmtime_r(&t, &tm_buf) != NULL) {
            strftime(ts, sizeof(ts), "%Y-%m-%dT%H:%M:%SZ", &tm_buf);
        }
    }
    double load_pct = (reg->n_slots == 0)
        ? 0.0
        : 100.0 * (double)reg->n_slots / (double)SERVICE_REGISTRY_HASH_SIZE;

    fprintf(stderr, "[service_registry] Loaded %s:\n",
            reg->source_path[0] ? reg->source_path : "(no path)");
    fprintf(stderr, "[service_registry]   protected_ips:  %zu\n",
            reg->n_protected_ips);
    fprintf(stderr, "[service_registry]   profiles:       %zu\n",
            reg->n_profiles);
    fprintf(stderr, "[service_registry]   catchalls:      %zu (across %zu IPs × 4 each)\n",
            reg->n_catchalls, reg->n_protected_ips);
    fprintf(stderr, "[service_registry]   services:       %zu\n",
            reg->n_services);
    fprintf(stderr, "[service_registry]   total slots:    %zu / %d\n",
            reg->n_slots, SERVICE_REGISTRY_MAX_TOTAL_SLOTS);
    fprintf(stderr, "[service_registry]   hash load:      %zu / %d = %.1f%%\n",
            reg->n_slots, SERVICE_REGISTRY_HASH_SIZE, load_pct);
    fprintf(stderr, "[service_registry]   reload_count:   %u\n",
            reg->reload_count);
    fprintf(stderr, "[service_registry]   loaded_at:      %s\n", ts);
    fprintf(stderr, "[service_registry]   learning_mode:  %s\n",
            reg->learning_mode ? "ENABLED (no phase transitions)"
                               : "disabled");
}

const char *service_proto_kind_name(uint8_t k) {
    switch (k) {
    case SERVICE_PROTO_TCP:            return "TCP";
    case SERVICE_PROTO_UDP:            return "UDP";
    case SERVICE_PROTO_ICMP:           return "ICMP";
    case SERVICE_PROTO_CATCHALL_TCP:   return "CATCHALL_TCP";
    case SERVICE_PROTO_CATCHALL_UDP:   return "CATCHALL_UDP";
    case SERVICE_PROTO_CATCHALL_ICMP:  return "CATCHALL_ICMP";
    case SERVICE_PROTO_CATCHALL_OTHER: return "CATCHALL_OTHER";
    default:                           return "UNKNOWN";
    }
}

/* =========================================================================
 *  P3 — Process-global registry pointer
 *
 *  The active registry is published exactly once at startup (main.c) and
 *  potentially re-published on P6's SIGHUP reload. Hot-path readers in
 *  P7+ will use the acquire load. Because the store happens before any
 *  packet is processed against the registry, the release/acquire pair
 *  guarantees readers see a fully initialised struct.
 *
 *  Atomics path: C11 <stdatomic.h>. No GCC __atomic_* fallback was
 *  required (gcc 11.4 + c_std=c11 in meson.build supports it).
 * ========================================================================= */
static _Atomic(const struct service_registry *) g_active_registry = NULL;

const struct service_registry *service_registry_get_global(void) {
    return atomic_load_explicit(&g_active_registry, memory_order_acquire);
}

const struct service_registry *
service_registry_set_global(const struct service_registry *reg) {
    return atomic_exchange_explicit(&g_active_registry, reg,
                                     memory_order_release);
}

const char *service_registry_get_source_path(void) {
    const struct service_registry *reg = service_registry_get_global();
    if (reg == NULL) return NULL;
    return reg->source_path[0] ? reg->source_path : NULL;
}
