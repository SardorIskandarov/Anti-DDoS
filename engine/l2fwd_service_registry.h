#ifndef __L2FWD_SERVICE_REGISTRY_H__
#define __L2FWD_SERVICE_REGISTRY_H__

/**
 * @file   l2fwd_service_registry.h
 * @brief  Per-service detection registry (loaded from services.json at boot).
 *
 * This is the public API for the service registry introduced by the
 * big-bang refactor (P0-P17). At runtime the engine consults this
 * registry — instead of the old static C profile table — to pick the
 * `struct l2_profile` for every (dst_ip, port, proto) tuple.
 *
 * Lifecycle:
 *   1. service_registry_init()    — zero the struct.
 *   2. service_registry_load()    — parse services.json from disk.
 *   3. service_registry_validate()— enforce all 12 schema rules.
 *   4. (Hot path) service_registry_lookup_exact() / _catchall().
 *   5. service_registry_destroy() — release all internal state.
 *
 * All functions are thread-safe READS once the registry is loaded.
 * Mutations (init/load/destroy) are NOT concurrent — caller serialises.
 *
 * Status:
 *   P1 (this commit): types + stub implementations only. No JSON
 *   parsing yet; service_registry_load() returns
 *   SERVICE_REGISTRY_ERR_INTERNAL.
 *   P2-P4 will flesh out parsing, validation, and lookup.
 */

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

/* P1 NOTE — `service_registry` embeds an ARRAY of struct l2_profile by
 * value (see below), so sizeof(struct l2_profile) must be known at the
 * point of inclusion. We therefore include the full profile header here
 * rather than forward-declaring. The "no coupling" wish from the P1
 * spec is unattainable while the value-array layout stands; see the
 * deviation note in the P1 status report. */
#include "l2fwd_l2_profile.h"

/* -------------------------------------------------------------------------
 * Sizing constants
 *
 * MAX_SERVICES sits at 200 (well below the 328 engine table cap so we
 * never re-size mid-cutover). With 32 protected IPs × 4 catchalls = 128
 * catchall slots reserved, the total slot count fits in 200 + 128 = 328.
 *
 * HASH_SIZE must remain a power of two: the lookup function uses
 * `index & (HASH_SIZE - 1)` instead of modulo.
 *
 * MAX_PROFILES is the cap on distinct profile names referenced by the
 * registry (services + catchalls). 64 leaves headroom over the 12
 * shipped at P0 (1 generic + 11 IP-specific).
 * ------------------------------------------------------------------------- */
#define SERVICE_REGISTRY_MAX_SERVICES       200
#define SERVICE_REGISTRY_MAX_PROTECTED_IPS  32
#define SERVICE_REGISTRY_CATCHALLS_PER_IP   4
#define SERVICE_REGISTRY_MAX_TOTAL_SLOTS    (SERVICE_REGISTRY_MAX_SERVICES + \
                                             SERVICE_REGISTRY_MAX_PROTECTED_IPS * \
                                             SERVICE_REGISTRY_CATCHALLS_PER_IP)
#define SERVICE_REGISTRY_HASH_SIZE          512    /* power of 2 */
#define SERVICE_REGISTRY_MAX_PROFILES       64
#define SERVICE_REGISTRY_SERVICE_NAME_MAX   64
#define SERVICE_REGISTRY_PROFILE_NAME_MAX   64
#define SERVICE_REGISTRY_PATH_MAX           256

/* -------------------------------------------------------------------------
 * Return codes
 *
 * All public functions return one of these. Negative = error; zero = ok.
 * Stub implementations in P1 return SERVICE_REGISTRY_ERR_INTERNAL for
 * anything beyond _init / _destroy.
 * ------------------------------------------------------------------------- */
#define SERVICE_REGISTRY_OK              0
#define SERVICE_REGISTRY_ERR_IO         -1   /* file open/read/write failure   */
#define SERVICE_REGISTRY_ERR_PARSE      -2   /* JSON structural error          */
#define SERVICE_REGISTRY_ERR_VALIDATE   -3   /* schema rule violated           */
#define SERVICE_REGISTRY_ERR_CAPACITY   -4   /* would exceed MAX_*             */
#define SERVICE_REGISTRY_ERR_NOT_FOUND  -5   /* lookup miss (for non-NULL APIs)*/
#define SERVICE_REGISTRY_ERR_INTERNAL   -6   /* contract violation / not-yet   */

/* -------------------------------------------------------------------------
 * enum service_proto_kind
 *
 * Used as the `proto_kind` byte in service_key_t. The first three values
 * (TCP / UDP / ICMP) describe explicit service entries; the four CATCHALL_*
 * values are synthetic slots that match any (port, dst_ip) when no
 * specific service entry applies.
 *
 * CATCHALL_OTHER catches any IP protocol that is not TCP/UDP/ICMP
 * (GRE, ESP, IP-in-IP, exotic).
 *
 * KIND_MAX is a sentinel — keep it as the last value.
 * ------------------------------------------------------------------------- */
enum service_proto_kind {
    SERVICE_PROTO_TCP            = 1,
    SERVICE_PROTO_UDP            = 2,
    SERVICE_PROTO_ICMP           = 3,
    SERVICE_PROTO_CATCHALL_TCP   = 4,
    SERVICE_PROTO_CATCHALL_UDP   = 5,
    SERVICE_PROTO_CATCHALL_ICMP  = 6,
    SERVICE_PROTO_CATCHALL_OTHER = 7,
    SERVICE_PROTO_KIND_MAX       = 8,
};

/**
 * @brief True iff k denotes one of the four CATCHALL_* kinds.
 */
static inline bool service_proto_kind_is_catchall(uint8_t k) {
    return k >= SERVICE_PROTO_CATCHALL_TCP && k <= SERVICE_PROTO_CATCHALL_OTHER;
}

/**
 * @brief True iff k denotes an explicit TCP / UDP / ICMP service entry.
 */
static inline bool service_proto_kind_is_specific(uint8_t k) {
    return k >= SERVICE_PROTO_TCP && k <= SERVICE_PROTO_ICMP;
}

/* -------------------------------------------------------------------------
 * service_offproto_config — per-profile off-protocol detection thresholds.
 *
 * Mirrors the JSON profile object's `tier1_offproto` section. The C
 * engine doesn't consume these yet (the off-protocol detector arrives
 * in P9), but the loader parses + stores them so the JSON is the
 * single source of truth from P2 onward.
 *
 * Kept in a parallel array (service_registry.offproto[]) rather than
 * inside struct l2_profile so P2 does not need to modify
 * l2fwd_l2_profile.{c,h}.
 * ------------------------------------------------------------------------- */
struct service_offproto_config {
    double suspicious_threshold;   /**< Fires OFFPROTO_SUSPICIOUS when reached. */
    double attack_threshold;       /**< Fires OFFPROTO_ATTACK when reached.     */
};

/* -------------------------------------------------------------------------
 * service_key_t
 *
 * The 8-byte lookup key: dst_ip (host byte order), port (host byte
 * order; 0 for ICMP and catchall entries), proto_kind, and a single
 * padding byte that MUST always be zero so memcmp() and the hash
 * function never see uninitialised padding.
 *
 * Packed to make the 8-byte assertion below sound on any reasonable
 * x86-64 ABI. Aligned naturally to 4 bytes.
 * ------------------------------------------------------------------------- */
typedef struct service_key {
    uint32_t target_ip;   /**< host byte order */
    uint16_t port;        /**< host byte order; 0 for ICMP / catchalls */
    uint8_t  proto_kind;  /**< enum service_proto_kind */
    uint8_t  _pad;        /**< MUST be zero, for clean memcmp + hash */
} __attribute__((packed)) service_key_t;
_Static_assert(sizeof(service_key_t) == 8, "service_key_t must be 8 bytes packed");

/* -------------------------------------------------------------------------
 * service_descriptor
 *
 * One slot in service_registry.slots[]. Holds the key, the human-readable
 * service name (free-form, ASCII), the profile-name reference, and a
 * resolved pointer to the actual struct l2_profile object embedded in
 * service_registry.profiles[]. The pointer is only valid for the
 * lifetime of its containing service_registry.
 *
 * is_catchall is derived from proto_kind at load time and cached so the
 * hot path never has to test the enum range.
 * ------------------------------------------------------------------------- */
struct service_descriptor {
    service_key_t            key;
    char                     name[SERVICE_REGISTRY_SERVICE_NAME_MAX];
    char                     profile_name[SERVICE_REGISTRY_PROFILE_NAME_MAX];
    const struct l2_profile *profile;        /**< resolved at load time */
    bool                     detection_enabled;
    bool                     is_catchall;    /**< derived from proto_kind */
    uint64_t                 added_at_unix;  /**< seconds since epoch     */
};

/* -------------------------------------------------------------------------
 * service_registry
 *
 * The full in-memory registry. One instance is allocated by the caller
 * (typically as a file-scope or `rte_zmalloc`-backed object in
 * l2fwd_ddos_collector.c at P5).
 *
 * Layout choice: descriptors live in a contiguous array
 * (slots[MAX_TOTAL_SLOTS]); hash_table[] holds slot indices, so the
 * lookup chain is one cache line per probe.
 *
 * profile storage:
 *   profiles[]      — the concrete struct l2_profile objects.
 *   profile_names[] — parallel array of profile-name strings.
 *   n_profiles      — number of populated entries.
 *
 * Concrete (non-opaque) on purpose: the engine needs sizeof() to embed
 * the registry inside the larger collector struct in P5. Callers must
 * still treat fields as private and access via the API.
 * ------------------------------------------------------------------------- */
struct service_registry {
    struct service_descriptor  slots[SERVICE_REGISTRY_MAX_TOTAL_SLOTS];
    size_t                     n_slots;           /**< total used (services + catchalls) */
    size_t                     n_services;        /**< specific entries  */
    size_t                     n_catchalls;       /**< catchall slots    */
    size_t                     n_protected_ips;
    uint32_t                   protected_ips[SERVICE_REGISTRY_MAX_PROTECTED_IPS];

    struct l2_profile          profiles[SERVICE_REGISTRY_MAX_PROFILES];
    char                       profile_names[SERVICE_REGISTRY_MAX_PROFILES][SERVICE_REGISTRY_PROFILE_NAME_MAX];
    /**
     * Parallel array of `tier1_offproto` thresholds, indexed the same
     * way as profiles[]. Populated by service_registry_load(); not yet
     * read by the engine.
     */
    struct service_offproto_config offproto[SERVICE_REGISTRY_MAX_PROFILES];
    size_t                     n_profiles;

    /**
     * Open-addressed hash table; values are indices into slots[].
     * -1 means empty. Sized at SERVICE_REGISTRY_HASH_SIZE (power of 2)
     * so probing uses bitmask not modulo.
     */
    int32_t                    hash_table[SERVICE_REGISTRY_HASH_SIZE];

    bool                       learning_mode;   /**< When true, phase
        transitions are suppressed engine-wide. EWMA baselines and
        counters still update normally. Used for data collection
        before threshold tuning. */

    uint64_t                   loaded_at_unix;
    uint32_t                   reload_count;
    char                       source_path[SERVICE_REGISTRY_PATH_MAX];
};

/* -------------------------------------------------------------------------
 * Public API — Lifecycle
 * ------------------------------------------------------------------------- */

/**
 * @brief Zero a service_registry and prepare it for loading.
 *
 * Sets all hash_table[] entries to -1 (empty). After this call, the
 * registry is in a well-defined "empty" state — lookups return NULL,
 * the slot/profile arrays are zeroed. Idempotent.
 *
 * @param reg  Caller-owned registry struct. Must not be NULL.
 * @return     SERVICE_REGISTRY_OK on success;
 *             SERVICE_REGISTRY_ERR_INTERNAL on contract violation.
 */
int service_registry_init(struct service_registry *reg);

/**
 * @brief Load and parse services.json into the given registry.
 *
 * Reads the entire file, parses it with cJSON, populates the slot,
 * profile, and catchall arrays, runs validation (rules 1-12 from
 * services_schema.md), and builds the hash table.
 *
 * Atomicity: if loading fails partway, the registry is left in an
 * inconsistent state. Callers should re-init() before retrying.
 *
 * @param reg   Initialised registry.
 * @param path  Absolute or working-dir-relative path to services.json.
 * @return      SERVICE_REGISTRY_OK on success;
 *              SERVICE_REGISTRY_ERR_IO if the file can't be opened/read;
 *              SERVICE_REGISTRY_ERR_PARSE on JSON structural error;
 *              SERVICE_REGISTRY_ERR_VALIDATE on schema rule violation;
 *              SERVICE_REGISTRY_ERR_CAPACITY if the file exceeds limits;
 *              SERVICE_REGISTRY_ERR_INTERNAL on unexpected failure.
 *
 * @note P1 STUB: always returns SERVICE_REGISTRY_ERR_INTERNAL.
 */
int service_registry_load(struct service_registry *reg, const char *path);

/**
 * @brief Re-check all 12 schema rules against the loaded registry.
 *
 * Used as a defensive double-check after load() and as a CI step.
 * Writes a human-readable description of the FIRST violation found
 * into `err` (NUL-terminated, truncated to errlen-1 if needed).
 *
 * @param reg     Loaded registry.
 * @param err     Caller-owned buffer for the error string. Must not be NULL
 *                if errlen > 0.
 * @param errlen  Size of err[] in bytes.
 * @return        SERVICE_REGISTRY_OK if every rule passes;
 *                SERVICE_REGISTRY_ERR_VALIDATE on the first violation;
 *                SERVICE_REGISTRY_ERR_INTERNAL on contract violation.
 *
 * @note P1 STUB: always returns SERVICE_REGISTRY_ERR_INTERNAL.
 */
int service_registry_validate(const struct service_registry *reg,
                              char *err, size_t errlen);

/**
 * @brief Release any internal state and zero the struct.
 *
 * In v1, since the struct is fully embedded (no heap pointers), this
 * is equivalent to service_registry_init() — but callers should
 * always use destroy() in case future versions add allocations.
 *
 * @param reg  Loaded registry.
 */
void service_registry_destroy(struct service_registry *reg);

/* -------------------------------------------------------------------------
 * Public API — Hot-path lookups
 *
 * Both lookups are O(1) average via the hash table. They are CONST on
 * the registry; nothing they touch may mutate. Safe to call from any
 * lcore once the registry is loaded.
 * ------------------------------------------------------------------------- */

/**
 * @brief Find the explicit service descriptor for (target_ip, port, proto_kind).
 *
 * @param reg          Loaded registry.
 * @param target_ip    Destination IP in host byte order.
 * @param port         Destination port in host byte order
 *                     (0 for ICMP; the function will only match SERVICE_PROTO_ICMP).
 * @param proto_kind   One of SERVICE_PROTO_TCP / _UDP / _ICMP.
 *                     Passing a catchall kind is a programming error —
 *                     use service_registry_lookup_catchall() instead.
 * @return             Pointer to the matching descriptor, or NULL if none.
 *                     The pointer is valid until the registry is reloaded
 *                     or destroyed.
 *
 * @note P1 STUB: always returns NULL.
 */
const struct service_descriptor *service_registry_lookup_exact(
    const struct service_registry *reg,
    uint32_t target_ip, uint16_t port, uint8_t proto_kind);

/**
 * @brief Find the catchall descriptor for (target_ip, catchall_kind).
 *
 * @param reg            Loaded registry.
 * @param target_ip      Destination IP in host byte order.
 * @param catchall_kind  One of SERVICE_PROTO_CATCHALL_TCP / _UDP /
 *                       _ICMP / _OTHER. Passing a specific kind is a
 *                       programming error.
 * @return               Pointer to the matching catchall descriptor,
 *                       or NULL if the IP is not in protected_ips or
 *                       the registry isn't loaded.
 *
 * @note P1 STUB: always returns NULL.
 */
const struct service_descriptor *service_registry_lookup_catchall(
    const struct service_registry *reg,
    uint32_t target_ip, uint8_t catchall_kind);

/* -------------------------------------------------------------------------
 * Diagnostics
 * ------------------------------------------------------------------------- */

/**
 * @brief Print a one-line summary of the registry to stdout.
 *
 * Format:
 *   Service registry: N slots (S services, C catchalls, P profiles, I protected IPs)
 *
 * Intended for human-readable boot-time logging; not for parsing.
 */
void service_registry_log_summary(const struct service_registry *reg);

/**
 * @brief Translate a service_proto_kind value to its uppercase name.
 *
 * @param k  One of the enum values, or any 0..255 integer.
 * @return   "TCP" / "UDP" / "ICMP" / "CATCHALL_TCP" / "CATCHALL_UDP" /
 *           "CATCHALL_ICMP" / "CATCHALL_OTHER" / "UNKNOWN".
 *           The pointer is to static storage; do NOT free.
 */
const char *service_proto_kind_name(uint8_t k);

/**
 * @brief Resolve (target_ip, port, proto_kind) to a slot index.
 *
 * Like service_registry_lookup_exact() but returns the integer index
 * into reg->slots[] instead of a pointer. Useful for diagnostics, gold
 * tests, and dashboards that want a stable handle.
 *
 * @return The slot index in `[0, reg->n_slots)` on hit; -1 on miss.
 *
 * @note P1 STUB: always returns -1.
 */
int service_registry_slot_index(const struct service_registry *reg,
                                uint32_t target_ip, uint16_t port,
                                uint8_t proto_kind);

/**
 * @brief True iff `ip` (host byte order) is in reg->protected_ips[].
 *
 * Added in P7 for the per-service hot path's inbound/outbound
 * direction classifier. Linear scan over the protected_ips array
 * (typically <= 11 entries, capped at SERVICE_REGISTRY_MAX_PROTECTED_IPS).
 *
 * Stateless, thread-safe (read-only on the registry).
 */
bool service_registry_is_protected_ip(const struct service_registry *reg,
                                      uint32_t ip);

/* -------------------------------------------------------------------------
 * P3: process-global registry pointer
 *
 * Exactly one registry is "active" per process. main.c installs it at
 * startup via service_registry_set_global(); future hot-path consumers
 * (P7+) read it via service_registry_get_global(). Reads use acquire
 * semantics; the install uses release semantics, so any hot-path reader
 * observing a non-NULL pointer also observes a fully initialised
 * registry.
 *
 * In P3 the hot path does NOT consume the registry yet — these
 * accessors exist purely to land the wiring contract.
 * ------------------------------------------------------------------------- */

/**
 * @brief Return the active process-global registry, or NULL if none.
 *
 * The pointer is stable for the lifetime of the process unless
 * service_registry_set_global() is called (startup, and P6's SIGHUP
 * reload). Hot-path callers may treat NULL as "no per-service detection
 * available".
 *
 * Thread-safe: uses an atomic load with acquire semantics.
 */
const struct service_registry *service_registry_get_global(void);

/**
 * @brief Atomically install `reg` as the new process-global registry.
 *
 * Uses an atomic exchange with release semantics so concurrent readers
 * observe a fully initialised registry. Passing NULL clears the global.
 *
 * @return The previous global pointer (NULL if none was installed). The
 *         caller may free it (P6 reload) or retain it for inspection.
 */
const struct service_registry *
service_registry_set_global(const struct service_registry *reg);

/**
 * @brief Source path of the active registry, or NULL if none loaded.
 *
 * Returns a pointer into the active registry's internal `source_path`
 * buffer (already set by service_registry_load()). The returned pointer
 * is valid until the next service_registry_set_global() call.
 */
const char *service_registry_get_source_path(void);

#endif /* __L2FWD_SERVICE_REGISTRY_H__ */
