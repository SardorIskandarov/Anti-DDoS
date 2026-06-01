#ifndef __L2FWD_SERVICE_SNAPSHOT_H__
#define __L2FWD_SERVICE_SNAPSHOT_H__

/**
 * @file   l2fwd_service_snapshot.h
 * @brief  Per-service raw-telemetry snapshot — the C↔Python detection contract.
 *
 * BACKGROUND
 * ----------
 * The detection brain (feature derivation + Tier-0/Tier-1 scoring + the phase
 * machine + baseline freeze) is moving from C (l2fwd_service_features.c /
 * l2fwd_service_scoring.c) to Python. After the migration the C data plane
 * keeps ONLY: per-packet counting, per-packet sketch updates, double-buffered
 * window banks, sketch-estimate computation, and a minimal always-on
 * absolute-floor fail-safe. Everything statistical/decisional lives in Python.
 *
 * This header defines the ONE artifact that crosses the language boundary: a
 * fixed-size, per-slot RAW snapshot record. The C producer publishes one record
 * per active slot, once per 1 Hz tick, into a double-buffered POSIX shared-memory
 * region. The Python detector reads the published bank and computes the verdict.
 *
 * Unlike the legacy wire protocol (l2fwd_service_wire.h), this channel ships
 * RAW counters + sketch ESTIMATES (scalars) — never computed scores, never raw
 * HLL/CM registers. Python owns all derived state.
 *
 * LAYOUT DISCIPLINE (read before editing)
 * ---------------------------------------
 *   - Same-host shared memory: fields are NATIVE byte order (little-endian on
 *     x86-64), NOT big-endian like the socket wire. No byte-swapping.
 *   - Fields are ordered strictly by descending alignment (8B → 4B → 2B → 1B)
 *     so the struct has NO internal padding and a predictable, stable layout
 *     that the NumPy mirror in ddos_monitor/detection/snapshot.py can reproduce exactly.
 *   - The record is a FIXED stride for every slot, sized for the worst case
 *     (CATCHALL_OTHER carries all proto arms). Typed slots leave the unused
 *     arms zero. Fixed stride = trivial indexing on both sides.
 *   - ANY change to the record or header layout MUST:
 *       1. bump SERVICE_SNAPSHOT_RECORD_VERSION,
 *       2. update the field table in l2fwd_service_snapshot.c (the producer
 *          hashes it into the shm header at init), and
 *       3. update the mirror + LAYOUT_HASH check in ddos_monitor/detection/snapshot.py.
 *     The runtime layout-hash check (FNV-1a over the field table) is the safety
 *     net that turns silent drift into a loud refusal-to-attach.
 *
 * DERIVABILITY CONTRACT
 * ---------------------
 * Every column the Python collector currently writes to ClickHouse must be
 * derivable from this record plus Python-owned detection state. Concretely:
 *   - raw counters (inbound/outbound/proto) are carried verbatim;
 *   - HLL/CM results are carried as ESTIMATES (est_* doubles, src_24_*);
 *   - ttl_mean/ttl_stddev are derived in Python from ttl_sum/ttl_sum_sq;
 *   - phase/scores/tier0-risk/dominant/burst-z are COMPUTED in Python;
 *   - profile_name[8] mirrors the legacy 8-byte truncation for column parity.
 */

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

#include "l2fwd_service_registry.h"   /* SERVICE_REGISTRY_MAX_TOTAL_SLOTS */

struct service_stats_array;

/* -------------------------------------------------------------------------
 * Contract constants
 * ------------------------------------------------------------------------- */

/* Shared-memory object name (POSIX shm_open → visible at /dev/shm/<name>).
 * The leading slash is the shm_open convention; the Python side opens the
 * mirrored path /dev/shm/anti_ddos_snapshot. */
#define SERVICE_SNAPSHOT_SHM_NAME      "/anti_ddos_snapshot"
#define SERVICE_SNAPSHOT_SHM_PATH      "/dev/shm/anti_ddos_snapshot"

/* Header magic: 'A''D''S''1' (Anti-DDoS Snapshot, format 1). */
#define SERVICE_SNAPSHOT_MAGIC_0       0x41  /* 'A' */
#define SERVICE_SNAPSHOT_MAGIC_1       0x44  /* 'D' */
#define SERVICE_SNAPSHOT_MAGIC_2       0x53  /* 'S' */
#define SERVICE_SNAPSHOT_MAGIC_3       0x31  /* '1' */

/* Bump on ANY shm-header layout change. */
#define SERVICE_SNAPSHOT_FORMAT_VERSION  1u
/* Bump on ANY per-slot record layout change (see LAYOUT DISCIPLINE above).
 * v2: ttl_sum/ttl_sum_sq + tcp/udp_pkt_size_sum/sum_sq → ttl_mean/M2 +
 *     tcp/udp_pkt_size_mean/M2 (Welford-true; eliminates catastrophic
 *     cancellation at high Gbps). Same offsets, same record size, type only. */
#define SERVICE_SNAPSHOT_RECORD_VERSION  2u

/* Fixed per-slot record stride, in bytes. Asserted below. */
#define SERVICE_SNAPSHOT_RECORD_SIZE     384u
/* Fixed header size, in bytes. Asserted below. */
#define SERVICE_SNAPSHOT_HEADER_SIZE     128u

/* Number of slots per bank == the stats-array capacity. */
#define SERVICE_SNAPSHOT_CAPACITY        SERVICE_REGISTRY_MAX_TOTAL_SLOTS

/* Length of the truncated profile-name label carried per record (parity with
 * the legacy wire identity section). */
#define SERVICE_SNAPSHOT_PROFILE_NAME_LEN 8u

/* FNV-1a 32-bit layout hash of the record field table. Computed by Python
 * (ddos_monitor/detection/snapshot.py, the authoritative layout definition) and verified
 * by the producer at init against the value it computes from its own field
 * table; mismatch is a fatal configuration error. Baked here as the agreed
 * constant for the current RECORD_VERSION. */
#define SERVICE_SNAPSHOT_LAYOUT_HASH     0x6A2EA116u  /* from ddos_monitor/detection/snapshot.py (v2: ttl/pkt_size Welford) */

/* -------------------------------------------------------------------------
 * Per-slot raw snapshot record (FIXED 384 B, native byte order)
 *
 * Field order is locked: 8-byte block, then 4-byte, 2-byte, 1-byte, then
 * reserved padding to the 384-byte stride. Do not reorder without bumping
 * SERVICE_SNAPSHOT_RECORD_VERSION and updating the Python mirror.
 * ------------------------------------------------------------------------- */
struct service_snapshot_record {
    /* --- 8-byte block: raw u64 counters ------------------------------- */

    /* Common inbound (mirrors service_common_stats). */
    uint64_t inbound_pkts;          /* off   0 */
    uint64_t inbound_bytes;         /* off   8 */
    uint64_t off_proto_pkts;        /* off  16 */
    uint64_t ip_frag_pkts;          /* off  24 */
    double   ttl_mean;              /* off  32  Welford running mean (per window)  */
    double   ttl_M2;                /* off  40  Welford running Σ(x−mean)² (idem)  */

    /* Outbound (mirrors service_outbound_stats; widened to u64). */
    uint64_t out_pkts;              /* off  48 */
    uint64_t out_bytes;             /* off  56 */
    uint64_t out_tcp_pkts;          /* off  64 */
    uint64_t out_udp_pkts;          /* off  72 */
    uint64_t out_icmp_pkts;         /* off  80 */

    /* TCP arm raw counters (mirrors service_tcp_stats scalar fields). */
    uint64_t tcp_pkts;              /* off  88 */
    uint64_t tcp_bytes;             /* off  96 */
    uint64_t syn_pkts;              /* off 104 */
    uint64_t syn_ack_pkts;          /* off 112 */
    uint64_t fin_ack_pkts;          /* off 120 */
    uint64_t rst_pkts;              /* off 128 */
    uint64_t ack_data_pkts;         /* off 136 */
    uint64_t empty_ack_pkts;        /* off 144 */
    uint64_t zero_window_pkts;      /* off 152 */
    uint64_t small_window_pkts;     /* off 160 */
    double   tcp_pkt_size_mean;     /* off 168  Welford running mean (per window)  */
    double   tcp_pkt_size_M2;       /* off 176  Welford running Σ(x−mean)² (idem)  */
    uint64_t tcp_cm_src_port_top_count; /* off 184 */
    uint64_t tcp_cm_src_port_total;     /* off 192 */

    /* UDP arm raw counters (mirrors service_udp_stats scalar fields). */
    uint64_t udp_pkts;              /* off 200 */
    uint64_t udp_bytes;             /* off 208 */
    double   udp_pkt_size_mean;     /* off 216  Welford running mean (per window)  */
    double   udp_pkt_size_M2;       /* off 224  Welford running Σ(x−mean)² (idem)  */
    uint64_t udp_cm_src_port_top_count; /* off 232 */
    uint64_t udp_cm_src_port_total;     /* off 240 */

    /* ICMP arm raw counters (mirrors service_icmp_stats). */
    uint64_t icmp_pkts;             /* off 248 */
    uint64_t icmp_echo_pkts;        /* off 256 */
    uint64_t icmp_bytes;            /* off 264 */

    /* OTHER arm raw counters (mirrors service_other_stats scalar fields). */
    uint64_t other_pkts;            /* off 272 */
    uint64_t other_bytes;           /* off 280 */

    /* --- 8-byte block: sketch ESTIMATES (doubles) --------------------- */
    double   est_unique_src_ips;    /* off 288  HLL(common.unique_src_ips)   */
    double   est_unique_flows;      /* off 296  HLL(common.unique_flows)     */
    double   src_24_top1_share;     /* off 304  CM /24 top-1 share           */
    double   src_24_entropy;        /* off 312  CM /24 Shannon entropy       */
    double   est_tcp_new_flows;     /* off 320  HLL(tcp unique_new_flows)    */
    double   est_udp_flows;         /* off 328  HLL(udp udp_flows)           */
    double   est_other_dst_ports;   /* off 336  HLL(other unique_dst_ports)  */

    /* --- 4-byte block ------------------------------------------------- */
    uint32_t target_ip;             /* off 344  host byte order              */
    uint32_t window_count;          /* off 348  slot->window_count           */

    /* --- 2-byte block ------------------------------------------------- */
    uint16_t port;                  /* off 352  host byte order; 0 for ICMP  */

    /* --- 1-byte block ------------------------------------------------- */
    uint8_t  proto_kind;            /* off 354  enum service_proto_kind      */
    uint8_t  is_catchall;           /* off 355  0/1                          */
    uint8_t  absolute_floor_fired;  /* off 356  C fail-safe: floor breached  */
    char     profile_name[SERVICE_SNAPSHOT_PROFILE_NAME_LEN]; /* off 357..364 */

    uint8_t  reserved[19];          /* off 365..383  pad to 384, future use  */
};

/* -------------------------------------------------------------------------
 * Shared-memory region header (FIXED 128 B, native byte order)
 *
 * Followed immediately by two contiguous banks of SERVICE_SNAPSHOT_CAPACITY
 * records each:
 *
 *   [ header (128 B) ][ bank 0: capacity × 384 B ][ bank 1: capacity × 384 B ]
 *
 * Publication protocol (single producer, one-or-more readers):
 *   1. Producer fills the INACTIVE bank's records [0 .. n_active).
 *   2. Producer stores seq_bank[inactive] = ++seq and produced_ts_ns.
 *   3. Producer publishes by storing active_bank = inactive with RELEASE order.
 *   4. Reader loads active_bank with ACQUIRE order, reads that bank (which the
 *      producer is no longer writing — it now fills the other one), and uses
 *      seq_bank[active] to detect "new data since last read". The 1 Hz cadence
 *      gives readers a full second to consume ~hundreds of KB (microseconds),
 *      so a bank is never torn under any realistic timing.
 * ------------------------------------------------------------------------- */
struct service_snapshot_shm_header {
    uint8_t  magic[4];              /* off   0  'A''D''S''1'                  */
    uint32_t format_version;        /* off   4  SERVICE_SNAPSHOT_FORMAT_VERSION */
    uint32_t record_version;        /* off   8  SERVICE_SNAPSHOT_RECORD_VERSION */
    uint32_t record_size;           /* off  12  SERVICE_SNAPSHOT_RECORD_SIZE  */
    uint32_t layout_hash;           /* off  16  FNV-1a of the record field table */
    uint32_t capacity;              /* off  20  records per bank             */
    uint32_t n_active;              /* off  24  populated records this publish */
    uint32_t active_bank;           /* off  28  0 or 1 (atomic, published)   */
    uint64_t registry_epoch;        /* off  32  bumps on SIGHUP reload       */
    uint64_t seq_bank0;             /* off  40  monotonic publish seq, bank 0 */
    uint64_t seq_bank1;             /* off  48  monotonic publish seq, bank 1 */
    uint64_t produced_ts_ns;        /* off  56  UNIX epoch ns of last publish */
    uint8_t  reserved[64];          /* off  64..127  future use              */
};

/* -------------------------------------------------------------------------
 * Compile-time invariants — the layout is a wire contract; assert it.
 * ------------------------------------------------------------------------- */
_Static_assert(sizeof(struct service_snapshot_record) == SERVICE_SNAPSHOT_RECORD_SIZE,
               "service_snapshot_record must be exactly 384 bytes");
_Static_assert(sizeof(struct service_snapshot_shm_header) == SERVICE_SNAPSHOT_HEADER_SIZE,
               "service_snapshot_shm_header must be exactly 128 bytes");
_Static_assert(offsetof(struct service_snapshot_record, est_unique_src_ips) == 288,
               "double block must start at offset 288 (no padding before it)");
_Static_assert(offsetof(struct service_snapshot_record, target_ip) == 344,
               "u32 block must start at offset 344 (no padding before it)");
_Static_assert(offsetof(struct service_snapshot_record, profile_name) == 357,
               "profile_name must start at offset 357");

/* -------------------------------------------------------------------------
 * Producer API (implemented in l2fwd_service_snapshot.c — P1)
 * ------------------------------------------------------------------------- */

/**
 * Create + map the shared-memory region, initialise the header (magic,
 * versions, capacity, layout hash), and verify the locally-computed layout
 * hash equals SERVICE_SNAPSHOT_LAYOUT_HASH. Idempotent w.r.t. a stale region
 * from a previous run (it is unlinked and recreated).
 *
 * @return 0 on success; negative on shm_open/ftruncate/mmap failure or a
 *         layout-hash mismatch (a build/config bug — fail loud).
 */
int service_snapshot_producer_init(void);

/**
 * Publish one tick: walk the frozen accumulation bank, fill the inactive shm
 * bank's records (raw counters + sketch estimates + absolute-floor flag),
 * then flip active_bank. Must be called from the 1 Hz tick on the main lcore,
 * after the window has been frozen.
 *
 * @param arr            the per-slot stats array (read-only here).
 * @param now_ns         UNIX epoch ns for produced_ts_ns.
 * @param registry_epoch current registry generation (for reader re-alignment).
 */
void service_snapshot_publish(const struct service_stats_array *arr,
                              uint64_t now_ns,
                              uint64_t registry_epoch);

/** Unmap + unlink the region. Idempotent. */
void service_snapshot_producer_destroy(void);

/** FNV-1a 32-bit hash of the record field table (the value baked into the
 * header). Exposed so a unit test can compare it against the Python mirror. */
uint32_t service_snapshot_compute_layout_hash(void);

#endif /* __L2FWD_SERVICE_SNAPSHOT_H__ */
