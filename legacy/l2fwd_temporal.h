/*
 * ============================================================================
 *  LEGACY MODULE — PRESERVED DURING DUAL-WRITE (Phase 3 — P7..P15)
 * ============================================================================
 *
 *  Status:      ACTIVE-LEGACY
 *  Retirement:  P16 cutover commit
 *  Destination: legacy/  (preserved as forensic reference)
 *
 *  This file is part of the per-IP detection architecture that is being
 *  replaced by the per-service architecture under l2fwd_service_*.{c,h}.
 *  It REMAINS COMPILED and ACTIVE during P7..P15 because:
 *
 *    1. It is the cross-validation reference that proves the new per-service
 *       hot path produces equivalent aggregate counters.
 *    2. It provides the rollback path until the new engine is signed off
 *       at P18.
 *
 *  DO NOT delete or rename this file before P16. The big-bang cutover
 *  prompt (P16) will move it to legacy/ atomically as part of the
 *  deprecation switch.
 *
 *  See docs/architecture_status.md and docs/migration_map.md for the
 *  full classification of every source file in this project.
 * ============================================================================
 */
#ifndef __L2FWD_TEMPORAL_H__
#define __L2FWD_TEMPORAL_H__

#include <stdint.h>
#include <stdbool.h>

/* ============================================================================
 * Layer-2 multi-timescale temporal observability — data structures + API.
 *
 * This module is shadow / observability only. It must never affect the
 * existing 1-second detection state, the 62-column CSV, the policy module,
 * the L3 bridge, or any packet hot-path counter. Every field defined here
 * is updated exclusively from the 1Hz timer on the main lcore, AFTER the
 * 1-second feature extraction and detection pass and BEFORE the per-window
 * counter reset.
 *
 * This header introduces the data layout and the init / reset / state-string
 * helpers only. Bucket folding, ring promotion, baseline updates, scoring,
 * and TEMP line emission are added in subsequent commits without reordering
 * any of the field lists below. Field-order changes invalidate the parser,
 * the ClickHouse insert order, and persisted rows.
 *
 * --------------------------------------------------------------------------
 * Include-order precondition (intentional: NOT self-contained).
 *
 * This header references `struct ewma_state` by value inside
 * `struct l2_temporal_baselines`. We deliberately do NOT include
 * l2fwd_ddos_collector.h here. l2fwd_ddos_collector.h embeds
 * `struct l2_temporal_state` inside `struct dst_ip_stats`, so a back-
 * include here would create a circular reference where include guards
 * skip the collector header on the second visit and leave
 * `struct l2_temporal_state` undefined at the embed site.
 *
 * Consumers must include l2fwd_ddos_collector.h before this header,
 * either directly or transitively. The standard pattern is:
 *
 *   #include "l2fwd_ddos_collector.h"   // defines struct ewma_state and
 *                                       // re-includes this header itself
 *
 * which already provides every type used here (the second `#include
 * "l2fwd_temporal.h"` in the .c file becomes a no-op via the guard).
 *
 * Inside l2fwd_ddos_collector.h, the `#include "l2fwd_temporal.h"`
 * line must appear AFTER the definition of `struct ewma_state` and
 * BEFORE the definition of `struct dst_ip_stats`.
 * ========================================================================== */

/* Bucket geometry. */
#define L2_TEMP_BUCKET_SECONDS  10
#define L2_TEMP_RING_BUCKETS    30

/* TEMP line / ClickHouse schema version. Bump when columns are added,
 * removed, renamed, or reordered. The Python parser keys an allow-list off
 * this value; rows tagged with an unsupported schema_ver are dropped. */
#define L2_TEMP_SCHEMA_VERSION  1

/* Score-formula / weight version. Bump when the score functions or their
 * weights change without a column change, so historical rows can still be
 * compared meaningfully. Independent of L2_TEMP_SCHEMA_VERSION. */
#define L2_TEMP_ROLLUP_VERSION  1

/* Human-readable label, kept for log lines. TEMP rows themselves use the
 * numeric L2_TEMP_SCHEMA_VERSION / L2_TEMP_ROLLUP_VERSION constants above. */
#define L2_TEMP_VERSION         "temporal_v1"

/* ============================================================================
 * Scale index — fixes the 0/1/2 mapping used by every per-scale array in
 * this header (e.g. ratio_pps, z_pps in l2_temporal_result). Used as both
 * an index value and as the array dimension via L2_TEMP_SCALE_COUNT.
 *
 * The order is locked and must match the TEMP-line / ClickHouse-row
 * `window_sec` ordering: 10s comes before 60s comes before 300s.
 * ========================================================================== */
typedef enum {
    L2_TEMP_SCALE_10S   = 0,
    L2_TEMP_SCALE_60S   = 1,
    L2_TEMP_SCALE_300S  = 2,
    L2_TEMP_SCALE_COUNT = 3,
} l2_temp_scale_t;

/* ============================================================================
 * Temporal state classification (5 conservative phases).
 *
 * Anonymous enum + typedef mirrors detection_state_t in
 * l2fwd_detection_engine.h. A tagged `enum l2_temporal_state` would collide
 * with `struct l2_temporal_state` defined below (single tag namespace in C).
 * ========================================================================== */
typedef enum {
    L2_TEMPORAL_WARMUP     = 0,   /* baseline not yet ready for this scale */
    L2_TEMPORAL_NORMAL     = 1,   /* score < L2_TEMP_SCORE_NORMAL_MAX      */
    L2_TEMPORAL_WATCH      = 2,   /* < L2_TEMP_SCORE_WATCH_MAX             */
    L2_TEMPORAL_SUSPICIOUS = 3,   /* < L2_TEMP_SCORE_SUSPICIOUS_MAX        */
    L2_TEMPORAL_STRONG     = 4,   /* >= L2_TEMP_SCORE_SUSPICIOUS_MAX       */
} l2_temporal_state_t;

/* ============================================================================
 * Score thresholds — conservative phase boundaries (locked).
 *
 *   score < L2_TEMP_SCORE_NORMAL_MAX         -> L2_TEMPORAL_NORMAL
 *   score < L2_TEMP_SCORE_WATCH_MAX          -> L2_TEMPORAL_WATCH
 *   score < L2_TEMP_SCORE_SUSPICIOUS_MAX     -> L2_TEMPORAL_SUSPICIOUS
 *   else                                     -> L2_TEMPORAL_STRONG
 *
 * Baseline-not-ready and low-confidence overrides take precedence and
 * force L2_TEMPORAL_WARMUP regardless of score.
 * ========================================================================== */
#define L2_TEMP_SCORE_NORMAL_MAX     0.40
#define L2_TEMP_SCORE_WATCH_MAX      0.65
#define L2_TEMP_SCORE_SUSPICIOUS_MAX 0.85

/* ============================================================================
 * Score-fusion weights — locked. Each row sums to 1.0.
 *
 *   10s : volume + protocol_shift + persistence
 *   60s : volume + protocol_shift + ramp + persistence
 *   300s: volume + protocol_shift + persistence
 *
 * The 10s and 300s scales intentionally do not contribute a ramp term,
 * so the corresponding ramp_score field stays at 0.0 in their export rows.
 * Rebalancing weights without changing columns must bump
 * L2_TEMP_ROLLUP_VERSION (not L2_TEMP_SCHEMA_VERSION).
 * ========================================================================== */
#define L2_TEMP_W10_VOLUME       0.45
#define L2_TEMP_W10_PROTOCOL     0.25
#define L2_TEMP_W10_PERSISTENCE  0.30

#define L2_TEMP_W60_VOLUME       0.35
#define L2_TEMP_W60_PROTOCOL     0.25
#define L2_TEMP_W60_RAMP         0.20
#define L2_TEMP_W60_PERSISTENCE  0.20

#define L2_TEMP_W300_VOLUME      0.45
#define L2_TEMP_W300_PROTOCOL    0.30
#define L2_TEMP_W300_PERSISTENCE 0.25

/* ============================================================================
 * Temporal EWMA half-life-based smoothing factors, one per scale.
 *
 * Approximate half-life (in number of closed windows of that scale):
 *   10s baseline  : ~60 closed windows  ≈ 10  minutes  (alpha = 0.0115)
 *   60s baseline  : ~45 closed windows  ≈ 45  minutes  (alpha = 0.0153)
 *   300s baseline : ~48 closed windows  ≈ 4   hours    (alpha = 0.0143)
 *
 * The 10s baseline learns fastest, the 300s baseline slowest. Each
 * alpha is applied to every ewma_state inside the corresponding scale
 * group of l2_temporal_baselines. Bumping these values without changing
 * any column must bump L2_TEMP_ROLLUP_VERSION (not _SCHEMA_VERSION).
 * ========================================================================== */
#define L2_TEMP_ALPHA_10S    0.0115
#define L2_TEMP_ALPHA_60S    0.0153
#define L2_TEMP_ALPHA_300S   0.0143

/* ============================================================================
 * Per-scale valid_seconds floors — "enough data to trust the score".
 *
 * Below the floor, the temporal phase is forced to L2_TEMPORAL_WARMUP
 * regardless of the computed score, and baselines for that scale are
 * NOT updated. In the current pipeline buckets are only pushed onto the
 * ring at exactly L2_TEMP_BUCKET_SECONDS (= 10), so valid_seconds is
 * always a multiple of 10 and these floors function primarily as a
 * defensive safety net for partial-bucket scenarios that may emerge in
 * future revisions (e.g. forced bucket flush on shutdown).
 * ========================================================================== */
#define L2_TEMP_VALID_10S_MIN    8
#define L2_TEMP_VALID_60S_MIN    45
#define L2_TEMP_VALID_300S_MIN   220

/* ============================================================================
 * Sub-score normalisation constants (locked).
 *
 *   L2_TEMP_VOLUME_RATIO_FULL : avg_/baseline ratio that maps to score 1.0.
 *                               Below 1.0 maps to 0; between 1.0 and FULL
 *                               linearly to [0,1].
 *   L2_TEMP_VOLUME_Z_FULL     : z-score above the baseline mean that maps
 *                               to score 1.0. Negative z maps to 0.
 *   L2_TEMP_PROTO_SHIFT_FULL  : positive ratio shift (current minus
 *                               baseline) that maps to score 1.0.
 *   L2_TEMP_RAMP_FULL         : latest-10s vs earlier-50s ratio that
 *                               maps to score 1.0 (60s scale only).
 *
 * Tuning these without changing TEMP / ClickHouse columns must bump
 * L2_TEMP_ROLLUP_VERSION.
 * ========================================================================== */
#define L2_TEMP_VOLUME_RATIO_FULL   5.0
#define L2_TEMP_VOLUME_Z_FULL       4.0
#define L2_TEMP_PROTO_SHIFT_FULL    0.5
#define L2_TEMP_RAMP_FULL           3.0

/* ============================================================================
 * 10-second accumulator bucket.
 *
 * One instance is the "currently filling" bucket; thirty more live in the
 * ring as completed history. All fields are owned by a single lcore (the
 * main lcore), so no atomics are required.
 *
 * NOTE on sum_*_ratio fields below: udp_flow_ratio, src_ip_ratio, and
 * dst_port_ratio are derived from per-second HyperLogLog outputs that the
 * 1-second collector resets every second. We therefore accumulate them
 * here as plain per-second sums and divide by valid_seconds on bucket
 * close. The resulting window value is a "per-second-averaged ratio"
 * over the window, NOT a true full-window HLL union. A rename + rollup
 * version bump will be required if a true HLL-union ring is ever added.
 * ========================================================================== */
struct l2_temporal_bucket_10s {
    /* 0..L2_TEMP_BUCKET_SECONDS folded 1-second windows. */
    uint8_t  filled_seconds;

    /* Window-aggregated raw counters (sums of per-second values). */
    uint64_t total_pkts;
    uint64_t total_bytes;
    uint64_t tcp_pkts;
    uint64_t tcp_bytes;
    uint64_t udp_pkts;
    uint64_t udp_bytes;
    uint64_t icmp_pkts;
    uint64_t icmp_echo_pkts;
    uint64_t syn_pkts;
    uint64_t synack_pkts;
    uint64_t finack_pkts;
    uint64_t rst_pkts;
    uint64_t ack_data_pkts;

    /* 1-second feature aggregations (volume).
     *   sum_*  : running sum of the per-second feature value; divided by
     *            filled_seconds to derive avg_* on bucket close.
     *   min_*  : minimum per-second value observed in this bucket.
     *   max_*  : maximum per-second value observed in this bucket.
     * Initialised to 0 / DBL_MAX / 0 respectively by l2_temporal_bucket_reset. */
    double sum_pps;
    double min_pps;
    double max_pps;

    double sum_bps;
    double min_bps;
    double max_bps;

    double sum_fps;
    double min_fps;
    double max_fps;

    /* 1-second feature aggregations (HLL-derived ratios — sums only).
     * See note in the struct comment: these are per-second averages over
     * the window, not full-window HLL unions. */
    double sum_udp_flow_ratio;
    double sum_src_ip_ratio;
    double sum_dst_port_ratio;

    /* Existing 1-second detector evidence rolled up across this bucket.
     * Used for ramp / persistence inputs without rerunning detection. */
    double  sum_tier0_global_risk;
    double  max_tier0_global_risk;
    double  max_tier1_tcp_score;
    double  max_tier1_udp_score;
    double  max_tier1_icmp_score;
    double  max_tier1_dist_score;
    double  max_tier1_final_score;

    /* Per-second detection_state tally (mutually exclusive; sum equals
     * filled_seconds). uint8_t is sufficient for a 10-second bucket. */
    uint8_t normal_count;
    uint8_t warmup_count;
    uint8_t suspicious_count;
    uint8_t attack_count;
};

/* ============================================================================
 * Finalised window statistics — the export-ready snapshot for one of the
 * 10s / 60s / 300s scales. Populated when a bucket closes (10s) or every N
 * bucket closes (60s = every 6, 300s = every 30).
 *
 * window_sec disambiguates which scale this stats block represents and is
 * the value that must appear unchanged in the TEMP line / ClickHouse row.
 * ========================================================================== */
struct l2_temporal_window_stats {
    uint16_t window_sec;          /* 10, 60, or 300                        */
    uint32_t valid_seconds;       /* count of folded 1s windows backing it */

    /* Raw counters, summed across the contributing buckets. */
    uint64_t total_pkts;
    uint64_t total_bytes;
    uint64_t tcp_pkts;
    uint64_t tcp_bytes;
    uint64_t udp_pkts;
    uint64_t udp_bytes;
    uint64_t icmp_pkts;
    uint64_t icmp_echo_pkts;
    uint64_t syn_pkts;
    uint64_t synack_pkts;
    uint64_t finack_pkts;
    uint64_t rst_pkts;
    uint64_t ack_data_pkts;

    /* Volume metrics. avg_* = sum_* / valid_seconds; min_* / max_* are
     * the min/max of the per-second values across contributing buckets. */
    double avg_pps, min_pps, max_pps;
    double avg_bps, min_bps, max_bps;
    double avg_fps, min_fps, max_fps;

    /* Protocol share ratios (current window). */
    double tcp_pps_ratio;
    double tcp_bps_ratio;
    double udp_pps_ratio;
    double udp_bps_ratio;
    double icmp_pps_ratio;
    double icmp_echo_ratio;

    /* TCP flag ratios (current window). */
    double tcp_syn_ratio;
    double tcp_synack_ratio;
    double tcp_finack_ratio;
    double tcp_rst_ratio;
    double tcp_ack_data_ratio;

    /* HLL-derived ratios — per-second averages over the window. NOT a true
     * full-window unique-count ratio: the 1-second collector resets HLL
     * sketches every second, so each contributing second's ratio is the
     * per-second value (unique_*_in_that_second / total_in_that_second).
     * The temporal value here is the mean of those per-second ratios.
     * If a future revision adds an HLL-union ring across the window the
     * semantics will change and L2_TEMP_ROLLUP_VERSION must be bumped. */
    double udp_flow_ratio;
    double src_ip_ratio;
    double dst_port_ratio;

    /* Per-second detection_state tallies summed over the contributing
     * buckets. Identity invariant:
     *   normal + warmup + suspicious + attack == valid_seconds. */
    uint32_t normal_count;
    uint32_t warmup_count;
    uint32_t suspicious_count;
    uint32_t attack_count;

    /* Detector evidence carried through unchanged from existing 1s scores. */
    double avg_tier0_global_risk;
    double max_tier0_global_risk;
    double max_tier1_tcp_score;
    double max_tier1_udp_score;
    double max_tier1_icmp_score;
    double max_tier1_dist_score;
    double max_tier1_final_score;
};

/* ============================================================================
 * Per-IP EWMA baselines, one ewma_state per (feature × scale).
 *
 * Reuses struct ewma_state from l2fwd_ddos_collector.h to inherit the same
 * variance-ceiling logic that the existing 1-second tiers use. The alpha
 * for each member is configured per-scale at init time (10s / 60s / 300s).
 *
 * Both PPS-share and BPS-share baselines are tracked so per-byte protocol
 * shifts (e.g. an amplification flood) can be detected even when packet
 * shares look normal. The udp_flow_ratio / src_ip_ratio / dst_port_ratio /
 * icmp_echo_ratio baselines are tracked too — bear in mind the values
 * being smoothed are per-second-averaged ratios (see note above), so the
 * baseline EWMA is over those per-second-averaged values, not over a
 * true unique-count series.
 * ========================================================================== */
struct l2_temporal_baselines {
    /* 10-second baselines. */
    struct ewma_state pps_10s, bps_10s, fps_10s;
    struct ewma_state tcp_pps_ratio_10s,  tcp_bps_ratio_10s;
    struct ewma_state udp_pps_ratio_10s,  udp_bps_ratio_10s,  udp_flow_ratio_10s;
    struct ewma_state icmp_pps_ratio_10s, icmp_echo_ratio_10s;
    struct ewma_state tcp_syn_ratio_10s, tcp_synack_ratio_10s, tcp_finack_ratio_10s,
                      tcp_rst_ratio_10s, tcp_ack_data_ratio_10s;
    struct ewma_state src_ip_ratio_10s, dst_port_ratio_10s;

    /* 60-second baselines. */
    struct ewma_state pps_60s, bps_60s, fps_60s;
    struct ewma_state tcp_pps_ratio_60s,  tcp_bps_ratio_60s;
    struct ewma_state udp_pps_ratio_60s,  udp_bps_ratio_60s,  udp_flow_ratio_60s;
    struct ewma_state icmp_pps_ratio_60s, icmp_echo_ratio_60s;
    struct ewma_state tcp_syn_ratio_60s, tcp_synack_ratio_60s, tcp_finack_ratio_60s,
                      tcp_rst_ratio_60s, tcp_ack_data_ratio_60s;
    struct ewma_state src_ip_ratio_60s, dst_port_ratio_60s;

    /* 300-second baselines. */
    struct ewma_state pps_300s, bps_300s, fps_300s;
    struct ewma_state tcp_pps_ratio_300s,  tcp_bps_ratio_300s;
    struct ewma_state udp_pps_ratio_300s,  udp_bps_ratio_300s,  udp_flow_ratio_300s;
    struct ewma_state icmp_pps_ratio_300s, icmp_echo_ratio_300s;
    struct ewma_state tcp_syn_ratio_300s, tcp_synack_ratio_300s, tcp_finack_ratio_300s,
                      tcp_rst_ratio_300s, tcp_ack_data_ratio_300s;
    struct ewma_state src_ip_ratio_300s, dst_port_ratio_300s;
};

/* ============================================================================
 * Temporal evaluation result — compact per-scale arrays only.
 *
 * Updated at each bucket close. The struct is intentionally narrow: it
 * holds *score outputs* (per-scale), classification, and the volumetric
 * comparison values used by the dashboard, but it does NOT keep three
 * full struct l2_temporal_window_stats copies. The window_stats type is
 * still defined and used at export time as a stack-local / scratch
 * object: bucket close populates one, derives the values stored here,
 * formats the TEMP line, and discards it. Keeping three copies in the
 * per-IP state would cost ~1.1 KB per IP for data that is otherwise
 * regenerable on demand.
 *
 * Every per-scale array is indexed by l2_temp_scale_t (0=10s, 1=60s,
 * 2=300s). Index order is locked and matches the TEMP / ClickHouse
 * column order so reads can iterate scales without translation.
 *
 *   evaluated[s]            : true once enough closed buckets exist for s
 *   baseline_ready[s]       : per-scale EWMA warmup completion flag
 *   score[s]                : fused score for scale s
 *   volume_score[s]         : sub-score (volumetric)
 *   protocol_shift_score[s] : sub-score (protocol mix shift)
 *   persistence_score[s]    : sub-score (suspicious + attack seconds /
 *                             valid_seconds)
 *   ramp_score[s]           : sub-score; computed only for s==60s per
 *                             the locked weight matrix, 0.0 elsewhere.
 *                             Depends on the contributing 10s buckets
 *                             being supplied in chronological
 *                             (oldest-to-newest) order — see
 *                             collect_recent_buckets_chronological() in
 *                             l2fwd_temporal.c. Do not change that
 *                             ordering without updating ramp_score.
 *   ratio_<m>[s]            : last_avg_<m> / (baseline.mean + ε)
 *   z_<m>[s]                : (last_avg_<m> - mean) / sqrt(var + ε)
 *   state[s]                : phase classification for scale s
 * ========================================================================== */
struct l2_temporal_result {
    bool   evaluated[L2_TEMP_SCALE_COUNT];
    bool   baseline_ready[L2_TEMP_SCALE_COUNT];

    double score[L2_TEMP_SCALE_COUNT];
    double volume_score[L2_TEMP_SCALE_COUNT];
    double protocol_shift_score[L2_TEMP_SCALE_COUNT];
    double persistence_score[L2_TEMP_SCALE_COUNT];
    double ramp_score[L2_TEMP_SCALE_COUNT];

    double ratio_pps[L2_TEMP_SCALE_COUNT];
    double ratio_bps[L2_TEMP_SCALE_COUNT];
    double ratio_fps[L2_TEMP_SCALE_COUNT];

    double z_pps[L2_TEMP_SCALE_COUNT];
    double z_bps[L2_TEMP_SCALE_COUNT];
    double z_fps[L2_TEMP_SCALE_COUNT];

    l2_temporal_state_t state[L2_TEMP_SCALE_COUNT];
};

/* ============================================================================
 * Top-level per-IP temporal state.
 *
 * Embedded by value in struct dst_ip_stats in a later commit. Until that
 * embedding lands, this struct exists only as a typed scratchpad for unit
 * coverage and does not affect the runtime in any way.
 * ========================================================================== */
struct l2_temporal_state {
    struct l2_temporal_bucket_10s current_10s;
    struct l2_temporal_bucket_10s ring_10s[L2_TEMP_RING_BUCKETS];

    /* Ring discipline:
     *   ring_index  - next slot to overwrite (0..L2_TEMP_RING_BUCKETS-1).
     *   ring_filled - number of valid completed buckets, capped at
     *                 L2_TEMP_RING_BUCKETS once the ring saturates. */
    uint8_t  ring_index;
    uint8_t  ring_filled;

    /* Number of 1-second windows folded into current_10s so far (0..10).
     * Distinct from current_10s.filled_seconds purely so the public-facing
     * counter survives the in-place reset of current_10s if the rotation
     * implementation later changes. */
    uint32_t seconds_into_current_10s;

    struct l2_temporal_baselines baselines;
    struct l2_temporal_result    last_result;
};

/* ============================================================================
 * Forward declarations of types defined in l2fwd_ddos_collector.h /
 * l2fwd_detection_engine.h.
 *
 * Used only as pointer parameters in l2_temporal_update_1s() below, so a
 * forward declaration is sufficient and lets us avoid pulling in
 * l2fwd_detection_engine.h here (which would re-trigger the include
 * cycle that the precondition note above is designed to prevent).
 * ========================================================================== */
struct dst_ip_stats;
struct tier0_features;
struct tier1_tcp_features;
struct tier1_udp_features;
struct tier1_icmp_features;
struct tier1_dist_features;
struct detection_result;

/* ============================================================================
 * Public API — initialisation / reset / state stringification + the
 * once-per-1s update hook (still shadow / internal: does not export TEMP
 * records and does not feed the existing 1-second detector).
 *
 * The TEMP line emitter and baseline / score updates remain unwritten;
 * they are added in subsequent commits so the runtime wiring lands as a
 * deliberate, reviewable diff.
 * ========================================================================== */

/**
 * Reset a 10-second bucket to its empty initial state.
 *
 * Zero-fills all counters and seeds min_pps / min_bps / min_fps to a
 * sentinel "no observation yet" value (DBL_MAX) so the first folded
 * second always wins the min comparison. Safe to call on a NULL pointer.
 */
void l2_temporal_bucket_reset(struct l2_temporal_bucket_10s *b);

/**
 * Initialise a per-IP temporal state to a clean shadow/observability
 * baseline. Resets the current bucket and every ring slot, zeroes the
 * baselines (alphas are configured by a later commit), zeroes every
 * comparison array in last_result, and sets last_result.state to
 * L2_TEMPORAL_WARMUP. Safe to call on a NULL pointer.
 *
 * EWMA alphas are intentionally left at zero here. They will be set in
 * the same commit that wires the temporal scoring path into the runtime,
 * so the alpha policy lives next to the code that uses it.
 */
void l2_temporal_init(struct l2_temporal_state *st);

/**
 * Map an l2_temporal_state_t to a stable, comma-free string suitable for
 * inclusion in CSV / TEMP line output. Returns "UNKNOWN" for out-of-range
 * values to keep downstream parsers from desynchronising.
 */
const char *l2_temporal_state_str(l2_temporal_state_t state);

/* ============================================================================
 * TEMP record schema — locked at L2_TEMP_SCHEMA_VERSION = 1, 79 fields.
 *
 * Each TEMP line is one record for one (dst_ip × window_sec) pair, sent
 * over the dedicated temporal Unix-domain socket only. Lines start with
 * the literal token "TEMP" so the parser can dispatch by record-type
 * before any field-count check.
 *
 *    1  TEMP                              record-type token
 *    2  schema_ver                        L2_TEMP_SCHEMA_VERSION
 *    3  rollup_ver                        L2_TEMP_ROLLUP_VERSION
 *    4  timestamp_ms                      end of just-closed second
 *    5  port                              DPDK port id
 *    6  dst_ip                            dotted-quad string
 *    7  window_sec                        10 / 60 / 300
 *    8  bucket_epoch_ms                   start of window: ts - vs*1000
 *    9  valid_seconds                     contributing 1s slots
 *   10  baseline_ready                    0 / 1
 *   11  temporal_state                    WARMUP|NORMAL|WATCH|SUSPICIOUS|STRONG
 *
 *   Volume (12-29): per metric (pps, bps, fps) -- avg, em, ratio, z, min, max
 *   Protocol-share pairs (30-43): tcp_pps/bps, udp_pps/bps/flow, icmp_pps/echo
 *                                  each as (current, baseline)
 *   TCP-flag pairs (44-53): syn/synack/finack/rst/ack_data each as (cur, base)
 *   Distribution pairs (54-57): src_ip_ratio, dst_port_ratio (cur, base)
 *   Raw counters (58-70): total/tcp/udp/icmp pkts+bytes, icmp_echo,
 *                          syn/synack/finack/rst/ack_data pkts
 *   Per-state seconds (71-74): normal, warmup, suspicious, attack
 *   Scores (75-79): volume, protocol_shift, persistence, ramp,
 *                    temporal_score (fused, per-scale)
 *
 *   Sum: 11 + 18 + 14 + 10 + 4 + 13 + 4 + 5 = 79.
 *
 * Discipline (locked): any add / remove / rename / reorder of a column
 * MUST be paired in the same commit with parser updates, ClickHouse
 * insert-order updates, and a bump of L2_TEMP_SCHEMA_VERSION. Score-
 * formula or weight changes that leave the column set untouched bump
 * L2_TEMP_ROLLUP_VERSION instead.
 * ========================================================================== */

/**
 * Fold the just-completed 1-second window into the per-IP temporal state,
 * score every scale that just finalised, and best-effort emit one TEMP
 * line per finalised scale on the dedicated temporal socket
 * (`temporal_sock_fd`). Never writes to the IP socket.
 *
 * Called exactly once per active dst_ip per 1-second tick from the main-
 * lcore timer in ddos_log_and_reset_stats(), AFTER the existing detector
 * pass populates `det_result` and BEFORE the per-IP counters are reset.
 *
 * On every call:
 *   - the 1-second raw counters from `stats` are added into the current
 *     in-progress 10s bucket (total_pkts, total_bytes, tcp/udp/icmp,
 *     icmp_echo, syn / synack / finack / rst / ack_data);
 *   - the 1s volume features `t0->{pps,bps,fps}` are aggregated as
 *     sum / min / max in the current bucket;
 *   - the per-second HLL-derived ratios `t1_udp->udp_flow_ratio`,
 *     `t1_dist->src_ip_ratio`, `t1_dist->dst_port_ratio` are accumulated
 *     as plain sums (per-second-averaged at finalize time);
 *   - the detector evidence is rolled up: sum + max of tier0_global_risk,
 *     max of every tier1 score, and a per-state count from
 *     `det_result->state` into normal / warmup / suspicious / attack;
 *   - `filled_seconds` and `seconds_into_current_10s` are incremented.
 *
 * When the in-progress bucket reaches L2_TEMP_BUCKET_SECONDS (= 10) it is
 * pushed onto the ring, the in-progress bucket is reset, and the function
 * derives a stack-local `struct l2_temporal_window_stats` for the 10s
 * scale, plus 60s and 300s scales when `ring_filled` is at least 6 and 30
 * respectively. Empty buckets are NEVER inserted into the ring during
 * traffic gaps. The window_stats objects are NOT stored in `last_result`;
 * they live only on the stack long enough to (a) feed the scoring step
 * (state / per-scale scores get written into `last_result`), (b) optionally
 * update baselines under the locked anti-poisoning gate, and (c) emit
 * one 79-field TEMP line on `temporal_sock_fd`.
 *
 * TEMP export rules:
 *   - one TEMP line is emitted per finalised scale in the order
 *     10s -> 60s -> 300s, as those scales have data;
 *   - emission uses the dedicated temporal Unix-domain socket
 *     (`temporal_sock_fd`); the existing 62-column IP socket is never
 *     touched and the IP CSV content is byte-for-byte unchanged;
 *   - `temporal_sock_fd < 0` skips emission silently; send() failures
 *     are swallowed and never affect the IP record stream.
 *
 * Returns:
 *   true  - a 10-second bucket just closed on this call.
 *   false - the in-progress bucket has not yet reached 10 seconds, or any
 *           pointer argument was NULL.
 *
 * Behavioural restrictions (still preserved):
 *   - does not modify `stats`, the existing 1-second detector, or any
 *     non-temporal field of any other module;
 *   - is not called from the packet hot path;
 *   - never writes anything except (i) per-IP temporal state, (ii) TEMP
 *     lines on `temporal_sock_fd`. The IP CSV stream is untouched.
 *
 * `t1_tcp` and `t1_icmp` remain in the signature for forward
 * compatibility with later instrumentation but are not consumed by this
 * revision (TCP-flag and ICMP ratios are derived from raw counters at
 * window finalisation, not from per-second ratios).
 */
bool l2_temporal_update_1s(struct l2_temporal_state *st,
                           const struct dst_ip_stats *stats,
                           uint16_t port,
                           const char *dst_ip_str,
                           const struct tier0_features *t0,
                           const struct tier1_tcp_features *t1_tcp,
                           const struct tier1_udp_features *t1_udp,
                           const struct tier1_icmp_features *t1_icmp,
                           const struct tier1_dist_features *t1_dist,
                           const struct detection_result *det_result,
                           uint64_t timestamp_ms,
                           int temporal_sock_fd);

#endif /* __L2FWD_TEMPORAL_H__ */