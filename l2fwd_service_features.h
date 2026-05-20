#ifndef __L2FWD_SERVICE_FEATURES_H__
#define __L2FWD_SERVICE_FEATURES_H__

/**
 * @file   l2fwd_service_features.h
 * @brief  Per-service feature extraction + sketch math — P8.
 *
 * P7 wired raw counters into per-service slots. P8 builds the "thinking
 * layer" that converts those raw counters into ratios + EWMA-tracked
 * baselines that P9's detection scorer will consume.
 *
 * The module owns four classes of primitive:
 *
 *   1. HyperLogLog (HLL) — distinct-count over a stream of 32-bit hashes.
 *      Used for unique_src_ips, unique_flows, etc.
 *   2. Count-Min sketch (CM) — heavy-hitter + entropy estimator over a
 *      stream of keys. Used for src_port concentration and /24
 *      distribution metrics.
 *   3. EWMA — incremental mean+variance tracker, Welford's online form
 *      for the exponentially-weighted case.
 *   4. Burst window — rolling 3-second sample buffer + z-score.
 *
 * Plus the per-slot orchestrator service_features_compute_one() that
 * weaves all of these together once per 1Hz tick.
 *
 * P9 will add the scoring (Tier-0 CUSUM, Tier-1 sigmoid fusion). P10
 * will define the binary protocol that emits these features to the
 * Python collector.
 */

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

/* Forward declarations — concrete types are in the consumer modules. */
struct service_stats;
struct service_stats_array;
struct service_hll;
struct service_cm_src_port;
struct service_cm_src_24;
struct service_burst_window;
struct service_ewma_state;
struct service_temporal_state;

/* -------------------------------------------------------------------------
 * 1.1 HyperLogLog primitives
 *
 * Register layout: 1024 single-byte registers (see l2fwd_service_stats.h).
 * Hashed key: 32-bit; low 10 bits address a register, the remaining 22
 * bits feed the "leading 1-bit position" estimator. The 32-bit hash size
 * caps the engine's recoverable cardinality at ~10^7 per slot per
 * window before linear-counting bias dominates — well above any traffic
 * we expect.
 * ------------------------------------------------------------------------- */

/**
 * Hot-path: insert one 32-bit hash. O(1), branch-light.
 */
void service_hll_insert(struct service_hll *hll, uint32_t hash);

/**
 * Per-tick: estimate cardinality. Walks all 1024 registers and applies
 * the standard HLL formula with small-range correction. Not called per
 * packet.
 */
double service_hll_estimate(const struct service_hll *hll);

/**
 * Zero the register array. Per-window reset semantics decided by the
 * caller; the default at P8 is to PRESERVE across windows.
 */
void service_hll_reset(struct service_hll *hll);

/* -------------------------------------------------------------------------
 * 1.2 Count-Min sketch primitives
 *
 * Width × depth: 256×4 for src_port (16-bit key, 4 KB sketch),
 *                512×4 for src_/24 (24-bit key, 8 KB sketch).
 * Heavy-hitter (top_port / top_net24 + top_count) is tracked
 * incrementally on every insert by taking the row-min as the per-key
 * count estimate.
 * ------------------------------------------------------------------------- */

void service_cm_src_port_insert(struct service_cm_src_port *cm, uint16_t port);
void service_cm_src_24_insert  (struct service_cm_src_24   *cm, uint32_t src_ip);

/** Top-1 share = top_count / total. Returns 0 if total == 0. */
double service_cm_top1_share(uint64_t top_count, uint64_t total);

/**
 * Shannon entropy across the /24 sketch's row-0 column counts.
 * Returned in bits (log base 2). A uniform distribution over k buckets
 * gives entropy ~ log2(k); a single hot bucket gives entropy ~ 0.
 */
double service_cm_src_24_entropy(const struct service_cm_src_24 *cm);

void service_cm_src_port_reset(struct service_cm_src_port *cm);
void service_cm_src_24_reset  (struct service_cm_src_24   *cm);

/* -------------------------------------------------------------------------
 * 1.3 EWMA — incremental mean + variance tracker
 *
 * The update is Welford's online algorithm adapted for the EWMA case:
 *
 *   diff           = x - mean_old
 *   mean_new       = mean_old + α * diff
 *   variance_new   = (1 - α) * (variance_old + α * diff²)
 *
 * On first observation (state->initialized == false), seeds mean=x,
 * variance=0, initialized=true. sample_count always increments.
 * ------------------------------------------------------------------------- */

void   service_ewma_update (struct service_ewma_state *state, double x,
                            double alpha, double variance_ceiling_factor);
double service_ewma_z_score(const struct service_ewma_state *state, double x);

/* -------------------------------------------------------------------------
 * 1.4 Burst window — rolling 3-sample buffer with z-score
 *
 * Push semantics:
 *   - samples[0..filled-1] hold the most recent up-to-3 1-second values
 *   - filled <  3: append at samples[filled], increment filled
 *   - filled == 3: shift left, place new sample at samples[2]
 *   - After insertion, mean and stddev are recomputed (Bessel-corrected
 *     when filled >= 2). z_last = (sample - mean) / stddev, or 0.0 when
 *     filled < 2 or stddev < ε.
 * ------------------------------------------------------------------------- */

void service_burst_window_push (struct service_burst_window *bw, double sample);
void service_burst_window_reset(struct service_burst_window *bw);

/* -------------------------------------------------------------------------
 * 1.5 Welford-style mean + sample stddev from running sums
 *
 *   mean   = sum / n
 *   stddev = sqrt((sum_sq - sum² / n) / (n - 1))  [Bessel-corrected]
 *
 * Returns mean=0, stddev=0 for n=0. Returns mean only and stddev=0 for
 * n=1. Used for TTL stddev and packet-size coefficient of variation.
 * ------------------------------------------------------------------------- */
void service_compute_mean_stddev(uint64_t sum,
                                  uint64_t sum_sq,
                                  uint64_t n,
                                  double *out_mean,
                                  double *out_stddev);

/* -------------------------------------------------------------------------
 * 1.6 Per-slot feature extraction
 *
 * Walks one slot's raw 1-second counters + sketches and refreshes:
 *   - common_ewma.*           (pps, bps, fps, burst_*, ttl_stddev,
 *                              src_ip_ratio, src_24_top1_share,
 *                              src_24_entropy, off_proto_pkts_ratio,
 *                              other_proto_ratio, dst_port_ratio)
 *   - proto.{tcp/udp/icmp}.ewma  (proto-specific ratios)
 *   - common.bw_{pps,bps,fps}    (burst-window push)
 *
 * MUST be called BEFORE service_stats_reset_window_all() — the raw
 * counters disappear after reset. Does NOT touch detection_state or
 * temporal_state.
 * ------------------------------------------------------------------------- */
void service_features_compute_one(struct service_stats *slot);
void service_features_compute_all(struct service_stats_array *arr);

/* -------------------------------------------------------------------------
 * 1.7 Temporal ring-buffer push + window recompute
 *
 * One sample per slot per tick. The push wraps the head modulo
 * SERVICE_TEMPORAL_MAX_SAMPLES (300), caps sample_count at that bound,
 * always increments total_samples_seen, and then recomputes the three
 * derived window aggregates by walking backward from the head over each
 * window's size_seconds samples.
 * ------------------------------------------------------------------------- */
void service_temporal_push_sample(struct service_temporal_state *tmp,
                                   uint64_t now_ns,
                                   uint64_t pkts,
                                   uint64_t bytes,
                                   uint64_t flows,
                                   uint8_t  phase);

void service_temporal_recompute_windows(struct service_temporal_state *tmp);

/* -------------------------------------------------------------------------
 * 1.8 Convenience HLL-cardinality accessors
 * ------------------------------------------------------------------------- */
double service_features_unique_src_ips(const struct service_stats *slot);
double service_features_unique_flows  (const struct service_stats *slot);

#endif /* __L2FWD_SERVICE_FEATURES_H__ */
