#ifndef __L2FWD_SERVICE_FEATURES_H__
#define __L2FWD_SERVICE_FEATURES_H__

/**
 * @file   l2fwd_service_features.h
 * @brief  Per-service probabilistic-sketch primitives (HLL + Count-Min).
 *
 * POST-CUTOVER SCOPE: the engine no longer derives features or computes the
 * detection verdict in C — that is the Python detection brain's job
 * (ddos_monitor/detection), fed by the raw-telemetry snapshot. What remains
 * here are the per-packet sketch primitives the data plane still needs:
 *
 *   1. HyperLogLog (HLL) — distinct-count over a stream of 32-bit hashes
 *      (unique source IPs, unique flows).
 *   2. Count-Min sketch (CM) — heavy-hitter + entropy over a stream of keys
 *      (src-port concentration, /24 distribution).
 *
 * The hot path INSERTS into these per packet; the snapshot producer reads the
 * ESTIMATES once per 1 Hz tick and ships the scalars to Python. The former
 * EWMA / burst / Welford / per-slot feature orchestrator / temporal push live
 * on as the frozen parity reference in legacy/reference/ — see P5.
 */

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

/* Forward declarations — concrete types are in l2fwd_service_stats.h. */
struct service_hll;
struct service_cm_src_port;
struct service_cm_src_24;

/* -------------------------------------------------------------------------
 * HyperLogLog primitives
 *
 * Register layout: 1024 single-byte registers. Hashed key is 32-bit; the low
 * 10 bits address a register, the remaining 22 bits feed the leading-1-bit
 * estimator.
 * ------------------------------------------------------------------------- */

/** Hot-path: insert one 32-bit hash. O(1), branch-light. */
void service_hll_insert(struct service_hll *hll, uint32_t hash);

/** Per-tick: estimate cardinality (standard HLL + small-range correction). */
double service_hll_estimate(const struct service_hll *hll);

/** Zero the register array (sketches PRESERVE across windows by default). */
void service_hll_reset(struct service_hll *hll);

/* -------------------------------------------------------------------------
 * Count-Min sketch primitives
 *
 * Width × depth: 256×4 for src_port, 512×4 for src_/24. The heavy-hitter
 * (top_* + top_count) is tracked incrementally via the row-min estimate.
 * ------------------------------------------------------------------------- */

void service_cm_src_port_insert(struct service_cm_src_port *cm, uint16_t port);
void service_cm_src_24_insert  (struct service_cm_src_24   *cm, uint32_t src_ip);

/** Top-1 share = top_count / total. Returns 0 if total == 0. */
double service_cm_top1_share(uint64_t top_count, uint64_t total);

/** Shannon entropy (bits) across the /24 sketch's row-0 column counts. */
double service_cm_src_24_entropy(const struct service_cm_src_24 *cm);

void service_cm_src_port_reset(struct service_cm_src_port *cm);
void service_cm_src_24_reset  (struct service_cm_src_24   *cm);

#endif /* __L2FWD_SERVICE_FEATURES_H__ */
