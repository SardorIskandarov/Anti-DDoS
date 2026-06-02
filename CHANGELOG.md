# Changelog 

## v3.1.0 — Tier-1.5 L3 amplification & carpet-bombing detection (2026-05-12)

Added 3 EWMA-tracked features to the Tier-1.5 L3 channel via
count-min-sketch infrastructure:

  - src_port_top1_share: top-1 source-port count / total L4 pkts
    (detects UDP amplification — the #1 attack class in 2025)
  - src_24_top1_share: top-1 /24-prefix count / total pkts
    (detects single-network attacker concentration)
  - src_24_entropy: Shannon entropy over /24 heavy hitters
    (detects carpet bombing, distinguishes scattered botnets
     from single-source floods)

Architecture:
  - Count-min sketch (4 rows × 16/32 buckets) per dst_ip per
    sketch; ~135 KB total memory across ~150 protected IPs.
  - Top-K=16 heavy-hitter array maintained on the fast path.
  - 4 hashes via multiplicative hashing with distinct primes.
  - All 3 features use EWMA + norm_dist, contribute to
    compute_tier1_l3_score via the existing weight-application
    block.
  - Short-circuit guard extended to all 6 L3 weights. Detection
    state byte-identical to pre-v3.1 baseline (verified).

Schema impact:
  - IP CSV: 88 → 94 columns (+3 raw + 3 EWMA)
  - traffic_stats: +6 columns via additive ALTER TABLE
  - dst_ip_temporal_stats: unchanged
  - 11 manually-tuned profiles: unchanged
  - Dashboard: +3 charts in existing L3 section

Deployment: C binary + Python parser + ClickHouse migration
deploy as one atomic unit. Rollback together to 88-column path.

## v3.0.2 — Pre-position L3 sigmoid coefficients on manual profiles (2026-05-12)

Latent landmine fix: the 11 manually-tuned profiles in
l2fwd_l2_profile.c had sigmoid_k_l3 = 0.0 and sigmoid_d0_l3 = 0.0
(designated-init defaults). The short-circuit in
compute_tier1_l3_score hid this from view in shadow mode (all
L3 weights at 0.0 → early return). But the moment any L3 weight
on a manually-tuned profile became non-zero in a future
activation, sigmoid_score(d, 0, 0) would have returned 0.500
constant, flipping that IP into SUSPICIOUS every window.

Fix: added .sigmoid_k_l3 = 0.90 and .sigmoid_d0_l3 = 1.40
(matching l2_profile_default) to all 11 manual profiles.
Runtime behavior unchanged (short-circuit still fires); the
change pre-positions math so that future L3 weight activation
on any IP produces sensible scores.

No detection / parser / DB / dashboard changes.

## v3.0 — Tier-1.5 L3 channel: spoofing / fragment / exotic-protocol detection (2026-05-12)

Added 3 new behavioral features in a new parallel decision channel
(Tier-1.5 L3), runnable alongside Tier-1 TCP/UDP/ICMP/DIST:

EWMA-tracked (1):
  - ttl_stddev: standard deviation of received TTL values
    (source-spoofing indicator)

Threshold-based (2):
  - ip_frag_ratio: fraction of fragmented IP packets
    (fragment-flood indicator)
  - other_proto_ratio: fraction of non-TCP/UDP/ICMP packets
    (GRE/ESP/exotic protocol indicator)

Architecture:
  - L3 features form a NEW PARALLEL channel, NOT folded into
    existing Tier-1 family fusion.
  - tier1_l3_score is computed via independent sigmoid (k_l3, d0_l3).
  - Final decision uses attack_evidence = max(tier1_final_score,
    tier1_l3_score), so either channel can confirm an attack.
  - All w_feat_* weights default 0.0. Detection state byte-identical
    to pre-v3 baseline (verified).

Threshold features (ip_frag, other_proto) use:
  signal = clamp01((value - noise_floor) / (saturation - noise_floor))
instead of EWMA deviation, because organic baselines are ~0.0 on
most hosts and EWMA produces unreliable signals near zero.

Schema impact:
  - IP CSV: 82 → 88 columns (+3 raw + 3 derived)
  - traffic_stats: +6 columns via additive ALTER TABLE
  - dst_ip_temporal_stats: unchanged
  - 11 manually-tuned profiles: unchanged

Deferred to v3.1:
  - src_port_top1_share (UDP amplification)
  - src_24_top1_share, src_24_entropy (carpet bombing)
  These require count-min sketch infrastructure and ship separately.

Deployment: C binary + Python parser + ClickHouse migration deploy
as one atomic unit. Rollback the binary and Python parser together.

## v2 — Tier-1 behavioral feature expansion (date 2026-05-07)

Added 10 new behavioral features to the Layer-2 detection engine:

TCP (8 features):
  - empty_ack_ratio: ACK-only packets with no payload
    (state-exhaustion signature)
  - zero_window_ratio: TCP receive window == 0
  - small_window_ratio: 0 < TCP receive window < 1024
  - new_flow_ratio: SYN-flagged unique flows / all unique flows
  - syn_fin_ratio: connection-open vs connection-close balance
    (Laplace +1, capped at 50.0)
  - syn_to_synack_ratio: TCP handshake asymmetry
    (Laplace +1, capped at 50.0)
  - tcp_pkt_size_cov: coefficient of variation of TCP packet sizes
  - tcp_mean_pkt_size: mean TCP packet size (bytes)

UDP (2 features):
  - udp_pkt_size_cov: coefficient of variation of UDP packet sizes
  - udp_mean_pkt_size: mean UDP packet size (bytes;
    amplification signature)

All new features default to weight 0.0 in profiles. They are
computed and logged but do NOT affect detection state until
explicitly enabled per-IP via w_feat_* profile fields. The 11
existing manually-tuned profiles are unchanged in behavior.

Schema impact:
  - IP CSV: 62 → 82 columns (+10 raw, +10 EWMA)
  - traffic_stats ClickHouse table: +20 columns via additive
    ALTER TABLE ADD COLUMN IF NOT EXISTS
  - dst_ip_temporal_stats: unchanged in this release

Calibration coupling: when activating a new feature weight for an
IP, sigmoid_d0 should be re-tuned for that profile. See
l2fwd_l2_profile.h block comment for guidance.

Deployment: C binary, Python parser, and ClickHouse migration
must deploy as one atomic unit (Python parser is strict on
column count). Rollback the binary and the Python parser
together.
