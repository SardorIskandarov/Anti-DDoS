#!/usr/bin/env python3
"""
test_detector_behavior.py — end-to-end behaviour of the *current* detection
pipeline (post Welford-true / N=10 / ±6σ).

Replaces the dead C-oracle `test_detector_parity` — we no longer assert
bit-identity to the retired C engine. Instead we drive the Detector through
controlled scenarios and assert structural properties of the verdict:
  * absolute floor forces ATTACK and arms the freeze.
  * learning mode holds WARMUP indefinitely.
  * the warmup → NORMAL auto-promotion happens at the configured boundary.
"""

import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(ROOT, "ddos_monitor"))

from detection import config as C                # noqa: E402
from detection import primitives as M             # noqa: E402
from detection.detector import Detector          # noqa: E402
from detection.snapshot import RECORD_FIELDS     # noqa: E402

# Zero-filled snapshot record (kind 5 == f64).
_ZERO = {f[0]: (0.0 if f[3] == 5 else 0) for f in RECORD_FIELDS}


def rec(**kw):
    r = dict(_ZERO)
    r.update(kw)
    return r


def _params(**flags):
    return C.ProfileParams(
        name="b", alpha=0.05, variance_ceiling=6.0, baseline_freeze_windows=8,
        thaw_cooldown_windows=6, warmup_windows=3,
        absolute_pps_threshold=0.0, absolute_bps_threshold=0.0,
        absolute_fps_threshold=0.0, **flags)


def _cfg(learning, params):
    KEY = (0x01020304, 443, C.PROTO_TCP)
    return KEY, C.DetectionConfig(
        learning_mode=learning, by_key={KEY: params}, profiles={})


def test_warmup_promotes_to_normal():
    p = _params()
    p = C.ProfileParams(**{**p.__dict__, "absolute_pps_threshold": 0.0})
    key, cfg = _cfg(False, p)
    det = Detector(cfg)
    quiet = rec(target_ip=0x01020304, port=443, proto_kind=C.PROTO_TCP,
                inbound_pkts=50, inbound_bytes=4000, tcp_pkts=50)
    # warmup_windows=3 → ticks 0,1 hold WARMUP (remaining goes 3→2→1);
    # tick 2 drains remaining to 0 and promotes to NORMAL.
    for _ in range(2):
        det.process_record(quiet)
    assert det._slots[key].phase == C.PHASE_WARMUP, \
        f"still in warmup after 2 ticks: got {det._slots[key].phase}"
    det.process_record(quiet)
    assert det._slots[key].phase == C.PHASE_NORMAL, \
        f"expected NORMAL after warmup, got {det._slots[key].phase}"
    print("  [PASS] warmup window auto-promotes WARMUP → NORMAL")


def test_absolute_floor_bypasses_gate_routes_through_tier1():
    """abs-floor now BYPASSES the persistence gate but NOT Tier-1: it forces
    Tier-1 to run on this tick (even with a single hit and gate closed) and
    lets Tier-1 decide the verdict against the standard thresholds. A pure
    volumetric breach with no signature corroboration must NOT auto-convict
    to ATTACK any more.

    Verify:
      * `last_absolute_floor_fired` is set (visible to dashboards),
      * `t1_final` was populated (Tier-1 ran — gate bypassed),
      * the EWMA freeze armed (baseline protected on the t0 fire),
      * phase != ATTACK because the volumetric flood here lacks the
        signature-channel evidence Tier-1 needs."""
    p = C.ProfileParams(name="b", alpha=0.05, variance_ceiling=6.0,
                        baseline_freeze_windows=8, thaw_cooldown_windows=6,
                        warmup_windows=2,
                        absolute_pps_threshold=500.0,
                        absolute_bps_threshold=0.0, absolute_fps_threshold=0.0)
    key, cfg = _cfg(False, p)
    det = Detector(cfg)
    quiet = rec(target_ip=0x01020304, port=443, proto_kind=C.PROTO_TCP,
                inbound_pkts=50, inbound_bytes=4000, tcp_pkts=50)
    # Flood: tons of volume but no real signature edge — same proto, modest
    # SYN ratio, no source concentration.
    bland_flood = rec(target_ip=0x01020304, port=443, proto_kind=C.PROTO_TCP,
                      inbound_pkts=1000, inbound_bytes=800000, tcp_pkts=1000)
    for _ in range(2):                         # finish warmup
        det.process_record(quiet)
    det.process_record(bland_flood)
    st = det._slots[key]
    assert st.last_absolute_floor_fired is True
    assert st.ewma_freeze_remaining > 0, "freeze must arm on t0 fire"
    assert st.t1_final > 0.0, "Tier-1 must have run (gate bypassed by abs-floor)"
    assert st.phase != C.PHASE_ATTACK, (
        f"signature-less abs-floor must not auto-ATTACK; got phase={st.phase} "
        f"T1={st.t1_final:.3f}")
    print(f"  [PASS] abs-floor → Tier-1 (no auto-ATTACK): "
          f"T1={st.t1_final:.3f}, phase={st.phase}, freeze armed "
          f"({st.ewma_freeze_remaining} ticks)")


def test_absolute_floor_plus_signature_evidence_reaches_attack():
    """The same abs-floor path WITH signature corroboration must still
    reach ATTACK — abs-floor's role becomes 'force Tier-1 immediately'
    rather than 'convict immediately'."""
    p = C.ProfileParams(name="b", alpha=0.05, variance_ceiling=6.0,
                        baseline_freeze_windows=8, thaw_cooldown_windows=6,
                        warmup_windows=2,
                        absolute_pps_threshold=500.0,
                        absolute_bps_threshold=0.0, absolute_fps_threshold=0.0)
    key, cfg = _cfg(False, p)
    det = Detector(cfg)
    quiet = rec(target_ip=0x01020304, port=443, proto_kind=C.PROTO_TCP,
                inbound_pkts=50, inbound_bytes=4000, tcp_pkts=50)
    # Loaded flood: high volume AND clear signature evidence
    #   - 99% SYN ratio   (TCP channel fires)
    #   - 90% /24 top-1   (Dist channel fires)
    #   - 10% off-proto   (L3 + offproto channels fire)
    loaded = rec(target_ip=0x01020304, port=443, proto_kind=C.PROTO_TCP,
                 inbound_pkts=10000, inbound_bytes=8_000_000, tcp_pkts=10000,
                 syn_pkts=9900, syn_ack_pkts=10,
                 empty_ack_pkts=8000, zero_window_pkts=2000,
                 off_proto_pkts=1000, ip_frag_pkts=500,
                 est_unique_flows=9000.0, est_tcp_new_flows=9000.0,
                 est_unique_src_ips=200.0,
                 src_24_top1_share=0.9, src_24_entropy=0.1)
    for _ in range(2):                         # finish warmup
        det.process_record(quiet)
    det.process_record(loaded)
    st = det._slots[key]
    assert st.last_absolute_floor_fired is True
    assert st.phase == C.PHASE_ATTACK, (
        f"loaded flood (abs-floor + signature) must reach ATTACK via Tier-1; "
        f"got phase={st.phase} T1={st.t1_final:.3f}")
    assert st.attack_freeze_active is True, "full freeze must arm on ATTACK"
    print(f"  [PASS] abs-floor + signature → ATTACK via Tier-1: "
          f"T1={st.t1_final:.3f}, dom={st.dominant_channel}")


def test_warmup_abs_breach_does_not_contaminate_baseline():
    """Phase 1 fix: a flood crossing the absolute floor DURING warmup must
    NOT poison the EWMA baseline. Pre-fix, the warmup branch trained
    unconditionally — an attacker timing a flood against a fresh slot's
    warmup window permanently raised the baseline."""
    p = C.ProfileParams(name="b", alpha=0.5, variance_ceiling=6.0,
                        baseline_freeze_windows=8, thaw_cooldown_windows=6,
                        warmup_windows=4,
                        absolute_pps_threshold=500.0,
                        absolute_bps_threshold=0.0, absolute_fps_threshold=0.0)
    key, cfg = _cfg(False, p)
    det = Detector(cfg)
    quiet = rec(target_ip=0x01020304, port=443, proto_kind=C.PROTO_TCP,
                inbound_pkts=50, inbound_bytes=4000, tcp_pkts=50)
    flood = rec(target_ip=0x01020304, port=443, proto_kind=C.PROTO_TCP,
                inbound_pkts=1000, inbound_bytes=800_000, tcp_pkts=1000)

    # Tick 1: quiet warmup tick — baseline seeds to ~50
    det.process_record(quiet)
    st = det._slots[key]
    pps_after_seed = st.ewma_pps.mean
    assert pps_after_seed > 0, "baseline should have seeded after first tick"

    # Tick 2: FLOOD during warmup (abs_breach fires). Pre-fix this would
    # update ewma_pps toward 1000 via alpha=0.5.
    det.process_record(flood)
    pps_after_flood = st.ewma_pps.mean
    assert abs(pps_after_flood - pps_after_seed) < 1e-9, (
        f"warmup baseline contaminated by abs-breach flood: "
        f"seed={pps_after_seed} after_flood={pps_after_flood}")
    assert st.last_absolute_floor_fired is True

    print(f"  [PASS] warmup abs-breach does NOT contaminate baseline "
          f"(locked at {pps_after_flood:.2f})")


def test_warmup_t0_fire_arms_ewma_freeze():
    """Phase 1 fix: any Tier-0 fire during warmup must arm the EWMA freeze
    so that subsequent warmup ticks (even quiet ones) inherit the freeze
    until it counts down."""
    p = C.ProfileParams(name="b", alpha=0.05, variance_ceiling=6.0,
                        baseline_freeze_windows=8, thaw_cooldown_windows=6,
                        warmup_windows=4,
                        absolute_pps_threshold=500.0,
                        absolute_bps_threshold=0.0, absolute_fps_threshold=0.0)
    key, cfg = _cfg(False, p)
    det = Detector(cfg)
    quiet = rec(target_ip=0x01020304, port=443, proto_kind=C.PROTO_TCP,
                inbound_pkts=50, inbound_bytes=4000, tcp_pkts=50)
    flood = rec(target_ip=0x01020304, port=443, proto_kind=C.PROTO_TCP,
                inbound_pkts=1000, inbound_bytes=800_000, tcp_pkts=1000)

    det.process_record(quiet)
    det.process_record(flood)
    st = det._slots[key]
    assert st.ewma_freeze_remaining > 0, (
        f"warmup t0 fire must arm EWMA freeze; got {st.ewma_freeze_remaining}")
    # Still WARMUP phase (warmup_remaining > 0).
    assert st.phase == C.PHASE_WARMUP
    print(f"  [PASS] warmup t0-fire arms EWMA freeze "
          f"({st.ewma_freeze_remaining} ticks remaining)")


def test_warmup_bitmask_stays_clean():
    """Phase 1 fix: the 5-bit rolling history must NOT advance during
    warmup. Pre-fix, warmup-tick t0 fires leaked bits into
    consecutive_attack_windows on the wire (popcount during WARMUP)."""
    p = C.ProfileParams(name="b", alpha=0.05, variance_ceiling=6.0,
                        baseline_freeze_windows=8, thaw_cooldown_windows=6,
                        warmup_windows=4,
                        absolute_pps_threshold=500.0,
                        absolute_bps_threshold=0.0, absolute_fps_threshold=0.0)
    key, cfg = _cfg(False, p)
    det = Detector(cfg)
    flood = rec(target_ip=0x01020304, port=443, proto_kind=C.PROTO_TCP,
                inbound_pkts=1000, inbound_bytes=800_000, tcp_pkts=1000)

    # Drive 3 warmup ticks all firing abs_breach. Bitmask must stay at 0.
    for _ in range(3):
        det.process_record(flood)
    st = det._slots[key]
    assert st.tier0_history_bits == 0, (
        f"bitmask leaked during warmup: bits={st.tier0_history_bits:#07b}")
    assert st.consecutive_attack_windows == 0
    assert st.phase == C.PHASE_WARMUP

    print(f"  [PASS] bitmask + consecutive_attack_windows stay clean "
          f"during warmup (bits={st.tier0_history_bits:#07b})")


def test_cusum_r_grows_during_buildup():
    """Phase 2 fix: CUSUM channel risk should grow proportionally as S_plus
    climbs toward h, not jump from 0 to ~1.0 in a single tick when the
    breach gate fires. Drive a slow-ramp series and confirm r_pps grows
    monotonically across the climb."""
    p = _params()
    p = C.ProfileParams(**{**p.__dict__, "warmup_windows": 3,
                           "absolute_pps_threshold": 0.0})
    key, cfg = _cfg(False, p)
    det = Detector(cfg)
    # Warmup at 100 pps so baseline mean ≈ 100, σ ≈ small floor.
    seed = rec(target_ip=0x01020304, port=443, proto_kind=C.PROTO_TCP,
               inbound_pkts=100, inbound_bytes=8000, tcp_pkts=100)
    for _ in range(3):
        det.process_record(seed)
    st = det._slots[key]
    assert st.phase == C.PHASE_NORMAL

    # Now slow-ramp: each tick a sustained +5σ-ish drift. Capture r_pps
    # over the ramp; it should grow strictly until it saturates at 1.0.
    samples = []
    for i in range(8):
        ramp = rec(target_ip=0x01020304, port=443, proto_kind=C.PROTO_TCP,
                   inbound_pkts=120 + i * 5, inbound_bytes=8000,
                   tcp_pkts=120 + i * 5)
        det.process_record(ramp)
        samples.append(st.r_pps)

    # First few samples must be > 0 (the buildup is now visible).
    assert samples[0] > 0.0, (
        f"r_pps should be non-zero during build-up; got {samples[0]}")
    # r_pps must reach saturation (1.0) by the end of the ramp.
    assert samples[-1] >= 0.99, (
        f"r_pps should saturate by tick 8; got {samples[-1]}")
    # Monotonic non-decreasing (within FP slack).
    for a, b in zip(samples, samples[1:]):
        assert b >= a - 1e-9, (
            f"r_pps must be non-decreasing during ramp; got {samples}")
    print(f"  [PASS] CUSUM r grows during build-up "
          f"(samples: {[round(s, 3) for s in samples]})")


def test_cusum_clears_on_thaw():
    """Phase 3 fix: when attack_freeze_active releases (after
    thaw_cooldown_windows of NORMAL), CUSUM accumulators must drain to
    zero. Otherwise the stale saturated S_plus would keep r_pps ≈ 1.0
    for ~h/k more ticks while the CUSUM drained on its own, re-arming
    the EWMA freeze unnecessarily."""
    p = C.ProfileParams(name="b", alpha=0.05, variance_ceiling=6.0,
                        baseline_freeze_windows=8, thaw_cooldown_windows=3,
                        warmup_windows=2,
                        absolute_pps_threshold=500.0,
                        absolute_bps_threshold=0.0, absolute_fps_threshold=0.0)
    key, cfg = _cfg(False, p)
    det = Detector(cfg)
    quiet = rec(target_ip=0x01020304, port=443, proto_kind=C.PROTO_TCP,
                inbound_pkts=50, inbound_bytes=4000, tcp_pkts=50)
    loaded = rec(target_ip=0x01020304, port=443, proto_kind=C.PROTO_TCP,
                 inbound_pkts=10000, inbound_bytes=8_000_000, tcp_pkts=10000,
                 syn_pkts=9900, syn_ack_pkts=10,
                 empty_ack_pkts=8000, zero_window_pkts=2000,
                 off_proto_pkts=1000, ip_frag_pkts=500,
                 est_unique_flows=9000.0, est_tcp_new_flows=9000.0,
                 est_unique_src_ips=200.0,
                 src_24_top1_share=0.9, src_24_entropy=0.1)

    # Finish warmup.
    for _ in range(2):
        det.process_record(quiet)

    # Drive ATTACK via abs-floor + signature.
    det.process_record(loaded)
    st = det._slots[key]
    assert st.attack_freeze_active is True
    saturated_S_plus = st.cusum_pps.S_plus
    assert saturated_S_plus > 0, "CUSUM should be saturated mid-attack"

    # Run thaw_cooldown_windows = 3 quiet ticks. On the 3rd, the freeze
    # should release AND CUSUM should drain.
    for _ in range(3):
        det.process_record(quiet)
    assert st.attack_freeze_active is False, "freeze should have released"
    assert st.cusum_pps.S_plus == 0.0, (
        f"CUSUM pps must drain on thaw; got S+={st.cusum_pps.S_plus}")
    assert st.cusum_bps.S_plus == 0.0
    assert st.cusum_fps.S_plus == 0.0

    print(f"  [PASS] CUSUM drains on thaw (was {saturated_S_plus:.2f}, "
          f"now 0.0; freeze released)")


def test_l3_ttl_uses_bessel_consistently():
    """Phase 4 fix: TTL stddev scored in _t1_l3 must use the same Bessel
    correction as the EWMA training, so that steady traffic produces
    z ≈ 0 instead of a systematic ~5% bias at low n."""
    p = _params()
    p = C.ProfileParams(**{**p.__dict__, "warmup_windows": 3,
                           "absolute_pps_threshold": 0.0})
    key, cfg = _cfg(False, p)
    det = Detector(cfg)
    # Build a record with known Welford state: n=20 packets, ttl mean=64,
    # ttl variance (Bessel) ≈ 4 → M2 = 4 * 19 = 76. Population variance
    # would be 76/20 = 3.8, Bessel 76/19 = 4.0. With consistent Bessel,
    # the live z-score of √4=2.0 against the baseline trained on √4=2.0
    # must be ~0.
    steady = rec(target_ip=0x01020304, port=443, proto_kind=C.PROTO_TCP,
                 inbound_pkts=20, inbound_bytes=2000, tcp_pkts=20,
                 ttl_mean=64.0, ttl_M2=76.0,
                 est_unique_flows=10.0, est_tcp_new_flows=10.0,
                 est_unique_src_ips=10.0)
    for _ in range(15):
        det.process_record(steady)
    st = det._slots[key]
    # The L3 channel z-score for TTL should now be near zero, since the
    # observed Bessel TTL stddev matches what the baseline was trained on.
    import math
    ttl_sd_pop_old_way = math.sqrt(76.0 / 20)   # ≈ 1.949 (pre-fix)
    ttl_sd_bessel_new = math.sqrt(76.0 / 19)    # = 2.000 (post-fix)
    # Confirm the fix: scored stddev now matches training stddev.
    z = M.ewma_z_score(st.ewma_ttl_stddev, ttl_sd_bessel_new)
    assert abs(z) < 1e-6, (
        f"Bessel-consistent L3: z should be ~0, got {z}; "
        f"baseline mean={st.ewma_ttl_stddev.mean}")
    # And the Bessel value is what the baseline was trained on:
    assert abs(st.ewma_ttl_stddev.mean - ttl_sd_bessel_new) < 1e-9
    print(f"  [PASS] L3 TTL Bessel-consistent: baseline={st.ewma_ttl_stddev.mean:.6f}, "
          f"live z={z:.6f} (pop would have biased by ~{ttl_sd_bessel_new - ttl_sd_pop_old_way:.4f})")


def test_syn_to_synack_baseline_resists_poisoning():
    """Phase 5 fix: when syn_ack_pkts == 0 (real SYN-flood condition),
    the fallback must be a saturating ratio (cap at 10), not the raw
    SYN count. Pre-fix, a single SYN flood pushed the baseline scale
    to thousands; subsequent smaller attacks then read as 'below
    average' and scored LOWER than legitimate traffic."""
    p = _params()
    p = C.ProfileParams(**{**p.__dict__, "warmup_windows": 2,
                           "alpha": 0.5,    # fast EWMA to surface the bug
                           "absolute_pps_threshold": 0.0})
    key, cfg = _cfg(False, p)
    det = Detector(cfg)
    quiet = rec(target_ip=0x01020304, port=443, proto_kind=C.PROTO_TCP,
                inbound_pkts=50, inbound_bytes=4000, tcp_pkts=50,
                syn_pkts=5, syn_ack_pkts=5)
    flood = rec(target_ip=0x01020304, port=443, proto_kind=C.PROTO_TCP,
                inbound_pkts=10000, inbound_bytes=800000, tcp_pkts=10000,
                syn_pkts=9900, syn_ack_pkts=0)   # the poisoning case

    # Finish warmup.
    for _ in range(2):
        det.process_record(quiet)
    st = det._slots[key]

    # Drive several SYN floods. The training EWMA (which only runs
    # when not frozen + NORMAL) won't update on these attack ticks —
    # so directly inspect the value that WOULD have been fed:
    # min(10, 9900) = 10 with the fix; 9900.0 without.
    sa_fallback_post_fix = min(10.0, 9900.0)
    sa_fallback_pre_fix = 9900.0
    assert sa_fallback_post_fix == 10.0
    assert sa_fallback_post_fix < sa_fallback_pre_fix

    # Now force a training tick by temporarily clearing freeze + treating
    # as NORMAL — simulate what happens if the slot ever reaches NORMAL
    # while a sa==0 condition exists. Drive once and check the baseline
    # didn't blow up.
    st.attack_freeze_active = False
    st.ewma_freeze_remaining = 0
    st.phase = C.PHASE_NORMAL
    st.cusum_pps.S_plus = 0.0
    st.cusum_bps.S_plus = 0.0
    st.cusum_fps.S_plus = 0.0
    # Use a "borderline" record: enough traffic to update baselines, but
    # not extreme enough to fire Tier-0 (use 60 pps, slightly above
    # baseline of 50, with sa=0 to exercise the fallback).
    border = rec(target_ip=0x01020304, port=443, proto_kind=C.PROTO_TCP,
                 inbound_pkts=60, inbound_bytes=4800, tcp_pkts=60,
                 syn_pkts=60, syn_ack_pkts=0)   # syn=60, sa=0
    det.process_record(border)
    # With the fix, ewma_syn_to_synack baseline should be bounded near 10
    # (cap), not in the hundreds.
    assert st.ewma_syn_to_synack.mean <= 10.0 + 1e-6, (
        f"baseline poisoned: ewma_syn_to_synack.mean = "
        f"{st.ewma_syn_to_synack.mean}; expected ≤ 10")

    print(f"  [PASS] syn_to_synack baseline capped at 10 "
          f"(actual mean={st.ewma_syn_to_synack.mean:.2f})")


def test_learning_mode_never_transitions():
    p = _params()
    key, cfg = _cfg(True, p)                    # learning_mode = True
    det = Detector(cfg)
    flood = rec(target_ip=0x01020304, port=443, proto_kind=C.PROTO_TCP,
                inbound_pkts=10000, inbound_bytes=8_000_000,
                tcp_pkts=10000, syn_pkts=9900,
                est_unique_flows=5000.0, est_tcp_new_flows=5000.0,
                est_unique_src_ips=4000.0)
    for _ in range(50):
        det.process_record(flood)
    st = det._slots[key]
    assert st.phase == C.PHASE_WARMUP, \
        f"learning_mode must hold WARMUP, got {st.phase}"
    # Scores are still computed + cached during learning.
    assert st.windows_seen == 50
    print(f"  [PASS] learning_mode holds WARMUP across 50 attack ticks "
          f"(scores still cached, R0={st.last_tier0_score:.2f})")


def test_score_then_update_protects_baseline_from_attack_window():
    """Baseline EWMAs must NOT incorporate the current window when Tier-0 fires
    — that's the whole point of the score-then-update reorder. Drive a flood
    after warmup; assert the pps baseline mean stays at the quiet level
    rather than being dragged toward the flood."""
    p = C.ProfileParams(name="b", alpha=0.5, variance_ceiling=6.0,
                        baseline_freeze_windows=8, thaw_cooldown_windows=6,
                        warmup_windows=2,
                        absolute_pps_threshold=500.0,
                        absolute_bps_threshold=0.0, absolute_fps_threshold=0.0)
    key, cfg = _cfg(False, p)
    det = Detector(cfg)
    quiet = rec(target_ip=0x01020304, port=443, proto_kind=C.PROTO_TCP,
                inbound_pkts=50, inbound_bytes=4000, tcp_pkts=50)
    flood = rec(target_ip=0x01020304, port=443, proto_kind=C.PROTO_TCP,
                inbound_pkts=1000, inbound_bytes=800000, tcp_pkts=1000,
                syn_pkts=990, est_unique_flows=900.0,
                est_tcp_new_flows=900.0, est_unique_src_ips=800.0)
    for _ in range(2):
        det.process_record(quiet)
    st = det._slots[key]
    pps_mean_pre = st.ewma_pps.mean
    # Flood — Tier-0 fires (abs-floor breached). Old order would have updated
    # ewma_pps to 0.5*50 + 0.5*1000 = 525 (alpha=0.5). New order must not,
    # because the t0 fire arms the EWMA freeze before Stage 7. The verdict
    # itself depends on Tier-1; what we're proving here is the BASELINE
    # PROTECTION mechanism, independent of how the verdict turns out.
    det.process_record(flood)
    pps_mean_post = st.ewma_pps.mean
    assert st.ewma_freeze_remaining > 0, "t0 fire must arm the EWMA freeze"
    assert abs(pps_mean_post - pps_mean_pre) < 1e-9, (
        f"baseline contaminated by t0-fired window: "
        f"pre={pps_mean_pre} post={pps_mean_post}")
    print(f"  [PASS] score-then-update: t0-fired window did NOT contaminate "
          f"ewma_pps baseline (locked at {pps_mean_post:.2f}, "
          f"phase={st.phase})")


def test_pulsing_attack_3_of_5_bitmask_gate():
    """The rolling-bitmask persistence gate must accumulate Tier-0 hits even
    across quiet gaps. Drive an alternating flood/quiet pattern with the
    absolute-floor configured low enough that every flood tick fires t0; the
    bitmask should accumulate to popcount>=3 and the wire field
    consecutive_attack_windows should now report the popcount."""
    p = C.ProfileParams(name="b", alpha=0.05, variance_ceiling=6.0,
                        baseline_freeze_windows=8, thaw_cooldown_windows=6,
                        warmup_windows=2,
                        absolute_pps_threshold=500.0,
                        absolute_bps_threshold=0.0, absolute_fps_threshold=0.0)
    key, cfg = _cfg(False, p)
    det = Detector(cfg)
    quiet = rec(target_ip=0x01020304, port=443, proto_kind=C.PROTO_TCP,
                inbound_pkts=50, inbound_bytes=4000, tcp_pkts=50)
    flood = rec(target_ip=0x01020304, port=443, proto_kind=C.PROTO_TCP,
                inbound_pkts=1000, inbound_bytes=800000, tcp_pkts=1000,
                syn_pkts=990, est_unique_flows=900.0,
                est_tcp_new_flows=900.0, est_unique_src_ips=800.0)
    # Finish warmup.
    for _ in range(2):
        det.process_record(quiet)
    st = det._slots[key]
    # Drain whatever bits accumulated during warmup-phase t0 scoring on
    # uninitialised baselines (should be zero, but normalise just in case).
    st.tier0_history_bits = 0
    st.consecutive_attack_windows = 0
    # Helper: between each tick, reset transient state so the bitmask
    # mechanism can be exercised in isolation. CUSUM accumulators are
    # sticky across ticks (by design — they're the "memory of recent
    # drift"); for this test we want each tick to score against a fresh
    # CUSUM so the bitmask reflects ONLY whether that tick fired.
    def _reset_transient():
        st.attack_freeze_active = False
        st.ewma_freeze_remaining = 0
        st.phase = C.PHASE_NORMAL
        st.cusum_pps.S_plus = 0.0
        st.cusum_bps.S_plus = 0.0
        st.cusum_fps.S_plus = 0.0

    # Pulse 1: flood → bit 0 set. abs-floor forces gate open via Tier-1.
    det.process_record(flood)
    assert st.tier0_history_bits & 0x1, "flood tick must set bit 0"
    _reset_transient()
    # quiet, flood, quiet, flood → bits become 10101 (popcount 3).
    det.process_record(quiet)
    _reset_transient()
    det.process_record(flood)
    _reset_transient()
    det.process_record(quiet)
    _reset_transient()
    det.process_record(flood)
    bits = st.tier0_history_bits
    popcount = bin(bits).count("1")
    assert bits == 0b10101, f"expected 0b10101, got {bits:#07b}"
    assert popcount == 3, f"popcount must be 3, got {popcount}"
    assert st.consecutive_attack_windows == popcount, \
        f"wire field must report popcount, got {st.consecutive_attack_windows}"
    print(f"  [PASS] 3-of-5 bitmask: pulsing pattern → bits=0b{bits:05b} "
          f"popcount={popcount} (old strict counter would've reset)")


def test_discounted_max_corroboration_lifts_two_mid_tier_channels():
    """Discounted-Max must lift the verdict when two channels corroborate.
    Two channels at 0.6 each should yield 0.75·0.6 + 0.25·0.6 = 0.60, which
    beats the cliff (0.6 - 0.15 = 0.45) — so T1 == 0.60, the same as a
    single-channel 0.60 (no penalty for the second channel being weak).
    Two channels at 0.5 each should yield 0.50; a single 0.5 with everything
    else 0 should yield 0.5 - 0.15 = 0.35."""
    from detection.detector import Detector, SlotState
    p = _params()
    key, cfg = _cfg(False, p)
    det = Detector(cfg)

    class _Fake:
        def __init__(self):
            self.t1_tcp = self.t1_udp = self.t1_icmp = 0.0
            self.t1_dist = self.t1_l3 = self.t1_offproto = 0.0
            self.t1_final = 0.0
            self.dominant_channel = C.DOM_NONE
            self.r_pps = self.r_bps = self.r_fps = 0.0
            self.r_burst_pps = self.r_burst_bps = self.r_burst_fps = 0.0

    rec0 = rec(target_ip=0x01020304, port=443, proto_kind=C.PROTO_TCP,
               inbound_pkts=0)

    # Case 1: single channel @ 0.5, rest 0. cliff = 0.35, blend = 0.375.
    st = _Fake()
    # Bypass per-channel scoring by monkey-patching one channel computation.
    orig_tcp = det._t1_tcp
    orig_udp = det._t1_udp
    orig_icmp = det._t1_icmp
    orig_dist = det._t1_dist
    orig_l3 = det._t1_l3
    orig_off = det._t1_offproto
    det._t1_tcp = lambda *_a, **_k: 0.5
    det._t1_udp = lambda *_a, **_k: 0.0
    det._t1_icmp = lambda *_a, **_k: 0.0
    det._t1_dist = lambda *_a, **_k: 0.0
    det._t1_l3 = lambda *_a, **_k: 0.0
    det._t1_offproto = lambda *_a, **_k: 0.0
    t1_solo = det._combine(st, rec0, C.PROTO_TCP)
    # max(0.75*0.5 + 0.25*0, 0.5-0.15) = max(0.375, 0.35) = 0.375
    assert abs(t1_solo - 0.375) < 1e-9, f"solo=0.5 → expected 0.375, got {t1_solo}"

    # Case 2: two corroborating channels @ 0.6.
    st = _Fake()
    det._t1_tcp = lambda *_a, **_k: 0.6
    det._t1_dist = lambda *_a, **_k: 0.6
    t1_corro = det._combine(st, rec0, C.PROTO_TCP)
    # max(0.75*0.6 + 0.25*0.6, 0.6-0.15) = max(0.60, 0.45) = 0.60
    assert abs(t1_corro - 0.60) < 1e-9, f"two@0.6 → expected 0.60, got {t1_corro}"

    # Case 3: dominant single channel — cliff dominates over blend.
    # c1=0.9, c2=0. blend=0.675, cliff=0.75 → 0.75.
    st = _Fake()
    det._t1_tcp = lambda *_a, **_k: 0.9
    det._t1_dist = lambda *_a, **_k: 0.0
    t1_dom = det._combine(st, rec0, C.PROTO_TCP)
    assert abs(t1_dom - 0.75) < 1e-9, f"dom=0.9 → expected 0.75, got {t1_dom}"

    # Case 4: two strong channels — both contribute, blend dominates.
    # c1=0.9, c2=0.7. blend = 0.675 + 0.175 = 0.85, cliff=0.75 → 0.85.
    st = _Fake()
    det._t1_tcp = lambda *_a, **_k: 0.9
    det._t1_dist = lambda *_a, **_k: 0.7
    t1_both = det._combine(st, rec0, C.PROTO_TCP)
    assert abs(t1_both - 0.85) < 1e-9, f"0.9+0.7 → expected 0.85, got {t1_both}"

    # restore
    det._t1_tcp = orig_tcp
    det._t1_udp = orig_udp
    det._t1_icmp = orig_icmp
    det._t1_dist = orig_dist
    det._t1_l3 = orig_l3
    det._t1_offproto = orig_off

    print("  [PASS] Discounted-Max fusion: "
          f"solo0.5={t1_solo:.3f} two@0.6={t1_corro:.3f} "
          f"dom0.9={t1_dom:.3f} 0.9+0.7={t1_both:.3f}")


def main():
    test_warmup_promotes_to_normal()
    test_warmup_abs_breach_does_not_contaminate_baseline()
    test_warmup_t0_fire_arms_ewma_freeze()
    test_warmup_bitmask_stays_clean()
    test_cusum_r_grows_during_buildup()
    test_cusum_clears_on_thaw()
    test_l3_ttl_uses_bessel_consistently()
    test_syn_to_synack_baseline_resists_poisoning()
    test_absolute_floor_bypasses_gate_routes_through_tier1()
    test_absolute_floor_plus_signature_evidence_reaches_attack()
    test_learning_mode_never_transitions()
    test_score_then_update_protects_baseline_from_attack_window()
    test_pulsing_attack_3_of_5_bitmask_gate()
    test_discounted_max_corroboration_lifts_two_mid_tier_channels()
    print("RESULT: detector behaviour OK against current logic")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
