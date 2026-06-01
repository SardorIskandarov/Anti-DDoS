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


def test_absolute_floor_forces_attack_and_arms_freeze():
    # absolute_pps_threshold=500; flood of 1000 pps must force ATTACK and arm
    # both freezes (full ATTACK + EWMA-only).
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
    for _ in range(2):                         # finish warmup
        det.process_record(quiet)
    det.process_record(flood)
    st = det._slots[key]
    assert st.phase == C.PHASE_ATTACK, f"expected ATTACK, got {st.phase}"
    assert st.last_absolute_floor_fired is True
    assert st.attack_freeze_active is True, "full freeze must arm on ATTACK"
    print(f"  [PASS] abs-floor → ATTACK (R0={st.last_tier0_score:.3f}); "
          f"freeze armed")


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
    # Flood — abs-floor fires → ATTACK. Old order would have updated
    # ewma_pps to 0.5*50 + 0.5*1000 = 525 (alpha=0.5). New order must not.
    det.process_record(flood)
    pps_mean_post = st.ewma_pps.mean
    assert st.phase == C.PHASE_ATTACK
    assert abs(pps_mean_post - pps_mean_pre) < 1e-9, (
        f"baseline contaminated by attack window: "
        f"pre={pps_mean_pre} post={pps_mean_post}")
    print(f"  [PASS] score-then-update: ATTACK window did NOT contaminate "
          f"ewma_pps baseline (locked at {pps_mean_post:.2f})")


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
    # Pulse 1: flood → bit 0 set. abs-floor also forces ATTACK, sets the
    # attack-freeze. We assert the BIT was set regardless.
    det.process_record(flood)
    assert st.tier0_history_bits & 0x1, "flood tick must set bit 0"
    # Now reset freeze so quiet ticks can resume normal scoring (the goal
    # here is to exercise the bitmask shift mechanics, not the freeze).
    st.attack_freeze_active = False
    st.ewma_freeze_remaining = 0
    st.phase = C.PHASE_NORMAL
    # quiet, flood, quiet, flood → bits become 10101 (popcount 3).
    det.process_record(quiet)
    det.process_record(flood)
    st.attack_freeze_active = False
    st.ewma_freeze_remaining = 0
    st.phase = C.PHASE_NORMAL
    det.process_record(quiet)
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
    test_absolute_floor_forces_attack_and_arms_freeze()
    test_learning_mode_never_transitions()
    test_score_then_update_protects_baseline_from_attack_window()
    test_pulsing_attack_3_of_5_bitmask_gate()
    test_discounted_max_corroboration_lifts_two_mid_tier_channels()
    print("RESULT: detector behaviour OK against current logic")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
