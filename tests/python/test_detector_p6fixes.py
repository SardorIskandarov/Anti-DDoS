#!/usr/bin/env python3
"""
test_detector_p6fixes.py — verify the P6 post-parity detection fixes behave as
intended when ENABLED, and that they are OFF by default (so the C-parity tests
stay valid). Each fix is a per-profile flag defaulting to False.

Fixes covered:
  * fix_fps_source — the fps EWMA baseline tracks the SAME (common) flow
    estimate the CUSUM observes. This kills the ICMP false-fps-breach: with the
    fix OFF the ICMP baseline trains to ~0 (proto estimate is 0) while the
    observation is non-zero → permanent fps breach; with it ON the baseline
    tracks the observation → no breach.
  * fix_frag_zscore — the IP-fragment ratio is scored against its learned
    baseline instead of the coarse `frag_r * 20` ramp, so a service whose
    *normal* traffic carries fragments is no longer perpetually penalised.

Run:  python3 tests/python/test_detector_p6fixes.py
"""

import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(ROOT, "ddos_monitor"))

from detection import config as C                # noqa: E402
from detection.detector import Detector          # noqa: E402
from detection.snapshot import RECORD_FIELDS     # noqa: E402

_ZERO = {f[0]: (0.0 if f[3] == 5 else 0) for f in RECORD_FIELDS}  # kind 5 == f64


def rec(**kw):
    r = dict(_ZERO)
    r.update(kw)
    return r


def params(ip, port, kind, **flags):
    return C.ProfileParams(
        name="p6", alpha=0.05, variance_ceiling=3.0, baseline_freeze_windows=8,
        thaw_cooldown_windows=6, warmup_windows=3,
        absolute_pps_threshold=0.0, absolute_bps_threshold=0.0,
        absolute_fps_threshold=0.0, **flags)


def run(kind, port, flags, record, ticks=12):
    ip = 0x01020304
    key = (ip, port, kind)
    cfg = C.DetectionConfig(learning_mode=False,
                            by_key={key: params(ip, port, kind, **flags)},
                            profiles={})
    det = Detector(cfg)
    for _ in range(ticks):
        det.process_record(record)
    return det, det._slots[key]


def test_fps_source_fixes_icmp_false_breach():
    # ICMP slot: proto flow estimate is 0 (no ICMP flow HLL), common flow
    # estimate is steady non-zero. inbound==icmp pkts steady.
    r = rec(target_ip=0x01020304, port=0, proto_kind=C.PROTO_ICMP,
            inbound_pkts=100, inbound_bytes=8000, icmp_pkts=100,
            icmp_echo_pkts=100, est_unique_flows=50.0,
            est_unique_src_ips=50.0)

    _, off = run(C.PROTO_ICMP, 0, {}, r)
    _, on = run(C.PROTO_ICMP, 0, {"fix_fps_source": True}, r)

    assert off.r_fps > 0.9, f"OFF should show the false fps breach, got {off.r_fps}"
    assert on.r_fps < 0.01, f"ON should NOT breach fps, got {on.r_fps}"
    print(f"  [PASS] fix_fps_source: ICMP r_fps  OFF={off.r_fps:.3f} (false breach) "
          f"-> ON={on.r_fps:.3f} (clean)")


def test_frag_zscore_learns_normal_fragmentation():
    # TCP slot whose NORMAL traffic is 10% fragmented, uniform TTL, no off-proto.
    r = rec(target_ip=0x01020304, port=443, proto_kind=C.PROTO_TCP,
            inbound_pkts=100, inbound_bytes=64000, tcp_pkts=100,
            ip_frag_pkts=10,                      # frag_r = 0.10 (steady/normal)
            ttl_mean=64.0, ttl_M2=0.0,                    # uniform TTL=64, zero variance
            est_unique_flows=100.0, est_tcp_new_flows=100.0,
            est_unique_src_ips=80.0)

    det_off, off = run(C.PROTO_TCP, 443, {}, r)
    det_on, on = run(C.PROTO_TCP, 443, {"fix_frag_zscore": True}, r)

    # Score the L3 channel directly on the learned baselines.
    l3_off = det_off._t1_l3(off, r)
    l3_on = det_on._t1_l3(on, r)

    # OFF penalises normal fragmentation: z_frag = z_to_score(0.1*20 = 2.0).
    import detection.primitives as M
    expect_off_zfrag = M.z_to_score(2.0)
    # ON: baseline learned frag_r=0.1 -> z=0 -> z_to_score(0) ~ 0.047.
    expect_on_zfrag = M.z_to_score(0.0)
    assert expect_off_zfrag > expect_on_zfrag
    assert l3_on < l3_off - 0.03, \
        f"fix should lower L3 on normal-frag traffic: on={l3_on:.4f} off={l3_off:.4f}"
    print(f"  [PASS] fix_frag_zscore: L3 on normal-frag traffic  "
          f"OFF={l3_off:.4f} -> ON={l3_on:.4f} (learned baseline = benign)")


def test_flags_default_off():
    p = C.ProfileParams.from_json("d", {})
    assert p.fix_fps_source is False and p.fix_frag_zscore is False
    p2 = C.DEFAULT_PROFILE
    assert p2.fix_fps_source is False and p2.fix_frag_zscore is False
    # JSON wiring: detection_fixes section flips them on.
    p3 = C.ProfileParams.from_json("e", {"detection_fixes": {"fps_source": True}})
    assert p3.fix_fps_source is True and p3.fix_frag_zscore is False
    print("  [PASS] flags default OFF; services.json detection_fixes wires them on")


def main():
    test_flags_default_off()
    test_fps_source_fixes_icmp_false_breach()
    test_frag_zscore_learns_normal_fragmentation()
    print("RESULT: P6 fixes behave as intended (and are OFF by default)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
