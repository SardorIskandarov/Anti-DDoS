#!/usr/bin/env python3
"""
test_detector_primitives.py — self-consistency tests for the math primitives
post-Welford / post-burst-window-N=10 / post-±6σ.

These replace the now-retired C-oracle parity tests (`test_detector_math_parity`
and `test_detector_parity`). The Python brain is the single source of truth;
these tests pin down properties of the primitives — convergence, numerical
stability, monotonicity, edge cases — against the *current* implementation.
"""

import math
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(ROOT, "ddos_monitor"))

from detection import primitives as M   # noqa: E402

_OK = "  [PASS]"


# ---------------------------------------------------------------------------
# EWMA
# ---------------------------------------------------------------------------

def test_ewma_seed_and_converge():
    st = M.EwmaState()
    M.ewma_update(st, 100.0, 0.5, M.EWMA_DEFAULT_VARIANCE_CEILING)
    assert st.initialized and st.mean == 100.0 and st.variance == 0.0
    # Constant stream → mean tracks, variance stays at the σ-floor.
    for _ in range(50):
        M.ewma_update(st, 100.0, 0.5, M.EWMA_DEFAULT_VARIANCE_CEILING)
    assert abs(st.mean - 100.0) < 1e-9
    floor = M.EWMA_MIN_STDDEV_REL * 100.0
    assert st.variance <= floor * floor * (1 + 1e-9), f"variance must hit σ-floor; got {st.variance}"
    print(f"{_OK} EWMA seeds + converges; variance pinned at σ-floor")


def test_ewma_winsor_C6_lets_flash_crowd_through():
    # Steady baseline → small variance → ±C·σ clamp is the question.
    st = M.EwmaState()
    for x in [100, 102, 99, 101, 100, 103, 98, 100, 101, 102]:
        M.ewma_update(st, float(x), 0.05, M.EWMA_DEFAULT_VARIANCE_CEILING)
    pre_mean = st.mean
    # A 3× flash crowd (well past ±3σ but well within ±6σ on a quiet baseline).
    M.ewma_update(st, 300.0, 0.05, M.EWMA_DEFAULT_VARIANCE_CEILING)
    moved = st.mean - pre_mean
    # With ±6σ clamp on this baseline, the diff is winsorised to 6σ. σ here is
    # the σ-floor (~1.0 since mean ~100, floor=1% of |mean|). So clamp ≈ 6.0
    # and α·6 = 0.3 — mean nudges noticeably. With the old ±3σ clamp the move
    # would be half that. Assert the wider clamp allowed a larger update.
    st2 = M.EwmaState()
    for x in [100, 102, 99, 101, 100, 103, 98, 100, 101, 102]:
        M.ewma_update(st2, float(x), 0.05, 3.0)  # old C-oracle clamp
    pre2 = st2.mean
    M.ewma_update(st2, 300.0, 0.05, 3.0)
    moved_tight = st2.mean - pre2
    assert moved > moved_tight * 1.5, (
        f"±6σ should allow noticeably more baseline movement than ±3σ; "
        f"wide={moved:.4f} tight={moved_tight:.4f}")
    print(f"{_OK} ±6σ winsor lets flash crowds nudge the baseline "
          f"(wide={moved:.4f} > tight={moved_tight:.4f})")


# ---------------------------------------------------------------------------
# Burst window — Welford-online correctness
# ---------------------------------------------------------------------------

def _reference_pop_mean_var(samples):
    n = len(samples)
    mean = sum(samples) / n
    M2 = sum((x - mean) ** 2 for x in samples)
    return mean, M2


def test_burst_fill_then_steady_state_matches_two_pass():
    """Welford-online (fill + rolling-remove) must match a fresh two-pass
    Σ(x − mean)² over the live buffer to <1e-9 — that's the numerical safety
    claim of the new burst window."""
    bw = M.BurstWindow()
    N = M.BURST_WINDOW_SIZE
    # Drive 5 * N samples spanning ~10 orders of magnitude (Gbps-class values
    # where the old `Σx² − (Σx)²/n` formula loses precision).
    sequence = [1e10 + i * 1e7 + (i % 7) * 1e6 for i in range(5 * N)]
    pushed = []
    for s in sequence:
        M.burst_window_push(bw, s)
        pushed.append(s)
        live = pushed[-min(len(pushed), N):]
        ref_mean, ref_M2 = _reference_pop_mean_var(live)
        assert abs(bw.mean - ref_mean) < 1e-9 * max(1.0, abs(ref_mean)), \
            f"mean drift: {bw.mean} vs {ref_mean}"
        # Allow a tiny FP slack: rolling-remove accumulates noise but stays
        # bounded for reasonable N. 1e-3 relative is generous; in practice the
        # error here is ~1e-12.
        ref_M2_safe = max(ref_M2, 1.0)
        assert abs(bw.M2 - ref_M2) / ref_M2_safe < 1e-9, \
            f"M2 drift: {bw.M2} vs {ref_M2}"
    print(f"{_OK} burst window (N={N}): rolling Welford == two-pass to <1e-9 "
          f"over {len(sequence)} pushes at Gbps magnitudes")


def test_burst_window_stable_at_extreme_volumes():
    """No NaN / negative variance / crash on bytes-per-second at 100 Gbps."""
    bw = M.BurstWindow()
    for _ in range(M.BURST_WINDOW_SIZE * 3):
        M.burst_window_push(bw, 1.25e11)        # ~100 Gbps in bps
    # Constant input → variance must be 0 (or σ-floor) and stddev finite.
    assert bw.M2 >= 0.0 and math.isfinite(bw.stddev)
    assert bw.stddev < 1.0, f"constant stream stddev should be ~0, got {bw.stddev}"
    print(f"{_OK} burst window stable at ~100 Gbps; stddev={bw.stddev:.3g}")


# ---------------------------------------------------------------------------
# CUSUM + sigmoid (unchanged — quick smoke)
# ---------------------------------------------------------------------------

def test_cusum_breach_on_sustained_drift():
    cs = M.CusumState()
    fired = False
    for _ in range(20):
        if M.cusum_update(cs, 200.0, 100.0, 5.0, 0.5, 4.0):
            fired = True
            break
    assert fired, "CUSUM must fire on sustained 20σ drift"
    print(f"{_OK} CUSUM fires on sustained drift (S+={cs.S_plus:.2f})")


def test_z_to_score_curve():
    assert M.z_to_score(0.0) == M.z_to_score(-0.0)
    assert abs(M.z_to_score(3.0) - 0.5) < 1e-9
    assert M.z_to_score(0.0) < M.z_to_score(3.0) < M.z_to_score(6.0) < 1.0
    assert M.z_to_score(1e9) == 1.0, "huge |z| must clamp to 1.0 (no OverflowError)"
    print(f"{_OK} z_to_score: monotonic, centred at 3, overflow-safe")


# ---------------------------------------------------------------------------


def main():
    test_ewma_seed_and_converge()
    test_ewma_winsor_C6_lets_flash_crowd_through()
    test_burst_fill_then_steady_state_matches_two_pass()
    test_burst_window_stable_at_extreme_volumes()
    test_cusum_breach_on_sustained_drift()
    test_z_to_score_curve()
    print("RESULT: detection primitives OK (Welford-true, N=10, ±6σ)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
