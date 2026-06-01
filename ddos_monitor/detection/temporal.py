"""
temporal.py — per-slot temporal aggregation (10s / 60s / 300s rolling windows).

Exact port of the C ring buffer: l2fwd_service_temporal_state.{h,c} +
service_temporal_push_sample / service_temporal_recompute_windows
(l2fwd_service_features.c:575-644). One TemporalState per slot; push one
sample per 1 Hz window, then read the three derived windows.

Drives the win_{10s,60s,300s}_{total_pkts,peak_pps,attack_seconds} columns and
the service_temporal_aggregates rows the collector writes — so it must match C.
Verified by tests/python/test_detector_parity.py (the harness pushes the same
samples through the C ring and diffs).
"""

# Mirror l2fwd_service_temporal_state.h
WINDOW_SIZES = (10, 60, 300)          # 10S / 60S / 300S, in seconds
MAX_SAMPLES = 300

# Phase ordinals counted as attack / suspicious seconds (features.c:50-51).
_PHASE_SUSPICIOUS = 2
_PHASE_ATTACK = 3


class TemporalWindowAgg:
    __slots__ = ("size_seconds", "total_pkts", "peak_pps",
                 "attack_seconds", "suspicious_seconds", "mean_pps")

    def __init__(self, size_seconds):
        self.size_seconds = size_seconds
        self.total_pkts = 0
        self.peak_pps = 0.0
        self.attack_seconds = 0
        self.suspicious_seconds = 0
        self.mean_pps = 0.0


class TemporalState:
    """1 Hz ring of (pkts, bytes, flows, phase) samples + three derived windows.

    Newest sample lives at (sample_head - 1) mod MAX_SAMPLES, exactly like the C
    side, so the backward walk reproduces the same window membership."""

    __slots__ = ("samples", "sample_head", "sample_count", "windows")

    def __init__(self):
        self.samples = [(0, 0, 0, 0)] * MAX_SAMPLES   # (pkts, bytes, flows, phase)
        self.sample_head = 0
        self.sample_count = 0
        self.windows = [TemporalWindowAgg(s) for s in WINDOW_SIZES]

    def push(self, pkts: int, bytes_: int, flows: int, phase: int) -> None:
        """Port of service_temporal_push_sample (features.c:575-598)."""
        self.samples[self.sample_head] = (pkts, bytes_, flows, phase)
        self.sample_head = (self.sample_head + 1) % MAX_SAMPLES
        if self.sample_count < MAX_SAMPLES:
            self.sample_count += 1
        self._recompute()

    def _recompute(self) -> None:
        """Port of service_temporal_recompute_windows (features.c:600-644)."""
        for win in self.windows:
            want = win.size_seconds
            have = self.sample_count if self.sample_count < want else want

            total_p = 0
            peak_p = 0
            attack_secs = 0
            susp_secs = 0
            for k in range(have):
                i = (self.sample_head + MAX_SAMPLES - 1 - k) % MAX_SAMPLES
                pkts, _bytes, _flows, phase = self.samples[i]
                total_p += pkts
                if pkts > peak_p:
                    peak_p = pkts
                if phase == _PHASE_ATTACK:
                    attack_secs += 1
                elif phase == _PHASE_SUSPICIOUS:
                    susp_secs += 1

            win.total_pkts = total_p
            win.peak_pps = float(peak_p)
            win.mean_pps = (float(total_p) / have) if have > 0 else 0.0
            win.attack_seconds = attack_secs
            win.suspicious_seconds = susp_secs

    # convenience accessors keyed by window size
    def window(self, size_seconds: int) -> TemporalWindowAgg:
        for w in self.windows:
            if w.size_seconds == size_seconds:
                return w
        raise KeyError(size_seconds)

    # checkpoint helpers
    def to_state(self):
        return {
            "samples": self.samples,
            "sample_head": self.sample_head,
            "sample_count": self.sample_count,
        }

    def load_state(self, d):
        self.samples = list(d["samples"])
        self.sample_head = int(d["sample_head"])
        self.sample_count = int(d["sample_count"])
        self._recompute()
