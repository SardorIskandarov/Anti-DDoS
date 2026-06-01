"""
detection — the Python detection brain for the Anti-DDoS engine.

Consumes the raw-telemetry snapshot the C data plane publishes to shared memory
and reproduces the full detection verdict (Tier-0 / Tier-1 / phase machine /
freeze) that previously lived in C. Proven bit-for-bit equivalent to
l2fwd_service_features.c + l2fwd_service_scoring.c by tests/test_detector_*.py.

Modules:
    snapshot    — C<->Python shm record contract + zero-copy reader
    primitives  — exact ports of the EWMA / CUSUM / burst / sigmoid math
    config      — hardcoded scoring constants + per-slot profile params loader
    detector    — Detector + SlotState (the per-tick verdict)
    temporal    — 10s/60s/300s rolling-window aggregation
    output      — build the WireMessage the collector's writers consume
    pipeline    — DetectionPipeline: snapshot bank -> WireMessages + checkpoint
"""

from .config import DetectionConfig, ProfileParams, load_config
from .detector import Detector, SlotState
from .snapshot import SnapshotReader, SnapshotLayoutError
from .temporal import TemporalState
from .output import build_wire_message
from .pipeline import DetectionPipeline

__all__ = [
    "DetectionConfig", "ProfileParams", "load_config",
    "Detector", "SlotState",
    "SnapshotReader", "SnapshotLayoutError",
    "TemporalState", "build_wire_message", "DetectionPipeline",
]
