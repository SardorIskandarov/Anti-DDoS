"""
config.py (detection package) — detection constants + per-slot profile parameters.

PARITY RULE (critical): l2fwd_service_scoring.c HARDCODES most tuning constants
and ignores the matching profile fields in services.json. To reproduce the
running C verdict, Python must do the same: the SCORING_* values below are the
hardcoded scoring.c #defines, and ProfileParams reads from services.json ONLY
the handful of fields the C actually consumes (verified against
l2fwd_service_registry.c:339-376 and the features/scoring source):

    alpha                 <- profiles.<p>.tier0.alpha            (features.c pick_alpha)
    variance_ceiling      <- profiles.<p>.tier0.variance_ceiling_factor
    baseline_freeze_win   <- profiles.<p>.tier1.baseline_freeze_windows
    thaw_cooldown_win     <- profiles.<p>.tier1.thaw_cooldown_windows
    warmup_windows        <- profiles.<p>.tier1.warmup_windows
    absolute_{pps,bps,fps}_threshold <- profiles.<p>.tier0.absolute_*_threshold
    learning_mode         <- top-level "learning_mode"

Everything else in the JSON (tier0.weights, cusum_k/h, tier0/tier1 thresholds,
fusion_weights, sigmoid_*, v2_feature_weights, tier1_l3 weights) is parsed by
the C loader but NOT used by scoring.c — so Python ignores it too. Wiring those
in is the post-parity "config unification" improvement, which changes verdicts.
"""

import socket
import struct
from dataclasses import dataclass

# ---------------------------------------------------------------------------
# Hardcoded scoring constants — verbatim from l2fwd_service_scoring.c:36-79.
# ---------------------------------------------------------------------------

TIER0_K = 0.5                       # SCORING_DEFAULT_TIER0_K
TIER0_H = 4.0                       # SCORING_DEFAULT_TIER0_H
SUSPICIOUS_THRESHOLD = 0.5          # SCORING_DEFAULT_SUSPICIOUS_THRESHOLD
ATTACK_THRESHOLD = 0.7              # SCORING_DEFAULT_ATTACK_THRESHOLD
BURST_Z_THRESHOLD = 15.0            # SCORING_BURST_Z_THRESHOLD

# Tier-0 weighted-risk fusion weights (SCORING_T0_W_*).
T0_W_PPS = 2.5
T0_W_BPS = 1.5
T0_W_FPS = 0.5
T0_W_BURST_PPS = 0.8
T0_W_BURST_BPS = 0.6
T0_W_BURST_FPS = 0.3

T0_GATE_RISK_THRESHOLD = 5.0        # SCORING_T0_GATE_RISK_THRESHOLD
T0_ATTACK_RISK_THRESHOLD = 6.0      # SCORING_T0_ATTACK_RISK_THRESHOLD
GATE_PERSISTENCE_WINDOWS = 3        # SCORING_GATE_PERSISTENCE_WINDOWS
DOMINANT_FLOOR = 0.15               # SCORING_DOMINANT_FLOOR

# Per-channel minimum inbound packets before Tier-1 scores (all 10).
TCP_MIN_PKTS = 10
UDP_MIN_PKTS = 10
ICMP_MIN_PKTS = 10
DIST_MIN_PKTS = 10
L3_MIN_PKTS = 10
OFFPROTO_MIN_PKTS = 10

# Fallback windows when the profile leaves them 0 (pick_* helpers).
DEFAULT_FREEZE_WINDOWS = 60         # SCORING_DEFAULT_FREEZE_WINDOWS
DEFAULT_THAW_WINDOWS = 30           # SCORING_DEFAULT_THAW_WINDOWS
DEFAULT_WARMUP_WINDOWS = 400        # SERVICE_DETECTION_DEFAULT_WARMUP_WINDOWS

# Per-profile fallbacks when services.json leaves the knob unset.
# DEFAULT_VARIANCE_CEILING: raised from the C oracle's 3.0 to 6.0 — network
# PPS/BPS are heavy-tailed (Pareto-ish), so a tight ±3σ winsorisation starves
# the baseline on legitimate flash crowds. ±6σ keeps definitive attack spikes
# clamped while letting natural bursts update the baseline.
DEFAULT_ALPHA = 0.05
DEFAULT_VARIANCE_CEILING = 6.0

# ---------------------------------------------------------------------------
# Enums — mirror the C enums (kept identical to wire_parser for consistency).
# ---------------------------------------------------------------------------

PHASE_WARMUP, PHASE_NORMAL, PHASE_SUSPICIOUS, PHASE_ATTACK = 0, 1, 2, 3

PROTO_TCP, PROTO_UDP, PROTO_ICMP = 1, 2, 3
PROTO_CATCHALL_TCP, PROTO_CATCHALL_UDP = 4, 5
PROTO_CATCHALL_ICMP, PROTO_CATCHALL_OTHER = 6, 7

# enum service_dominant_channel (scoring.h order; matches wire_parser).
(DOM_NONE, DOM_PPS, DOM_BPS, DOM_FPS, DOM_TCP, DOM_UDP,
 DOM_ICMP, DOM_DIST, DOM_L3, DOM_OFFPROTO) = range(10)

_PROTO_NAME_TO_KIND_SPECIFIC = {"TCP": PROTO_TCP, "UDP": PROTO_UDP,
                                "ICMP": PROTO_ICMP}
_PROTO_NAME_TO_KIND_CATCHALL = {"tcp": PROTO_CATCHALL_TCP,
                                "udp": PROTO_CATCHALL_UDP,
                                "icmp": PROTO_CATCHALL_ICMP,
                                "other": PROTO_CATCHALL_OTHER}


def ip_to_int(ip_str: str) -> int:
    """Dotted-quad -> host-order uint32, matching C key.target_ip
    (= rte_be_to_cpu_32 of the network-order address)."""
    return struct.unpack(">I", socket.inet_aton(ip_str))[0]


# ---------------------------------------------------------------------------
# Per-slot profile parameters (only the C-consumed fields).
# ---------------------------------------------------------------------------


@dataclass
class ProfileParams:
    name: str
    alpha: float
    variance_ceiling: float
    baseline_freeze_windows: int
    thaw_cooldown_windows: int
    warmup_windows: int
    absolute_pps_threshold: float
    absolute_bps_threshold: float
    absolute_fps_threshold: float

    # --- P6 post-parity detection fixes (per-profile, default OFF) ---------
    # Each flag defaults to False, which reproduces the C engine's behaviour
    # bit-for-bit (the frozen parity oracle). Set to true in a profile's
    # "detection_fixes" section to opt that slot into the corrected logic.
    #
    #   fix_fps_source  — feed the fps EWMA baseline the COMMON unique-flows
    #                     estimate (the same source the CUSUM observes) instead
    #                     of the proto-specific estimate. Fixes the baseline/
    #                     observation mismatch AND the ICMP false-fps-breach
    #                     (where the proto estimate is always 0).
    #   fix_frag_zscore — score the IP-fragment ratio with a real EWMA z-score
    #                     instead of the hardcoded `frag_r * 20` ramp.
    fix_fps_source: bool = False
    fix_frag_zscore: bool = False

    @staticmethod
    def from_json(name: str, prof: dict) -> "ProfileParams":
        """Build from a services.json profile object, applying the SAME
        '<=0 means use default' fallbacks the C pick_* helpers apply."""
        t0 = prof.get("tier0", {}) or {}
        t1 = prof.get("tier1", {}) or {}
        fixes = prof.get("detection_fixes", {}) or {}

        def pos_or(value, default):
            try:
                v = float(value)
            except (TypeError, ValueError):
                return default
            return v if v > 0.0 else default

        def uint_or(value, default):
            try:
                v = int(value)
            except (TypeError, ValueError):
                return default
            return v if v > 0 else default

        def nonneg(value):
            try:
                v = float(value)
            except (TypeError, ValueError):
                return 0.0
            return v if v > 0.0 else 0.0   # 0 disables the channel (C semantics)

        return ProfileParams(
            name=name,
            alpha=pos_or(t0.get("alpha"), DEFAULT_ALPHA),
            variance_ceiling=pos_or(t0.get("variance_ceiling_factor"),
                                    DEFAULT_VARIANCE_CEILING),
            baseline_freeze_windows=uint_or(t1.get("baseline_freeze_windows"),
                                            DEFAULT_FREEZE_WINDOWS),
            thaw_cooldown_windows=uint_or(t1.get("thaw_cooldown_windows"),
                                          DEFAULT_THAW_WINDOWS),
            warmup_windows=uint_or(t1.get("warmup_windows"),
                                   DEFAULT_WARMUP_WINDOWS),
            absolute_pps_threshold=nonneg(t0.get("absolute_pps_threshold")),
            absolute_bps_threshold=nonneg(t0.get("absolute_bps_threshold")),
            absolute_fps_threshold=nonneg(t0.get("absolute_fps_threshold")),
            fix_fps_source=bool(fixes.get("fps_source", False)),
            fix_frag_zscore=bool(fixes.get("frag_zscore", False)),
        )


# Built-in fallback used when a slot's profile can't be resolved (mirrors the
# C "profile NULL -> all defaults" path; every C slot normally has a profile).
DEFAULT_PROFILE = ProfileParams(
    name="<default>",
    alpha=DEFAULT_ALPHA,
    variance_ceiling=DEFAULT_VARIANCE_CEILING,
    baseline_freeze_windows=DEFAULT_FREEZE_WINDOWS,
    thaw_cooldown_windows=DEFAULT_THAW_WINDOWS,
    warmup_windows=DEFAULT_WARMUP_WINDOWS,
    absolute_pps_threshold=0.0,
    absolute_bps_threshold=0.0,
    absolute_fps_threshold=0.0,
)


@dataclass
class DetectionConfig:
    """Loaded view of services.json: learning_mode + a per-slot resolver."""
    learning_mode: bool
    # (ip_int, port, proto_kind) -> ProfileParams
    by_key: dict
    profiles: dict   # name -> ProfileParams

    def params_for(self, ip_int: int, port: int, proto_kind: int) -> ProfileParams:
        p = self.by_key.get((ip_int, port, proto_kind))
        return p if p is not None else DEFAULT_PROFILE


def load_config(services_json: dict) -> DetectionConfig:
    """Replicate the C registry's slot->profile resolution from services.json.

    Specific services (TCP/UDP/ICMP on a port) come from the "services" list;
    catchall slots (port 0) come from "catchall_assignments[ip][proto]". The
    resulting key tuples match the service_key the snapshot carries.
    """
    learning_mode = bool(services_json.get("learning_mode", False))

    profiles = {}
    for name, prof in (services_json.get("profiles", {}) or {}).items():
        profiles[name] = ProfileParams.from_json(name, prof)

    def resolve(name):
        return profiles.get(name, DEFAULT_PROFILE)

    by_key = {}

    # Explicit services -> specific proto_kind slots.
    for svc in services_json.get("services", []) or []:
        try:
            ip = ip_to_int(svc["target_ip"])
            port = int(svc.get("port", 0))
            kind = _PROTO_NAME_TO_KIND_SPECIFIC.get(str(svc.get("proto", "")).upper())
        except (KeyError, ValueError, OSError):
            continue
        if kind is None:
            continue
        by_key[(ip, port, kind)] = resolve(svc.get("profile"))

    # Catchall assignments -> CATCHALL_* slots (port 0).
    for ip_str, protos in (services_json.get("catchall_assignments", {}) or {}).items():
        try:
            ip = ip_to_int(ip_str)
        except OSError:
            continue
        for proto_family, pname in (protos or {}).items():
            kind = _PROTO_NAME_TO_KIND_CATCHALL.get(str(proto_family).lower())
            if kind is None:
                continue
            by_key[(ip, 0, kind)] = resolve(pname)

    return DetectionConfig(learning_mode=learning_mode, by_key=by_key,
                           profiles=profiles)
