# layer3_v1.py — Layer 3 V1 scoring, policy, and bridge socket listener
#
# Responsibilities (this file only):
#   - extract features from a per-source snapshot dict
#   - compute five sub-scores
#   - maintain per-source persistence memory
#   - fuse sub-scores into a single suspicious_score in [0, 1]
#   - apply evidence-damping and contribution-gating safeguards
#   - run the per-source policy state machine
#   - return a PolicyDecision (action, TTL, reason codes) each window
#   - export active policies to the policy file atomically
#   - listen on the UNIX bridge socket for C→Python snapshots
#   - process completed windows and update shared_state
#
# NOT in this file:
#   - dashboard / API layer
#
# Ordering contract:
#   score_source(snap) MUST be called before generate_policy() for the same
#   (src_ip, dst_ip, window).  score_source() writes the current window's
#   final score into _persistence, which generate_policy() then reads to
#   determine whether persistence requirements for strong actions are met.
#
# Record types received from C bridge (newline-delimited JSON):
#   src_snapshot  — one source entity for one victim in one window
#   window_end    — signals that all snapshots for a victim window have arrived
#
# Public API:
#   score_source(snap)                          -> ScoringResult dict
#   generate_policy(src_ip, dst_ip, score_res)  -> PolicyDecision
#   process_window_end(dst_ip, meta)            -> None
#   export_policies()                           -> int
#   start_listener()                            -> None
#   stop_listener()                             -> None
#   clear_victim_persistence(dst_ip)            -> None
#   clear_source_persistence(src_ip, dst_ip)    -> None
#   clear_victim_policies(dst_ip)               -> None
#   clear_source_policy(src_ip, dst_ip)         -> None

import json
import math
import os
import socket
import threading
import time
from collections import deque
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple

import config
from shared_state import (
    l3,
    SourceEntry, PolicyEntry, L3Event,
    EVENT_ATTACK_START, EVENT_ATTACK_END, EVENT_POLICY_SET,
    EVENT_POLICY_ESCALATE, EVENT_POLICY_DEESCALATE,
    EVENT_SOURCE_CLEARED,
)

# =============================================================================
# SECTION 1 — Types
# =============================================================================

# ScoringResult returned by score_source().
# {
#   "score":     float in [0, 1],
#   "subscores": {"contribution": f, "protocol_abnormality": f,
#                 "handshake_abnormality": f, "persistence": f,
#                 "concentration": f},
#   "context":   "TCP" | "UDP" | "ICMP" | "MIXED",
#   "features":  dict of extracted feature values (no private helpers),
#   "flags":     list of short reason strings for dominant sub-scores,
# }
ScoringResult = Dict

# Internal feature dict produced by extract_features().
# Keys starting with "_" are private helpers for sub-score functions.
# Keys without "_" are the public V1 feature set.
Features = Dict

# =============================================================================
# SECTION 2 — Persistence memory (scoring)
#
# { (src_ip, dst_ip): deque(maxlen=PERSISTENCE_WINDOW_SIZE) }
#
# Each entry holds the final suspicious_score from a past window.
# Written by score_source() AFTER the full score is computed so that a
# source's current window never influences its own persistence sub-score.
# =============================================================================

_persistence: Dict[Tuple[str, str], deque] = {}

# =============================================================================
# SECTION 3 — Utility
# =============================================================================

def _clamp(v: float, lo: float = 0.0, hi: float = 1.0) -> float:
    return lo if v < lo else (hi if v > hi else v)


def _safe_ratio(numerator: int, denominator: int) -> float:
    """Return numerator / denominator, clamped to [0, 1]. Returns 0 if denom <= 0."""
    if denominator <= 0:
        return 0.0
    return _clamp(numerator / denominator)

# =============================================================================
# SECTION 4 — Feature extraction
# =============================================================================

def extract_features(snap: dict) -> Features:
    """
    Build the V1 feature vector from a raw source snapshot dict.

    All raw fields are sanitised: missing keys default to zero; denominators
    are guarded.  TCP flag ratios are only computed when tcp_pkts >= MIN_TCP_PKTS;
    below that threshold they are set to 0.0 to prevent unstable ratios from
    tiny samples from dominating the score.

    Private helpers (prefixed "_") carry derived values needed by the
    sub-score functions but are not part of the public feature set.
    """
    # --- Raw counters from bridge snapshot ---
    pkt_count         = max(int(snap.get("pkt_count",          0)), 0)
    byte_count        = max(int(snap.get("byte_count",         0)), 0)
    tcp_pkts          = max(int(snap.get("tcp_pkts",           0)), 0)
    syn_pkts          = max(int(snap.get("syn_pkts",           0)), 0)
    rst_pkts          = max(int(snap.get("rst_pkts",           0)), 0)
    ack_only_pkts     = max(int(snap.get("ack_only_pkts",      0)), 0)
    unique_dst_ports  = max(int(snap.get("unique_dst_ports",   1)), 1)
    unique_flows      = max(int(snap.get("unique_flows",       0)), 0)
    victim_total_pkts  = max(int(snap.get("victim_total_pkts",  1)), 1)
    victim_total_bytes = max(int(snap.get("victim_total_bytes", 1)), 1)
    duration_sec      = max(float(snap.get("duration_sec",  1.0)), 0.001)

    # --- Volume features ---
    source_pps_to_victim = pkt_count  / duration_sec
    source_bps_to_victim = byte_count * 8.0 / duration_sec
    source_flow_rate     = unique_flows / duration_sec
    avg_bytes_per_packet = byte_count / max(pkt_count, 1)

    # active_duration: how long this source was active in the window.
    # In V1 the C bridge resets per-source state every second, so this is
    # always <= duration_sec (nominally 1.0).  When the bridge gains a
    # per-source first_seen field, replace this with
    # (window_end_ms - first_seen_ms) / 1000.0.
    active_duration = min(duration_sec, 1.0)

    # --- TCP ratio features ---
    # Require MIN_TCP_PKTS before trusting flag ratios.
    if tcp_pkts >= config.MIN_TCP_PKTS:
        source_syn_ratio      = _safe_ratio(syn_pkts,      tcp_pkts)
        source_rst_ratio      = _safe_ratio(rst_pkts,      tcp_pkts)
        source_ack_only_ratio = _safe_ratio(ack_only_pkts, tcp_pkts)
    else:
        source_syn_ratio      = 0.0
        source_rst_ratio      = 0.0
        source_ack_only_ratio = 0.0

    # --- Share features ---
    share_of_total_attack_pkts  = pkt_count  / victim_total_pkts
    share_of_total_attack_bytes = byte_count / victim_total_bytes

    return {
        # Public V1 features
        "source_pps_to_victim":         source_pps_to_victim,
        "source_bps_to_victim":         source_bps_to_victim,
        "source_flow_rate":             source_flow_rate,
        "source_syn_ratio":             source_syn_ratio,
        "source_rst_ratio":             source_rst_ratio,
        "source_ack_only_ratio":        source_ack_only_ratio,
        "avg_bytes_per_packet":         avg_bytes_per_packet,
        "unique_dst_ports":             unique_dst_ports,
        "active_duration":              active_duration,
        "share_of_total_attack_pkts":   share_of_total_attack_pkts,
        "share_of_total_attack_bytes":  share_of_total_attack_bytes,
        # Private helpers (sub-score functions read these)
        "_pkt_count":           pkt_count,
        "_tcp_pkts":            tcp_pkts,
        "_duration_sec":        duration_sec,
        "_victim_total_pkts":   victim_total_pkts,
    }

# =============================================================================
# SECTION 5 — Attack context resolution
# =============================================================================

def resolve_attack_context(snap: dict, feats: Features) -> str:
    """
    Map the Layer 2 attack_type label from the snapshot to a scoring context.

    The context selects:
      - which weight row to use in config.WEIGHTS
      - which formula to use in protocol_abnormality and handshake_abnormality

    Falls back to TCP dominance inference when attack_type is absent or
    unrecognised.  Falls back to MIXED when no clear dominance is found.
    MIXED is always a valid fallback and its weight set is deliberately
    conservative.
    """
    attack_type = str(snap.get("attack_type", "")).upper().strip()

    # Direct lookup from Layer 2 label.
    ctx = config.ATTACK_TYPE_TO_CONTEXT.get(attack_type)
    if ctx is not None:
        return ctx

    # Fallback: infer from TCP fraction in this source's own traffic.
    pkt_count = feats["_pkt_count"]
    if pkt_count > 0 and feats["_tcp_pkts"] / pkt_count > 0.70:
        return "TCP"

    # Without per-source UDP/ICMP counters in V1 we cannot distinguish them.
    return "MIXED"

# =============================================================================
# SECTION 6 — Sub-score functions
# Each function returns a float in [0, 1].
# Each function is pure: no side-effects, no global reads except config.
# =============================================================================

def compute_contribution_score(feats: Features) -> float:
    """
    How much of the victim's attack load does this source carry?

    Three signals are averaged:
      - packet share:  what fraction of victim packets came from this source
      - byte share:    what fraction of victim bytes came from this source
      - flow share:    this source's flow rate vs 20% of victim's flow rate

    Each signal saturates at the normalisation reference (config.CONTRIBUTION_NORM_*).
    A source carrying 20% of attack traffic on any dimension reaches score 1.0
    on that signal.  Averaging prevents a source that dominates only one
    dimension from scoring artificially high.
    """
    s_pkt  = min(feats["share_of_total_attack_pkts"]  / config.CONTRIBUTION_NORM_PKT,  1.0)
    s_byte = min(feats["share_of_total_attack_bytes"] / config.CONTRIBUTION_NORM_BYTE, 1.0)

    victim_fps = feats["_victim_total_pkts"] / feats["_duration_sec"]
    flow_norm  = max(victim_fps * config.CONTRIBUTION_NORM_FLOW, 1.0)  # guard /0
    s_flow = min(feats["source_flow_rate"] / flow_norm, 1.0)

    return _clamp((s_pkt + s_byte + s_flow) / 3.0)


def compute_protocol_abnormality_score(feats: Features, context: str) -> float:
    """
    Does this source's protocol behaviour deviate from legitimate traffic?

    TCP context:
        Driven by TCP flag ratios.  Any of SYN-heavy, RST-heavy, or ACK-only-
        heavy traffic is abnormal.  The maximum of the three signals is used so
        that single-vector floods (e.g. pure SYN) score fully.

    UDP context:
        No flag information available at Layer 3 V1 resolution.  Raw bandwidth
        contribution relative to a reference BPS is used instead.

    ICMP context:
        Packet rate relative to a reference PPS.

    MIXED:
        Tries TCP flag analysis first when TCP evidence is sufficient, then
        takes the max with a volume-based score so the stronger signal wins.
    """
    if context == "TCP":
        syn_anom = min(feats["source_syn_ratio"]      / config.TCP_SYN_SATURATION, 1.0)
        rst_anom = min(feats["source_rst_ratio"]      / config.TCP_RST_SATURATION, 1.0)
        ack_anom = min(feats["source_ack_only_ratio"] / config.TCP_ACK_SATURATION, 1.0)
        return _clamp(max(syn_anom, rst_anom, ack_anom))

    if context == "UDP":
        return _clamp(feats["source_bps_to_victim"] / config.UDP_REFERENCE_BPS)

    if context == "ICMP":
        return _clamp(feats["source_pps_to_victim"] / config.ICMP_REFERENCE_PPS)

    # MIXED: use whichever signal is strongest.
    if feats["_tcp_pkts"] >= config.MIN_TCP_PKTS:
        syn_anom  = min(feats["source_syn_ratio"]      / config.TCP_SYN_SATURATION, 1.0)
        rst_anom  = min(feats["source_rst_ratio"]      / config.TCP_RST_SATURATION, 1.0)
        ack_anom  = min(feats["source_ack_only_ratio"] / config.TCP_ACK_SATURATION, 1.0)
        flag_score = _clamp(max(syn_anom, rst_anom, ack_anom))
    else:
        flag_score = 0.0

    vol_score = _clamp(feats["source_bps_to_victim"] / config.UDP_REFERENCE_BPS)
    return _clamp(max(flag_score, vol_score))


def compute_handshake_abnormality_score(feats: Features, context: str) -> float:
    """
    Does this source send SYNs without completing TCP handshakes?

    Incompleteness = syn_ratio - ack_only_ratio.

    A source sending only SYNs:  syn_ratio → 1.0, ack_only_ratio → 0.0,
    incompleteness → 1.0.

    A source completing connections has ACK-data packets (ack_only_ratio up),
    which closes the gap and reduces the score.

    Only meaningful for TCP-heavy contexts.  For UDP/ICMP returns 0.0 directly.
    For MIXED the signal is halved because TCP dominance is unconfirmed.

    Requires at least MIN_TCP_PKTS for a stable estimate; returns 0.0 otherwise.
    """
    if context not in ("TCP", "MIXED"):
        return 0.0

    if feats["_tcp_pkts"] < config.MIN_TCP_PKTS:
        return 0.0

    incompleteness = feats["source_syn_ratio"] - feats["source_ack_only_ratio"]

    # For MIXED: dampen because TCP dominance is uncertain.
    if context == "MIXED":
        incompleteness *= 0.5

    return _clamp(incompleteness / config.HANDSHAKE_INCOMPLETENESS_NORM)


def compute_concentration_score(feats: Features) -> float:
    """
    How narrowly focused is this source on the attacked victim and service?

    Two independent signals are averaged:

    port_concentration:
        Low unique_dst_ports → source hammers one port, not scanning.
        Uses log1p so single-port sources score near 1.0 and a handful of
        ports gives a moderate score.
          1 port  → 1.0
          2 ports → ~0.59
          5 ports → ~0.37
         10 ports → ~0.26

    share_concentration:
        High fraction of victim attack packets → source is a dominant
        contributor, not scattered across many targets.
        Saturates at config.CONCENTRATION_SHARE_NORM (15%).
    """
    port_conc  = 1.0 / (1.0 + math.log1p(max(feats["unique_dst_ports"] - 1, 0)))
    share_conc = min(feats["share_of_total_attack_pkts"] / config.CONCENTRATION_SHARE_NORM, 1.0)

    return _clamp((port_conc + share_conc) / 2.0)


def compute_persistence_score(src_ip: str, dst_ip: str) -> float:
    """
    How consistently has this source been suspicious across recent windows?

    Reads _persistence[(src_ip, dst_ip)] — a deque of past final scores.
    A past window counts as "suspicious" if its score was at or above
    config.PERSISTENCE_SUSPICIOUS_THRESHOLD.

    Returns 0.0 for sources with no history (first window ever seen).

    NOTE: called BEFORE _persistence is updated for the current window.
    The current window's final score is appended by score_source() after
    this function returns, so a source never influences its own persistence.
    """
    history = _persistence.get((src_ip, dst_ip))
    if not history:
        return 0.0

    suspicious_windows = sum(
        1 for s in history
        if s >= config.PERSISTENCE_SUSPICIOUS_THRESHOLD
    )
    return _clamp(suspicious_windows / config.PERSISTENCE_WINDOW_SIZE)

# =============================================================================
# SECTION 7 — Weighted fusion
# =============================================================================

def fuse_subscores(subscores: dict, context: str) -> float:
    """
    Compute the raw suspicious score as a weighted sum of the five sub-scores.

    Uses config.WEIGHTS[context].  All weight rows sum to 1.0, so the raw
    score is already in [0, 1] before safeguards are applied.

    The context is guaranteed to be a valid key in config.WEIGHTS because
    resolve_attack_context() always returns one of TCP/UDP/ICMP/MIXED and
    config.WEIGHTS defines all four rows.
    """
    weights = config.WEIGHTS[context]
    return _clamp(sum(weights[k] * subscores[k] for k in weights))

# =============================================================================
# SECTION 8 — Safeguards
# =============================================================================

def apply_safeguards(
    raw_score: float,
    feats: Features,
    persistence: float,
) -> float:
    """
    Apply two conservative corrections to the fused score.

    Safeguard 1 — Low-evidence damping:
        If pkt_count < MIN_EVIDENCE_PKTS the ratio features are unreliable
        (small samples produce extreme ratios).  The score is multiplied by
        (pkt_count / MIN_EVIDENCE_PKTS), scaling it toward zero.
        A source with 1 packet cannot exceed score 0.1 regardless of flags.

    Safeguard 2 — Low-contribution cap:
        A source contributing < 0.1% of victim traffic is likely a background
        talker that happens to have anomalous ratios rather than an attacker.
        Unless it has been consistently suspicious (persistence >= 0.60),
        cap the score at CONTRIBUTION_GATE_CAP.
        This ensures tiny sources never reach RATE_LIMIT_HARD or BLOCK from
        a single window of weird-looking but low-volume traffic.
    """
    score     = raw_score
    pkt_count = feats["_pkt_count"]

    # Safeguard 1 — Low-evidence damping.
    if pkt_count < config.MIN_EVIDENCE_PKTS:
        score *= pkt_count / config.MIN_EVIDENCE_PKTS

    # Safeguard 2 — Low-contribution cap.
    if (feats["share_of_total_attack_pkts"] < config.MIN_CONTRIBUTION_GATE
            and persistence < 0.60):
        score = min(score, config.CONTRIBUTION_GATE_CAP)

    return _clamp(score)

# =============================================================================
# SECTION 9 — Reason codes
# =============================================================================

# Sub-scores above this fraction of their maximum are included in reason flags.
_REASON_THRESHOLD = 0.60

def build_reason_flags(subscores: dict) -> list:
    """
    Return a compact list of short strings naming the dominant sub-scores.

    A sub-score is included when it is >= _REASON_THRESHOLD.  This gives the
    policy layer (and dashboard) a quick explanation without a full SHAP-style
    decomposition.

    Examples:
      ["HIGH_CONTRIBUTION", "SYN_HEAVY"]
      ["PERSISTENT", "PORT_CONCENTRATED"]
    """
    labels = {
        "contribution":          "HIGH_CONTRIBUTION",
        "protocol_abnormality":  "PROTO_ABNORMAL",
        "handshake_abnormality": "SYN_HEAVY",
        "persistence":           "PERSISTENT",
        "concentration":         "PORT_CONCENTRATED",
    }
    return [labels[k] for k, v in subscores.items() if v >= _REASON_THRESHOLD]

# =============================================================================
# SECTION 10 — Scoring persistence state management
# =============================================================================

def clear_victim_persistence(dst_ip: str) -> None:
    """
    Remove all persistence history for every source tracked against dst_ip.

    Call this when Layer 2 signals that an attack on dst_ip has ended, so
    stale history does not carry over into the next attack session.
    """
    keys = [k for k in _persistence if k[1] == dst_ip]
    for k in keys:
        del _persistence[k]


def clear_source_persistence(src_ip: str, dst_ip: str) -> None:
    """Remove persistence history for one (src_ip, dst_ip) pair."""
    _persistence.pop((src_ip, dst_ip), None)

# =============================================================================
# SECTION 11 — Public scoring entrypoint
# =============================================================================

def score_source(snap: dict) -> ScoringResult:
    """
    Compute the Layer 3 V1 suspicious score for one source snapshot.

    This is the single public entry point for the scoring engine.  It is
    designed to be called once per source per victim per second while an
    attack session is active.

    Pipeline:
        snap
          → extract_features()
          → resolve_attack_context()
          → compute_contribution_score()
          → compute_protocol_abnormality_score()
          → compute_handshake_abnormality_score()
          → compute_concentration_score()
          → compute_persistence_score()   ← reads history (previous windows)
          → fuse_subscores()
          → apply_safeguards()
          → update _persistence            ← writes history (current window)

    Parameters
    ----------
    snap : dict
        One src_snapshot record from the Layer 3 bridge.  Required fields:
            src_ip, dst_ip, pkt_count, byte_count, tcp_pkts, syn_pkts,
            rst_pkts, ack_only_pkts, unique_dst_ports, unique_flows,
            victim_total_pkts, victim_total_bytes, duration_sec, attack_type

    Returns
    -------
    ScoringResult dict:
        "score"     float in [0, 1]
        "subscores" five named sub-scores, each in [0, 1]
        "context"   resolved attack context string
        "features"  public feature vector (no "_" private helpers)
        "flags"     compact list of dominant sub-score reason strings
    """
    src_ip = str(snap.get("src_ip", ""))
    dst_ip = str(snap.get("dst_ip", ""))

    # 1. Feature extraction.
    feats = extract_features(snap)

    # 2. Attack context.
    context = resolve_attack_context(snap, feats)

    # 3. Four stateless sub-scores.
    contribution          = compute_contribution_score(feats)
    protocol_abnormality  = compute_protocol_abnormality_score(feats, context)
    handshake_abnormality = compute_handshake_abnormality_score(feats, context)
    concentration         = compute_concentration_score(feats)

    # 4. Persistence sub-score — reads history from PREVIOUS windows only.
    #    Must be called before _persistence is updated for this window.
    persistence = compute_persistence_score(src_ip, dst_ip)

    subscores = {
        "contribution":          contribution,
        "protocol_abnormality":  protocol_abnormality,
        "handshake_abnormality": handshake_abnormality,
        "persistence":           persistence,
        "concentration":         concentration,
    }

    # 5. Weighted fusion.
    raw_score = fuse_subscores(subscores, context)

    # 6. Safeguards.
    final_score = apply_safeguards(raw_score, feats, persistence)

    # 7. Update persistence memory with this window's final score.
    #    Happens after the score is finalised so it does not affect the current
    #    window's persistence sub-score.
    key = (src_ip, dst_ip)
    if key not in _persistence:
        _persistence[key] = deque(maxlen=config.PERSISTENCE_WINDOW_SIZE)
    _persistence[key].append(final_score)

    # 8. Build compact reason flags.
    flags = build_reason_flags(subscores)

    # Strip private helpers before returning features to callers.
    public_features = {k: v for k, v in feats.items() if not k.startswith("_")}

    return {
        "score":     final_score,
        "subscores": subscores,
        "context":   context,
        "features":  public_features,
        "flags":     flags,
    }


# =============================================================================
# SECTION 12 — Policy generation: types and severity constants
# =============================================================================

# Numeric severity for each action — used only for escalation/de-escalation
# comparison.  Not exported; callers use action name strings.
_SEVERITY: Dict[str, int] = {
    "ALLOW":           0,
    "RATE_LIMIT_SOFT": 1,
    "RATE_LIMIT_HARD": 2,
    "BLOCK":           3,
}

# One-step-down table: the action one level below each action.
_STEP_DOWN: Dict[str, str] = {
    "BLOCK":           "RATE_LIMIT_HARD",
    "RATE_LIMIT_HARD": "RATE_LIMIT_SOFT",
    "RATE_LIMIT_SOFT": "ALLOW",
    "ALLOW":           "ALLOW",
}


@dataclass
class PolicyDecision:
    """
    The output of generate_policy() for one (src_ip, dst_ip) window.

    Fields
    ------
    action:       The action to enforce this window.
    ttl_sec:      Full TTL for this action; 0 means no entry needed in C table.
    rate_pps:     Packet-per-second limit; 0 for ALLOW and BLOCK.
    score:        Suspicious score from the current window.
    subscores:    Five sub-scores from the current window.
    flags:        Dominant reason codes from the current window.
    consecutive:  Consecutive suspicious windows counted from _persistence tail.
    changed:      True if action level changed from the previous window.
    escalated:    True if action level increased this window.
    deescalating: True if score dropped but action is being held (hysteresis).
    """
    src_ip:       str
    dst_ip:       str
    action:       str
    ttl_sec:      int
    rate_pps:     int
    score:        float
    subscores:    dict
    flags:        List[str]
    consecutive:  int
    changed:      bool
    escalated:    bool
    deescalating: bool


# =============================================================================
# SECTION 13 — Policy state memory
#
# One _PolicyState per (src_ip, dst_ip) pair.  Tracks the current enforced
# action and the de-escalation hold counter.
# =============================================================================

@dataclass
class _PolicyState:
    action:               str    # current action
    deescalation_counter: int    # consecutive windows where target < current
    changed_at:           float  # unix timestamp of last action change


_policy_states: Dict[Tuple[str, str], _PolicyState] = {}

# =============================================================================
# SECTION 14 — Policy state machine helpers
# =============================================================================

def _consecutive_suspicious_tail(src_ip: str, dst_ip: str) -> int:
    """
    Count how many of the most recent windows were all suspicious, counting
    backwards from the newest until a non-suspicious window is found.

    Called AFTER score_source() has updated _persistence for the current
    window, so the current window's score is included in the count.

    Examples (PERSISTENCE_SUSPICIOUS_THRESHOLD = 0.50):
        history = [0.80, 0.90, 0.92]  →  3
        history = [0.80, 0.30, 0.92]  →  1  (0.30 breaks the streak)
        history = [0.30, 0.20, 0.10]  →  0
        history = []                  →  0
    """
    history = _persistence.get((src_ip, dst_ip))
    if not history:
        return 0
    count = 0
    for score in reversed(history):
        if score >= config.PERSISTENCE_SUSPICIOUS_THRESHOLD:
            count += 1
        else:
            break
    return count


def _target_action(score: float, consecutive: int) -> str:
    """
    Determine what action level is warranted right now, ignoring any current
    policy state and hysteresis.

    BLOCK requires both a high score AND enough consecutive suspicious windows.
    RATE_LIMIT_HARD similarly requires persistence.
    RATE_LIMIT_SOFT only requires the score threshold (persistence = 1 window).
    ALLOW is the default when no threshold is crossed.

    The state machine in generate_policy() then applies hysteresis on top of
    this target to decide the actual enforced action.
    """
    if (score >= config.THRESHOLD_BLOCK
            and consecutive >= config.PERSISTENCE_REQUIRED["BLOCK"]):
        return "BLOCK"

    if (score >= config.THRESHOLD_RATE_LIMIT_HARD
            and consecutive >= config.PERSISTENCE_REQUIRED["RATE_LIMIT_HARD"]):
        return "RATE_LIMIT_HARD"

    if score >= config.THRESHOLD_RATE_LIMIT_SOFT:
        return "RATE_LIMIT_SOFT"

    return "ALLOW"

# =============================================================================
# SECTION 15 — Policy generation: main function
# =============================================================================

def generate_policy(src_ip: str, dst_ip: str,
                    scoring_result: ScoringResult) -> PolicyDecision:
    """
    Run one cycle of the per-source policy state machine.

    Must be called AFTER score_source() for the same (src_ip, dst_ip, window)
    so that _persistence already contains the current window's score.

    State machine rules
    -------------------
    Escalation (target_severity > current_severity):
        Apply immediately.  Reset de-escalation counter.

    Same level (target_severity == current_severity):
        Renew TTL.  Reset de-escalation counter.
        Anti-flapping: any upward pressure resets the hold counter.

    De-escalation (target_severity < current_severity):
        Increment de-escalation counter.
        - If counter < DEESCALATION_WINDOWS: hold current action (hysteresis).
          TTL is still renewed to keep the policy active during the hold.
        - If counter >= DEESCALATION_WINDOWS: step down exactly ONE level.
          Reset counter.

    De-escalation is always one step at a time.  To fall from BLOCK to ALLOW
    requires (2 steps × DEESCALATION_WINDOWS) consecutive low-score windows.

    BLOCK is never permanent: it has a finite TTL that is only renewed when
    the score still warrants it.  If Python stops calling generate_policy,
    C's TTL countdown will expire the policy within TTL_DEFAULTS["BLOCK"].

    Parameters
    ----------
    src_ip, dst_ip : str
        Identify the (source, victim) pair being evaluated.
    scoring_result : ScoringResult
        The dict returned by score_source() for the same window.

    Returns
    -------
    PolicyDecision dataclass.
    """
    score    = scoring_result["score"]
    subscores = scoring_result["subscores"]
    flags    = scoring_result["flags"]
    now      = time.monotonic()

    # How many consecutive suspicious windows (including the current one)?
    consecutive = _consecutive_suspicious_tail(src_ip, dst_ip)

    # What action would be warranted right now, ignoring current state?
    target = _target_action(score, consecutive)
    target_sev = _SEVERITY[target]

    # Retrieve or initialise policy state for this pair.
    key = (src_ip, dst_ip)
    state = _policy_states.get(key)
    if state is None:
        state = _PolicyState(
            action="ALLOW",
            deescalation_counter=0,
            changed_at=now,
        )
        _policy_states[key] = state

    current     = state.action
    current_sev = _SEVERITY[current]

    changed      = False
    escalated    = False
    deescalating = False

    if target_sev > current_sev:
        # ── Escalation: apply immediately ────────────────────────────────────
        state.action               = target
        state.deescalation_counter = 0
        state.changed_at           = now
        changed   = True
        escalated = True

    elif target_sev == current_sev:
        # ── Same level: renew, reset hold counter ────────────────────────────
        state.deescalation_counter = 0
        # action unchanged

    else:
        # ── De-escalation candidate ──────────────────────────────────────────
        state.deescalation_counter += 1

        if state.deescalation_counter >= config.DEESCALATION_WINDOWS:
            # Threshold reached: step down exactly one level.
            state.action               = _STEP_DOWN[current]
            state.deescalation_counter = 0
            state.changed_at           = now
            changed = True
        else:
            # Hold current action (hysteresis): keep enforcing, renew TTL.
            deescalating = True

    new_action = state.action
    ttl        = config.TTL_DEFAULTS.get(new_action, 0)
    rate_pps   = config.RATE_PPS_DEFAULTS.get(new_action, 0)

    return PolicyDecision(
        src_ip       = src_ip,
        dst_ip       = dst_ip,
        action       = new_action,
        ttl_sec      = ttl,
        rate_pps     = rate_pps,
        score        = score,
        subscores    = subscores,
        flags        = flags,
        consecutive  = consecutive,
        changed      = changed,
        escalated    = escalated,
        deescalating = deescalating,
    )

# =============================================================================
# SECTION 16 — Policy state management
# =============================================================================

def clear_victim_policies(dst_ip: str) -> None:
    """
    Remove all policy states for every source tracked against dst_ip.

    Call this together with clear_victim_persistence() when Layer 2 reports
    that an attack on dst_ip has ended.
    """
    keys = [k for k in _policy_states if k[1] == dst_ip]
    for k in keys:
        del _policy_states[k]


def clear_source_policy(src_ip: str, dst_ip: str) -> None:
    """Remove policy state for one (src_ip, dst_ip) pair."""
    _policy_states.pop((src_ip, dst_ip), None)

# =============================================================================
# SECTION 18 — Policy file export
# =============================================================================

def _format_policy_line(action: str, src_ip: str, dst_ip: str) -> str:
    """
    Format one policy file line.

    File format (space-separated, one entry per line):
        ACTION SRC_IP DST_IP TTL RATE_PPS

    TTL and RATE_PPS are derived from config so they always match the
    canonical defaults; individual PolicyDecision objects are not stored
    between windows.
    """
    ttl      = config.TTL_DEFAULTS.get(action, 0)
    rate_pps = config.RATE_PPS_DEFAULTS.get(action, 0)
    return f"{action} {src_ip} {dst_ip} {ttl} {rate_pps}"


def export_policies() -> int:
    """
    Write all active non-ALLOW policies to the policy file atomically.

    Shadow mode  (config.L3_ENFORCE_MODE = False, the default):
        Writes an empty file.  C's reload loop sees a valid zero-entry file
        and enforces nothing.  Policies are generated and logged normally;
        only the file write is suppressed, keeping shadow mode truly inert.

    Enforce mode (config.L3_ENFORCE_MODE = True):
        Writes one line per active non-ALLOW policy sourced from
        _policy_states.  ALLOW entries are skipped — ALLOW means "no
        restriction", which is expressed by the absence of a line.

    Atomic write:
        Content is written to config.L3_POLICY_FILE_TMP first, then
        os.replace() renames it to config.L3_POLICY_FILE_PATH in a single
        kernel operation.  C never reads a partially-written file.

    Returns
    -------
    int
        Number of policy lines written (always 0 in shadow mode).
    """
    lines: List[str] = []

    if config.L3_ENFORCE_MODE:
        for (src_ip, dst_ip), state in _policy_states.items():
            if state.action == "ALLOW":
                continue
            lines.append(_format_policy_line(state.action, src_ip, dst_ip))

    # Write an empty file in shadow mode so C never reads a stale file from
    # a previous enforce-mode session.
    content = "".join(line + "\n" for line in lines)

    try:
        with open(config.L3_POLICY_FILE_TMP, "w") as fh:
            fh.write(content)
        os.replace(config.L3_POLICY_FILE_TMP, config.L3_POLICY_FILE_PATH)
    except OSError as exc:
        # Non-fatal: C keeps enforcing the last successfully written file
        # until the next successful export.
        print(f"[L3] policy export error: {exc}", flush=True)
        return 0

    return len(lines)


# =============================================================================
# SECTION 19 — Window buffer
#
# { dst_ip: [src_snapshot_dict, ...] }
#
# src_snapshot records are accumulated here as they arrive from the C bridge.
# The list is consumed and cleared when the matching window_end record arrives.
# Holds at most one in-progress window per dst_ip at a time; the C bridge
# guarantees all src_snapshots for a window arrive before its window_end.
# =============================================================================

_window_buffer: Dict[str, List[dict]] = {}

# =============================================================================
# SECTION 20 — Window processing
# =============================================================================

def _handle_attack_end(dst_ip: str) -> None:
    """
    Tear down all Layer 3 state for a victim whose attack has just ended.

    Logs ATTACK_END, clears scoring and policy FSM memory, removes all
    shared state for the victim.  Does NOT remove events (kept for history).
    """
    l3.add_event(L3Event(
        timestamp  = time.time(),
        event_type = EVENT_ATTACK_END,
        dst_ip     = dst_ip,
    ))
    clear_victim_persistence(dst_ip)
    clear_victim_policies(dst_ip)
    l3.clear_victim(dst_ip)


def process_window_end(dst_ip: str, meta: dict) -> None:
    """
    Process one completed victim window end-to-end.

    Called when a window_end record arrives from the C bridge for dst_ip.
    Consumes all buffered src_snapshot records for dst_ip, scores each
    source, updates the policy FSM, synchronises shared_state, and exports
    the policy file — all in a single synchronous call.

    Parameters
    ----------
    dst_ip : str
        Victim IP address.
    meta : dict
        The window_end record.  Expected fields:
            det_state         "WARMUP" | "NORMAL" | "SUSPICIOUS" | "ATTACK"
            attack_type       Layer 2 attack_type_str() value
            window_ms         epoch milliseconds of window end
            victim_total_pkts total packets to victim this window
            victim_total_bytes total bytes to victim this window
    """
    det_state          = str(meta.get("det_state",   "NORMAL")).upper()
    attack_type        = str(meta.get("attack_type", "UNKNOWN"))
    window_ms          = int(meta.get("window_ms",    0))
    victim_total_pkts  = max(int(meta.get("victim_total_pkts",  1)), 1)
    victim_total_bytes = max(int(meta.get("victim_total_bytes", 1)), 1)

    snaps = _window_buffer.pop(dst_ip, [])

    # ── Layer 2 says normal/warm-up: check if an attack just ended ───────────
    if det_state in ("NORMAL", "WARMUP"):
        if l3.get_attack_session(dst_ip) is not None:
            _handle_attack_end(dst_ip)
            export_policies()
        # Nothing further to score; discard any buffered snapshots.
        return

    # ── SUSPICIOUS or ATTACK: active session ─────────────────────────────────

    # Log ATTACK_START on the first window of a new session.
    if l3.get_attack_session(dst_ip) is None:
        l3.add_event(L3Event(
            timestamp  = time.time(),
            event_type = EVENT_ATTACK_START,
            dst_ip     = dst_ip,
            detail     = attack_type,
        ))

    l3.update_attack_session_window(dst_ip, det_state, attack_type)

    # ── Score each source and run the policy FSM ──────────────────────────────
    now = time.time()
    scored_entries: List[SourceEntry] = []

    for snap in snaps:
        src_ip = str(snap.get("src_ip", "")).strip()
        if not src_ip:
            continue

        # Inject victim-level totals from window_end so score_source() has
        # accurate share denominators regardless of what the bridge sent.
        snap["victim_total_pkts"]  = victim_total_pkts
        snap["victim_total_bytes"] = victim_total_bytes
        snap["attack_type"]        = attack_type
        snap["det_state"]          = det_state

        result   = score_source(snap)
        decision = generate_policy(src_ip, dst_ip, result)

        scored_entries.append(SourceEntry(
            src_ip     = src_ip,
            dst_ip     = dst_ip,
            score      = result["score"],
            subscores  = result["subscores"],
            context    = result["context"],
            window_ms  = window_ms,
            updated_at = now,
        ))

        if decision.action != "ALLOW":
            l3.set_policy(PolicyEntry(
                src_ip     = src_ip,
                dst_ip     = dst_ip,
                action     = decision.action,
                ttl_sec    = decision.ttl_sec,
                rate_pps   = decision.rate_pps,
                score      = result["score"],
                subscores  = result["subscores"],
                created_at = now,
                expires_at = now + decision.ttl_sec,
            ))
            if decision.changed:
                l3.add_event(L3Event(
                    timestamp  = now,
                    event_type = EVENT_POLICY_ESCALATE if decision.escalated
                                 else EVENT_POLICY_DEESCALATE,
                    dst_ip     = dst_ip,
                    src_ip     = src_ip,
                    action     = decision.action,
                    score      = result["score"],
                ))
            else:
                l3.add_event(L3Event(
                    timestamp  = now,
                    event_type = EVENT_POLICY_SET,
                    dst_ip     = dst_ip,
                    src_ip     = src_ip,
                    action     = decision.action,
                    score      = result["score"],
                ))
        else:
            # Source no longer warrants a policy — remove it from shared state.
            removed = l3.remove_policy(src_ip, dst_ip)
            if removed is not None:
                l3.add_event(L3Event(
                    timestamp  = now,
                    event_type = EVENT_SOURCE_CLEARED,
                    dst_ip     = dst_ip,
                    src_ip     = src_ip,
                    score      = result["score"],
                ))

    # ── Push scored sources and export policies ───────────────────────────────
    if scored_entries:
        l3.update_top_sources(dst_ip, scored_entries)

    export_policies()


# =============================================================================
# SECTION 21 — UNIX socket listener
# =============================================================================

_listener_thread: Optional[threading.Thread] = None
_listener_stop = threading.Event()


def _dispatch_record(line: str) -> None:
    """
    Parse one JSON line and route it to the appropriate handler.

    Silently drops malformed JSON and unknown record types.
    """
    try:
        rec = json.loads(line)
    except json.JSONDecodeError:
        return

    rtype  = rec.get("type", "")
    dst_ip = str(rec.get("dst_ip", "")).strip()

    if not dst_ip:
        return

    if rtype == "src_snapshot":
        if dst_ip not in _window_buffer:
            _window_buffer[dst_ip] = []
        _window_buffer[dst_ip].append(rec)

    elif rtype == "window_end":
        process_window_end(dst_ip, rec)

    # Unknown type: ignored.


def _handle_connection(conn: socket.socket) -> None:
    """
    Read newline-delimited JSON records from one connected client until EOF.
    """
    buf = ""
    try:
        with conn:
            while not _listener_stop.is_set():
                try:
                    chunk = conn.recv(65536)
                except OSError:
                    break
                if not chunk:
                    break
                buf += chunk.decode("utf-8", errors="replace")
                while "\n" in buf:
                    line, buf = buf.split("\n", 1)
                    line = line.strip()
                    if line:
                        _dispatch_record(line)
    except Exception:
        pass


def _run_listener(sock_path: str) -> None:
    """
    Main listener loop.  Runs in a daemon thread.

    Creates the UNIX stream socket, accepts client connections one at a time,
    and delegates each to _handle_connection().  Exits cleanly when
    _listener_stop is set.
    """
    if os.path.exists(sock_path):
        try:
            os.unlink(sock_path)
        except OSError:
            pass

    srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        srv.bind(sock_path)
    except OSError as exc:
        print(f"[L3] listener bind failed ({sock_path}): {exc}", flush=True)
        return

    srv.listen(1)
    srv.settimeout(1.0)  # allows periodic _listener_stop checks

    print(f"[L3] listener started on {sock_path}", flush=True)
    while not _listener_stop.is_set():
        try:
            conn, _ = srv.accept()
        except socket.timeout:
            continue
        except OSError:
            break
        _handle_connection(conn)

    srv.close()
    try:
        os.unlink(sock_path)
    except OSError:
        pass
    print("[L3] listener stopped", flush=True)


def start_listener() -> None:
    """
    Start the UNIX socket listener in a background daemon thread.

    The thread exits when stop_listener() is called or when the process
    terminates.  Safe to call only once per process lifetime.
    """
    global _listener_thread
    _listener_stop.clear()
    _listener_thread = threading.Thread(
        target  = _run_listener,
        args    = (config.L3_BRIDGE_SOCKET_PATH,),
        daemon  = True,
        name    = "l3-bridge-listener",
    )
    _listener_thread.start()


def stop_listener() -> None:
    """Signal the listener thread to stop and wait for it (up to 3 s)."""
    _listener_stop.set()
    if _listener_thread is not None:
        _listener_thread.join(timeout=3.0)


# =============================================================================
# SECTION 17 — Self-test  (python3 layer3_v1.py)
# =============================================================================

if __name__ == "__main__":

    # ── Helpers ───────────────────────────────────────────────────────────────

    def _bar(v: float, width: int = 36) -> str:
        filled = round(v * width)
        return f"[{'#' * filled}{'.' * (width - filled)}] {v:.3f}"

    def _print_result(label: str, r: dict) -> None:
        print(f"\n{'─' * 60}")
        print(f"  {label}")
        print(f"  context : {r['context']}")
        print(f"  score   : {_bar(r['score'])}")
        print(f"  flags   : {r['flags'] or '(none)'}")
        print("  subscores:")
        for k, v in r["subscores"].items():
            print(f"    {k:<26s} {_bar(v, 20)}")

    def _print_policy(label: str, p: PolicyDecision) -> None:
        action_pad = f"{p.action:<16s}"
        tags = []
        if p.escalated:    tags.append("ESCALATED")
        if p.deescalating: tags.append("HOLDING")
        if p.changed and not p.escalated: tags.append("STEPPED DOWN")
        if not p.changed and not p.deescalating: tags.append("renewed" if p.action != "ALLOW" else "no-op")
        tag_str = "  ".join(tags) if tags else ""
        print(f"  {label:<38s}  action={action_pad}  "
              f"ttl={p.ttl_sec:>2d}s  score={p.score:.3f}  "
              f"consec={p.consecutive}  {tag_str}")

    # ── Scoring self-tests (unchanged from previous version) ─────────────────

    syn_snap = {
        "src_ip": "1.2.3.4",        "dst_ip": "10.0.0.190",
        "window_ms": 1000,
        "pkt_count": 16000,         "byte_count": 960_000,
        "tcp_pkts":  16000,         "syn_pkts": 15800,
        "rst_pkts":  100,           "ack_only_pkts": 100,
        "unique_dst_ports": 1,      "unique_flows": 1,
        "victim_total_pkts": 80000, "victim_total_bytes": 4_800_000,
        "duration_sec": 1.0,
        "attack_type": "SYN_FLOOD", "det_state": "ATTACK",
    }
    r1  = score_source(syn_snap)
    r1b = score_source(syn_snap)
    r1c = score_source(syn_snap)
    _print_result("SYN flood — dominant, window 1",  r1)
    _print_result("SYN flood — window 2 (persistence builds)", r1b)
    _print_result("SYN flood — window 3 (persistence stronger)", r1c)

    # ── Policy self-tests ─────────────────────────────────────────────────────
    # Tests use synthetic score injection via _simulate_window() so the
    # policy state machine can be driven with exact scores independently of
    # the scoring engine's feature computation.

    def _simulate_window(
        src_ip: str, dst_ip: str, score: float
    ) -> PolicyDecision:
        """
        Inject a synthetic score into _persistence and run generate_policy.

        This bypasses score_source() and lets us drive the policy state machine
        with exact scores for deterministic tests.  Do not use in production.
        """
        key = (src_ip, dst_ip)
        if key not in _persistence:
            _persistence[key] = deque(maxlen=config.PERSISTENCE_WINDOW_SIZE)
        _persistence[key].append(score)

        fake_result: ScoringResult = {
            "score":    score,
            "subscores": {k: score for k in
                          ["contribution", "protocol_abnormality",
                           "handshake_abnormality", "persistence",
                           "concentration"]},
            "context":  "TCP",
            "features": {},
            "flags":    build_reason_flags(
                {k: score for k in ["contribution", "protocol_abnormality",
                                    "handshake_abnormality", "persistence",
                                    "concentration"]}),
        }
        return generate_policy(src_ip, dst_ip, fake_result)

    # ────────────────────────────────────────────────────────────────────────
    # Policy test A — Escalation ladder
    #
    # Score starts at 0.60 (above SOFT, below HARD), then rises to 0.75
    # (above HARD, needs 2 consecutive), then to 0.92 (above BLOCK, needs 3).
    #
    # Expected:
    #   W1  score=0.60  consecutive=1  → RATE_LIMIT_SOFT  (1 >= required 1)
    #   W2  score=0.75  consecutive=2  → RATE_LIMIT_HARD  (2 >= required 2)
    #   W3  score=0.92  consecutive=3  → BLOCK             (3 >= required 3)
    # ────────────────────────────────────────────────────────────────────────
    SRC_A, DST = "10.1.1.1", "10.0.0.190"

    print(f"\n\n{'═' * 62}")
    print(f"  POLICY TEST A — Escalation ladder")
    print(f"  thresholds: SOFT={config.THRESHOLD_RATE_LIMIT_SOFT}  "
          f"HARD={config.THRESHOLD_RATE_LIMIT_HARD}  "
          f"BLOCK={config.THRESHOLD_BLOCK}")
    print(f"  persistence required: {config.PERSISTENCE_REQUIRED}")
    print(f"{'═' * 62}")

    pA1 = _simulate_window(SRC_A, DST, 0.60)
    _print_policy("W1  score=0.60  (expect SOFT)", pA1)

    pA2 = _simulate_window(SRC_A, DST, 0.75)
    _print_policy("W2  score=0.75  (expect HARD)", pA2)

    pA3 = _simulate_window(SRC_A, DST, 0.92)
    _print_policy("W3  score=0.92  (expect BLOCK)", pA3)

    assert pA1.action == "RATE_LIMIT_SOFT", f"Expected RATE_LIMIT_SOFT, got {pA1.action}"
    assert pA2.action == "RATE_LIMIT_HARD", f"Expected RATE_LIMIT_HARD, got {pA2.action}"
    assert pA3.action == "BLOCK",           f"Expected BLOCK, got {pA3.action}"
    assert pA2.escalated and pA3.escalated, "Escalation flags not set"
    print("  ✓ Escalation assertions passed")

    # ────────────────────────────────────────────────────────────────────────
    # Policy test B — De-escalation with hysteresis
    #
    # Start from BLOCK (built over 3 windows at 0.92), then drop score to 0.30.
    # DEESCALATION_WINDOWS = 2 means each step down takes 2 low-score windows.
    #
    # Expected sequence after BLOCK is established:
    #   W4   score=0.30  counter=1/2  → BLOCK (HOLDING)
    #   W5   score=0.30  counter=2/2  → RATE_LIMIT_HARD (stepped down)
    #   W6   score=0.30  counter=1/2  → RATE_LIMIT_HARD (HOLDING)
    #   W7   score=0.30  counter=2/2  → RATE_LIMIT_SOFT (stepped down)
    #   W8   score=0.30  counter=1/2  → RATE_LIMIT_SOFT (HOLDING)
    #   W9   score=0.30  counter=2/2  → ALLOW (stepped down)
    # ────────────────────────────────────────────────────────────────────────
    SRC_B = "10.1.1.2"

    print(f"\n\n{'═' * 62}")
    print(f"  POLICY TEST B — De-escalation with hysteresis")
    print(f"  de-escalation windows required: {config.DEESCALATION_WINDOWS}")
    print(f"{'═' * 62}")

    # Build up to BLOCK first.
    for i in range(1, 4):
        p = _simulate_window(SRC_B, DST, 0.92)
        _print_policy(f"W{i}  score=0.92  (build BLOCK)", p)

    de_results = []
    for i in range(4, 10):
        p = _simulate_window(SRC_B, DST, 0.30)
        de_results.append(p)
        _print_policy(f"W{i}  score=0.30", p)

    # W4 and W5: BLOCK → BLOCK (hold) → RATE_LIMIT_HARD
    assert de_results[0].action == "BLOCK"          and de_results[0].deescalating, \
        f"W4: expected BLOCK+HOLDING, got {de_results[0].action}"
    assert de_results[1].action == "RATE_LIMIT_HARD" and de_results[1].changed, \
        f"W5: expected RATE_LIMIT_HARD+changed, got {de_results[1].action}"
    # W6 and W7: RATE_LIMIT_HARD → RATE_LIMIT_HARD (hold) → RATE_LIMIT_SOFT
    assert de_results[2].action == "RATE_LIMIT_HARD" and de_results[2].deescalating, \
        f"W6: expected RATE_LIMIT_HARD+HOLDING, got {de_results[2].action}"
    assert de_results[3].action == "RATE_LIMIT_SOFT"  and de_results[3].changed, \
        f"W7: expected RATE_LIMIT_SOFT+changed, got {de_results[3].action}"
    # W8 and W9: RATE_LIMIT_SOFT → RATE_LIMIT_SOFT (hold) → ALLOW
    assert de_results[4].action == "RATE_LIMIT_SOFT"  and de_results[4].deescalating, \
        f"W8: expected RATE_LIMIT_SOFT+HOLDING, got {de_results[4].action}"
    assert de_results[5].action == "ALLOW"             and de_results[5].changed, \
        f"W9: expected ALLOW+changed, got {de_results[5].action}"
    print("  ✓ De-escalation assertions passed")

    # ────────────────────────────────────────────────────────────────────────
    # Policy test C — TTL renewal and re-escalation interrupts de-escalation
    #
    # 1. Establish RATE_LIMIT_SOFT, then show TTL renewed each window.
    # 2. Begin de-escalation (low score), then spike score again.
    #    De-escalation counter must reset and action stay at current level.
    # ────────────────────────────────────────────────────────────────────────
    SRC_C = "10.1.1.3"

    print(f"\n\n{'═' * 62}")
    print(f"  POLICY TEST C — TTL renewal and de-escalation interrupt")
    print(f"{'═' * 62}")

    # Three windows at SOFT score.
    for i in range(1, 4):
        p = _simulate_window(SRC_C, DST, 0.65)
        _print_policy(f"W{i}  score=0.65  (expect SOFT, TTL renewed)", p)
        assert p.action == "RATE_LIMIT_SOFT", f"W{i}: expected RATE_LIMIT_SOFT, got {p.action}"
        assert p.ttl_sec == config.TTL_DEFAULTS["RATE_LIMIT_SOFT"], \
            f"W{i}: TTL should be {config.TTL_DEFAULTS['RATE_LIMIT_SOFT']}, got {p.ttl_sec}"

    # Drop score to start de-escalation.
    pC4 = _simulate_window(SRC_C, DST, 0.30)
    _print_policy("W4  score=0.30  (de-escalation counter starts: 1/2)", pC4)
    assert pC4.deescalating, "W4: should be holding"

    # Score spikes back up — interrupts de-escalation, renews TTL.
    pC5 = _simulate_window(SRC_C, DST, 0.65)
    _print_policy("W5  score=0.65  (spike → counter resets, still SOFT)", pC5)
    assert pC5.action == "RATE_LIMIT_SOFT" and not pC5.deescalating, \
        "W5: score spike should reset hold counter"

    # Now drop again for two full windows to confirm it steps down.
    pC6 = _simulate_window(SRC_C, DST, 0.30)
    pC7 = _simulate_window(SRC_C, DST, 0.30)
    _print_policy("W6  score=0.30  (hold 1/2)", pC6)
    _print_policy("W7  score=0.30  (step to ALLOW)", pC7)
    assert pC6.deescalating,       "W6: should be holding"
    assert pC7.action == "ALLOW",  "W7: should have stepped down to ALLOW"
    print("  ✓ TTL renewal and interrupt assertions passed")

    # ── Policy export demo ────────────────────────────────────────────────────
    # Builds a known set of policy states, then exercises export in both
    # shadow mode and enforce mode.
    #
    # After each export the file content is read back and checked so that
    # the test is self-contained and does not require external tooling.

    import tempfile, os as _os

    print(f"\n\n{'═' * 62}")
    print(f"  POLICY EXPORT DEMO")
    print(f"{'═' * 62}")

    # Redirect export paths to temp files so the demo is safe to run
    # without root and without affecting a running system.
    _tmp_dir = tempfile.mkdtemp(prefix="l3_export_test_")
    _saved_path     = config.L3_POLICY_FILE_PATH
    _saved_tmp_path = config.L3_POLICY_FILE_TMP
    config.L3_POLICY_FILE_PATH = _os.path.join(_tmp_dir, "l3_policies.txt")
    config.L3_POLICY_FILE_TMP  = config.L3_POLICY_FILE_PATH + ".tmp"

    # Inject known policy states directly.
    _policy_states.clear()
    _policy_states[("192.0.2.10", "10.0.0.1")] = _PolicyState(
        action="BLOCK", deescalation_counter=0, changed_at=0.0)
    _policy_states[("192.0.2.20", "10.0.0.1")] = _PolicyState(
        action="RATE_LIMIT_HARD", deescalation_counter=0, changed_at=0.0)
    _policy_states[("192.0.2.30", "10.0.0.1")] = _PolicyState(
        action="RATE_LIMIT_SOFT", deescalation_counter=0, changed_at=0.0)
    _policy_states[("192.0.2.40", "10.0.0.1")] = _PolicyState(
        action="ALLOW", deescalation_counter=0, changed_at=0.0)

    # ── Demo 1: shadow mode (default) ─────────────────────────────────────
    config.L3_ENFORCE_MODE = False
    n = export_policies()
    with open(config.L3_POLICY_FILE_PATH) as fh:
        shadow_content = fh.read()

    print(f"\n  Shadow mode  (L3_ENFORCE_MODE=False)")
    print(f"  Lines written : {n}  (expected 0)")
    print(f"  File content  : {repr(shadow_content)}  (expected empty string)")
    assert n == 0,               f"shadow: expected 0 lines, got {n}"
    assert shadow_content == "", f"shadow: expected empty file, got {repr(shadow_content)}"
    print("  ✓ Shadow mode assertions passed")

    # ── Demo 2: enforce mode ───────────────────────────────────────────────
    config.L3_ENFORCE_MODE = True
    n = export_policies()
    with open(config.L3_POLICY_FILE_PATH) as fh:
        enforce_lines = [l.strip() for l in fh if l.strip()]

    print(f"\n  Enforce mode (L3_ENFORCE_MODE=True)")
    print(f"  Lines written : {n}  (expected 3 — ALLOW skipped)")
    for line in enforce_lines:
        print(f"    {line}")

    assert n == 3, f"enforce: expected 3 lines, got {n}"
    assert not any("ALLOW" in l for l in enforce_lines), "ALLOW must not appear in export"
    assert any("BLOCK"           in l for l in enforce_lines), "BLOCK missing"
    assert any("RATE_LIMIT_HARD" in l for l in enforce_lines), "RATE_LIMIT_HARD missing"
    assert any("RATE_LIMIT_SOFT" in l for l in enforce_lines), "RATE_LIMIT_SOFT missing"

    # Spot-check format: "ACTION SRC DST TTL RATE_PPS"
    for line in enforce_lines:
        parts = line.split()
        assert len(parts) == 5, f"expected 5 fields, got {len(parts)}: {line}"
        action, src, dst, ttl, rate = parts
        assert int(ttl)  == config.TTL_DEFAULTS[action],      f"TTL mismatch for {action}"
        assert int(rate) == config.RATE_PPS_DEFAULTS[action],  f"rate_pps mismatch for {action}"
    print("  ✓ Enforce mode assertions passed")

    # Restore config and clean up temp files.
    config.L3_ENFORCE_MODE      = False
    config.L3_POLICY_FILE_PATH  = _saved_path
    config.L3_POLICY_FILE_TMP   = _saved_tmp_path
    _os.unlink(_os.path.join(_tmp_dir, "l3_policies.txt"))
    _os.rmdir(_tmp_dir)

    # ── Window processing demo ────────────────────────────────────────────────
    # Injects records directly into _window_buffer and calls process_window_end
    # to verify the full scoring → policy → shared_state → export pipeline
    # without requiring a running socket or a live C bridge.

    print(f"\n\n{'═' * 62}")
    print(f"  WINDOW PROCESSING DEMO  (direct injection, no socket)")
    print(f"{'═' * 62}")

    DST_DEMO = "10.0.0.200"

    # Two source snapshots for a single SYN flood window.
    _window_buffer[DST_DEMO] = [
        {
            "type": "src_snapshot",
            "src_ip": "203.0.113.10", "dst_ip": DST_DEMO,
            "window_ms": 3000,
            "pkt_count": 18000, "byte_count": 1_080_000,
            "tcp_pkts": 18000, "syn_pkts": 17900,
            "rst_pkts": 50,    "ack_only_pkts": 50,
            "unique_dst_ports": 1, "unique_flows": 1,
            "duration_sec": 1.0,
        },
        {
            "type": "src_snapshot",
            "src_ip": "203.0.113.20", "dst_ip": DST_DEMO,
            "window_ms": 3000,
            "pkt_count": 400, "byte_count": 24_000,
            "tcp_pkts": 400, "syn_pkts": 390,
            "rst_pkts": 5,   "ack_only_pkts": 5,
            "unique_dst_ports": 1, "unique_flows": 1,
            "duration_sec": 1.0,
        },
    ]

    # Redirect export to a temp file for this demo too.
    _tmp2 = tempfile.mkdtemp(prefix="l3_proc_test_")
    config.L3_POLICY_FILE_PATH = _os.path.join(_tmp2, "l3_policies.txt")
    config.L3_POLICY_FILE_TMP  = config.L3_POLICY_FILE_PATH + ".tmp"
    config.L3_ENFORCE_MODE     = True

    process_window_end(DST_DEMO, {
        "type": "window_end",
        "dst_ip": DST_DEMO,
        "det_state": "ATTACK",
        "attack_type": "SYN_FLOOD",
        "window_ms": 3000,
        "victim_total_pkts":  90000,
        "victim_total_bytes": 5_400_000,
    })

    session  = l3.get_attack_session(DST_DEMO)
    sources  = l3.get_top_sources(DST_DEMO)
    policies = l3.get_policies_for_victim(DST_DEMO)
    events   = l3.get_events_for_victim(DST_DEMO)

    print(f"\n  Attack session : det_state={session.det_state}"
          f"  attack_type={session.attack_type}"
          f"  windows={session.window_count}")
    print(f"\n  Top sources ({len(sources)}):")
    for s in sources:
        print(f"    {s.src_ip:<16s}  score={s.score:.3f}  context={s.context}")
    print(f"\n  Active policies ({len(policies)}):")
    for p in policies:
        print(f"    {p.src_ip:<16s}  action={p.action:<16s}  ttl={p.ttl_sec}s")
    print(f"\n  Events logged ({len(events)}):")
    for e in events:
        src = e.src_ip or "-"
        print(f"    [{e.event_type:<24s}]  src={src:<16s}  score={e.score:.3f}")

    assert session is not None,        "attack session must exist after ATTACK window_end"
    assert session.window_count == 1,  "first window → window_count=1"
    assert len(sources) == 2,          f"expected 2 scored sources, got {len(sources)}"
    assert sources[0].score > sources[1].score, "sources must be sorted descending by score"
    assert any(e.event_type == EVENT_ATTACK_START for e in events), \
        "ATTACK_START event expected"
    print("\n  ✓ Window processing assertions passed")

    # Verify buffer was consumed.
    assert DST_DEMO not in _window_buffer, "buffer must be empty after process_window_end"
    print("  ✓ Window buffer cleared after processing")

    # Restore and clean up.
    config.L3_ENFORCE_MODE     = False
    config.L3_POLICY_FILE_PATH = _saved_path
    config.L3_POLICY_FILE_TMP  = _saved_tmp_path
    try:
        _os.unlink(_os.path.join(_tmp2, "l3_policies.txt"))
    except FileNotFoundError:
        pass
    _os.rmdir(_tmp2)

    # ── Summary ───────────────────────────────────────────────────────────────
    print(f"\n{'═' * 62}")
    print(f"  Persistence entries : {len(_persistence)}")
    print(f"  Policy state entries: {len(_policy_states)}")
    print(f"  All assertions passed.")
    print(f"{'═' * 62}")
