# shared_state.py — Layer 3 V1 in-memory state
#
# Provides thread-safe containers for the four Layer 3 runtime structures:
#   - active attack sessions
#   - latest top suspicious sources (per victim)
#   - active policies
#   - recent Layer 3 events
#
# All external access goes through the module-level `l3` singleton.
# Callers never touch the underlying dicts/deques directly.

import threading
import time
from collections import deque
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple

import config


# Shared in-memory data structure for real-time dashboard
latest_traffic_data = []
data_lock = threading.Lock()


# =============================================================================
# DATA STRUCTURES
# Plain dataclasses — no logic, just named fields with clear types.
# =============================================================================

@dataclass
class AttackSession:
    """One active attack against a single destination IP."""
    dst_ip: str
    attack_type: str          # Layer 2 attack_type_str() value
    det_state: str            # "SUSPICIOUS" or "ATTACK"
    started_at: float         # unix timestamp of first detection
    last_seen_at: float       # unix timestamp of most recent window
    window_count: int = 0     # number of 1-second windows detected so far


@dataclass
class SourceEntry:
    """Scored source IP seen attacking one victim in one window."""
    src_ip: str
    dst_ip: str
    score: float              # suspicious_score in [0, 1]
    subscores: Dict[str, float]
    context: str              # "TCP" | "UDP" | "ICMP" | "MIXED"
    window_ms: int            # epoch ms of the window this score covers
    updated_at: float         # unix timestamp of last update


@dataclass
class PolicyEntry:
    """One active Layer 3 policy for a (src_ip, dst_ip) pair."""
    src_ip: str
    dst_ip: str
    action: str               # "ALLOW" | "RATE_LIMIT_SOFT" | "RATE_LIMIT_HARD" | "BLOCK"
    ttl_sec: int              # TTL as written to the policy file
    rate_pps: int             # 0 for BLOCK/ALLOW
    score: float              # suspicious_score that produced this policy
    subscores: Dict[str, float]
    created_at: float         # unix timestamp
    expires_at: float         # unix timestamp (created_at + ttl_sec)


@dataclass
class L3Event:
    """A single Layer 3 event for the events log."""
    timestamp: float
    event_type: str           # see EVENT_* constants below
    dst_ip: str
    src_ip: str = ""          # empty for victim-level events
    action: str = ""          # policy action involved, if any
    score: float = 0.0
    detail: str = ""          # free-form human-readable note


# Event type constants — used as L3Event.event_type values.
EVENT_ATTACK_START: str = "ATTACK_START"
EVENT_ATTACK_END: str = "ATTACK_END"
EVENT_POLICY_SET: str = "POLICY_SET"
EVENT_POLICY_EXPIRED: str = "POLICY_EXPIRED"
EVENT_POLICY_ESCALATE: str = "POLICY_ESCALATE"
EVENT_POLICY_DEESCALATE: str = "POLICY_DEESCALATE"
EVENT_SOURCE_CLEARED: str = "SOURCE_CLEARED"


# =============================================================================
# LAYER 3 STATE — thread-safe singleton
# =============================================================================

class Layer3State:
    """
    Thread-safe in-memory store for all active Layer 3 runtime state.

    One lock guards all four containers. All public methods acquire the lock
    internally so callers never need to manage it.

    Designed to be accessed by:
      - layer3_v1.py  (writer: scoring loop, policy generation)
      - web.py        (reader: dashboard API endpoints)
    """

    def __init__(self) -> None:
        self._lock = threading.Lock()

        # dst_ip -> AttackSession
        self._attack_sessions: Dict[str, AttackSession] = {}

        # dst_ip -> list of SourceEntry, sorted descending by score, capped at
        # config.L3_MAX_TOP_SOURCES_PER_VICTIM
        self._top_sources: Dict[str, List[SourceEntry]] = {}

        # (src_ip, dst_ip) -> PolicyEntry
        self._active_policies: Dict[Tuple[str, str], PolicyEntry] = {}

        # Ring buffer of recent events across all victims
        self._events: deque = deque(maxlen=config.L3_MAX_EVENTS)

    # -------------------------------------------------------------------------
    # Attack sessions
    # -------------------------------------------------------------------------

    def set_attack_session(self, session: AttackSession) -> None:
        """Insert or replace the attack session for session.dst_ip."""
        with self._lock:
            self._attack_sessions[session.dst_ip] = session

    def update_attack_session_window(
        self,
        dst_ip: str,
        det_state: str,
        attack_type: str,
    ) -> None:
        """
        Refresh last_seen_at and increment window_count for an existing session.
        Creates a new session if one does not already exist for dst_ip.
        """
        now = time.time()
        with self._lock:
            existing = self._attack_sessions.get(dst_ip)
            if existing is None:
                self._attack_sessions[dst_ip] = AttackSession(
                    dst_ip=dst_ip,
                    attack_type=attack_type,
                    det_state=det_state,
                    started_at=now,
                    last_seen_at=now,
                    window_count=1,
                )
            else:
                existing.last_seen_at = now
                existing.window_count += 1
                existing.det_state = det_state
                existing.attack_type = attack_type

    def remove_attack_session(self, dst_ip: str) -> Optional[AttackSession]:
        """Remove and return the session for dst_ip, or None if absent."""
        with self._lock:
            return self._attack_sessions.pop(dst_ip, None)

    def get_attack_session(self, dst_ip: str) -> Optional[AttackSession]:
        with self._lock:
            return self._attack_sessions.get(dst_ip)

    def get_all_attack_sessions(self) -> List[AttackSession]:
        """Return a snapshot list of all active sessions."""
        with self._lock:
            return list(self._attack_sessions.values())

    # -------------------------------------------------------------------------
    # Top suspicious sources
    # -------------------------------------------------------------------------

    def update_top_sources(self, dst_ip: str, sources: List[SourceEntry]) -> None:
        """
        Replace the top-sources list for dst_ip with a new scored list.
        The list is sorted descending by score and truncated to the configured
        maximum before storing.
        """
        sorted_sources = sorted(sources, key=lambda s: s.score, reverse=True)
        capped = sorted_sources[:config.L3_MAX_TOP_SOURCES_PER_VICTIM]
        with self._lock:
            self._top_sources[dst_ip] = capped

    def get_top_sources(self, dst_ip: str) -> List[SourceEntry]:
        """Return the current top-sources list for dst_ip (empty if none)."""
        with self._lock:
            return list(self._top_sources.get(dst_ip, []))

    def clear_top_sources(self, dst_ip: str) -> None:
        with self._lock:
            self._top_sources.pop(dst_ip, None)

    # -------------------------------------------------------------------------
    # Active policies
    # -------------------------------------------------------------------------

    def set_policy(self, policy: PolicyEntry) -> None:
        """Insert or replace the policy for (policy.src_ip, policy.dst_ip)."""
        with self._lock:
            self._active_policies[(policy.src_ip, policy.dst_ip)] = policy

    def remove_policy(self, src_ip: str, dst_ip: str) -> Optional[PolicyEntry]:
        """Remove and return the policy for (src_ip, dst_ip), or None."""
        with self._lock:
            return self._active_policies.pop((src_ip, dst_ip), None)

    def get_policy(self, src_ip: str, dst_ip: str) -> Optional[PolicyEntry]:
        with self._lock:
            return self._active_policies.get((src_ip, dst_ip))

    def get_policies_for_victim(self, dst_ip: str) -> List[PolicyEntry]:
        """Return all active policies targeting dst_ip."""
        with self._lock:
            return [p for p in self._active_policies.values() if p.dst_ip == dst_ip]

    def get_all_policies(self) -> List[PolicyEntry]:
        with self._lock:
            return list(self._active_policies.values())

    def remove_policies_for_victim(self, dst_ip: str) -> int:
        """Remove all policies for dst_ip. Returns count removed."""
        with self._lock:
            keys = [k for k in self._active_policies if k[1] == dst_ip]
            for k in keys:
                del self._active_policies[k]
            return len(keys)

    # -------------------------------------------------------------------------
    # Events
    # -------------------------------------------------------------------------

    def add_event(self, event: L3Event) -> None:
        """Append an event to the ring buffer (oldest is dropped when full)."""
        with self._lock:
            self._events.append(event)

    def get_recent_events(self, n: int = 50) -> List[L3Event]:
        """Return up to n most recent events, newest first."""
        with self._lock:
            events = list(self._events)
        return list(reversed(events))[:n]

    def get_events_for_victim(self, dst_ip: str, n: int = 50) -> List[L3Event]:
        """Return up to n most recent events for dst_ip, newest first."""
        with self._lock:
            events = [e for e in self._events if e.dst_ip == dst_ip]
        return list(reversed(events))[:n]

    # -------------------------------------------------------------------------
    # Bulk teardown helpers (called when attack ends)
    # -------------------------------------------------------------------------

    def clear_victim(self, dst_ip: str) -> None:
        """
        Remove all Layer 3 state for a victim that is no longer under attack.

        Removes: attack session, top sources, active policies.
        Does NOT remove events (kept for history).
        """
        with self._lock:
            self._attack_sessions.pop(dst_ip, None)
            self._top_sources.pop(dst_ip, None)
            keys = [k for k in self._active_policies if k[1] == dst_ip]
            for k in keys:
                del self._active_policies[k]

    # -------------------------------------------------------------------------
    # Diagnostics
    # -------------------------------------------------------------------------

    def summary(self) -> dict:
        """Return a lightweight count summary (no copies of full records)."""
        with self._lock:
            return {
                "attack_sessions": len(self._attack_sessions),
                "victims_tracked": len(self._top_sources),
                "active_policies": len(self._active_policies),
                "events_buffered": len(self._events),
            }


# =============================================================================
# MODULE-LEVEL SINGLETON
# Import this and use it directly:
#   from shared_state import l3
#   l3.set_attack_session(...)
# =============================================================================

l3: Layer3State = Layer3State()
