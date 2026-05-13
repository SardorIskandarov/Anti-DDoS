#!/usr/bin/env python3
"""Validate services.json against the v1 schema.

Implements the 12 validation rules defined in
service_registry/docs/services_schema.md. Stdlib-only.

Usage:
    python3 validate_services_json.py [path]
        --verbose: print structure summary on success
        --strict:  reject unknown top-level / profile / service keys

Exit codes:
    0 → valid
    1 → one or more validation failures (every violation printed)
    2 → I/O / parse failure
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any, Iterable


# ---------------------------------------------------------------------------
# Constants from the schema
# ---------------------------------------------------------------------------

SCHEMA_VERSION = 1
MAX_PROTECTED_IPS = 32
MAX_EXPANDED_SERVICE_AND_CATCHALL_ENTRIES = 328
VALID_PROTOS = ("TCP", "UDP", "ICMP")
CATCHALL_PROTO_KEYS = ("tcp", "udp", "icmp", "other")

# Top-level keys allowed in --strict mode.
ALLOWED_TOP_KEYS = (
    "version",
    "metadata",
    "protected_ips",
    "profiles",
    "catchall_assignments",
    "services",
)

# Profile section keys allowed in --strict mode.
ALLOWED_PROFILE_KEYS = (
    "tier0",
    "tier1",
    "tier1_l3",
    "tier1_offproto",
    "v2_feature_weights",
)

# Service keys allowed in --strict mode.
ALLOWED_SERVICE_KEYS = (
    "name", "target_ip", "port", "port_range", "proto", "profile",
    "detection_enabled", "added_at", "added_by", "notes",
)


# ---------------------------------------------------------------------------
# Validation framework
# ---------------------------------------------------------------------------

class Validator:
    """Accumulates violations across all rule checks.

    Each rule_N method appends one or more strings to self.violations.
    Returns True iff every rule passed.
    """

    def __init__(self, doc: dict, strict: bool = False) -> None:
        self.doc = doc
        self.strict = strict
        self.violations: list[str] = []

    def fail(self, rule: int, msg: str) -> None:
        self.violations.append(f"  [rule {rule}] {msg}")

    def run_all(self) -> bool:
        # Order matters slightly — later rules assume the structure is
        # roughly correct. Each rule individually guards against missing
        # keys so they all run independently.
        self.rule_1_version()
        self.rule_11_protected_ip_count()
        self.rule_2_service_target_ip_in_protected()
        self.rule_3_service_profile_in_profiles()
        self.rule_4_catchall_one_per_protected_ip()
        self.rule_5_catchall_has_all_four_keys()
        self.rule_6_catchall_profile_refs_in_profiles()
        self.rule_7_no_duplicate_services()
        self.rule_8_service_proto_valid()
        self.rule_9_service_port_valid()
        self.rule_10_total_entry_cap()
        self.rule_12_weights_and_thresholds()
        if self.strict:
            self.strict_unknown_top_keys()
            self.strict_unknown_profile_keys()
            self.strict_unknown_service_keys()
        return not self.violations

    # ------------------------------------------------------------------
    # Rule 1: version == 1
    # ------------------------------------------------------------------
    def rule_1_version(self) -> None:
        v = self.doc.get("version")
        if v != SCHEMA_VERSION:
            self.fail(
                1,
                f"version must equal {SCHEMA_VERSION}, got {v!r}",
            )

    # ------------------------------------------------------------------
    # Rule 11: n_protected_ips ≤ 32
    # ------------------------------------------------------------------
    def rule_11_protected_ip_count(self) -> None:
        ips = self.doc.get("protected_ips")
        if not isinstance(ips, list):
            self.fail(11, "protected_ips must be a list of dotted-quad strings")
            return
        if len(ips) > MAX_PROTECTED_IPS:
            self.fail(
                11,
                f"too many protected_ips: {len(ips)} (max {MAX_PROTECTED_IPS})",
            )
        for ip in ips:
            if not isinstance(ip, str) or not _is_dotted_quad(ip):
                self.fail(11, f"invalid IP in protected_ips: {ip!r}")

    # ------------------------------------------------------------------
    # Rule 2: every service.target_ip ∈ protected_ips
    # ------------------------------------------------------------------
    def rule_2_service_target_ip_in_protected(self) -> None:
        ips = set(self.doc.get("protected_ips", []) or [])
        services = self.doc.get("services", []) or []
        if not isinstance(services, list):
            self.fail(2, "services must be a list")
            return
        for idx, svc in enumerate(services):
            if not isinstance(svc, dict):
                self.fail(2, f"services[{idx}] is not an object")
                continue
            tip = svc.get("target_ip")
            if tip is None:
                self.fail(2, f"services[{idx}] missing target_ip")
                continue
            if tip not in ips:
                self.fail(
                    2,
                    f"services[{idx}].target_ip = {tip!r} not in protected_ips",
                )

    # ------------------------------------------------------------------
    # Rule 3: every service.profile ∈ profiles
    # ------------------------------------------------------------------
    def rule_3_service_profile_in_profiles(self) -> None:
        profiles = self.doc.get("profiles", {}) or {}
        if not isinstance(profiles, dict):
            self.fail(3, "profiles must be an object")
            return
        services = self.doc.get("services", []) or []
        if not isinstance(services, list):
            return  # rule 2 will have flagged
        for idx, svc in enumerate(services):
            if not isinstance(svc, dict):
                continue
            pname = svc.get("profile")
            if pname is None:
                self.fail(3, f"services[{idx}] missing profile")
                continue
            if pname not in profiles:
                self.fail(
                    3,
                    f"services[{idx}].profile = {pname!r} not in profiles{{}}",
                )

    # ------------------------------------------------------------------
    # Rule 4: catchall_assignments has one entry per protected_ip
    # ------------------------------------------------------------------
    def rule_4_catchall_one_per_protected_ip(self) -> None:
        ips = set(self.doc.get("protected_ips", []) or [])
        ca = self.doc.get("catchall_assignments")
        if not isinstance(ca, dict):
            self.fail(4, "catchall_assignments must be an object")
            return
        ca_keys = set(ca.keys())
        missing = ips - ca_keys
        extra = ca_keys - ips
        for ip in sorted(missing):
            self.fail(4, f"protected_ip {ip!r} has no catchall_assignments entry")
        for ip in sorted(extra):
            self.fail(4, f"catchall_assignments has extra IP {ip!r} not in protected_ips")

    # ------------------------------------------------------------------
    # Rule 5: each catchall entry has all 4 keys
    # ------------------------------------------------------------------
    def rule_5_catchall_has_all_four_keys(self) -> None:
        ca = self.doc.get("catchall_assignments")
        if not isinstance(ca, dict):
            return  # rule 4 will have flagged
        for ip, entry in ca.items():
            if not isinstance(entry, dict):
                self.fail(5, f"catchall_assignments[{ip!r}] is not an object")
                continue
            for k in CATCHALL_PROTO_KEYS:
                if k not in entry:
                    self.fail(
                        5,
                        f"catchall_assignments[{ip!r}] missing key {k!r}",
                    )
            extra_keys = set(entry.keys()) - set(CATCHALL_PROTO_KEYS)
            for k in sorted(extra_keys):
                self.fail(
                    5,
                    f"catchall_assignments[{ip!r}] has unexpected key {k!r}",
                )

    # ------------------------------------------------------------------
    # Rule 6: each catchall profile reference ∈ profiles
    # ------------------------------------------------------------------
    def rule_6_catchall_profile_refs_in_profiles(self) -> None:
        profiles = self.doc.get("profiles", {}) or {}
        ca = self.doc.get("catchall_assignments")
        if not isinstance(ca, dict) or not isinstance(profiles, dict):
            return
        for ip, entry in ca.items():
            if not isinstance(entry, dict):
                continue
            for k, pname in entry.items():
                if not isinstance(pname, str):
                    self.fail(6, f"catchall_assignments[{ip!r}][{k!r}] is not a string")
                    continue
                if pname not in profiles:
                    self.fail(
                        6,
                        f"catchall_assignments[{ip!r}][{k!r}] = {pname!r} "
                        "not in profiles{}",
                    )

    # ------------------------------------------------------------------
    # Rule 7: no two services share (target_ip, port, proto) — expanded
    # ------------------------------------------------------------------
    def rule_7_no_duplicate_services(self) -> None:
        services = self.doc.get("services", []) or []
        if not isinstance(services, list):
            return
        # seen: (target_ip, proto, port) -> first service index that claimed it
        seen: dict[tuple[str, str, int], int] = {}
        for idx, svc in enumerate(services):
            if not isinstance(svc, dict):
                continue
            tip = svc.get("target_ip")
            proto = svc.get("proto")
            try:
                ports = _expand_ports(svc)
            except ValueError:
                continue  # rule 9 will flag the bad port shape
            if tip is None or proto is None:
                continue
            for p in ports:
                key = (tip, proto, p)
                if key in seen:
                    self.fail(
                        7,
                        f"services[{idx}] duplicates "
                        f"(target_ip={tip!r}, proto={proto!r}, port={p}) "
                        f"already claimed by services[{seen[key]}]",
                    )
                else:
                    seen[key] = idx

    # ------------------------------------------------------------------
    # Rule 8: proto ∈ {TCP, UDP, ICMP}
    # ------------------------------------------------------------------
    def rule_8_service_proto_valid(self) -> None:
        services = self.doc.get("services", []) or []
        if not isinstance(services, list):
            return
        for idx, svc in enumerate(services):
            if not isinstance(svc, dict):
                continue
            proto = svc.get("proto")
            if proto not in VALID_PROTOS:
                self.fail(
                    8,
                    f"services[{idx}].proto = {proto!r} not in {VALID_PROTOS}",
                )

    # ------------------------------------------------------------------
    # Rule 9: port shape valid, ICMP must have port=0 and no port_range
    # ------------------------------------------------------------------
    def rule_9_service_port_valid(self) -> None:
        services = self.doc.get("services", []) or []
        if not isinstance(services, list):
            return
        for idx, svc in enumerate(services):
            if not isinstance(svc, dict):
                continue
            has_port = "port" in svc
            has_range = "port_range" in svc
            proto = svc.get("proto")

            if not has_port and not has_range:
                self.fail(
                    9,
                    f"services[{idx}] must have either port or port_range",
                )
                continue
            if has_port and has_range:
                self.fail(
                    9,
                    f"services[{idx}] has both port and port_range "
                    "(exactly one required)",
                )
                continue

            if has_port:
                p = svc["port"]
                if not isinstance(p, int) or isinstance(p, bool):
                    self.fail(
                        9,
                        f"services[{idx}].port must be an integer, got "
                        f"{type(p).__name__}",
                    )
                elif not (0 <= p <= 65535):
                    self.fail(
                        9,
                        f"services[{idx}].port = {p} out of range [0, 65535]",
                    )

            if has_range:
                if proto == "ICMP":
                    self.fail(
                        9,
                        f"services[{idx}] is ICMP and must not use port_range",
                    )
                else:
                    pr = svc["port_range"]
                    if not isinstance(pr, str):
                        self.fail(
                            9,
                            f"services[{idx}].port_range must be a string",
                        )
                    else:
                        m = re.fullmatch(r"\s*(\d+)\s*-\s*(\d+)\s*", pr)
                        if not m:
                            self.fail(
                                9,
                                f"services[{idx}].port_range = {pr!r} "
                                "must match 'LOW-HIGH'",
                            )
                        else:
                            low, high = int(m.group(1)), int(m.group(2))
                            if not (0 <= low <= 65535 and 0 <= high <= 65535):
                                self.fail(
                                    9,
                                    f"services[{idx}].port_range bounds "
                                    f"({low}, {high}) outside [0, 65535]",
                                )
                            if low > high:
                                self.fail(
                                    9,
                                    f"services[{idx}].port_range = {pr!r} "
                                    "has LOW > HIGH",
                                )

            if proto == "ICMP" and has_port and svc.get("port") != 0:
                self.fail(
                    9,
                    f"services[{idx}] is ICMP, port must be 0, got {svc['port']!r}",
                )

    # ------------------------------------------------------------------
    # Rule 10: expanded entries + (n_protected_ips × 4) ≤ 328
    # ------------------------------------------------------------------
    def rule_10_total_entry_cap(self) -> None:
        n_ips = len(self.doc.get("protected_ips", []) or [])
        services = self.doc.get("services", []) or []
        expanded = 0
        if isinstance(services, list):
            for svc in services:
                if not isinstance(svc, dict):
                    continue
                try:
                    expanded += len(_expand_ports(svc))
                except ValueError:
                    pass
        total = expanded + (n_ips * 4)
        if total > MAX_EXPANDED_SERVICE_AND_CATCHALL_ENTRIES:
            self.fail(
                10,
                f"expanded service count ({expanded}) + "
                f"(n_protected_ips × 4 = {n_ips * 4}) = {total} "
                f"exceeds engine table cap "
                f"{MAX_EXPANDED_SERVICE_AND_CATCHALL_ENTRIES}",
            )

    # ------------------------------------------------------------------
    # Rule 12: weights ≥ 0; probability fields ∈ [0, 1]
    # ------------------------------------------------------------------
    def rule_12_weights_and_thresholds(self) -> None:
        profiles = self.doc.get("profiles")
        if not isinstance(profiles, dict):
            return
        for pname, p in profiles.items():
            if not isinstance(p, dict):
                self.fail(12, f"profiles[{pname!r}] is not an object")
                continue
            self._check_weights(pname, p)
            self._check_probability_thresholds(pname, p)

    def _check_weights(self, pname: str, p: dict) -> None:
        """All weight-style fields must be non-negative."""
        weight_paths: list[tuple[str, ...]] = [
            # Tier-0 weights
            ("tier0", "weights", "pps"),
            ("tier0", "weights", "bps"),
            ("tier0", "weights", "fps"),
            ("tier0", "weights", "burst_pps"),
            ("tier0", "weights", "burst_bps"),
            ("tier0", "weights", "burst_fps"),
            # Tier-1 fusion weights
            ("tier1", "fusion_weights", "tcp"),
            ("tier1", "fusion_weights", "udp"),
            ("tier1", "fusion_weights", "icmp"),
            ("tier1", "fusion_weights", "dist"),
            # Tier-1.5 L3 weights
            ("tier1_l3", "weights", "ttl_stddev"),
            ("tier1_l3", "weights", "ip_frag_ratio"),
            ("tier1_l3", "weights", "other_proto_ratio"),
            ("tier1_l3", "weights", "src_port_top1_share"),
            ("tier1_l3", "weights", "src_24_top1_share"),
            ("tier1_l3", "weights", "src_24_entropy"),
            # V2 feature weights
            ("v2_feature_weights", "empty_ack_ratio"),
            ("v2_feature_weights", "zero_window_ratio"),
            ("v2_feature_weights", "small_window_ratio"),
            ("v2_feature_weights", "new_flow_ratio"),
            ("v2_feature_weights", "syn_fin_ratio"),
            ("v2_feature_weights", "syn_to_synack_ratio"),
            ("v2_feature_weights", "tcp_pkt_size_cov"),
            ("v2_feature_weights", "tcp_mean_pkt_size"),
            ("v2_feature_weights", "udp_pkt_size_cov"),
            ("v2_feature_weights", "udp_mean_pkt_size"),
        ]
        for path in weight_paths:
            val = _get_path(p, path)
            if val is None:
                self.fail(
                    12,
                    f"profiles[{pname!r}] missing required weight {'.'.join(path)}",
                )
                continue
            if not isinstance(val, (int, float)) or isinstance(val, bool):
                self.fail(
                    12,
                    f"profiles[{pname!r}].{'.'.join(path)} must be a number, "
                    f"got {type(val).__name__}",
                )
                continue
            if val < 0.0:
                self.fail(
                    12,
                    f"profiles[{pname!r}].{'.'.join(path)} = {val} "
                    "must be ≥ 0.0",
                )

    def _check_probability_thresholds(self, pname: str, p: dict) -> None:
        """Probability-shaped fields must lie in [0, 1]."""
        prob_paths: list[tuple[str, ...]] = [
            ("tier1", "normal_threshold"),
            ("tier1", "suspicious_threshold"),
            ("tier1_offproto", "suspicious_threshold"),
            ("tier1_offproto", "attack_threshold"),
        ]
        for path in prob_paths:
            val = _get_path(p, path)
            if val is None:
                self.fail(
                    12,
                    f"profiles[{pname!r}] missing required probability "
                    f"{'.'.join(path)}",
                )
                continue
            if not isinstance(val, (int, float)) or isinstance(val, bool):
                self.fail(
                    12,
                    f"profiles[{pname!r}].{'.'.join(path)} must be a number",
                )
                continue
            if not (0.0 <= val <= 1.0):
                self.fail(
                    12,
                    f"profiles[{pname!r}].{'.'.join(path)} = {val} "
                    "must be in [0, 1]",
                )

    # ------------------------------------------------------------------
    # --strict checks
    # ------------------------------------------------------------------
    def strict_unknown_top_keys(self) -> None:
        for k in self.doc.keys():
            if k not in ALLOWED_TOP_KEYS:
                self.fail(0, f"[strict] unknown top-level key {k!r}")

    def strict_unknown_profile_keys(self) -> None:
        profiles = self.doc.get("profiles", {}) or {}
        if not isinstance(profiles, dict):
            return
        for pname, p in profiles.items():
            if not isinstance(p, dict):
                continue
            for k in p.keys():
                if k not in ALLOWED_PROFILE_KEYS:
                    self.fail(
                        0,
                        f"[strict] profiles[{pname!r}] has unknown key {k!r}",
                    )

    def strict_unknown_service_keys(self) -> None:
        services = self.doc.get("services", []) or []
        if not isinstance(services, list):
            return
        for idx, svc in enumerate(services):
            if not isinstance(svc, dict):
                continue
            for k in svc.keys():
                if k not in ALLOWED_SERVICE_KEYS:
                    self.fail(
                        0,
                        f"[strict] services[{idx}] has unknown key {k!r}",
                    )


# ---------------------------------------------------------------------------
# Utility helpers (module-level so tests can import them later)
# ---------------------------------------------------------------------------

_DOTTED_QUAD_RE = re.compile(
    r"\A(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})\Z"
)


def _is_dotted_quad(s: str) -> bool:
    m = _DOTTED_QUAD_RE.match(s)
    if not m:
        return False
    return all(0 <= int(x) <= 255 for x in m.groups())


def _expand_ports(svc: dict) -> list[int]:
    """Return the set of ports a service entry occupies.

    Raises ValueError on a malformed port_range; rule_9 will flag it
    separately, so callers can ignore the exception."""
    if "port" in svc:
        p = svc["port"]
        if not isinstance(p, int) or isinstance(p, bool):
            raise ValueError("port not an int")
        return [p]
    if "port_range" in svc:
        pr = svc["port_range"]
        if not isinstance(pr, str):
            raise ValueError("port_range not a string")
        m = re.fullmatch(r"\s*(\d+)\s*-\s*(\d+)\s*", pr)
        if not m:
            raise ValueError("port_range bad shape")
        low, high = int(m.group(1)), int(m.group(2))
        if low > high:
            raise ValueError("port_range LOW > HIGH")
        return list(range(low, high + 1))
    raise ValueError("neither port nor port_range")


def _get_path(obj: dict, path: Iterable[str]) -> Any:
    cur: Any = obj
    for key in path:
        if not isinstance(cur, dict) or key not in cur:
            return None
        cur = cur[key]
    return cur


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main() -> int:
    script_dir = Path(__file__).resolve().parent
    default_path = (script_dir / ".." / "services.json").resolve()
    parser = argparse.ArgumentParser(
        description="Validate services.json against the v1 schema."
    )
    parser.add_argument(
        "path",
        nargs="?",
        type=Path,
        default=default_path,
        help=f"Path to services.json (default: {default_path})",
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Print parsed structure summary even on success.",
    )
    parser.add_argument(
        "--strict",
        action="store_true",
        help="Reject unknown top-level / profile / service keys.",
    )
    args = parser.parse_args()

    if not args.path.exists():
        print(f"[FAIL] file not found: {args.path}", file=sys.stderr)
        return 2

    try:
        text = args.path.read_text(encoding="utf-8")
        doc = json.loads(text)
    except json.JSONDecodeError as exc:
        print(f"[FAIL] JSON parse error in {args.path}: {exc}", file=sys.stderr)
        return 2
    except OSError as exc:
        print(f"[FAIL] I/O error reading {args.path}: {exc}", file=sys.stderr)
        return 2

    if not isinstance(doc, dict):
        print(f"[FAIL] {args.path} top-level value must be an object", file=sys.stderr)
        return 1

    v = Validator(doc, strict=args.strict)
    ok = v.run_all()
    if not ok:
        print(f"[FAIL] services.json failed validation "
              f"({len(v.violations)} violation(s)):")
        for line in v.violations:
            print(line)
        return 1

    n_services = len(doc.get("services", []) or [])
    n_catchalls = len(doc.get("catchall_assignments", {}) or {})
    n_profiles = len(doc.get("profiles", {}) or {})
    n_ips = len(doc.get("protected_ips", []) or [])
    print(
        f"[OK] services.json is valid: "
        f"{n_services} services, {n_catchalls} catchalls, "
        f"{n_profiles} profiles, {n_ips} protected_ips"
    )
    if args.verbose:
        print()
        print(f"  version:             {doc.get('version')}")
        print(f"  metadata.last_modified: {doc.get('metadata', {}).get('last_modified')}")
        print(f"  metadata.modified_by:   {doc.get('metadata', {}).get('modified_by')}")
        print(f"  protected_ips ({n_ips}):")
        for ip in doc.get("protected_ips", []) or []:
            print(f"    - {ip}")
        print(f"  profiles ({n_profiles}):")
        for pname in (doc.get("profiles", {}) or {}).keys():
            print(f"    - {pname}")
        print(f"  services ({n_services})")
        if args.strict:
            print("  (--strict mode passed: no unknown keys)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
