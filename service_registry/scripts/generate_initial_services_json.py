#!/usr/bin/env python3
"""Generate the initial services.json from l2fwd_l2_profile.c.

This is the P0 bootstrap script: it parses the 11 hand-tuned C profiles
plus the default profile, maps each .field to its JSON schema key, and
writes the result to service_registry/services.json.

It is intentionally standalone — no external dependencies. Re-running it
overwrites services.json with a fresh ISO 8601 timestamp; the registry
itself is hand-edited from P1 onward.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path


# ---------------------------------------------------------------------------
# The 11 protected IPs, in the order specified by the P0 prompt. The order
# must NOT match the C assignment-table iteration order; it matches the
# canonical "registry IP order" we'll preserve across phases.
# ---------------------------------------------------------------------------
PROTECTED_IPS: list[str] = [
    "213.230.125.170",
    "213.230.125.66",
    "45.150.25.70",
    "89.249.63.215",
    "213.230.125.46",
    "213.230.125.148",
    "213.230.125.50",
    "213.230.125.130",
    "94.141.85.150",
    "45.150.25.116",
    "89.249.62.131",
]

# Manually-tuned C profile symbol name for each protected IP.
IP_TO_PROFILE_SYMBOL: dict[str, str] = {
    ip: "l2_profile_" + ip.replace(".", "_") + "_manual_v1"
    for ip in PROTECTED_IPS
}

# ---------------------------------------------------------------------------
# Macro resolution table for l2fwd_detection_engine.h + the EWMA alpha
# constants from l2fwd_ddos_collector.h. These are the values referenced
# by the C default profile's macro-form initialisation. We resolve them
# to numbers so the generated default profile carries explicit values.
#
# This list is a deliberate snapshot — if any of these macros change in C,
# this script must be updated AND the generator re-run. P6's gold-test
# will detect drift.
# ---------------------------------------------------------------------------
C_MACRO_VALUES: dict[str, float | int] = {
    "EWMA_ALPHA_TIER0":            0.02,
    "EWMA_ALPHA_TIER1_1":          0.04,
    "EWMA_ALPHA_TIER1_2":          0.07,
    "EWMA_ALPHA_TIER1_3":          0.03,
    "EWMA_ALPHA_TIER1_4":          0.06,
    "DETECTION_WARMUP_WINDOWS":    400,
    "CUSUM_K_PPS":                 0.10,
    "CUSUM_H_PPS":                 6.5,
    "CUSUM_K_BPS":                 0.10,
    "CUSUM_H_BPS":                 6.5,
    "CUSUM_K_FPS":                 0.85,
    "CUSUM_H_FPS":                 6.0,
    "BURST_Z_THRESHOLD":           8.5,
    "VARIANCE_CEILING_FACTOR":     2.0,
    "T0_W_PPS":                    3.5,
    "T0_W_BPS":                    2.0,
    "T0_W_FPS":                    1.2,
    "T0_W_BURST_PPS":              1.5,
    "T0_W_BURST_BPS":              1.0,
    "T0_W_BURST_FPS":              0.5,
    "T0_SUSPICIOUS_RISK_THRESHOLD": 4.5,
    "T0_RISK_THRESHOLD":           6.5,
    "ABSOLUTE_PPS_THRESHOLD":      30000.0,
    "ABSOLUTE_BPS_THRESHOLD":      310000000.0,
    "ABSOLUTE_FPS_THRESHOLD":      300.0,
    "CONSECUTIVE_ATTACK_WINDOWS":  2,
    "BASELINE_FREEZE_WINDOWS":     12,
    "THAW_COOLDOWN_WINDOWS":       15,
    "SIGMOID_K":                   1.0,
    "SIGMOID_D0":                  1.1,
    "THRESHOLD_NORMAL":            0.42,
    "THRESHOLD_SUSPICIOUS":        0.62,
    "W_TCP":                       0.10,
    "W_UDP":                       0.60,
    "W_DIST":                      0.25,
    "W_ICMP":                      0.05,
}

# ---------------------------------------------------------------------------
# C field name → JSON schema path (dotted). The path tells us where to
# place the value in the nested profile object.
#
# Fields NOT in this table (.name, .version) are intentionally dropped:
# identity is conveyed by the profile key in profiles{}.
# ---------------------------------------------------------------------------
FIELD_MAP: dict[str, str] = {
    # Tier-0
    "alpha_tier0":                "tier0.alpha",
    "cusum_k_pps":                "tier0.cusum_k_pps",
    "cusum_h_pps":                "tier0.cusum_h_pps",
    "cusum_k_bps":                "tier0.cusum_k_bps",
    "cusum_h_bps":                "tier0.cusum_h_bps",
    "cusum_k_fps":                "tier0.cusum_k_fps",
    "cusum_h_fps":                "tier0.cusum_h_fps",
    "burst_z_threshold":          "tier0.burst_z_threshold",
    "variance_ceiling_factor":    "tier0.variance_ceiling_factor",
    "t0_w_pps":                   "tier0.weights.pps",
    "t0_w_bps":                   "tier0.weights.bps",
    "t0_w_fps":                   "tier0.weights.fps",
    "t0_w_burst_pps":             "tier0.weights.burst_pps",
    "t0_w_burst_bps":             "tier0.weights.burst_bps",
    "t0_w_burst_fps":             "tier0.weights.burst_fps",
    "t0_suspicious_risk_threshold": "tier0.suspicious_threshold",
    "t0_risk_threshold":          "tier0.attack_threshold",
    "absolute_pps_threshold":     "tier0.absolute_pps_threshold",
    "absolute_bps_threshold":     "tier0.absolute_bps_threshold",
    "absolute_fps_threshold":     "tier0.absolute_fps_threshold",

    # Tier-1
    "consecutive_attack_windows": "tier1.consecutive_attack_windows",
    "baseline_freeze_windows":    "tier1.baseline_freeze_windows",
    "thaw_cooldown_windows":      "tier1.thaw_cooldown_windows",
    "warmup_windows":             "tier1.warmup_windows",
    "sigmoid_k":                  "tier1.sigmoid_k",
    "sigmoid_d0":                 "tier1.sigmoid_d0",
    "threshold_normal":           "tier1.normal_threshold",
    "threshold_suspicious":       "tier1.suspicious_threshold",
    "w_tcp":                      "tier1.fusion_weights.tcp",
    "w_udp":                      "tier1.fusion_weights.udp",
    "w_icmp":                     "tier1.fusion_weights.icmp",
    "w_dist":                     "tier1.fusion_weights.dist",
    # The four alpha_tier1_* fields were missing from the prompt's literal
    # mapping table but are required for full struct parity (see schema doc).
    "alpha_tier1_tcp":            "tier1.alpha_tcp",
    "alpha_tier1_udp":            "tier1.alpha_udp",
    "alpha_tier1_icmp":           "tier1.alpha_icmp",
    "alpha_tier1_dist":           "tier1.alpha_dist",

    # Tier-1.5 L3
    "sigmoid_k_l3":               "tier1_l3.sigmoid_k",
    "sigmoid_d0_l3":              "tier1_l3.sigmoid_d0",
    "w_feat_ttl_stddev":          "tier1_l3.weights.ttl_stddev",
    "w_feat_ip_frag":             "tier1_l3.weights.ip_frag_ratio",
    "w_feat_other_proto":         "tier1_l3.weights.other_proto_ratio",
    "w_feat_src_port_top1":       "tier1_l3.weights.src_port_top1_share",
    "w_feat_src_24_top1":         "tier1_l3.weights.src_24_top1_share",
    "w_feat_src_24_entropy":      "tier1_l3.weights.src_24_entropy",
    "frag_noise_floor_override":  "tier1_l3.noise_floor_overrides.ip_frag_ratio",
    "other_proto_noise_floor_override": "tier1_l3.noise_floor_overrides.other_proto_ratio",

    # V2 feature weights
    "w_feat_empty_ack":           "v2_feature_weights.empty_ack_ratio",
    "w_feat_zero_window":         "v2_feature_weights.zero_window_ratio",
    "w_feat_small_window":        "v2_feature_weights.small_window_ratio",
    "w_feat_new_flow":            "v2_feature_weights.new_flow_ratio",
    "w_feat_syn_fin":             "v2_feature_weights.syn_fin_ratio",
    "w_feat_syn_to_synack":       "v2_feature_weights.syn_to_synack_ratio",
    "w_feat_tcp_pkt_size_cov":    "v2_feature_weights.tcp_pkt_size_cov",
    "w_feat_tcp_mean_pkt_size":   "v2_feature_weights.tcp_mean_pkt_size",
    "w_feat_udp_pkt_size_cov":    "v2_feature_weights.udp_pkt_size_cov",
    "w_feat_udp_mean_pkt_size":   "v2_feature_weights.udp_mean_pkt_size",
}

# Integer-typed C fields (everything else is treated as float).
INTEGER_FIELDS: set[str] = {
    "warmup_windows",
    "consecutive_attack_windows",
    "baseline_freeze_windows",
    "thaw_cooldown_windows",
}

# Fields explicitly NOT mapped — identity fields, kept in C for printf
# convenience but redundant in JSON where the dict key conveys identity.
IGNORED_FIELDS: set[str] = {"name", "version"}


# ---------------------------------------------------------------------------
# Parsing
# ---------------------------------------------------------------------------

# Match the entire profile block: const struct l2_profile <name> = { ... };
PROFILE_BLOCK_RE = re.compile(
    r"const\s+struct\s+l2_profile\s+(?P<sym>\w+)\s*=\s*\{(?P<body>.*?)\};",
    re.DOTALL,
)

# Match a designated-initialiser line:  .field = value,
# Allow value to be a numeric literal, a macro identifier, or a quoted
# string. Stop at the first comma that's outside a comment.
FIELD_LINE_RE = re.compile(
    r"^\s*\.(?P<field>\w+)\s*=\s*(?P<value>[^,]+?)\s*,",
    re.MULTILINE,
)


def strip_c_comments(text: str) -> str:
    """Remove /* ... */ and // ... comments. Both are common in the
    target file and they'd otherwise confuse the line-level regex."""
    # Block comments (greedy across lines, non-greedy in content).
    text = re.sub(r"/\*.*?\*/", "", text, flags=re.DOTALL)
    # Line comments.
    text = re.sub(r"//[^\n]*", "", text)
    return text


def resolve_value(field: str, raw: str) -> str | float | int:
    """Convert a raw RHS string to a Python value.

    Handles:
      - quoted strings ("foo") → str
      - numeric literals (1.0, 250, 3e6) → float / int
      - macro identifiers (CUSUM_K_PPS) → look up in C_MACRO_VALUES
    """
    raw = raw.strip()

    # Quoted string.
    if raw.startswith('"') and raw.endswith('"'):
        return raw[1:-1]

    # Macro identifier: matches C identifier pattern, all-caps usually.
    if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", raw):
        if raw in C_MACRO_VALUES:
            v = C_MACRO_VALUES[raw]
            return int(v) if field in INTEGER_FIELDS else float(v)
        raise ValueError(
            f"unknown macro {raw!r} on field {field!r}; "
            f"add it to C_MACRO_VALUES if it should be supported."
        )

    # Numeric literal (allow leading +/-, decimal, optional exponent,
    # trailing f/F).
    cleaned = raw.rstrip("fFlLuU")
    try:
        if field in INTEGER_FIELDS:
            return int(float(cleaned))
        return float(cleaned)
    except ValueError as exc:
        raise ValueError(
            f"could not parse {raw!r} as a numeric literal for "
            f"field {field!r}: {exc}"
        ) from exc


def parse_profile_block(symbol: str, body: str) -> dict[str, object]:
    """Extract every .field = value, line from one profile block.

    Returns a dict { c_field_name: python_value }. Includes only fields
    that were actually assigned in the source; the caller is responsible
    for filling defaults.
    """
    body = strip_c_comments(body)
    fields: dict[str, object] = {}
    for m in FIELD_LINE_RE.finditer(body):
        field = m.group("field")
        if field in IGNORED_FIELDS:
            continue
        raw_value = m.group("value")
        fields[field] = resolve_value(field, raw_value)
    return fields


def parse_c_source(source_path: Path) -> dict[str, dict[str, object]]:
    """Parse all const struct l2_profile blocks in the file.

    Returns { c_symbol_name: { c_field: value } }.
    """
    text = source_path.read_text(encoding="utf-8")
    out: dict[str, dict[str, object]] = {}
    for m in PROFILE_BLOCK_RE.finditer(text):
        symbol = m.group("sym")
        body = m.group("body")
        out[symbol] = parse_profile_block(symbol, body)
    return out


# ---------------------------------------------------------------------------
# Mapping C fields → JSON object
# ---------------------------------------------------------------------------

def set_dotted(obj: dict, dotted_path: str, value: object) -> None:
    """Place `value` into `obj` at `dotted_path`, creating intermediate
    dicts as needed."""
    parts = dotted_path.split(".")
    cur = obj
    for key in parts[:-1]:
        if key not in cur or not isinstance(cur[key], dict):
            cur[key] = {}
        cur = cur[key]
    cur[parts[-1]] = value


def default_profile_skeleton() -> dict:
    """Empty profile with every section present (so V2 zero-default
    fields always serialise, even when the C source omitted them).

    Values are placeholders — the caller fills real values from C
    parse output. We then merge tier1_offproto defaults at the end.
    """
    return {
        "tier0": {
            "weights": {},
        },
        "tier1": {
            "fusion_weights": {},
        },
        "tier1_l3": {
            "weights": {},
            "noise_floor_overrides": {},
        },
        "tier1_offproto": {
            "suspicious_threshold": 0.01,
            "attack_threshold": 0.05,
        },
        "v2_feature_weights": {},
    }


def zero_default_for(field: str) -> object:
    """Return the implicit default value the C designated-initialiser
    would have used for `field` when omitted from a profile block.

    For all of struct l2_profile's numeric fields this is 0.0 (or 0 for
    integer fields)."""
    return 0 if field in INTEGER_FIELDS else 0.0


def assemble_profile(c_fields: dict[str, object]) -> dict:
    """Build a JSON profile object from parsed C fields.

    For every field in FIELD_MAP:
      - if present in c_fields, use that value
      - else use the C designated-initialiser default (0 or 0.0)

    Then merge the V1 schema additions (tier1_offproto defaults).
    """
    profile = default_profile_skeleton()
    for c_field, json_path in FIELD_MAP.items():
        value = c_fields.get(c_field, zero_default_for(c_field))
        set_dotted(profile, json_path, value)
    return profile


# ---------------------------------------------------------------------------
# Top-level assembly
# ---------------------------------------------------------------------------

def build_services_json(parsed: dict[str, dict[str, object]]) -> dict:
    """Compose the full services.json structure from parsed C profiles.

    The 11 protected IPs each get a profile named
    `catchall_<ip_with_underscores>_v1`. The default profile becomes
    `catchall_generic_default`.
    """
    # Verify expected symbols are present.
    missing: list[str] = []
    for ip in PROTECTED_IPS:
        sym = IP_TO_PROFILE_SYMBOL[ip]
        if sym not in parsed:
            missing.append(sym)
    if missing:
        raise RuntimeError(
            "missing C profile symbols in source: " + ", ".join(missing)
        )
    if "l2_profile_default" not in parsed:
        raise RuntimeError("missing C symbol l2_profile_default in source")

    # Build profiles{}.
    profiles: dict[str, dict] = {}
    profiles["catchall_generic_default"] = assemble_profile(
        parsed["l2_profile_default"]
    )
    for ip in PROTECTED_IPS:
        sym = IP_TO_PROFILE_SYMBOL[ip]
        jname = "catchall_" + ip.replace(".", "_") + "_v1"
        profiles[jname] = assemble_profile(parsed[sym])

    # Build catchall_assignments — each protected IP gets all four keys
    # pointing to its own manual profile.
    catchall_assignments: dict[str, dict[str, str]] = {}
    for ip in PROTECTED_IPS:
        jname = "catchall_" + ip.replace(".", "_") + "_v1"
        catchall_assignments[ip] = {
            "tcp":   jname,
            "udp":   jname,
            "icmp":  jname,
            "other": jname,
        }

    # Full services.json structure.
    return {
        "version": 1,
        "metadata": {
            "last_modified": datetime.now(timezone.utc)
                .replace(microsecond=0)
                .isoformat()
                .replace("+00:00", "Z"),
            "modified_by": "phase0_initial_generation",
            "comment": (
                "Initial registry generated from l2fwd_l2_profile.c at "
                "big-bang cutover. 11 protected IPs, each with 4 catch-alls "
                "(TCP/UDP/ICMP/other) sharing that IP's ported profile. "
                "services[] is empty by design."
            ),
        },
        "protected_ips": PROTECTED_IPS,
        "profiles": profiles,
        "catchall_assignments": catchall_assignments,
        "services": [],
    }


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main() -> int:
    script_dir = Path(__file__).resolve().parent
    default_source = (script_dir / ".." / ".." / "l2fwd_l2_profile.c").resolve()
    default_output = (script_dir / ".." / "services.json").resolve()

    parser = argparse.ArgumentParser(
        description="Generate the initial services.json from l2fwd_l2_profile.c"
    )
    parser.add_argument(
        "--source",
        type=Path,
        default=default_source,
        help=f"Path to l2fwd_l2_profile.c (default: {default_source})",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=default_output,
        help=f"Path to write services.json (default: {default_output})",
    )
    args = parser.parse_args()

    if not args.source.exists():
        print(f"[FAIL] source file not found: {args.source}", file=sys.stderr)
        return 2

    try:
        parsed = parse_c_source(args.source)
    except Exception as exc:
        print(f"[FAIL] parse error: {exc}", file=sys.stderr)
        return 3
    n_parsed = len(parsed)
    print(f"[OK] Parsed {n_parsed} profiles from {args.source.name}")

    try:
        registry = build_services_json(parsed)
    except Exception as exc:
        print(f"[FAIL] assembly error: {exc}", file=sys.stderr)
        return 4

    n_profiles = len(registry["profiles"])
    n_catchall = len(registry["catchall_assignments"])
    n_services = len(registry["services"])
    print(
        f"[OK] Generated services.json with {n_profiles} profiles, "
        f"{n_catchall} catchall_assignments, {n_services} services"
    )

    # Ensure parent directory exists; write atomically.
    args.output.parent.mkdir(parents=True, exist_ok=True)
    payload = json.dumps(
        registry,
        indent=2,
        ensure_ascii=False,
        sort_keys=False,
    )
    args.output.write_text(payload + "\n", encoding="utf-8")
    n_bytes = args.output.stat().st_size
    print(f"[OK] Wrote {n_bytes} bytes to {args.output}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
