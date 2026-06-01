# services.json — Schema (version 1)

This document specifies the JSON schema for the per-service detection
registry at `/home/user_1/Music/Anti-DDoS/config/services.json`.
It is the single source of truth for the upcoming per-service detection
architecture (P0–P17). Both the C engine (at startup) and the Python
validator (`scripts/validate_services_json.py`) enforce these rules.

The schema is intentionally narrow at v1: it locks the data shape and
the validation rules; it does NOT yet declare optional fields beyond
what the initial bootstrap needs. Forward-compatibility is provided by
the `version` field and the `--strict` validator flag (which rejects
unknown keys for future deployments that want to fail-closed).

---

## 1. Top-level structure

| Key                   | Type           | Required | Description                                                                 |
|-----------------------|----------------|----------|-----------------------------------------------------------------------------|
| `version`             | integer        | yes      | Schema version. Must equal `1` for v1.                                       |
| `metadata`            | object         | yes      | See §1.1.                                                                    |
| `protected_ips`       | array of strings | yes    | Dotted-quad IPv4 addresses, max 32. The set of IPs the engine protects.      |
| `profiles`            | object         | yes      | Map of `profile_name → profile_object`. See §2.                              |
| `catchall_assignments`| object         | yes      | Map of `ip_string → {tcp,udp,icmp,other}`. See §3.                           |
| `services`            | array of objects | yes    | Specific (IP, port, proto) services with their own profile. See §4.          |

Top-level order in the file is fixed for readability:
`version, metadata, protected_ips, profiles, catchall_assignments, services`.

### 1.1 metadata

```json
"metadata": {
  "last_modified": "2026-05-13T11:25:00Z",
  "modified_by":   "phase0_initial_generation",
  "comment":       "..."
}
```

| Key             | Type   | Required | Description                                |
|-----------------|--------|----------|--------------------------------------------|
| `last_modified` | string | yes      | ISO 8601 UTC timestamp.                    |
| `modified_by`   | string | yes      | Free-text actor (script name or username). |
| `comment`       | string | yes      | Free-text changelog note.                  |

---

## 2. Profile object schema

Each entry in `profiles{}` is a profile object. The key is the
**profile name** (the string used elsewhere in the file to reference
this profile). The value is a structured object grouped by detection
tier.

Every field in `struct l2_profile` (defined in `l2fwd_l2_profile.h`)
has a corresponding key in this schema. The mapping is bijective with
two exceptions:

- C `.name` / `.version` are not stored in JSON. The profile key acts
  as identity; storing the name twice would create drift potential.
- A new section `tier1_offproto` exists in JSON but has no C analog
  yet. The engine will consume it in a later phase (see P5).

### 2.1 Profile object structure

```json
"profile_name_here": {
  "tier0":              { /* CUSUM, burst-z, weights, thresholds, absolute overrides */ },
  "tier1":              { /* sigmoid, alphas, thresholds, fusion weights, persistence */ },
  "tier1_l3":           { /* Tier-1.5 L3 channel weights + sigmoid + noise floors */ },
  "tier1_offproto":     { /* NEW: per-service off-protocol thresholds */ },
  "v2_feature_weights": { /* TCP/UDP V2 behavioral feature weights */ }
}
```

### 2.2 `tier0` object

Maps to all CUSUM, burst-z, variance-ceiling, Tier-0 weight, suspicious
and attack risk thresholds, and absolute volumetric overrides.

| Key                          | Type   | Default      | C field                          |
|------------------------------|--------|--------------|----------------------------------|
| `alpha`                      | float  | `0.02`       | `.alpha_tier0`                   |
| `cusum_k_pps`                | float  | `0.10`       | `.cusum_k_pps`                   |
| `cusum_h_pps`                | float  | `6.5`        | `.cusum_h_pps`                   |
| `cusum_k_bps`                | float  | `0.10`       | `.cusum_k_bps`                   |
| `cusum_h_bps`                | float  | `6.5`        | `.cusum_h_bps`                   |
| `cusum_k_fps`                | float  | `0.85`       | `.cusum_k_fps`                   |
| `cusum_h_fps`                | float  | `6.0`        | `.cusum_h_fps`                   |
| `burst_z_threshold`          | float  | `8.5`        | `.burst_z_threshold`             |
| `variance_ceiling_factor`    | float  | `2.0`        | `.variance_ceiling_factor`       |
| `weights.pps`                | float  | `3.5`        | `.t0_w_pps`                      |
| `weights.bps`                | float  | `2.0`        | `.t0_w_bps`                      |
| `weights.fps`                | float  | `1.2`        | `.t0_w_fps`                      |
| `weights.burst_pps`          | float  | `1.5`        | `.t0_w_burst_pps`                |
| `weights.burst_bps`          | float  | `1.0`        | `.t0_w_burst_bps`                |
| `weights.burst_fps`          | float  | `0.5`        | `.t0_w_burst_fps`                |
| `suspicious_threshold`       | float  | `4.5`        | `.t0_suspicious_risk_threshold`  |
| `attack_threshold`           | float  | `6.5`        | `.t0_risk_threshold`             |
| `absolute_pps_threshold`     | float  | `30000.0`    | `.absolute_pps_threshold`        |
| `absolute_bps_threshold`     | float  | `310000000.0`| `.absolute_bps_threshold`        |
| `absolute_fps_threshold`     | float  | `300.0`      | `.absolute_fps_threshold`        |

### 2.3 `tier1` object

Sigmoid mapping, normal/suspicious thresholds, fusion weights, alphas
for the four Tier-1 channels, warm-up length, and persistence /
freeze / thaw windows.

| Key                          | Type    | Default | C field                       |
|------------------------------|---------|---------|-------------------------------|
| `sigmoid_k`                  | float   | `1.0`   | `.sigmoid_k`                  |
| `sigmoid_d0`                 | float   | `1.1`   | `.sigmoid_d0`                 |
| `normal_threshold`           | float   | `0.42`  | `.threshold_normal`           |
| `suspicious_threshold`       | float   | `0.62`  | `.threshold_suspicious`       |
| `fusion_weights.tcp`         | float   | `0.10`  | `.w_tcp`                      |
| `fusion_weights.udp`         | float   | `0.60`  | `.w_udp`                      |
| `fusion_weights.icmp`        | float   | `0.05`  | `.w_icmp`                     |
| `fusion_weights.dist`        | float   | `0.25`  | `.w_dist`                     |
| `alpha_tcp`                  | float   | `0.04`  | `.alpha_tier1_tcp`            |
| `alpha_udp`                  | float   | `0.07`  | `.alpha_tier1_udp`            |
| `alpha_icmp`                 | float   | `0.03`  | `.alpha_tier1_icmp`           |
| `alpha_dist`                 | float   | `0.06`  | `.alpha_tier1_dist`           |
| `warmup_windows`             | integer | `400`   | `.warmup_windows`             |
| `consecutive_attack_windows` | integer | `2`     | `.consecutive_attack_windows` |
| `baseline_freeze_windows`    | integer | `12`    | `.baseline_freeze_windows`    |
| `thaw_cooldown_windows`      | integer | `15`    | `.thaw_cooldown_windows`      |

**Note on `alpha_tcp/udp/icmp/dist`:** these correspond to
`.alpha_tier1_tcp` etc. in the C struct. The original spec mapping
table omitted them; this schema reinstates them to preserve full
parity with `struct l2_profile`. The C engine reads them today; the
JSON-driven loader will need to wire them via the same keys.

### 2.4 `tier1_l3` object

Tier-1.5 L3 sub-channel sigmoid + per-feature weights + per-profile
noise-floor overrides.

| Key                                          | Type  | Default | C field                              |
|----------------------------------------------|-------|---------|--------------------------------------|
| `sigmoid_k`                                  | float | `0.90`  | `.sigmoid_k_l3`                      |
| `sigmoid_d0`                                 | float | `1.40`  | `.sigmoid_d0_l3`                     |
| `weights.ttl_stddev`                         | float | `0.0`   | `.w_feat_ttl_stddev`                 |
| `weights.ip_frag_ratio`                      | float | `0.0`   | `.w_feat_ip_frag`                    |
| `weights.other_proto_ratio`                  | float | `0.0`   | `.w_feat_other_proto`                |
| `weights.src_port_top1_share`                | float | `0.0`   | `.w_feat_src_port_top1`              |
| `weights.src_24_top1_share`                  | float | `0.0`   | `.w_feat_src_24_top1`                |
| `weights.src_24_entropy`                     | float | `0.0`   | `.w_feat_src_24_entropy`             |
| `noise_floor_overrides.ip_frag_ratio`        | float | `0.0`   | `.frag_noise_floor_override`         |
| `noise_floor_overrides.other_proto_ratio`    | float | `0.0`   | `.other_proto_noise_floor_override`  |

A `noise_floor_overrides` value of `0.0` instructs the C engine to use
the macro defaults from `l2fwd_detection_engine.h`
(`L3_FRAG_NOISE_FLOOR = 0.05`, `L3_OTHER_PROTO_NOISE_FLOOR = 0.02`).

### 2.5 `tier1_offproto` object (NEW — no C analog yet)

Reserved for a future per-service feature: when a service is defined
on (IP, port, TCP), packets seen on that IP with proto≠TCP or
port≠service_port should accrue an "off-protocol" score that fires
its own SUSPICIOUS / ATTACK thresholds. These defaults are aggressive
because off-protocol traffic to a well-defined service is, by
construction, unwanted.

| Key                    | Type  | Default | Description                                       |
|------------------------|-------|---------|---------------------------------------------------|
| `suspicious_threshold` | float | `0.01`  | Fires `OFFPROTO_SUSPICIOUS` when reached.         |
| `attack_threshold`     | float | `0.05`  | Fires `OFFPROTO_ATTACK` when reached.             |

This section will be consumed by the engine in a later prompt (P5
ports the loader; the off-protocol detector is added in P9).

### 2.6 `v2_feature_weights` object

The 10 V2 behavioral feature weights. All defaults are `0.0` so V2
features remain inert until explicitly activated per service.

| Key                       | Type  | Default | C field                       |
|---------------------------|-------|---------|-------------------------------|
| `empty_ack_ratio`         | float | `0.0`   | `.w_feat_empty_ack`           |
| `zero_window_ratio`       | float | `0.0`   | `.w_feat_zero_window`         |
| `small_window_ratio`      | float | `0.0`   | `.w_feat_small_window`        |
| `new_flow_ratio`          | float | `0.0`   | `.w_feat_new_flow`            |
| `syn_fin_ratio`           | float | `0.0`   | `.w_feat_syn_fin`             |
| `syn_to_synack_ratio`     | float | `0.0`   | `.w_feat_syn_to_synack`       |
| `tcp_pkt_size_cov`        | float | `0.0`   | `.w_feat_tcp_pkt_size_cov`    |
| `tcp_mean_pkt_size`       | float | `0.0`   | `.w_feat_tcp_mean_pkt_size`   |
| `udp_pkt_size_cov`        | float | `0.0`   | `.w_feat_udp_pkt_size_cov`    |
| `udp_mean_pkt_size`       | float | `0.0`   | `.w_feat_udp_mean_pkt_size`   |

---

## 3. catchall_assignments

For every IP in `protected_ips`, there must be one entry mapping that
IP to a profile per protocol family. Layout:

```json
"catchall_assignments": {
  "213.230.125.170": {
    "tcp":   "catchall_213_230_125_170_v1",
    "udp":   "catchall_213_230_125_170_v1",
    "icmp":  "catchall_213_230_125_170_v1",
    "other": "catchall_213_230_125_170_v1"
  },
  ...
}
```

Semantics: when a packet arrives for IP X, if no explicit `services[]`
entry matches the `(IP, port, proto)` tuple, the engine consults
`catchall_assignments[X][proto]` to pick the profile. The `other` key
covers any IP protocol that isn't TCP/UDP/ICMP (GRE, ESP, exotic).

Different profiles per proto are permitted (e.g. an IP could pin its
UDP catchall to a tightened amplification-aware profile while keeping
TCP on a softer baseline). Mixed-profile assignments are an
intentional v1 feature, not v2 deferred work.

---

## 4. services schema

A `services[]` entry pins a specific `(target_ip, port, proto)` tuple
to a specific profile, taking precedence over the catchall. Empty at
P0 by design — fill it as services get tuned individually.

| Key                  | Type           | Required | Description                                              |
|----------------------|----------------|----------|----------------------------------------------------------|
| `name`               | string (1-64)  | yes      | Human-readable service identifier.                       |
| `target_ip`          | string         | yes      | Must be a member of `protected_ips`.                     |
| `port`               | integer        | one of   | Single port `[0, 65535]`.                                |
| `port_range`         | string         | one of   | `"LOW-HIGH"`, LOW ≤ HIGH, both in `[0, 65535]`.          |
| `proto`              | string enum    | yes      | One of `TCP`, `UDP`, `ICMP`.                             |
| `profile`            | string         | yes      | Must reference a key in `profiles{}`.                    |
| `detection_enabled`  | boolean        | yes      | When `false`, the service is parsed but not scored.      |
| `added_at`           | string         | no       | ISO 8601 timestamp. Free-text otherwise.                 |
| `added_by`           | string         | no       | Free-text actor.                                         |
| `notes`              | string         | no       | Free-text changelog.                                     |

Exactly one of `port` or `port_range` MUST be set. ICMP services
must have `port: 0` (and not use `port_range`).

### 4.1 Example with `port_range`

```json
{
  "name": "ephemeral-passive-ftp",
  "target_ip": "213.230.125.46",
  "port_range": "49152-65535",
  "proto": "TCP",
  "profile": "catchall_213_230_125_46_v1",
  "detection_enabled": true,
  "added_at": "2026-05-13T11:25:00Z",
  "added_by": "alice",
  "notes": "PASV data range; expand if FTP control deviates."
}
```

### 4.2 Example with single `port`

```json
{
  "name": "dns-resolver",
  "target_ip": "94.141.85.150",
  "port": 53,
  "proto": "UDP",
  "profile": "catchall_94_141_85_150_v1",
  "detection_enabled": true,
  "added_at": "2026-05-13T11:25:00Z"
}
```

A `port_range` is *expanded* by the engine into `(high - low + 1)`
logical service entries when validating limits — see rule 10 below.

---

## 5. Validation rules (numbered)

These 12 rules are the contract enforced by both
`scripts/validate_services_json.py` and (in a later phase) the C
loader. Every rule must independently fire.

| # | Rule                                                                                                       |
|---|------------------------------------------------------------------------------------------------------------|
| 1 | `version == 1`.                                                                                            |
| 2 | Every `service.target_ip` is a member of `protected_ips`.                                                  |
| 3 | Every `service.profile` references a key in `profiles{}`.                                                  |
| 4 | `catchall_assignments` has exactly one entry per `protected_ip` (no missing, no extra).                    |
| 5 | Each `catchall_assignments[ip]` has all four keys: `tcp`, `udp`, `icmp`, `other`.                          |
| 6 | Every catchall profile reference is a key in `profiles{}`.                                                 |
| 7 | No two `services[]` entries share the same `(target_ip, port, proto)` (port_range expanded for the check). |
| 8 | `service.proto` ∈ `{"TCP", "UDP", "ICMP"}`.                                                                |
| 9 | Single ports in `[0, 65535]`; ICMP services must have `port == 0` and must not use `port_range`.           |
| 10 | Expanded service count + `(n_protected_ips × 4)` ≤ 328 (engine table limit).                              |
| 11 | `n_protected_ips ≤ 32`.                                                                                   |
| 12 | All profile weights ≥ `0.0`; all probabilities (`tier1.{normal,suspicious}_threshold`, `tier1_l3.weights.*`, `tier1_offproto.{suspicious,attack}_threshold`) in `[0, 1]`. |

### Notes on rule 7 — port_range expansion

When checking uniqueness, a `port_range` "LOW-HIGH" expands to the
inclusive integer set. Two services that BOTH use ranges and OVERLAP
on the same `(target_ip, proto)` violate rule 7 even if their text
strings differ.

### Notes on rule 10 — the 328 cap

The DPDK engine sizes its lookup table at 328 entries (`32 IPs ×
(4 catchalls + ~7 typical services per IP) ≈ 320` plus headroom).
The validator enforces the hard cap. A `port_range` of width N counts
as N entries.

### Notes on rule 12 — bound on probability fields

Profile weights (Tier-0 `weights.*`, Tier-1 `fusion_weights.*`, V2 and
V3 feature weights) are non-negative floats with no upper bound. They
act as coefficients on `norm_dist` outputs; the sigmoid clamps the
final score.

Probability-shaped fields are explicitly bounded `[0, 1]`:
- `tier1.normal_threshold`, `tier1.suspicious_threshold`
- `tier1_l3.weights.*` are NOT probabilities (they are weights) — only the V2 / V3 weights and tier weights are weight-shaped; bounded ≥ 0 but not ≤ 1.
- `tier1_offproto.suspicious_threshold`, `tier1_offproto.attack_threshold`

Tier-0 thresholds (`suspicious_threshold`, `attack_threshold`) are
raw risk sums in the range `[0, ~10]` typically — not probabilities,
so they fall under the "≥ 0" rule only.

---

## 6. How the C engine and Python validator both enforce these rules

At P0 only the Python validator exists. The C engine still loads
profiles via the static `l2_profile_assignments[]` table in
`l2fwd_l2_profile.c`. Both enforcement paths converge by P5:

- **Python validator** (`scripts/validate_services_json.py`):
  - Runs as a pre-commit step and inside CI.
  - Implements all 12 rules above.
  - On failure, prints every violation found (not just the first).
  - On success, prints `[OK] services.json is valid: …`.

- **C engine loader** (added in P5):
  - Parses the same JSON at startup.
  - Re-runs rules 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11 (rule 12 is
    enforced at runtime via clamping where applicable).
  - Refuses to start if any rule fails — fails closed.

Drift between the two enforcers is itself a CI failure: a separate
gold-test (added in P6) loads a fixture services.json into both and
compares the parsed in-memory structures.

---

## 7. Forward-compatibility

- New top-level keys are reserved for future versions. The default
  validator silently ignores unknown top-level keys; `--strict` mode
  rejects them.
- New keys inside profile objects follow the same rule.
- Bumping `version` past 1 requires updating both validators in
  lockstep.

