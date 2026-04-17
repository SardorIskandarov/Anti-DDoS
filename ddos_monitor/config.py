# ============================================================================
# CLICKHOUSE DATABASE CONFIGURATION
# ============================================================================
CH_HOST = 'localhost'
CH_PORT = 9000
CH_USER = 'default'
CH_PASSWORD = 'sardor1217'
CH_DB = 'ddos_detection'
CH_TABLE = 'traffic_stats'

# ============================================================================
# UNIX SOCKET CONFIGURATION
# ============================================================================
SOCK_PATH = '/tmp/ddos_stats_socket'
BUFFER_SIZE = 65536

# ============================================================================
# BATCH PROCESSING CONFIGURATION
# ============================================================================
BATCH_SIZE = 100              # Records per database batch insert
RAM_BUFFER_SIZE = 1000        # Records to keep in RAM for dashboard

# ============================================================================
# FLASK WEB SERVER CONFIGURATION
# ============================================================================
FLASK_HOST = '0.0.0.0'
FLASK_PORT = 5000
FLASK_DEBUG = False

# ============================================================================
# TARGET IP / SUBNET FILTER
# Only dst_ip addresses falling within these networks are processed.
# Entries can be single IPs ("1.2.3.4") or CIDR subnets ("1.2.3.0/24").
# ============================================================================
TARGET_PREFIXES = [
    "213.230.125.0/29",
    "185.203.236.180/30",
    "93.188.85.124/30",
    "93.188.85.232/30",
    "45.150.25.136/29",
    "213.230.125.240/29",
    "94.141.85.109/32",
    "94.141.85.110/32",
    "213.230.125.16/28",
    "213.230.125.48/30",
    "213.230.125.128/30",
    "89.249.63.92/30",
    "185.203.236.64/27",
    "213.230.125.64/29",
    "94.141.85.105/32",
    "93.188.85.220/30",
    "89.249.63.112/29",
    "89.249.62.16/29",
    "89.249.62.130/32",
    "89.249.62.131/32",
    "89.249.62.132/32",
    "89.249.62.133/32",
    "89.249.62.134/32",
    "89.249.63.128/29",
    "89.249.62.136/29",
    "89.249.62.156/30",
    "89.249.63.84/30",
    "185.203.236.96/29",
    "45.150.25.240/29",
    "185.203.236.224/30",
    "94.141.85.107/32",
    "94.141.85.108/32",
    "185.203.237.16/29",
    "45.150.25.192/29",
    "185.203.237.176/30",
    "45.150.25.0/28",
    "89.249.63.176/30",
    "89.249.63.196/30",
    "185.203.236.172/30",
    "185.203.237.180/30",
    "185.203.237.24/30",
    "45.150.25.72/29",
    "45.150.25.96/30",
    "89.249.62.152/30",
    "45.150.25.248/30",
    "93.188.85.80/29",
    "93.188.85.164/30",
    "93.188.85.200/29",
    "93.188.85.212/30",
    "213.230.125.44/30",
    "213.230.125.104/29",
    "89.249.63.180/30",
    "213.230.125.160/27",
    "45.150.25.100/30",
    "89.249.63.140/30",
    "185.203.236.32/29",
    "185.203.236.48/28",
    "185.203.236.176/30",
    "185.203.236.40/29",
    "185.203.237.12/30",
    "213.230.125.144/28",
    "89.249.63.40/29",
    "89.249.63.32/30",
    "89.249.63.208/28",
    "89.249.63.36/30",
    "45.150.25.104/29",
    "45.150.25.124/30",
    "93.188.85.208/30",
    "93.188.85.160/30",
    "93.188.85.96/28",
    "185.203.236.248/29",
    "93.188.85.228/30",
    "185.203.236.168/30",
    "185.203.236.104/30",
    "45.150.25.64/30",
    "185.203.236.113/28",
    "185.203.236.128/29",
    "185.203.236.136/29",
    "94.141.85.72/29",
    "93.188.85.192/30",
    "213.230.125.120/29",
    "185.203.236.108/30",
    "89.249.63.100/30",
    "89.249.63.144/28",
    "45.150.25.68/30",
    "45.150.25.200/29",
    "89.249.63.160/28",
    "45.150.25.114/32",
    "45.150.25.115/32",
    "45.150.25.116/32",
    "45.150.25.117/32",
    "45.150.25.118/32",
    "94.141.85.80/28",
    "94.141.85.176/29",
    "89.249.63.18/32",
    "89.249.63.16/28",
    "89.249.63.19/32",
    "89.249.63.20/32",
    "89.249.63.21/32",
    "89.249.63.22/32",
    "89.249.63.24/32",
    "89.249.63.23/32",
    "89.249.63.25/32",
    "89.249.63.26/32",
    "89.249.63.27/32",
    "89.249.63.28/32",
    "94.141.85.98/32",
    "94.141.85.99/32",
    "94.141.85.100/32",
    "94.141.85.102/32",
    "94.141.85.103/32",
    "94.141.85.106/32",
    "94.141.85.149/32",
    "94.141.85.104/32",
    "94.141.85.152/32",
    "94.141.85.154/32",
    "94.141.85.156/32",
    "94.141.85.153/32",
    "94.141.85.147/32",
    "94.141.85.151/32",
    "94.141.85.150/32",
    "94.141.85.148/32",
    "94.141.85.157/32",
    "94.141.85.158/32",
    "94.141.85.146/32",
]

# config.py — Layer 3 V1 configuration
#
# All tunable constants live here. No logic. Import and use directly.
# Sections mirror the corrected plan so each value is easy to locate.

# =============================================================================
# PATHS
# =============================================================================

# UNIX socket: C bridge pushes per-source snapshots to Python here.
L3_BRIDGE_SOCKET_PATH: str = "/tmp/l3_bridge_socket"

# Flat text file: Python writes policies here; C reloads it once per second.
L3_POLICY_FILE_PATH: str = "/tmp/l3_policies.txt"

# Atomic-write staging file (Python writes here, then rename() to above).
L3_POLICY_FILE_TMP: str = "/tmp/l3_policies.txt.tmp"

# =============================================================================
# MODE FLAGS
# =============================================================================

# When False (shadow mode): Python generates policies but writes only ALLOW
# entries to the policy file. C enforces nothing. Safe default.
# When True (enforce mode): real policies are written and enforced by C.
L3_ENFORCE_MODE: bool = False

# When True: extra per-window diagnostic output to stdout.
L3_DEBUG_LOGGING: bool = False

# =============================================================================
# SUSPICIOUS SCORE THRESHOLDS
# Policies are only generated at or above these score levels.
# =============================================================================

# Suspicious score at or above which RATE_LIMIT_SOFT is applied.
THRESHOLD_RATE_LIMIT_SOFT: float = 0.55

# Suspicious score at or above which RATE_LIMIT_HARD is applied.
# Also requires persistence (see PERSISTENCE_REQUIRED below).
THRESHOLD_RATE_LIMIT_HARD: float = 0.72

# Suspicious score at or above which BLOCK is applied.
# Requires stronger persistence.
THRESHOLD_BLOCK: float = 0.88

# =============================================================================
# PERSISTENCE REQUIREMENTS
# Number of consecutive suspicious windows required before each action level
# is eligible. Prevents strong actions on a single anomalous window.
# =============================================================================

PERSISTENCE_REQUIRED: dict = {
    "RATE_LIMIT_SOFT": 1,   # can apply in the first suspicious window
    "RATE_LIMIT_HARD": 2,   # needs 2 consecutive suspicious windows
    "BLOCK":           3,   # needs 3 consecutive suspicious windows
}

# Number of consecutive non-suspicious windows required before de-escalation
# steps down one action level. Higher = slower de-escalation = less flapping.
DEESCALATION_WINDOWS: int = 2

# =============================================================================
# TTL DEFAULTS (seconds)
# All policies are temporary. C expires them via l3_policy_expire_tick().
# =============================================================================

TTL_DEFAULTS: dict = {
    "RATE_LIMIT_SOFT": 15,
    "RATE_LIMIT_HARD": 20,
    "BLOCK":           10,   # short; renewable only if score still >= THRESHOLD_BLOCK
}

# =============================================================================
# RATE LIMIT DEFAULTS (packets per second)
# Used by C token-bucket enforcement for RATE_LIMIT_* actions.
# 0 means "use C-side default" (reserved for BLOCK where rate is not relevant).
# =============================================================================

RATE_PPS_DEFAULTS: dict = {
    "RATE_LIMIT_SOFT": 1000,
    "RATE_LIMIT_HARD": 100,
    "BLOCK":           0,
}

# =============================================================================
# SUSPICIOUS SCORE WEIGHTS
# Weighted fusion: suspicious_score = sum(weight_k * subscore_k).
# Each row must sum to 1.0.
# =============================================================================

WEIGHTS: dict = {
    "TCP": {
        "contribution":          0.30,
        "protocol_abnormality":  0.25,
        "handshake_abnormality": 0.20,
        "persistence":           0.15,
        "concentration":         0.10,
    },
    "UDP": {
        "contribution":          0.35,
        "protocol_abnormality":  0.25,
        "handshake_abnormality": 0.05,
        "persistence":           0.20,
        "concentration":         0.15,
    },
    "ICMP": {
        "contribution":          0.35,
        "protocol_abnormality":  0.30,
        "handshake_abnormality": 0.00,
        "persistence":           0.20,
        "concentration":         0.15,
    },
    "MIXED": {
        "contribution":          0.30,
        "protocol_abnormality":  0.25,
        "handshake_abnormality": 0.10,
        "persistence":           0.20,
        "concentration":         0.15,
    },
}

# Mapping from Layer 2 attack_type_str() output to scoring context key above.
ATTACK_TYPE_TO_CONTEXT: dict = {
    "SYN_FLOOD":     "TCP",
    "ACK_FLOOD":     "TCP",
    "RST_FIN_FLOOD": "TCP",
    "UDP_FLOOD":     "UDP",
    "AMPLIFICATION": "UDP",
    "ICMP_FLOOD":    "ICMP",
    "DISTRIBUTED":   "MIXED",
    "MIXED":         "MIXED",
    "UNKNOWN":       "MIXED",
    "NONE":          "MIXED",
}

# =============================================================================
# PERSISTENCE WINDOW
# =============================================================================

# Number of recent per-window scores retained per (src_ip, dst_ip) pair.
PERSISTENCE_WINDOW_SIZE: int = 5

# A past window is counted as "suspicious" for persistence purposes if its
# final score was at or above this value.
PERSISTENCE_SUSPICIOUS_THRESHOLD: float = 0.50

# =============================================================================
# MINIMUM EVIDENCE THRESHOLDS
# Protect against unstable ratios computed from tiny packet samples.
# =============================================================================

# Below this packet count the full score is damped by (pkt_count / threshold).
MIN_EVIDENCE_PKTS: int = 10

# Below this TCP packet count, TCP flag ratios are set to 0.0 (unreliable).
MIN_TCP_PKTS: int = 5

# =============================================================================
# CONTRIBUTION GATING
# Prevents tiny background sources from reaching strong policy actions.
# =============================================================================

# Sources contributing less than this fraction of victim traffic are gated.
MIN_CONTRIBUTION_GATE: float = 0.001   # 0.1%

# Score cap applied when contribution is below the gate AND persistence < 0.60.
CONTRIBUTION_GATE_CAP: float = 0.60

# =============================================================================
# SUB-SCORE NORMALISATION REFERENCES
# =============================================================================

# Contribution: share at which each contribution signal reaches 1.0.
CONTRIBUTION_NORM_PKT: float = 0.20    # 20% of victim packets
CONTRIBUTION_NORM_BYTE: float = 0.20   # 20% of victim bytes
CONTRIBUTION_NORM_FLOW: float = 0.20   # 20% of victim fps

# Protocol abnormality — TCP flag saturation points.
TCP_SYN_SATURATION: float = 0.80
TCP_RST_SATURATION: float = 0.60
TCP_ACK_SATURATION: float = 0.80

# Protocol abnormality — non-TCP reference volumes.
UDP_REFERENCE_BPS: float = 100_000_000.0   # 100 Mbps
ICMP_REFERENCE_PPS: float = 10_000.0       # 10 kpps

# Handshake abnormality — incompleteness gap that maps to score 1.0.
HANDSHAKE_INCOMPLETENESS_NORM: float = 0.70

# Concentration — attack share fraction that maps share_concentration to 1.0.
CONCENTRATION_SHARE_NORM: float = 0.15

# =============================================================================
# SHARED STATE LIMITS
# =============================================================================

# Maximum number of Layer 3 events retained in the events ring buffer.
L3_MAX_EVENTS: int = 200

# Maximum number of top suspicious sources retained per attacked victim.
L3_MAX_TOP_SOURCES_PER_VICTIM: int = 20
