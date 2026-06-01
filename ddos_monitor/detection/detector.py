"""
detector.py — the Python detection brain.

One SlotState per service slot (keyed by identity), advanced once per 1 Hz
snapshot. The tick pipeline is feed-forward score-then-update — features are
derived from the raw counters of the current window, scored against the
*previous* tick's frozen baseline, the phase machine decides the verdict, and
the EWMA baselines are trained at the *end* only if the window's verdict is
NORMAL and the slot is not (now) frozen.

Per-tick stages:
    1. derive       — push burst windows + compute ratios/std-devs from snapshot
                      counters. No EWMA updates.
    2. Tier-0       — CUSUM(pps,bps,fps) + burst-z → weighted R0; scored
                      against the prior baseline mean/variance.
    3. abs-floor    — absolute-threshold breach short-circuits to ATTACK.
    4. persistence  — Tier-0-fired history is a 5-bit rolling bitmask; the
                      gate opens when popcount(history) >= GATE_PERSISTENCE_WINDOWS.
                      This catches pulsing/burst attacks the old strict
                      consecutive-counter missed.
    5. Tier-1       — per-proto + dist + L3 + offproto channels, fused with
                      Discounted-Max: T1 = max(0.75·c1 + 0.25·c2, c1 − 0.15)
                      where c1, c2 are the top-2 channel scores. This
                      corroboration-aware fusion lifts the verdict on two
                      mid-tier channels while capping the single-channel
                      penalty to 0.15.
    6. phase + freezes — abs/warmup/gate/thresholds → new phase; arm/release
                         attack-freeze and EWMA-freeze.
    7. update       — train EWMA baselines + burst-EWMA only if (not frozen)
                      and (verdict == NORMAL).

Per-profile P6 fix flags (default OFF) live on ProfileParams:
  * fix_fps_source   — fps EWMA baseline tracks the common flow estimate the
                       CUSUM observes (kills ICMP false-fps-breach).
  * fix_frag_zscore  — IP-fragment ratio is z-scored against its learned
                       baseline instead of the coarse `frag_r * 20` ramp.
"""

import math

from . import config as C
from . import primitives as M


# ---------------------------------------------------------------------------
# Per-slot state
# ---------------------------------------------------------------------------


class SlotState:
    """All persistent detection state for one slot (mirrors the parts of
    service_common_ewma / proto ewma / service_detection_state the scorer
    reads). EWMA channels are created lazily, identical to the C 'initialized'
    flag semantics."""

    def __init__(self, params: C.ProfileParams):
        self.params = params

        # Tier-0 EWMA baselines + CUSUM + burst windows.
        self.ewma_pps = M.EwmaState()
        self.ewma_bps = M.EwmaState()
        self.ewma_fps = M.EwmaState()
        self.ewma_burst_pps = M.EwmaState()
        self.ewma_burst_bps = M.EwmaState()
        self.ewma_burst_fps = M.EwmaState()
        self.cusum_pps = M.CusumState()
        self.cusum_bps = M.CusumState()
        self.cusum_fps = M.CusumState()
        self.bw_pps = M.BurstWindow()
        self.bw_bps = M.BurstWindow()
        self.bw_fps = M.BurstWindow()

        # Common Tier-1 EWMA baselines (dist + L3 + offproto).
        self.ewma_src_ip_ratio = M.EwmaState()
        self.ewma_src24_top1 = M.EwmaState()
        self.ewma_src24_entropy = M.EwmaState()
        self.ewma_ttl_stddev = M.EwmaState()
        self.ewma_off_proto_ratio = M.EwmaState()
        self.ewma_frag_ratio = M.EwmaState()   # P6 fix_frag_zscore only

        # Proto-arm Tier-1 EWMA baselines (only the scored channels).
        self.ewma_syn_ratio = M.EwmaState()
        self.ewma_empty_ack_ratio = M.EwmaState()
        self.ewma_zero_window_ratio = M.EwmaState()
        self.ewma_syn_to_synack = M.EwmaState()
        self.ewma_tcp_pkt_cov = M.EwmaState()
        self.ewma_udp_pps_ratio = M.EwmaState()
        self.ewma_udp_flow_ratio = M.EwmaState()
        self.ewma_udp_pkt_cov = M.EwmaState()
        self.ewma_udp_mean_pkt = M.EwmaState()
        self.ewma_icmp_pps_ratio = M.EwmaState()
        self.ewma_icmp_echo_ratio = M.EwmaState()

        # Phase machine.
        self.phase = C.PHASE_WARMUP
        self.prev_phase = C.PHASE_WARMUP
        self.warmup_remaining = params.warmup_windows
        self.warmup_windows_completed = 0
        # Rolling 5-bit history of Tier-0 fires: bit 0 is "this tick fired",
        # bits 1..4 are the previous four ticks. The persistence gate opens
        # when popcount(history) >= GATE_PERSISTENCE_WINDOWS (default 3/5),
        # which catches pulsing attacks the old strict consecutive counter
        # would reset on every quiet tick. `consecutive_attack_windows` is
        # repurposed as that popcount (kept for ClickHouse wire stability).
        self.tier0_history_bits = 0
        self.consecutive_attack_windows = 0
        self.ewma_freeze_remaining = 0
        self.consecutive_normal_windows = 0
        self.attack_freeze_active = False
        self.windows_seen = 0
        self.last_phase_change_window = 0

        # Cached per-tick outputs (consumed by the row builder).
        self.last_tier0_score = 0.0
        self.r_pps = self.r_bps = self.r_fps = 0.0
        self.r_burst_pps = self.r_burst_bps = self.r_burst_fps = 0.0
        self.t1_tcp = self.t1_udp = self.t1_icmp = 0.0
        self.t1_dist = self.t1_l3 = self.t1_offproto = 0.0
        self.t1_final = 0.0
        self.last_attack_evidence = 0.0
        self.dominant_channel = C.DOM_NONE
        self.last_absolute_floor_fired = False
        self.baseline_freeze_remaining = 0
        self.thaw_cooldown_remaining = 0
        self.bw_pps_z_last = 0.0
        self.bw_bps_z_last = 0.0

    # -- freeze predicates (scoring.c:828-842) --
    def is_frozen(self) -> bool:
        return self.attack_freeze_active or self.ewma_freeze_remaining > 0

    def cusum_frozen(self) -> bool:
        return self.attack_freeze_active


def _stddev_of(e: M.EwmaState) -> float:
    """scoring.c:128-132 — safe stddev from an EWMA state."""
    if not e.initialized:
        return 0.0
    if e.variance <= 0.0:
        return 0.0
    return math.sqrt(e.variance)


def _pop_cov_from_welford(mean: float, M2: float, n: int) -> float:
    """Population CoV from Welford state shipped in the snapshot.

    pop_var = M2 / n  (population variance, not Bessel — n divisor as used by
    the scoring layer historically). Welford-true: no catastrophic cancellation.
    """
    if n <= 0 or mean <= 0.0:
        return 0.0
    pop_var = (M2 / n) if n > 1 else 0.0
    if pop_var < 0.0:
        pop_var = 0.0
    return math.sqrt(pop_var) / mean


# ---------------------------------------------------------------------------
# Detector
# ---------------------------------------------------------------------------


class Detector:
    """Holds per-slot state keyed by service identity and advances it one
    snapshot at a time. Reload-safe: state survives across snapshots and is
    re-aligned by identity (the registry_epoch only signals when the slot set
    may have changed)."""

    def __init__(self, config: C.DetectionConfig):
        self.config = config
        self._slots = {}   # (ip, port, proto_kind) -> SlotState

    def _state_for(self, ip: int, port: int, kind: int) -> SlotState:
        key = (ip, port, kind)
        st = self._slots.get(key)
        if st is None:
            st = SlotState(self.config.params_for(ip, port, kind))
            self._slots[key] = st
        return st

    # -- the per-slot tick -------------------------------------------------

    def process_record(self, rec) -> None:
        """Advance one slot by one window from its snapshot record. ``rec`` is a
        NumPy structured row (or any object exposing the snapshot fields).

        Pipeline order (feed-forward, score-then-update):
          derive → Tier-0 → abs/gate → Tier-1 → phase → freezes → update.
        Baseline EWMAs are trained at the END only when the verdict is NORMAL
        and the slot is not (now) frozen — i.e. attack-tainted windows never
        contaminate the baseline."""
        ip = int(rec["target_ip"])
        port = int(rec["port"])
        kind = int(rec["proto_kind"])
        st = self._state_for(ip, port, kind)
        p = st.params

        # Freeze state at start of tick — Tier-0 CUSUM honours
        # cusum_frozen; we don't need `frozen` for scoring (we never update
        # baselines before scoring) but it's load-bearing for the end-of-tick
        # update gate (combined with the just-armed EWMA freeze).
        cusum_frozen = st.cusum_frozen()
        alpha, vcf = p.alpha, p.variance_ceiling

        # === STAGE 1: derive features from the current window ===
        # No EWMA updates here — every baseline EWMA seen by Tier-0/Tier-1
        # is the previous tick's frozen baseline.
        pps = float(int(rec["inbound_pkts"]))
        bps = float(int(rec["inbound_bytes"])) * 8.0
        fps_proto = self._fps_for_kind(rec, kind)        # EWMA/burst baseline input
        fps_obs = float(rec["est_unique_flows"])         # fps CUSUM observation
        # P6 fix_fps_source: feed the fps EWMA baseline the SAME source the
        # CUSUM observes. Default OFF preserves the historic C mismatch.
        fps_ewma_input = fps_obs if p.fix_fps_source else fps_proto

        # Burst windows are the *feature* (rolling 10-sample mean/stddev →
        # z_last), not a baseline; pushing them every tick advances the
        # rolling window. The ewma_burst_* EWMAs ARE baselines and are
        # only trained at end-of-tick.
        M.burst_window_push(st.bw_pps, pps)
        M.burst_window_push(st.bw_bps, bps)
        M.burst_window_push(st.bw_fps, fps_proto)
        st.bw_pps_z_last = st.bw_pps.z_last
        st.bw_bps_z_last = st.bw_bps.z_last

        inbound = int(rec["inbound_pkts"])
        # TTL stddev: Welford-true Bessel from the snapshot's mean/M2.
        ttl_sd_bessel = (math.sqrt(float(rec["ttl_M2"]) / (inbound - 1))
                         if inbound > 1 else 0.0)
        src_ip_ratio = (float(rec["est_unique_src_ips"]) / inbound) if inbound > 0 else 0.0
        off_ratio = (float(int(rec["off_proto_pkts"])) / inbound) if inbound > 0 else 0.0
        src24_top1 = float(rec["src_24_top1_share"])
        src24_ent = float(rec["src_24_entropy"])
        frag_r = (float(int(rec["ip_frag_pkts"])) / inbound) if inbound > 0 else 0.0

        # === STAGE 2: Tier-0 against the PRIOR baseline ===
        R0 = self._tier0(st, pps, bps, fps_obs, cusum_frozen)
        st.last_tier0_score = R0

        # === STAGE 3: absolute-floor fail-safe ===
        abs_breach = self._absolute_breach(rec, p, fps_obs)
        st.last_absolute_floor_fired = abs_breach

        # t0 3-level state
        if R0 >= C.T0_ATTACK_RISK_THRESHOLD:
            t0_state = C.PHASE_ATTACK
        elif R0 >= C.T0_GATE_RISK_THRESHOLD:
            t0_state = C.PHASE_SUSPICIOUS
        else:
            t0_state = C.PHASE_NORMAL
        # abs-floor counts as a t0 fire for the rolling history — a slot that
        # spikes hard enough to trip the floor should leave a "hit" bit
        # behind even if the next tick decays back below the gate.
        t0_fired = (t0_state != C.PHASE_NORMAL) or abs_breach

        # === STAGE 4: shift the rolling-bitmask history ===
        # bit 0 = current tick, bits 1..4 = previous four. Gate fires when
        # popcount(history) >= GATE_PERSISTENCE_WINDOWS. This catches pulsing
        # patterns (1,0,1,0,1) the old strict consecutive counter missed.
        st.tier0_history_bits = (
            ((st.tier0_history_bits << 1) | (1 if t0_fired else 0)) & 0x1F)
        popcount = bin(st.tier0_history_bits).count("1")
        # Wire field repurposed: now reports popcount-of-5 instead of
        # strict consecutive count (semantic change, schema stable).
        st.consecutive_attack_windows = popcount

        # === STAGE 5a: learning mode — score, cache, train, never transition ===
        if self.config.learning_mode:
            self._combine(st, rec, kind)
            st.last_attack_evidence = R0
            st.windows_seen += 1
            self._update_baselines(st, rec, kind, pps, bps, fps_ewma_input,
                                   ttl_sd_bessel, src_ip_ratio, off_ratio,
                                   src24_top1, src24_ent, frag_r, alpha, vcf, p)
            return

        old_phase = st.phase
        # Tick EWMA freeze countdown.
        if st.ewma_freeze_remaining > 0:
            st.ewma_freeze_remaining -= 1

        # === STAGE 5b: warmup — score, cache, train, auto-promote ===
        if st.warmup_remaining > 0:
            st.warmup_remaining -= 1
            st.warmup_windows_completed += 1
            self._combine(st, rec, kind)
            st.last_attack_evidence = R0
            if st.warmup_remaining == 0 and st.phase == C.PHASE_WARMUP:
                st.phase = C.PHASE_NORMAL
            # During warmup we always train — that's how the baseline boots.
            self._update_baselines(st, rec, kind, pps, bps, fps_ewma_input,
                                   ttl_sd_bessel, src_ip_ratio, off_ratio,
                                   src24_top1, src24_ent, frag_r, alpha, vcf, p)
            self._finalize(st, p, old_phase)
            return

        # === STAGE 5c/6: main path — gate, Tier-1, phase ===
        new_phase = old_phase

        if abs_breach:
            # Absolute floor forces ATTACK, bypass gate + Tier-1.
            self._combine(st, rec, kind)
            st.last_attack_evidence = R0
            new_phase = C.PHASE_ATTACK
        else:
            gate_open = popcount >= C.GATE_PERSISTENCE_WINDOWS
            if not gate_open:
                new_phase = C.PHASE_NORMAL
                st.last_attack_evidence = R0
            else:
                T1 = self._combine(st, rec, kind)
                st.last_attack_evidence = T1
                if T1 >= C.ATTACK_THRESHOLD:
                    new_phase = C.PHASE_ATTACK
                elif T1 >= C.SUSPICIOUS_THRESHOLD:
                    new_phase = C.PHASE_SUSPICIOUS
                else:
                    new_phase = C.PHASE_NORMAL

            # Arm the EWMA freeze the instant Tier-0 fires, even if the gate
            # didn't open this tick — protects the baseline from the spike.
            if t0_fired:
                fw = p.baseline_freeze_windows
                if st.ewma_freeze_remaining < fw:
                    st.ewma_freeze_remaining = fw

        st.phase = new_phase

        # Full-freeze arm/release.
        if new_phase == C.PHASE_ATTACK:
            st.attack_freeze_active = True
            st.consecutive_normal_windows = 0
        elif st.attack_freeze_active:
            if new_phase == C.PHASE_NORMAL:
                st.consecutive_normal_windows += 1
                if st.consecutive_normal_windows >= p.thaw_cooldown_windows:
                    st.attack_freeze_active = False
                    st.consecutive_normal_windows = 0
            else:
                st.consecutive_normal_windows = 0

        # === STAGE 7: end-of-tick baseline update ===
        # Train only when verdict is NORMAL *and* the slot is not (now) frozen.
        # st.is_frozen() reflects both the carried-over EWMA freeze countdown
        # *and* a freeze just armed this tick — so a Tier-0 fire that armed
        # the freeze blocks its own contaminating update.
        if (new_phase == C.PHASE_NORMAL) and (not st.is_frozen()):
            self._update_baselines(st, rec, kind, pps, bps, fps_ewma_input,
                                   ttl_sd_bessel, src_ip_ratio, off_ratio,
                                   src24_top1, src24_ent, frag_r, alpha, vcf, p)

        self._finalize(st, p, old_phase)

    # -- finalize: derive wire freeze fields + transition bookkeeping ------
    def _finalize(self, st: SlotState, p: C.ProfileParams, old_phase: int):
        # scoring.c:787-803
        if st.is_frozen():
            st.baseline_freeze_remaining = (st.ewma_freeze_remaining
                                            if st.ewma_freeze_remaining > 0 else 1)
        else:
            st.baseline_freeze_remaining = 0
        if st.attack_freeze_active:
            thaw = p.thaw_cooldown_windows
            st.thaw_cooldown_remaining = (thaw - st.consecutive_normal_windows
                                          if thaw > st.consecutive_normal_windows else 0)
        else:
            st.thaw_cooldown_remaining = 0

        if st.phase != old_phase:
            st.prev_phase = old_phase
            st.last_phase_change_window = st.windows_seen
        st.windows_seen += 1

    # -- fps proto selection (features.c estimate_flows_for_kind:355-370) --
    @staticmethod
    def _fps_for_kind(rec, kind: int) -> float:
        if kind in (C.PROTO_TCP, C.PROTO_CATCHALL_TCP):
            return float(rec["est_tcp_new_flows"])
        if kind in (C.PROTO_UDP, C.PROTO_CATCHALL_UDP):
            return float(rec["est_udp_flows"])
        if kind == C.PROTO_CATCHALL_OTHER:
            return float(rec["est_tcp_new_flows"]) + float(rec["est_udp_flows"])
        return 0.0   # ICMP / CATCHALL_ICMP have no flow HLL

    @staticmethod
    def _absolute_breach(rec, p: C.ProfileParams, fps_obs: float) -> bool:
        pps = float(int(rec["inbound_pkts"]))
        bps = float(int(rec["inbound_bytes"])) * 8.0
        if p.absolute_pps_threshold > 0.0 and pps >= p.absolute_pps_threshold:
            return True
        if p.absolute_bps_threshold > 0.0 and bps >= p.absolute_bps_threshold:
            return True
        if p.absolute_fps_threshold > 0.0 and fps_obs >= p.absolute_fps_threshold:
            return True
        return False

    # -- Tier-0 (scoring.c:195-271) ---------------------------------------
    def _tier0(self, st: SlotState, pps: float, bps: float, fps_obs: float,
               cusum_frozen: bool) -> float:
        k, h = C.TIER0_K, C.TIER0_H

        def chan(cusum, x, ewma):
            r = 0.0
            if not cusum_frozen:
                if M.cusum_update(cusum, x, ewma.mean, _stddev_of(ewma), k, h):
                    r = min(1.0, cusum.S_plus / h)
            else:
                r = min(1.0, cusum.S_plus / h)
            return r

        st.r_pps = chan(st.cusum_pps, pps, st.ewma_pps)
        st.r_bps = chan(st.cusum_bps, bps, st.ewma_bps)
        st.r_fps = chan(st.cusum_fps, fps_obs, st.ewma_fps)

        st.r_burst_pps = self._burst_risk(st.ewma_burst_pps, st.bw_pps.z_last)
        st.r_burst_bps = self._burst_risk(st.ewma_burst_bps, st.bw_bps.z_last)
        st.r_burst_fps = self._burst_risk(st.ewma_burst_fps, st.bw_fps.z_last)

        return (C.T0_W_PPS * st.r_pps + C.T0_W_BPS * st.r_bps
                + C.T0_W_FPS * st.r_fps + C.T0_W_BURST_PPS * st.r_burst_pps
                + C.T0_W_BURST_BPS * st.r_burst_bps
                + C.T0_W_BURST_FPS * st.r_burst_fps)

    @staticmethod
    def _burst_risk(ewma_burst: M.EwmaState, z_last: float) -> float:
        z = M.ewma_z_score(ewma_burst, z_last)
        r = abs(z) / C.BURST_Z_THRESHOLD
        return 1.0 if r > 1.0 else r

    # -- end-of-tick baseline update (Stage 7) ----------------------------
    def _update_baselines(self, st, rec, kind, pps, bps, fps_ewma_input,
                          ttl_sd_bessel, src_ip_ratio, off_ratio,
                          src24_top1, src24_ent, frag_r, alpha, vcf, p):
        """Train every baseline EWMA on the values derived for this tick.
        Caller decides when to call this — gate is (not frozen AND verdict
        NORMAL) on the main path, unconditional during warmup/learning."""
        M.ewma_update(st.ewma_pps, pps, alpha, vcf)
        M.ewma_update(st.ewma_bps, bps, alpha, vcf)
        M.ewma_update(st.ewma_fps, fps_ewma_input, alpha, vcf)
        M.ewma_update(st.ewma_burst_pps, st.bw_pps.z_last, alpha, vcf)
        M.ewma_update(st.ewma_burst_bps, st.bw_bps.z_last, alpha, vcf)
        M.ewma_update(st.ewma_burst_fps, st.bw_fps.z_last, alpha, vcf)
        M.ewma_update(st.ewma_ttl_stddev, ttl_sd_bessel, alpha, vcf)
        M.ewma_update(st.ewma_src_ip_ratio, src_ip_ratio, alpha, vcf)
        M.ewma_update(st.ewma_off_proto_ratio, off_ratio, alpha, vcf)
        M.ewma_update(st.ewma_src24_top1, src24_top1, alpha, vcf)
        M.ewma_update(st.ewma_src24_entropy, src24_ent, alpha, vcf)
        if p.fix_frag_zscore:
            M.ewma_update(st.ewma_frag_ratio, frag_r, alpha, vcf)
        self._update_proto_baselines(st, rec, kind, alpha, vcf)

    # -- per-proto baseline EWMA updates ----------------------------------
    def _update_proto_baselines(self, st, rec, kind, alpha, vcf):
        if kind in (C.PROTO_TCP, C.PROTO_CATCHALL_TCP, C.PROTO_CATCHALL_OTHER):
            tp = int(rec["tcp_pkts"])
            if tp > 0:
                dn = float(tp)
                M.ewma_update(st.ewma_syn_ratio, int(rec["syn_pkts"]) / dn, alpha, vcf)
                M.ewma_update(st.ewma_empty_ack_ratio, int(rec["empty_ack_pkts"]) / dn, alpha, vcf)
                M.ewma_update(st.ewma_zero_window_ratio, int(rec["zero_window_pkts"]) / dn, alpha, vcf)
                sa = int(rec["syn_ack_pkts"])
                syn_to_sa = (int(rec["syn_pkts"]) / sa) if sa > 0 else float(int(rec["syn_pkts"]))
                M.ewma_update(st.ewma_syn_to_synack, syn_to_sa, alpha, vcf)
                # Welford-true Bessel CoV: snapshot ships mean/M2 directly.
                mean = float(rec["tcp_pkt_size_mean"])
                sd = (math.sqrt(float(rec["tcp_pkt_size_M2"]) / (tp - 1))
                      if tp > 1 else 0.0)
                cov_bessel = (sd / mean) if mean > 0.0 else 0.0
                M.ewma_update(st.ewma_tcp_pkt_cov, cov_bessel, alpha, vcf)
        if kind in (C.PROTO_UDP, C.PROTO_CATCHALL_UDP, C.PROTO_CATCHALL_OTHER):
            up = int(rec["udp_pkts"])
            if up > 0:
                dn = float(up)
                mean = float(rec["udp_pkt_size_mean"])
                sd = (math.sqrt(float(rec["udp_pkt_size_M2"]) / (up - 1))
                      if up > 1 else 0.0)
                cov_bessel = (sd / mean) if mean > 0.0 else 0.0
                M.ewma_update(st.ewma_udp_pkt_cov, cov_bessel, alpha, vcf)
                M.ewma_update(st.ewma_udp_mean_pkt, mean, alpha, vcf)
                M.ewma_update(st.ewma_udp_flow_ratio,
                              float(rec["est_udp_flows"]) / dn, alpha, vcf)
                M.ewma_update(st.ewma_udp_pps_ratio, dn, alpha, vcf)
        if kind in (C.PROTO_ICMP, C.PROTO_CATCHALL_ICMP, C.PROTO_CATCHALL_OTHER):
            ip_ = int(rec["icmp_pkts"])
            if ip_ > 0:
                dn = float(ip_)
                M.ewma_update(st.ewma_icmp_echo_ratio,
                              int(rec["icmp_echo_pkts"]) / dn, alpha, vcf)
                M.ewma_update(st.ewma_icmp_pps_ratio, dn, alpha, vcf)

    # -- Tier-1 sub-channels (scoring.c:277-473) ---------------------------
    def _t1_tcp(self, st, rec, kind):
        if kind not in (C.PROTO_TCP, C.PROTO_CATCHALL_TCP, C.PROTO_CATCHALL_OTHER):
            return 0.0
        tp = int(rec["tcp_pkts"])
        if tp < C.TCP_MIN_PKTS:
            return 0.0
        dn = float(tp)
        syn_r = int(rec["syn_pkts"]) / dn
        empty_ack_r = int(rec["empty_ack_pkts"]) / dn
        zero_win_r = int(rec["zero_window_pkts"]) / dn
        sa = int(rec["syn_ack_pkts"])
        syn_to_sa = (int(rec["syn_pkts"]) / sa) if sa > 0 else float(int(rec["syn_pkts"]))
        pkt_cov = _pop_cov_from_welford(float(rec["tcp_pkt_size_mean"]),
                                        float(rec["tcp_pkt_size_M2"]), tp)
        z1 = M.ewma_z_score(st.ewma_syn_ratio, syn_r)
        z2 = M.ewma_z_score(st.ewma_empty_ack_ratio, empty_ack_r)
        z3 = M.ewma_z_score(st.ewma_zero_window_ratio, zero_win_r)
        z4 = M.ewma_z_score(st.ewma_syn_to_synack, syn_to_sa)
        z5 = M.ewma_z_score(st.ewma_tcp_pkt_cov, pkt_cov)
        s = (M.z_to_score(z1) + M.z_to_score(z2) + M.z_to_score(z3)
             + M.z_to_score(z4) + M.z_to_score(z5)) / 5.0
        return min(1.0, s)

    def _t1_udp(self, st, rec, kind):
        if kind not in (C.PROTO_UDP, C.PROTO_CATCHALL_UDP, C.PROTO_CATCHALL_OTHER):
            return 0.0
        up = int(rec["udp_pkts"])
        if up < C.UDP_MIN_PKTS:
            return 0.0
        dn = float(up)
        pkt_mean = float(rec["udp_pkt_size_mean"])
        pkt_cov = _pop_cov_from_welford(pkt_mean,
                                        float(rec["udp_pkt_size_M2"]), up)
        flow_r = float(rec["est_udp_flows"]) / dn
        z1 = M.ewma_z_score(st.ewma_udp_pps_ratio, dn)
        z2 = M.ewma_z_score(st.ewma_udp_flow_ratio, flow_r)
        z3 = M.ewma_z_score(st.ewma_udp_pkt_cov, pkt_cov)
        z4 = M.ewma_z_score(st.ewma_udp_mean_pkt, pkt_mean)
        s = (M.z_to_score(z1) + M.z_to_score(z2) + M.z_to_score(z3)
             + M.z_to_score(z4)) / 4.0
        return min(1.0, s)

    def _t1_icmp(self, st, rec, kind):
        if kind not in (C.PROTO_ICMP, C.PROTO_CATCHALL_ICMP, C.PROTO_CATCHALL_OTHER):
            return 0.0
        ic = int(rec["icmp_pkts"])
        if ic < C.ICMP_MIN_PKTS:
            return 0.0
        dn = float(ic)
        echo_r = int(rec["icmp_echo_pkts"]) / dn
        z1 = M.ewma_z_score(st.ewma_icmp_pps_ratio, dn)
        z2 = M.ewma_z_score(st.ewma_icmp_echo_ratio, echo_r)
        s = (M.z_to_score(z1) + M.z_to_score(z2)) / 2.0
        return min(1.0, s)

    def _t1_dist(self, st, rec):
        if int(rec["inbound_pkts"]) < C.DIST_MIN_PKTS:
            return 0.0
        inbound = int(rec["inbound_pkts"])
        sir = (float(rec["est_unique_src_ips"]) / inbound) if inbound > 0 else 0.0
        z_sir = M.ewma_z_score(st.ewma_src_ip_ratio, sir)
        z_top1 = M.ewma_z_score(st.ewma_src24_top1, float(rec["src_24_top1_share"]))
        z_ent = -M.ewma_z_score(st.ewma_src24_entropy, float(rec["src_24_entropy"]))
        s = (M.z_to_score(z_sir) + M.z_to_score(z_top1) + M.z_to_score(z_ent)) / 3.0
        return min(1.0, s)

    def _t1_l3(self, st, rec):
        if int(rec["inbound_pkts"]) < C.L3_MIN_PKTS:
            return 0.0
        pkts = int(rec["inbound_pkts"])
        dn = float(pkts)
        # Welford-true population TTL stddev (pop variance = M2/n).
        ttl_var = (float(rec["ttl_M2"]) / dn) if pkts > 1 else 0.0
        if ttl_var < 0.0:
            ttl_var = 0.0
        ttl_sd = math.sqrt(ttl_var)
        z_ttl = M.ewma_z_score(st.ewma_ttl_stddev, ttl_sd)
        frag_r = (float(int(rec["ip_frag_pkts"])) / dn) if pkts > 0 else 0.0
        if st.params.fix_frag_zscore:
            # P6: score the frag ratio against its learned baseline, like the
            # other L3 channels, instead of the coarse `frag_r * 20` ramp.
            z_frag = M.z_to_score(M.ewma_z_score(st.ewma_frag_ratio, frag_r))
        else:
            z_frag = M.z_to_score(frag_r * 20.0)   # coarse ramp (scoring.c:452)
        off_r = (float(int(rec["off_proto_pkts"])) / dn) if pkts > 0 else 0.0
        z_off = M.ewma_z_score(st.ewma_off_proto_ratio, off_r)
        s = (M.z_to_score(z_ttl) + z_frag + M.z_to_score(z_off)) / 3.0
        return min(1.0, s)

    def _t1_offproto(self, st, rec):
        if int(rec["inbound_pkts"]) < C.OFFPROTO_MIN_PKTS:
            return 0.0
        inbound = int(rec["inbound_pkts"])
        r = float(int(rec["off_proto_pkts"])) / inbound
        z = M.ewma_z_score(st.ewma_off_proto_ratio, r)
        return M.z_to_score(z)

    # -- combine + dominant -----------------------------------------------
    def _combine(self, st, rec, kind) -> float:
        """Discounted-Max Hybrid Fusion.

        Take the top-2 channel scores c1 >= c2 across {proto, dist, l3,
        offproto} and emit

            T1 = max(0.75·c1 + 0.25·c2, c1 − 0.15)

        The blend lifts the verdict when a second channel corroborates the
        leader; the (c1 − 0.15) cliff caps the punishment when only one
        channel is strong (so a clear single-channel attack isn't
        squashed). Saturates in [0, 1]."""
        st.t1_tcp = self._t1_tcp(st, rec, kind)
        st.t1_udp = self._t1_udp(st, rec, kind)
        st.t1_icmp = self._t1_icmp(st, rec, kind)
        st.t1_dist = self._t1_dist(st, rec)
        st.t1_l3 = self._t1_l3(st, rec)
        st.t1_offproto = self._t1_offproto(st, rec)

        if kind in (C.PROTO_TCP, C.PROTO_CATCHALL_TCP):
            proto_score = st.t1_tcp
        elif kind in (C.PROTO_UDP, C.PROTO_CATCHALL_UDP):
            proto_score = st.t1_udp
        elif kind in (C.PROTO_ICMP, C.PROTO_CATCHALL_ICMP):
            proto_score = st.t1_icmp
        elif kind == C.PROTO_CATCHALL_OTHER:
            proto_score = max(st.t1_tcp, st.t1_udp, st.t1_icmp)
        else:
            proto_score = 0.0

        # In-line top-2 of (proto, dist, l3, offproto) without sort/list
        # allocation — keeps the hot path branchy but allocation-free.
        a, b = proto_score, st.t1_dist
        if a >= b:
            c1, c2 = a, b
        else:
            c1, c2 = b, a
        v = st.t1_l3
        if v > c1:
            c2 = c1; c1 = v
        elif v > c2:
            c2 = v
        v = st.t1_offproto
        if v > c1:
            c2 = c1; c1 = v
        elif v > c2:
            c2 = v

        blended = 0.75 * c1 + 0.25 * c2
        floor = c1 - 0.15
        final_score = blended if blended > floor else floor
        if final_score < 0.0:
            final_score = 0.0
        elif final_score > 1.0:
            final_score = 1.0
        st.t1_final = final_score
        st.dominant_channel = self._dominant(st, kind)
        return st.t1_final

    def _dominant(self, st, kind) -> int:
        cand = {
            C.DOM_PPS: max(st.r_pps, st.r_burst_pps),
            C.DOM_BPS: max(st.r_bps, st.r_burst_bps),
            C.DOM_FPS: max(st.r_fps, st.r_burst_fps),
            C.DOM_DIST: st.t1_dist,
            C.DOM_L3: st.t1_l3,
            C.DOM_OFFPROTO: st.t1_offproto,
        }
        if kind in (C.PROTO_TCP, C.PROTO_CATCHALL_TCP):
            cand[C.DOM_TCP] = st.t1_tcp
        elif kind in (C.PROTO_UDP, C.PROTO_CATCHALL_UDP):
            cand[C.DOM_UDP] = st.t1_udp
        elif kind in (C.PROTO_ICMP, C.PROTO_CATCHALL_ICMP):
            cand[C.DOM_ICMP] = st.t1_icmp
        elif kind == C.PROTO_CATCHALL_OTHER:
            cand[C.DOM_TCP] = st.t1_tcp
            cand[C.DOM_UDP] = st.t1_udp
            cand[C.DOM_ICMP] = st.t1_icmp

        # ascending scan, strict-greater (low-enum tie-break), floor 0.15
        best_ch, best_v = C.DOM_NONE, 0.0
        for ch in range(C.DOM_PPS, C.DOM_OFFPROTO + 1):
            v = cand.get(ch, -1.0)
            if v > best_v:
                best_v, best_ch = v, ch
        return C.DOM_NONE if best_v < C.DOMINANT_FLOOR else best_ch
