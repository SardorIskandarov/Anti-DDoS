# Runbook 02 — Attack Alert Response

How to read a phase-transition alert, decide whether it is real, and respond.

---

## Detection phases

Every service slot (`IP:port:proto`) is always in exactly one of four phases.
The engine computes this per slot, every second.

| Phase        | Meaning                                                                 |
|--------------|-------------------------------------------------------------------------|
| `WARMUP`     | Slot is new or just reloaded; not enough history to score yet. Benign.  |
| `NORMAL`     | Traffic is within the slot's learned/configured baseline. Steady state. |
| `SUSPICIOUS` | Tier-1 score elevated — something is off, but not over the attack line. |
| `ATTACK`     | Tier-1 score over threshold — engine has classified this as an attack.  |

Normal operation: most slots `NORMAL`, the occasional `WARMUP` when a slot is
first seen, rare brief `SUSPICIOUS`. Sustained `SUSPICIOUS` or any `ATTACK` is
a signal to investigate.

---

## Reading the Alerts tab

The **Alerts** tab shows phase transitions, newest first, sourced from the
`service_phase_transitions` ClickHouse table. Each row is a *change* of phase
for one slot, with the timestamp, the slot identity, `from_phase` ->
`to_phase`, and the `tier1_final_score` at the moment of transition.

What to look for:

- **`NORMAL -> ATTACK`** directly — a sharp-onset attack (flood that ramps
  fast). High urgency.
- **`NORMAL -> SUSPICIOUS -> ATTACK`** over several rows — a developing
  attack. You may catch it mid-ramp.
- **Flapping** (`SUSPICIOUS <-> NORMAL` repeatedly on one slot) — usually a
  threshold tuned slightly too tight for that slot's natural variance, not an
  attack. Consider a profile adjustment (runbook 03).
- **Many distinct slots transitioning at once** — either a real broad attack,
  or a global threshold problem. Cross-check with the Overview tab phase tiles.

---

## Score interpretation — Tier-0 vs Tier-1

The engine scores in two tiers:

- **Tier-0** is the cheap per-packet/per-second screen. It decides whether a
  slot is even worth deeper analysis. A high Tier-0 alone is not a verdict —
  it is "look closer."
- **Tier-1** is the full per-service feature scoring. `tier1_final_score` is
  the number that drives the phase decision. This is the score you reason
  about when triaging an alert.

The Tier-1 final score is a weighted blend of component scores (rate,
distribution, protocol-conformance, temporal). On the **Slot Detail** tab you
can see the components individually — that breakdown is what tells you *which
kind* of attack it is.

---

## Common ATTACK patterns and their signatures

| Pattern                  | Tier-1 components that spike                          | Tell                                                            |
|--------------------------|-------------------------------------------------------|-----------------------------------------------------------------|
| TCP SYN flood            | Rate + protocol-conformance                           | pps way up, mostly SYN, few completed handshakes                |
| UDP flood                | Rate + protocol-conformance                           | pps/bps up on a UDP slot, packet-size distribution abnormal     |
| ICMP flood               | Rate + off-protocol                                   | ICMP volume on a slot that normally sees little/none            |
| Distribution anomaly     | Distribution score                                    | Unique-src-IP count spikes (botnet) **or** collapses (spoof)    |
| Off-protocol             | Off-protocol / protocol-conformance                   | Traffic on a port/proto the slot's profile does not expect      |

These overlap — a real attack often lights up more than one component. The
component mix is a hint, not a label.

---

## Drill-down path: alert -> slot detail -> time series

1. **Alerts tab** — note the slot (`IP:port:proto`) and the transition time.
2. **Services tab** — find that slot in the list (rows are phase-colored);
   confirm it is still elevated, not already back to `NORMAL`.
3. **Slot Detail tab** — open the slot. Read:
   - the **Tier-1 chart** trend — still climbing = active/escalating;
     plateaued high = sustained; falling = subsiding.
   - the **component breakdown** — identifies the attack type (table above).
   - **Unique src IPs** — single-source vs distributed.
   - the **temporal aggregates** (10s / 60s / 300s windows) — is this a
     one-second spike or a sustained trend across all three windows?

A spike visible only in the 10s window that is absent from the 60s/300s
windows is usually noise. A trend present in all three is a real event.

---

## False positive vs real attack

Lean **false positive** when:
- Only the 10s temporal window is elevated; 60s/300s are flat.
- The slot is flapping `SUSPICIOUS <-> NORMAL` with no score plateau.
- The slot just left `WARMUP` (scoring is still stabilizing).
- A known benign event explains it (deploy, backup job, traffic migration).

Lean **real attack** when:
- The Tier-1 score is sustained over threshold across all three temporal
  windows.
- The component breakdown matches a known pattern above.
- The unique-src-IP count is clearly anomalous (spike or collapse).
- Multiple related slots (same IP, different ports) transition together.

When unsure, treat as real until proven otherwise, but do not trigger upstream
mitigation until you have the component signature.

---

## Recommended response sequence

1. **Identify the slot** — exact `IP:port:proto` from the Alerts tab.
2. **Check Tier-1 component scores** (Slot Detail) — get the attack signature.
3. **Check Unique src IPs** — distributed (many sources) vs single-source vs
   spoofed (collapsed/implausible source diversity).
4. **Check temporal aggregates** (10s / 60s / 300s) — confirm it is a trend,
   establish onset time and whether it is still escalating.
5. **Coordinate with the network team** for upstream mitigation — this system
   *detects and reports*; it does not blackhole or rate-limit. Give them the
   slot, the onset time, the signature, and the source profile.
6. **Keep watching the Slot Detail chart** to confirm the mitigation works
   (score should fall, phase should return toward `NORMAL`).

---

## Acknowledging / silencing an alert

There is **no acknowledge or silence mechanism** in v1.0.0. The Alerts tab is
a live view of `service_phase_transitions`; the engine keeps scoring and keeps
recording transitions regardless of operator awareness.

In practice:
- "Acknowledging" is operational, not in-tool — note it in your incident
  channel / ticket.
- An alert "clears" when the slot transitions back to `NORMAL`; that
  transition shows up as its own row in the Alerts tab.
- Do not expect the alert to disappear — the historical transition rows are
  retained as the forensic record.

Webhook/email alerting and acknowledgement are explicitly v1.1 candidates
(see `docs/SIGN_OFF.md`, Known Limitations).
