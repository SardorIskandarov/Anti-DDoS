# Runbook 03 — Protected IP Management

How to add, remove, and re-tune protected IPs in the service registry, and how
the engine picks up the change without a restart.

---

## Where the registry lives

- **Source of truth:** `config/services.json` (committed to git).
- **Runtime copy:** `/tmp/svc.json` — what the engine actually reads. The
  engine's `ExecStartPre` copies `services.json` -> `/tmp/svc.json` on every
  start; for a live reload you update `/tmp/svc.json` and SIGHUP the engine.

The engine reloads the registry on `SIGHUP` (P6 reload subsystem). No restart,
no dropped traffic.

---

## Add a new protected IP

1. **Edit the registry.** Add the IP (and its service slots) to the
   appropriate list in `config/services.json`. Follow the existing
   structure exactly — see `config/docs/services_schema.md` for the
   schema.

2. **Validate the JSON before doing anything else:**

   ```bash
   python3 config/scripts/validate_services_json.py \
       config/services.json
   ```

   Do not proceed if validation fails — a malformed file will be rejected by
   the engine's reload (see "Reload failure recovery" below), but it is far
   better to catch it here.

3. **Trigger the reload.** Two equivalent options:

   - Via systemd (production):
     ```bash
     sudo cp config/services.json /tmp/svc.json
     sudo systemctl kill --signal=SIGHUP anti-ddos-engine.service
     ```
   - Via raw PID (dev or production):
     ```bash
     sudo cp config/services.json /tmp/svc.json
     sudo kill -HUP "$(pgrep -f l2fwd)"
     ```

   The engine re-reads `/tmp/svc.json` on the SIGHUP. Copy the file **before**
   sending the signal.

4. **Verify** in the dashboard **Registry** tab — the new IP / slots should
   appear. Cross-check the engine journal for a successful reload line:

   ```bash
   journalctl -u anti-ddos-engine -n 20 --no-pager
   ```

5. **Commit** `config/services.json` so the change survives the next
   engine restart (which re-copies from the committed file).

---

## Remove a protected IP

Same flow as adding, in reverse:

1. Remove the IP / its slots from `config/services.json`.
2. Validate: `python3 config/scripts/validate_services_json.py config/services.json`
3. Copy to `/tmp/svc.json` and SIGHUP the engine (commands above).
4. Verify the IP is gone from the **Registry** tab.
5. Commit the change.

The engine drops the removed slots cleanly on reload; their historical rows in
ClickHouse are INSERT-only and remain queryable.

---

## Change a profile's thresholds

Profiles define the detection thresholds a slot is scored against.

1. Edit the profile object in `config/services.json` — adjust the
   threshold fields, leave the structure intact.
2. Validate the JSON (same command as above).
3. Copy to `/tmp/svc.json` and SIGHUP the engine.
4. Watch the affected slots in the dashboard for a few minutes to confirm the
   new thresholds behave as intended (fewer false `SUSPICIOUS` flaps, or
   tighter detection, depending on the intent).
5. Commit.

Threshold tuning is the usual fix for a slot that flaps `SUSPICIOUS <-> NORMAL`
without a real attack (see runbook 02).

---

## Reload failure recovery

The reload subsystem is fail-safe by design:

- If the new `/tmp/svc.json` is **invalid** (bad JSON, schema violation, etc.),
  the engine **logs the reload error and keeps running on the previous, known-
  good registry**. There is no traffic loss and no engine restart.
- Symptom: you SIGHUP, the dashboard Registry tab does **not** change, and the
  engine journal shows a reload-rejected error.

Recovery:

1. Read the error: `journalctl -u anti-ddos-engine -n 30 --no-pager`.
2. Fix `config/services.json` (re-run the validator until clean).
3. Re-copy to `/tmp/svc.json` and SIGHUP again.
4. The engine never adopted the broken config, so there is nothing to roll
   back — it has been running the last-good registry the whole time.

If you need to get back to the committed state immediately:

```bash
sudo cp config/services.json /tmp/svc.json
sudo systemctl kill --signal=SIGHUP anti-ddos-engine.service
```

---

## Registry audit trail

Every adopted registry state is recorded in ClickHouse in the
`service_registry_snapshots` table (P13 registry audit). Use it to answer
"what was the registry at time T?" or "when did this slot get added?":

```sql
-- Most recent registry snapshots
SELECT snapshot_ts, slot_count, source
FROM ddos_detection.service_registry_snapshots
ORDER BY snapshot_ts DESC
LIMIT 10;
```

Only **successful** reloads produce a snapshot — a rejected reload (above)
does not, which is itself a useful signal: if you SIGHUP'd and no new snapshot
row appeared, the reload was rejected.
