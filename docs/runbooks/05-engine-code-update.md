# Runbook 05 — Engine / Code Update Procedures

How to safely roll out a change to each part of the stack. The right procedure
depends on *what* changed.

---

## Quick reference

| What changed                          | Procedure                                                    | Telemetry impact          |
|----------------------------------------|--------------------------------------------------------------|---------------------------|
| C engine code                          | `make` rebuild, then restart engine                          | ~3 s gap during restart   |
| Collector Python (`collector.py`, `main.py`, `wire_parser.py`) | restart collector (then engine)             | brief gap; engine reconnect |
| Dashboard Python (`web.py`)            | restart dashboard                                            | none (dashboard only)     |
| `services.json`                        | SIGHUP the engine — no restart                               | none                      |
| Wire-protocol signature change         | bump version both sides, rebuild C, restart engine + collector | brief gap               |

---

## After a C engine code change

1. Rebuild the engine binary:
   ```bash
   make
   ```
   This rebuilds `build/l2fwd` via meson/ninja. The currently-running engine
   keeps using the old binary in memory until it is restarted.

2. Restart the engine:
   ```bash
   sudo systemctl restart anti-ddos-engine
   ```
   This drops telemetry briefly — roughly **3 seconds** across the rebuild's
   restart window (the engine re-inits DPDK, re-copies `services.json` to
   `/tmp/svc.json`, re-waits for the collector socket, then resumes). The
   collector and dashboard are untouched.

3. Verify:
   ```bash
   make systemd-status
   journalctl -u anti-ddos-engine -n 30 --no-pager
   make smoke
   ```

Do **not** restart the collector for an engine-only change — there is no
reason to drop the socket.

---

## After a Python change (collector or dashboard)

### Dashboard (`web.py`)

```bash
sudo systemctl restart anti-ddos-dashboard
```

The dashboard is independent — no effect on the engine or collector. Verify
`curl http://localhost:5000/api/health` returns `status: ok`.

### Collector (`collector.py`, `main.py`, `wire_parser.py`)

```bash
sudo systemctl restart anti-ddos-collector
sudo systemctl restart anti-ddos-engine
```

Restarting the collector drops and re-creates `/tmp/ddos_stats_socket`. The
engine connects to that socket **once at startup and does not auto-reconnect**,
so it must be restarted after the collector. `make systemd-restart` does this
collector -> engine -> dashboard sequence for you.

---

## After a `services.json` change

No service restart. Copy to the runtime path and SIGHUP the engine:

```bash
sudo cp config/services.json /tmp/svc.json
sudo systemctl kill --signal=SIGHUP anti-ddos-engine.service
```

The engine hot-reloads the registry with no traffic loss. Full procedure,
validation, and reload-failure recovery are in **runbook 03**.

---

## After a wire-protocol signature change

The binary wire protocol between the C engine and the Python collector is
version-locked. Any change to the message layout (new field, reordered field,
size change) **must** be made on both sides, in the same change, in this
order:

1. **Bump the wire version constant in C.** Update the version define in the
   C wire source/header so the engine emits the new version byte.

2. **Bump the matching constant in Python `config.py`.** The collector
   validates the version byte on every message; update `WIRE_VERSION` (and any
   related size constants — `WIRE_MSG_SIZE`, `WIRE_PAYLOAD_SIZE`, etc.) so they
   match the C side byte-for-byte.

3. **Rebuild the C engine:**
   ```bash
   make
   ```

4. **Restart the engine and the collector — engine first, then collector:**
   ```bash
   sudo systemctl restart anti-ddos-engine
   sudo systemctl restart anti-ddos-collector
   ```
   Restart the engine first so it is emitting the new format before the
   collector starts parsing; then restart the collector so it picks up the new
   parser. (`make systemd-restart` also works — it restarts collector, engine,
   then dashboard; either order is fine as long as both are restarted close
   together.)

5. **Verify the collector is not logging parse errors:**
   ```bash
   journalctl -u anti-ddos-collector -n 30 --no-pager
   ```
   A version/size mismatch shows up immediately as parse errors — that means
   the C and Python constants disagree. Fix and re-verify before walking away.

### Why old data stays queryable

The ClickHouse schema is INSERT-only and is not coupled to the wire version.
Old rows written under the previous wire format remain valid rows in
`service_stats` / the other tables; queries over historical data are
unaffected. A wire change only affects messages produced *after* the upgrade.

---

## General principles

- **One change class at a time.** Don't combine a wire-protocol change with a
  `services.json` change in the same rollout — you lose the ability to bisect.
- **Always `make smoke` after.** It is the fast end-to-end confirmation that
  all four services are up, NICs are bound, ClickHouse is reachable, and fresh
  data is flowing.
- **Watch the journal during the restart**, not just after — a crash-loop is
  obvious in `journalctl -u <svc> -f` and easy to miss in a single
  after-the-fact status check.
- **Commit `services.json` and `config.py` changes** so they survive the next
  restart (the engine re-copies `services.json` from the committed file on
  every start).
