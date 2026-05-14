# Runbook 01 — Restart Procedures

How to restart the Anti-DDoS stack, in dev and in production, and how to
recover from the two most common "won't stay up" failure modes.

---

## Quick reference — which restart to use

| Situation                                  | Command                                              |
|---------------------------------------------|------------------------------------------------------|
| Dev box, iterating on code                  | `make stop && make run`                              |
| Production, restart everything              | `sudo systemctl restart anti-ddos.target`            |
| Production, restart one service             | `sudo systemctl restart anti-ddos-<svc>`             |
| Production, ordered restart of the 3 apps   | `make systemd-restart`                               |
| Engine binary rebuilt                       | `sudo systemctl restart anti-ddos-engine`            |
| Collector / dashboard Python changed        | `sudo systemctl restart anti-ddos-collector` (or `-dashboard`) |
| `services.json` changed                     | SIGHUP the engine — see runbook 03, no restart       |

`<svc>` is one of: `anti-ddos-dpdk-setup`, `anti-ddos-collector`,
`anti-ddos-engine`, `anti-ddos-dashboard`.

---

## Dev workflow restart

The dev workflow uses `setsid nohup` + PID files in `/tmp/`, not systemd.

```bash
make stop      # TERM the 3 processes, clean PID files
make run       # pre-flight cleanup, then start collector -> dashboard -> engine
make status    # confirm 3 PIDs + socket + port 5000
```

`make run` primes `sudo` once at the top, does its own pre-flight `pkill`, and
starts the three processes in dependency order. It is safe to run `make run`
after a crash without `make stop` first — the pre-flight cleanup handles
stragglers.

**Dev and prod are mutually exclusive.** Never run `make run` while the
systemd stack is active — both bind `/tmp/ddos_stats_socket` and port 5000.
Stop one before starting the other.

---

## Production restart — whole stack

```bash
sudo systemctl restart anti-ddos.target
```

`anti-ddos.target` `Wants` all four units. systemd restarts them respecting
the dependency graph:

1. `anti-ddos-dpdk-setup.service` (oneshot — re-binds NICs if needed; idempotent)
2. `anti-ddos-collector.service` (binds the socket)
3. `anti-ddos-engine.service` (waits for dpdk-setup + collector socket)
4. `anti-ddos-dashboard.service` (independent — only needs ClickHouse)

Verify afterward:

```bash
make systemd-status
make smoke
```

---

## Production restart — single service

```bash
sudo systemctl restart anti-ddos-engine
sudo systemctl restart anti-ddos-collector
sudo systemctl restart anti-ddos-dashboard
```

Caveat for the collector: when the collector restarts, the engine's client
connection to `/tmp/ddos_stats_socket` is dropped, and **the engine does not
auto-reconnect**. After restarting the collector, also restart the engine:

```bash
sudo systemctl restart anti-ddos-collector
sudo systemctl restart anti-ddos-engine
```

`make systemd-restart` does the correct collector -> engine -> dashboard
sequence automatically.

---

## Graceful drain (for engine updates)

When taking the engine down for a rebuild, the dashboard should reflect the
outage immediately rather than showing stale-but-green data:

1. Stop the engine first: `sudo systemctl stop anti-ddos-engine`
2. The dashboard's `/api/health` flips to `degraded` within ~30s as data
   goes stale — operators watching the dashboard see it right away.
3. Do the rebuild / change.
4. Start the engine: `sudo systemctl start anti-ddos-engine`
5. Leave the collector running the whole time — it just sees its client
   disconnect and reconnect.

Do **not** stop the collector for an engine-only change; there is no reason
to drop the socket.

---

## Recovery — "engine is in a restart loop"

Symptom: `systemctl status anti-ddos-engine` shows `activating (auto-restart)`
or repeated `Restart=` cycling.

```bash
# 1. Read the actual error
journalctl -u anti-ddos-engine -b --no-pager | tail -50

# 2. Confirm the NIC-binding prerequisite ran
systemctl status anti-ddos-dpdk-setup        # expect: active (exited)
journalctl -u anti-ddos-dpdk-setup -b --no-pager

# 3. Confirm the NICs are actually on vfio-pci
/usr/local/bin/dpdk-devbind.py --status | grep -E '0000:02:0[256]\.0'
#   0000:02:02.0 and 0000:02:05.0 -> drv=vfio-pci   (data plane)
#   0000:02:06.0                  -> drv=vmxnet3    (management — must stay kernel)

# 4. Confirm the collector socket exists (engine needs it at startup)
ls -l /tmp/ddos_stats_socket
```

Common causes:
- **NICs not bound** — re-run the setup: `sudo systemctl restart anti-ddos-dpdk-setup`,
  then `sudo systemctl restart anti-ddos-engine`. See runbook 05 and
  `docs/systemd_deployment.md`.
- **Socket missing** — collector isn't up; fix the collector first (below).
- **Hugepages** — `grep Huge /proc/meminfo`; should show 2048 × 2MB. This is
  set at the kernel level and not managed by P15.
- **Bad `services.json`** — engine logs a parse error and exits. Validate the
  file (runbook 03) and restore a known-good copy.

---

## Recovery — "collector won't start"

Symptom: `systemctl status anti-ddos-collector` shows `failed`, or it cycles.

```bash
# 1. Read the error
journalctl -u anti-ddos-collector -b --no-pager | tail -50

# 2. Is ClickHouse up? The collector Requires= it.
sudo systemctl status clickhouse-server

# 3. Socket permission / staleness
ls -l /tmp/ddos_stats_socket          # ExecStartPre removes it; should be re-created on start
#    If a stale socket owned by root is blocking the bind, remove it:
sudo rm -f /tmp/ddos_stats_socket && sudo systemctl restart anti-ddos-collector

# 4. Credentials — is /etc/anti-ddos/env present and readable by user_1?
sudo ls -l /etc/anti-ddos/env         # expect mode 0640, root:user_1
#    If CH_PASSWORD is wrong, the collector logs a ClickHouse auth error.
```

Common causes:
- **ClickHouse down** — see runbook 04. Start ClickHouse, then the collector.
- **Wrong / missing `CH_PASSWORD`** — fix `/etc/anti-ddos/env`, then restart.
  Note the collector still falls back to the dev default with a loud WARNING
  in the journal if the env file is absent.
- **Stale root-owned socket** — remove it and restart (step 3 above).

After the collector is healthy again, restart the engine so it reconnects to
the fresh socket.
