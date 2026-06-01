# Systemd Deployment

Production deployment of the Anti-DDoS per-service detection stack using
systemd. This is **purely additive** on top of the dev Makefile workflow
(`make run` / `make stop`) — it does not replace or modify it.

The stack has four systemd units — three long-running services plus one
one-shot boot-setup service — plus one target that groups them:

| Unit                            | Process                     | User    | Purpose                                          |
|----------------------------------|-----------------------------|---------|--------------------------------------------------|
| `anti-ddos-dpdk-setup.service`   | `systemd/dpdk-setup.sh`     | root    | One-shot: binds data-plane NICs to vfio-pci at boot |
| `anti-ddos-collector.service`    | `ddos_monitor/main.py`      | user_1  | Binds `/tmp/ddos_stats_socket`, inserts into ClickHouse |
| `anti-ddos-engine.service`       | `build/l2fwd` (DPDK)        | root    | L2 forwarder + per-service detection hot path    |
| `anti-ddos-dashboard.service`    | `ddos_monitor/web.py`       | user_1  | Flask dashboard + JSON API on `:5000`            |
| `anti-ddos.target`               | —                           | —       | Groups all of the above for single start/stop    |

The unit files are **staged** in `systemd/` in the repo. They are not active
until the operator installs them with `sudo make install-systemd`.

---

## DPDK NIC binding at boot (`anti-ddos-dpdk-setup.service`)

### Why it's needed

The engine is a DPDK application: it drives its data-plane NICs directly,
bypassing the kernel. For that the NICs must be bound to the `vfio-pci`
driver. This VM has **no IOMMU** (typical for VMware-based VMs), so `vfio-pci`
has to run in *no-IOMMU mode*.

The kernel **resets all NIC driver bindings on every reboot** — at boot the
data-plane NICs come back attached to the normal `vmxnet3` kernel driver. A
reboot test confirmed the symptom: the collector and dashboard auto-start
fine, but `anti-ddos-engine.service` fails because its NICs are no longer on
`vfio-pci`.

`anti-ddos-dpdk-setup.service` is a `Type=oneshot` service (with
`RemainAfterExit=yes`) that runs `systemd/dpdk-setup.sh` early in boot to
re-establish the binding before the engine starts. The engine now declares
`Requires=` / `After=anti-ddos-dpdk-setup.service`, so it will not launch
until the binding is in place.

### What the script does

`systemd/dpdk-setup.sh`, run as root:

1. Verifies `/usr/local/bin/dpdk-devbind.py` exists.
2. **Safety abort:** if the management NIC is somehow already bound to
   `vfio-pci`, it changes nothing and exits non-zero for operator recovery.
3. Enables vfio no-IOMMU mode (`echo 1 >
   /sys/module/vfio/parameters/enable_unsafe_noiommu_mode`), running
   `modprobe vfio-pci` first if the parameter isn't writable yet.
4. Binds each data-plane NIC to `vfio-pci` with `--noiommu-mode`.
5. Prints the final `dpdk-devbind.py --status` for the relevant devices.

It is **idempotent**: any NIC already bound to `vfio-pci` is skipped, so
re-running the service (or `systemctl restart`) is safe.

### Hardcoded PCI addresses

The script never auto-detects which NICs to bind — the addresses are
hardcoded:

| PCI address     | Role         | Action                                  |
|-----------------|--------------|-----------------------------------------|
| `0000:02:02.0`  | Data plane   | Bound to `vfio-pci`                     |
| `0000:02:05.0`  | Data plane   | Bound to `vfio-pci`                     |
| `0000:02:06.0`  | **Management (ens38, SSH)** | **NEVER touched** — not in the bind list, and the script aborts if it is found on `vfio-pci` |

Binding the management NIC would instantly kill SSH and require VMware-console
recovery. The script is built around never touching `0000:02:06.0`.

### Debugging

```bash
# Check it ran cleanly (should show "active (exited)")
systemctl status anti-ddos-dpdk-setup.service

# Full log of the last run
journalctl -u anti-ddos-dpdk-setup.service -b --no-pager

# Run the script by hand for testing (idempotent, safe to repeat)
sudo /home/user_1/Music/Anti-DDoS/systemd/dpdk-setup.sh

# Inspect current NIC bindings
/usr/local/bin/dpdk-devbind.py --status
```

If the engine still fails after this service is `active (exited)`, confirm the
two data-plane NICs show `drv=vfio-pci` in `dpdk-devbind.py --status`.

---

## One-time setup

```bash
sudo make install-systemd     # copy units to /etc/systemd/system, daemon-reload
sudo make systemd-enable      # enable auto-start on boot
sudo systemctl start anti-ddos.target
make systemd-status           # confirm all 3 are active
```

After `systemd-enable`, the full stack auto-starts on every boot.

---

## Startup ordering

Ordering is enforced by the unit dependencies, not by timing guesses:

1. **ClickHouse** (`clickhouse-server.service`) — assumed already installed and
   managed independently. Both the collector and dashboard declare
   `Requires=clickhouse-server.service`, so they will not start until it is up.
2. **Collector** starts next. Its `ExecStartPre` removes any stale
   `/tmp/ddos_stats_socket`, then `main.py` binds the socket as a server.
3. **Engine** declares `Requires=` / `After=` on **both**
   `anti-ddos-collector.service` and `anti-ddos-dpdk-setup.service`, so it
   waits for the collector socket *and* the NIC binding. Before launching
   `l2fwd`, its `ExecStartPre` copies `config/services.json` to
   `/tmp/svc.json` and then **polls for up to 10 s** for
   `/tmp/ddos_stats_socket` to exist. This poll is critical: the engine does a
   single non-blocking `connect()` at startup with no retry, so the socket
   must exist before it launches. (`anti-ddos-dpdk-setup.service` itself runs
   much earlier in boot — see the section above.)
4. **Dashboard** is independent of the collector and engine — it only needs
   ClickHouse. If the collector or engine crash, the dashboard stays up and
   serves stale data with the degraded health flag. This is by design:
   operators should always be able to reach the dashboard.

`anti-ddos.target` `Wants` all three, so `systemctl stop anti-ddos.target`
stops them in reverse dependency order.

---

## Daily operations

```bash
make systemd-status       # is-active for all 3 + recent state lines
make systemd-logs         # follow journalctl for all 3 (Ctrl+C to stop)
make systemd-restart      # restart collector -> engine -> dashboard, in order
```

Per-component log following:

```bash
make systemd-logs-collector
make systemd-logs-engine
make systemd-logs-dashboard
```

---

## Manual control (systemctl)

The Makefile targets are thin wrappers; you can always drive systemd directly:

```bash
# Whole stack
sudo systemctl start anti-ddos.target
sudo systemctl stop anti-ddos.target
sudo systemctl restart anti-ddos.target

# Per service
sudo systemctl start anti-ddos-engine.service
sudo systemctl stop anti-ddos-collector.service
sudo systemctl restart anti-ddos-dashboard.service

# Status / state
systemctl status anti-ddos-engine.service
systemctl is-active anti-ddos-collector.service
```

---

## Logs

systemd-journald captures stdout/stderr of all three services. No separate log
files, no log rotation to configure — journald handles retention.

```bash
# Last 100 lines, no pager
journalctl -u anti-ddos-engine.service -n 100 --no-pager

# Follow live
journalctl -u anti-ddos-engine.service -f

# All three at once
journalctl -u anti-ddos-collector.service -u anti-ddos-engine.service -u anti-ddos-dashboard.service -f

# Since last boot
journalctl -u anti-ddos-collector.service -b
```

Each unit sets `SyslogIdentifier=` (`anti-ddos-collector`, `anti-ddos-engine`,
`anti-ddos-dashboard`) so lines are easy to grep.

---

## Boot persistence

`sudo make systemd-enable` enables `anti-ddos.target` plus all three services,
so the stack comes back automatically after a VM reboot. To verify:

```bash
sudo make systemd-enable
sudo reboot
# ... SSH back in ...
make systemd-status
curl http://localhost:5000/api/health
```

To stop auto-starting on boot (without uninstalling):

```bash
sudo make systemd-disable
```

---

## Failure scenarios

### ClickHouse goes down
The collector and dashboard declare `Requires=clickhouse-server.service`. If
ClickHouse is down, they will fail to start (or be stopped if ClickHouse stops).
Once ClickHouse is back:

```bash
sudo systemctl restart anti-ddos-collector.service
sudo systemctl restart anti-ddos-dashboard.service
```

This system does **not** add any auto-recovery on ClickHouse unavailability
beyond what the collector already does internally.

### Engine crashes
systemd restarts it within ~5 s (`Restart=always`, `RestartSec=5`). The
collector keeps running. If data goes stale during the gap, the dashboard
shows degraded health. No operator action is normally needed.

### Collector crashes
systemd restarts it within ~3 s (`Restart=always`, `RestartSec=3`). However,
when the collector dies, the engine's socket connection to
`/tmp/ddos_stats_socket` is lost — and the engine does **not** auto-reconnect.
After the collector recovers, restart the engine so it reconnects:

```bash
sudo systemctl restart anti-ddos-engine.service
```

`make systemd-restart` does the collector → engine → dashboard sequence
correctly if you want to bounce the whole stack cleanly.

### Dashboard crashes
systemd restarts it within ~3 s. No effect on the engine or collector.

---

## Dev vs prod — mutually exclusive

`make run` (dev: `setsid nohup` + PID files in `/tmp/`) and
`make systemd-start` (prod: systemd) **cannot run at the same time**. Both
bind `/tmp/ddos_stats_socket` and port 5000. Running both leads to
double-bound sockets and port conflicts.

Always stop one before starting the other:

```bash
make stop            # stop the dev stack
sudo make systemd-start

# or the reverse
sudo make systemd-stop
make run
```

---

## Updating after a code change

The unit files point at the same binaries and scripts the dev workflow uses,
so updates are just a rebuild + restart:

- **Engine (C) code changed:** rebuild, then restart the engine.
  ```bash
  make                                        # rebuild build/l2fwd (meson/ninja)
  sudo systemctl restart anti-ddos-engine.service
  ```
- **Collector (Python) changed:**
  ```bash
  sudo systemctl restart anti-ddos-collector.service
  # then, since the engine does not auto-reconnect:
  sudo systemctl restart anti-ddos-engine.service
  ```
- **Dashboard (Python) changed:**
  ```bash
  sudo systemctl restart anti-ddos-dashboard.service
  ```
- **`config/services.json` changed:** the engine's `ExecStartPre`
  re-copies it to `/tmp/svc.json` on every start, so just restart the engine.

---

## Uninstall

```bash
sudo make uninstall-systemd
```

This stops all services, disables them, removes the unit files from
`/etc/systemd/system/`, and runs `daemon-reload`. **Data is preserved** — the
ClickHouse database and `config/services.json` are untouched. The
dev Makefile workflow (`make run`) continues to work unchanged.
