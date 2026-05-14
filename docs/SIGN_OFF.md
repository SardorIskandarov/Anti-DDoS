# Anti-DDoS Per-Service Detection System — Production Sign-Off

**Version**: 1.0.0
**Sign-off date**: <fill in>
**Approver**: <fill in>

## Acceptance Criteria

### Functional
- [ ] All 4 systemd services are active (`make systemd-status`)
- [ ] Reboot test passed: `sudo reboot` brings the stack back automatically
- [ ] Dashboard accessible at http://<host>:5000
- [ ] All 5 dashboard tabs render: Overview, Services, Slot Detail, Registry, Alerts
- [ ] ClickHouse has the new schema: `service_stats`, `service_phase_transitions`,
      `service_temporal_aggregates`, `service_registry_snapshots`
- [ ] Legacy `traffic_stats_legacy` table preserved (forensic data intact)

### Tests
- [ ] All C test harnesses pass: 436/436 assertions
  - `./build/test_service_registry_load`: 24/24
  - `./build/test_service_stats`: 57/57
  - `./build/test_service_detection_state`: 62/62
  - `./build/test_service_temporal_state`: 40/40
  - `./build/test_service_reload`: 54/54
  - `./build/test_service_features`: 56/56
  - `./build/test_service_scoring`: 52/52
  - `./build/test_service_wire`: 91/91
- [ ] Python wire parser tests pass: 12/12 (`python3 tests/test_wire_parser.py`)
- [ ] Integration smoke test passes (`make smoke`)

### Security / Operations
- [ ] Credentials in `/etc/anti-ddos/env` (mode 0640, root:user_1)
- [ ] `config.py` no longer hardcodes `CH_PASSWORD` (reads from env)
- [ ] `.gitignore` excludes `.env`, `__pycache__/`, `/etc/anti-ddos/`
- [ ] `__pycache__/` files removed from git index
- [ ] Legacy `database.py` and `shared_state.py` have deprecation headers

### Documentation
- [ ] 5 runbooks in `docs/runbooks/`
- [ ] `docs/monitoring.md` with reference queries
- [ ] `docs/systemd_deployment.md` covers all 4 services
- [ ] `docs/clickhouse_schema.md` covers all 4 new tables
- [ ] `docs/architecture_status.md` reflects post-P15 state

### Git
- [ ] All milestones tagged: `pre-p7-snapshot`, `p6.5-complete`, `p7-complete`,
      `p8-complete`, `p9-complete`, `p10-complete`, `p13-complete`, `p14-complete`,
      `systemd-complete`, `v1.0.0`
- [ ] Working tree clean
- [ ] All P0-P15 work committed

## Architecture Summary

End-to-end the system is a one-way telemetry pipeline with a hot detection
path at the front:

```
        NICs (vfio-pci)                  Unix socket            ClickHouse
   0000:02:02.0 + 0000:02:05.0          /tmp/ddos_stats_socket  ddos_detection
            │                                   │                   │
            ▼                                   ▼                   ▼
   ┌──────────────────┐  binary wire   ┌──────────────────┐   ┌──────────────┐
   │  DPDK L2 Engine  │ ─ ─ protocol ─▶│  Python Collector│──▶│  ClickHouse  │
   │   build/l2fwd    │   (v1, 416 B)  │ main.py/collector│   │  4 tables +  │
   │  per-service     │                │  batch INSERT    │   │  legacy tbl  │
   │  detection       │                └──────────────────┘   └──────┬───────┘
   │  (runs as root)  │                                              │
   └──────────────────┘                                              │
                                       ┌──────────────────┐          │
                                       │ Flask Dashboard  │◀─────────┘
                                       │     web.py       │  reads only
                                       │  :5000, 5 tabs   │
                                       └──────────────────┘
```

- **Engine** (`build/l2fwd`, root) — DPDK L2 forwarder; per-service feature
  extraction + two-tier scoring + phase classification; emits binary wire
  messages.
- **Collector** (`ddos_monitor/main.py`, user_1) — binds the Unix socket,
  parses the wire protocol, batch-inserts into ClickHouse.
- **Dashboard** (`ddos_monitor/web.py`, user_1) — Flask + Chart.js; reads
  ClickHouse only; independent of engine/collector liveness.
- **ClickHouse** — separate, independently-managed service; INSERT-only sink.
- Four systemd units (`anti-ddos-dpdk-setup`, `-collector`, `-engine`,
  `-dashboard`) grouped by `anti-ddos.target`; the oneshot `dpdk-setup` binds
  the data-plane NICs at boot so the stack survives reboots.

## Operational Reference

- Dev workflow: `make run / make stop / make status / make logs / make smoke`
- Prod workflow: `sudo systemctl start anti-ddos.target / make systemd-status / make systemd-logs`
- Health check: `curl http://localhost:5000/api/health`
- Dashboard: http://<host>:5000
- Runbooks: `docs/runbooks/01`–`05` — restart, attack response, IP management,
  ClickHouse recovery, code updates
- Monitoring: `docs/monitoring.md` — health checks, ClickHouse queries,
  dashboard signals

## Known Limitations (intentional, post-v1.0.0)

- Dashboard runs Flask dev server (not gunicorn). Acceptable for single-operator
  use; consider gunicorn for high-traffic dashboards.
- No HTTPS for dashboard. For internet exposure, front with reverse proxy + TLS.
- No alerting beyond dashboard. Adding webhooks/email is a v1.1 candidate.
- Single-VM deployment. Multi-host requires architecture changes.
- Engine restart drops ~3s of telemetry. Acceptable for non-mission-critical use.
- Telemetry is best-effort: a ClickHouse outage leaves a permanent gap in the
  historical record (no spool/replay). Detection itself is unaffected.
- `CH_PASSWORD` still has a hardcoded dev fallback in `config.py` (loud WARNING
  on use). Removing the fallback entirely is a future hardening pass.

## Sign-Off

By tagging `v1.0.0`, the operator certifies that all acceptance criteria above
are met and the system is production-ready.
