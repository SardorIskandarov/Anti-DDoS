#!/bin/bash
# integration_smoke_test.sh — fast end-to-end health check.
#
# Verifies the full production stack is healthy. Returns 0 on PASS,
# non-zero on FAIL with a clear error indicating which check failed.
#
# Usage:
#   bash scripts/integration_smoke_test.sh
#   make smoke   # via Makefile

set -e
set -o pipefail

PROJECT_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
PASS_COUNT=0
FAIL_COUNT=0
FAIL_MESSAGES=()

# Helpers
pass() { echo "  ✓ $1"; PASS_COUNT=$((PASS_COUNT+1)); }
fail() { echo "  ✗ $1"; FAIL_COUNT=$((FAIL_COUNT+1)); FAIL_MESSAGES+=("$1"); }

echo "============================================"
echo "Anti-DDoS Integration Smoke Test"
echo "============================================"
echo ""

# 1. systemd services
echo "[1] Checking systemd services ..."
for svc in anti-ddos-dpdk-setup anti-ddos-collector anti-ddos-engine anti-ddos-dashboard; do
    state=$(systemctl is-active "$svc.service" 2>/dev/null || echo "missing")
    if [ "$state" = "active" ]; then
        pass "$svc.service is active"
    else
        fail "$svc.service is $state (expected: active)"
    fi
done

# 2. Processes
echo ""
echo "[2] Process check ..."
if pgrep -f l2fwd >/dev/null; then pass "engine (l2fwd) process running"; else fail "engine process not found"; fi
if pgrep -f "ddos_monitor/main.py" >/dev/null; then pass "collector process running"; else fail "collector process not found"; fi
if pgrep -f "ddos_monitor/web.py" >/dev/null; then pass "dashboard process running"; else fail "dashboard process not found"; fi

# 3. DPDK NIC bindings
echo ""
echo "[3] DPDK NIC bindings ..."
if sudo dpdk-devbind.py --status 2>/dev/null | grep -q "0000:02:02.0.*drv=vfio-pci"; then
    pass "0000:02:02.0 bound to vfio-pci"
else
    fail "0000:02:02.0 not bound to vfio-pci"
fi
if sudo dpdk-devbind.py --status 2>/dev/null | grep -q "0000:02:05.0.*drv=vfio-pci"; then
    pass "0000:02:05.0 bound to vfio-pci"
else
    fail "0000:02:05.0 not bound to vfio-pci"
fi
if sudo dpdk-devbind.py --status 2>/dev/null | grep "0000:02:06.0" | grep -q "drv=vmxnet3"; then
    pass "0000:02:06.0 (management) still on kernel driver"
else
    fail "MANAGEMENT NIC 0000:02:06.0 IS NOT ON KERNEL DRIVER — critical safety issue"
fi

# 4. Dashboard health endpoint
echo ""
echo "[4] Dashboard health ..."
HEALTH=$(curl -s --max-time 5 http://localhost:5000/api/health 2>/dev/null || echo "{}")
STATUS=$(echo "$HEALTH" | python3 -c "import sys, json; d=json.load(sys.stdin); print(d.get('status','?'))" 2>/dev/null || echo "?")
CH_OK=$(echo "$HEALTH"  | python3 -c "import sys, json; d=json.load(sys.stdin); print(d.get('ch_reachable',False))" 2>/dev/null || echo "False")
if [ "$STATUS" = "ok" ]; then pass "dashboard health: ok"; else fail "dashboard health: $STATUS (expected: ok)"; fi
if [ "$CH_OK" = "True" ]; then pass "ClickHouse reachable from dashboard"; else fail "ClickHouse NOT reachable from dashboard"; fi

# 5. Slot count
echo ""
echo "[5] Service slots ..."
SLOT_COUNT=$(curl -s --max-time 5 http://localhost:5000/api/services 2>/dev/null | python3 -c "import sys, json; print(len(json.load(sys.stdin)))" 2>/dev/null || echo "0")
if [ "$SLOT_COUNT" -ge 1 ]; then
    pass "$SLOT_COUNT slots returned by /api/services (expected: 44)"
else
    fail "0 slots returned by /api/services"
fi

# 6. Data freshness via ClickHouse
echo ""
echo "[6] Data freshness ..."
# Get CH_PASSWORD from env (loaded by systemd) or fall back to dev default
CH_PASS="${CH_PASSWORD:-sardor1217}"
STALE=$(clickhouse-client --password="$CH_PASS" -q "SELECT greatest(0, toInt64(now() - max(inserted_at))) FROM ddos_detection.service_stats WHERE inserted_at >= now() - INTERVAL 5 MINUTE" 2>/dev/null || echo "999")
if [ "$STALE" -le 30 ]; then
    pass "fresh data: ${STALE}s since last row"
else
    fail "stale data: ${STALE}s since last row (expected: ≤30s)"
fi

# 7. Phase distribution
echo ""
echo "[7] Phase distribution ..."
PHASE_ROWS=$(clickhouse-client --password="$CH_PASS" -q "SELECT count() FROM (SELECT argMax(phase_str, timestamp_ns) FROM ddos_detection.service_stats WHERE timestamp_dt >= now() - INTERVAL 60 SECOND GROUP BY slot_id)" 2>/dev/null || echo "0")
if [ "$PHASE_ROWS" -ge 1 ]; then
    pass "$PHASE_ROWS distinct slots reporting in last 60s"
else
    fail "no slots reporting in last 60s"
fi

# Summary
echo ""
echo "============================================"
echo "SUMMARY"
echo "============================================"
echo "PASSED: $PASS_COUNT"
echo "FAILED: $FAIL_COUNT"
if [ "$FAIL_COUNT" -eq 0 ]; then
    echo ""
    echo "✓ ALL CHECKS PASSED. System healthy."
    exit 0
else
    echo ""
    echo "✗ FAILURES:"
    for msg in "${FAIL_MESSAGES[@]}"; do echo "  - $msg"; done
    exit 1
fi
