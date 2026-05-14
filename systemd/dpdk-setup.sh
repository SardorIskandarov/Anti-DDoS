#!/bin/bash
# anti-ddos-dpdk-setup — bind data-plane NICs to vfio-pci in no-IOMMU mode.
#
# Called by anti-ddos-dpdk-setup.service at boot, before the engine starts.
# Idempotent: if NICs are already bound, exits 0 cleanly.
#
# CRITICAL: only touches these two PCI addresses:
#   0000:02:02.0  (data plane, ens34)
#   0000:02:05.0  (data plane, ens37)
# NEVER touches 0000:02:06.0 (management NIC, ens38, used by SSH).

set -euo pipefail

LOG_PREFIX="[anti-ddos-dpdk-setup]"

NICS_TO_BIND=(
    "0000:02:02.0"
    "0000:02:05.0"
)

MANAGEMENT_NIC="0000:02:06.0"   # DO NOT TOUCH

DPDK_DEVBIND="/usr/local/bin/dpdk-devbind.py"
NOIOMMU_FLAG="/sys/module/vfio/parameters/enable_unsafe_noiommu_mode"

# --- Safety check 1: refuse to run if dpdk-devbind.py missing ---
if [ ! -x "$DPDK_DEVBIND" ]; then
    echo "$LOG_PREFIX ERROR: $DPDK_DEVBIND not found or not executable"
    exit 1
fi

# --- Safety check 2: refuse to run if management NIC isn't kernel-driven ---
# (If something went wrong and our management NIC ended up bound to DPDK, we
# stop immediately and let the operator recover — running our binding commands
# would not help.)
if "$DPDK_DEVBIND" --status 2>/dev/null | grep -q "$MANAGEMENT_NIC.*drv=vfio-pci"; then
    echo "$LOG_PREFIX CRITICAL: management NIC $MANAGEMENT_NIC is bound to vfio-pci."
    echo "$LOG_PREFIX This script will not modify anything. Manual operator recovery required."
    exit 1
fi

# --- Ensure no-IOMMU mode is enabled ---
if [ -w "$NOIOMMU_FLAG" ]; then
    current=$(cat "$NOIOMMU_FLAG" 2>/dev/null || echo "?")
    if [ "$current" != "Y" ] && [ "$current" != "1" ]; then
        echo "$LOG_PREFIX enabling vfio no-IOMMU mode (was: $current)"
        echo 1 > "$NOIOMMU_FLAG"
    else
        echo "$LOG_PREFIX vfio no-IOMMU mode already enabled (current: $current)"
    fi
else
    echo "$LOG_PREFIX WARNING: $NOIOMMU_FLAG not writable. vfio_pci module may not be loaded yet."
    echo "$LOG_PREFIX attempting to load vfio-pci kernel module ..."
    modprobe vfio-pci || true
    sleep 1
    if [ -w "$NOIOMMU_FLAG" ]; then
        echo 1 > "$NOIOMMU_FLAG"
        echo "$LOG_PREFIX vfio no-IOMMU mode enabled after modprobe"
    else
        echo "$LOG_PREFIX ERROR: cannot enable no-IOMMU mode — exiting"
        exit 1
    fi
fi

# --- Bind each data-plane NIC ---
for pci in "${NICS_TO_BIND[@]}"; do
    if [ "$pci" = "$MANAGEMENT_NIC" ]; then
        echo "$LOG_PREFIX REFUSING to bind management NIC $pci"
        exit 1
    fi

    # Is it already bound to vfio-pci?
    if "$DPDK_DEVBIND" --status 2>/dev/null | grep "$pci" | grep -q "drv=vfio-pci"; then
        echo "$LOG_PREFIX $pci already bound to vfio-pci — skipping"
        continue
    fi

    echo "$LOG_PREFIX binding $pci to vfio-pci (no-IOMMU mode) ..."
    if "$DPDK_DEVBIND" --bind=vfio-pci --noiommu-mode "$pci"; then
        echo "$LOG_PREFIX bound $pci OK"
    else
        echo "$LOG_PREFIX ERROR: failed to bind $pci"
        exit 1
    fi
done

# --- Final verification ---
echo "$LOG_PREFIX final state:"
"$DPDK_DEVBIND" --status | grep -E "0000:02:0[256]\.0" || true

echo "$LOG_PREFIX setup complete"
exit 0
