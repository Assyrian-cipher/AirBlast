#!/bin/bash

# Read the interface name from the temp file
if [ -f /tmp/airblast_interface.tmp ]; then
    ORIGINAL_IFACE=$(cat /tmp/airblast_interface.tmp)
else
    echo "Could not find interface name, trying default wlan0..."
    ORIGINAL_IFACE="wlan0"
fi

# Remove 'mon' suffix if present
BASE_IFACE=${ORIGINAL_IFACE%mon}

echo "Restoring network configuration..."

# First try with airmon-ng
if command -v airmon-ng &> /dev/null; then
    airmon-ng stop ${BASE_IFACE}mon &> /dev/null
    airmon-ng stop ${BASE_IFACE} &> /dev/null
fi

# Try manual method as backup
for iface in "${BASE_IFACE}" "${BASE_IFACE}mon"; do
    if ip link show "$iface" &> /dev/null; then
        ip link set "$iface" down &> /dev/null
        iwconfig "$iface" mode managed &> /dev/null
        ip link set "$iface" up &> /dev/null
    fi
done

# Start NetworkManager if needed
if ! systemctl is-active NetworkManager &> /dev/null; then
    systemctl start NetworkManager &> /dev/null
fi

# Clean up temp file
rm -f /tmp/airblast_interface.tmp

echo "Network configuration restored!"
