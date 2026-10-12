#!/usr/bin/env bash
source "$(dirname "$0")/common.sh"
sudo ip link del "$IFACE_TX" 2>/dev/null && echo "removed $IFACE_TX/$IFACE_RX"
