#!/usr/bin/env bash
# Virtual wire for live replay: tcpreplay -> veth0 ==> veth1 <- Snort & Suricata sniff
set -euo pipefail
source "$(dirname "$0")/common.sh"
sudo ip link add "$IFACE_TX" type veth peer name "$IFACE_RX" 2>/dev/null || true
for i in "$IFACE_TX" "$IFACE_RX"; do
  sudo ip link set "$i" up
  sudo ip link set "$i" promisc on
  sudo ethtool -K "$i" rx off tx off gro off lro off tso off gso off 2>/dev/null || true   # keep packets exactly as in the pcap
done
echo "veth pair ready: $IFACE_TX -> $IFACE_RX"
