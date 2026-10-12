#!/usr/bin/env bash
# Suricata sniffing the veth wire in real time. Writes logs/suricata/eve.json
set -euo pipefail
source "$(dirname "$0")/common.sh"
mkdir -p "$LOG_SURI"
exec sudo suricata -c "$SURICATA_YAML" -i "$IFACE_RX" -l "$LOG_SURI" -k none \
  --set "vars.address-groups.HOME_NET=[$HOME_NET]" --set "vars.address-groups.EXTERNAL_NET=any"
