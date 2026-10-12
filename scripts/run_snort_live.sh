#!/usr/bin/env bash
# Snort 3 sniffing the veth wire in real time. Writes logs/snort/alert_json.txt
set -euo pipefail
source "$(dirname "$0")/common.sh"
mkdir -p "$LOG_SNORT"
[ -f "$SNORT_LUA" ] || { echo "SNORT_LUA not found: $SNORT_LUA  (export SNORT_LUA=/path/to/snort.lua)"; exit 1; }
[ -f "$SNORT_RULES" ] || { echo "Rules missing: $SNORT_RULES  (run scripts/02_get_snort_rules.sh)"; exit 1; }
exec sudo snort -c "$SNORT_LUA" -R "$SNORT_RULES" -i "$IFACE_RX" -k none -A alert_json -l "$LOG_SNORT" \
  --lua "alert_json = { file = true, fields = '$SNORT_FIELDS' }"
