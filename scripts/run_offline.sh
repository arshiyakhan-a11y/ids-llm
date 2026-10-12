#!/usr/bin/env bash
# MODE A (no network interfaces needed): run Suricata and Snort on a pcap file, then run the pipeline once.
# usage: ./scripts/run_offline.sh pcaps/some.pcap
set -euo pipefail
source "$(dirname "$0")/common.sh"
PCAP="$(readlink -f "${1:?usage: run_offline.sh <file.pcap>}")"
PY="$ROOT/.venv/bin/python"; [ -x "$PY" ] || PY=python3
mkdir -p "$LOG_SURI" "$LOG_SNORT"
rm -f "$LOG_SURI"/eve.json "$LOG_SURI"/*.log "$LOG_SNORT"/alert_json.txt
echo "== Suricata =="
sudo suricata -c "$SURICATA_YAML" -r "$PCAP" -l "$LOG_SURI" -k none \
  --set "vars.address-groups.HOME_NET=[$HOME_NET]" --set "vars.address-groups.EXTERNAL_NET=any"
echo "== Snort =="
sudo snort -c "$SNORT_LUA" -R "$SNORT_RULES" -r "$PCAP" -k none -A alert_json -l "$LOG_SNORT" -q \
  --lua "alert_json = { file = true, fields = '$SNORT_FIELDS' }"
sudo chown -R "$USER":"$USER" "$LOG_SURI" "$LOG_SNORT"
cd "$ROOT"
"$PY" run_pipeline.py run --once --reset
echo "Now run: ./scripts/run_dashboard.sh"
