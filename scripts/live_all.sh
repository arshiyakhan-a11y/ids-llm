#!/usr/bin/env bash
# MODE B (real time): veth wire + Suricata + Snort + pipeline in background, replay in foreground.
# usage: SPEED=10 ./scripts/live_all.sh pcaps/some.pcap     (open the dashboard in another terminal)
set -euo pipefail
source "$(dirname "$0")/common.sh"
PCAP="${1:?usage: live_all.sh <file.pcap>}"
PY="$ROOT/.venv/bin/python"; [ -x "$PY" ] || PY=python3
mkdir -p "$LOG_SURI" "$LOG_SNORT"
rm -f "$LOG_SURI"/eve.json "$LOG_SNORT"/alert_json.txt
"$ROOT/scripts/03_veth_up.sh"
PIDS=()
cleanup() { echo "stopping..."; for p in "${PIDS[@]}"; do sudo kill "$p" 2>/dev/null || true; done; sudo pkill -x suricata 2>/dev/null || true; sudo pkill -x snort 2>/dev/null || true; }
trap cleanup EXIT INT TERM
"$ROOT/scripts/run_suricata_live.sh" > "$ROOT/logs/suricata_stdout.log" 2>&1 & PIDS+=($!)
"$ROOT/scripts/run_snort_live.sh"    > "$ROOT/logs/snort_stdout.log"    2>&1 & PIDS+=($!)
echo "waiting ${WARMUP:-30}s for Snort/Suricata to load rules (check logs/*_stdout.log)..."
sleep "${WARMUP:-30}"
( cd "$ROOT" && "$PY" run_pipeline.py run --reset ) & PIDS+=($!)
sleep 3
"$ROOT/scripts/replay.sh" "$PCAP"
echo "Replay finished. Pipeline keeps running for 60s to catch late flow records..."
sleep 60
