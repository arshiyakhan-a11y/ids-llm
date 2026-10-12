#!/usr/bin/env bash
# Ubuntu 22.04 / 24.04. Installs Suricata, tcpreplay, tools, Python venv. Snort 3 must be installed separately (see README).
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
sudo apt-get update
sudo apt-get install -y software-properties-common
sudo add-apt-repository -y ppa:oisf/suricata-stable
sudo apt-get update
sudo apt-get install -y suricata tcpreplay tcpdump wireshark-common jq ethtool python3-venv python3-pip curl
sudo suricata-update                      # downloads the free ET Open ruleset
python3 -m venv "$ROOT/.venv"
"$ROOT/.venv/bin/pip" install --upgrade pip
"$ROOT/.venv/bin/pip" install -r "$ROOT/requirements.txt"
echo
if command -v snort >/dev/null && snort -V 2>&1 | grep -q "Version 3"; then
  echo "Snort 3 found: $(snort -V 2>&1 | grep Version)"
else
  echo "!! Snort 3 NOT found. Install it from https://www.snort.org/downloads (Snort 3 install guide), then re-run."
fi
echo "Next: cp .env.example .env  &&  edit OPENAI_API_KEY ;  ./scripts/02_get_snort_rules.sh"
