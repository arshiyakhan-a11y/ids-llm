#!/usr/bin/env bash
# ONE-COMMAND SETUP + START for Kali/Debian/Ubuntu.  Run:  ./scripts/kali_start.sh
# Installs tools (Suricata, Snort, tcpdump), creates the Python venv, asks for your OpenAI key,
# downloads the Snort community rules, then opens the dashboard. Safe to re-run.
set -uo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
say() { printf '\n\033[1;36m== %s\033[0m\n' "$*"; }
warn() { printf '\033[1;33m!! %s\033[0m\n' "$*"; }

say "1/6  System packages (sudo password may be asked)"
sudo apt-get update -y
export DEBIAN_FRONTEND=noninteractive
sudo -E apt-get install -y suricata tcpdump tcpreplay curl ethtool python3-venv python3-pip || warn "some packages failed to install"
command -v snort >/dev/null || sudo -E apt-get install -y snort || warn "could not install snort from apt"

say "2/6  Suricata rules (ET Open)"
sudo suricata-update || warn "suricata-update failed (no internet?) - Suricata will use whatever rules it already has"

say "3/6  Snort check"
if command -v snort >/dev/null && snort -V 2>&1 | grep -q "Version 3"; then
  echo "OK: $(snort -V 2>&1 | grep -m1 Version)"
else
  warn "Snort 3 not found (need 'snort -V' to say Version 3.x). The dashboard will still run with Suricata only."
  warn "Install Snort 3 from https://www.snort.org/downloads and re-run this script."
fi
if [ -z "${SNORT_LUA:-}" ]; then
  for f in /usr/local/etc/snort/snort.lua /etc/snort/snort.lua /usr/etc/snort/snort.lua; do
    [ -f "$f" ] && export SNORT_LUA="$f" && break
  done
fi
echo "snort.lua: ${SNORT_LUA:-NOT FOUND}"

say "4/6  Python environment"
[ -d .venv ] || python3 -m venv .venv
.venv/bin/pip install --upgrade pip >/dev/null
.venv/bin/pip install -r requirements.txt || { warn "pip install failed - check internet"; exit 1; }

say "5/6  Snort community rules"
mkdir -p rules
if [ -f rules/snort3-community-rules/snort3-community.rules ]; then
  echo "already downloaded"
else
  ( cd rules && curl -fL -o snort3-community-rules.tar.gz https://www.snort.org/downloads/community/snort3-community-rules.tar.gz \
    && tar xzf snort3-community-rules.tar.gz ) || warn "could not download Snort rules (Snort will use only rules inside snort.lua)"
fi

say "6/6  OpenAI API key"
CUR=""; [ -f .env ] && CUR="$(grep -E '^OPENAI_API_KEY=' .env | cut -d= -f2- | tr -d '"'"'"' ')"
if [ -n "$CUR" ] && [ "$CUR" != "sk-your-key-here" ]; then
  read -rp "A key is already saved (${CUR:0:7}...). Keep it? [Y/n] " yn
  [[ "${yn:-Y}" =~ ^[Nn] ]] && CUR=""
else
  CUR=""
fi
if [ -z "$CUR" ]; then
  echo "Get a key at https://platform.openai.com/api-keys  (press Enter to skip: pipeline runs without the LLM step)"
  read -rsp "Paste your OpenAI API key (input hidden): " KEY; echo
  if [ -n "$KEY" ]; then
    printf 'OPENAI_API_KEY=%s\n' "$KEY" > .env && chmod 600 .env
    echo "Saved to .env"
  else
    warn "No key entered - LLM analysis will be skipped (untick it in the dashboard)."
  fi
fi

say "Starting dashboard -> http://localhost:8501   (Ctrl-C to stop)"
echo "In the sidebar: upload a pcap OR paste its full path, set HOME_NET, press 'Run analysis'."
exec .venv/bin/python -m streamlit run dashboard/app.py
