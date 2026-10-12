#!/usr/bin/env bash
# Downloads the free Snort 3 community ruleset into ./rules  (registered/subscriber rules need your own oinkcode).
set -euo pipefail
source "$(dirname "$0")/common.sh"
cd "$ROOT/rules"
curl -fL -o snort3-community-rules.tar.gz https://www.snort.org/downloads/community/snort3-community-rules.tar.gz
tar xzf snort3-community-rules.tar.gz
ls -1 snort3-community-rules/
echo "Rules ready: $SNORT_RULES"
