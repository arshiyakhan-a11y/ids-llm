#!/usr/bin/env bash
# Replay a CICIDS2017 pcap onto the veth wire.   SPEED=1 (original timing, default) | 10 (10x faster) | max
# usage: SPEED=10 ./scripts/replay.sh pcaps/Friday-WorkingHours.pcap
set -euo pipefail
source "$(dirname "$0")/common.sh"
PCAP="${1:?usage: replay.sh <file.pcap>}"
SPEED="${SPEED:-1}"
if [ "$SPEED" = "max" ]; then ARGS="--topspeed"; elif [ "$SPEED" = "1" ]; then ARGS=""; else ARGS="--multiplier=$SPEED"; fi
exec sudo tcpreplay --intf1="$IFACE_TX" $ARGS "$PCAP"
