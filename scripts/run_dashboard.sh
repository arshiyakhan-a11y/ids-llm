#!/usr/bin/env bash
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
PY="$ROOT/.venv/bin/python"; [ -x "$PY" ] || PY=python3
exec "$PY" -m streamlit run dashboard/app.py
