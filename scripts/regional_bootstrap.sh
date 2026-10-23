#!/bin/bash
# Installed stable launcher: the scheduler updates its clean runtime under lock.
set -euo pipefail
REPO="${BEST50_REPO:-$HOME/best50-vpn-regional-runtime}"
PYTHON="${BEST50_PYTHON:-/opt/homebrew/bin/python3}"
exec "$PYTHON" "$REPO/scripts/regional_scheduler.py" --repo "$REPO"
