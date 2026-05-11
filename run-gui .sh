#!/usr/bin/env bash
# DomainFront Tunnel GUI Launcher (Linux / macOS)
# Creates a local virtualenv, installs deps, then starts the GUI.
# Certificate management and config creation are handled inside the GUI.

set -e
cd "$(dirname "$0")"

VENV_DIR=".venv"

find_python() {
    for cmd in python3.12 python3.11 python3.10 python3 python; do
        if command -v "$cmd" >/dev/null 2>&1; then
            ver=$("$cmd" -c 'import sys;print("%d.%d"%sys.version_info[:2])' 2>/dev/null || echo "0.0")
            major=${ver%.*}; minor=${ver#*.}
            if [ "$major" -ge 3 ] && [ "$minor" -ge 10 ]; then
                echo "$cmd"
                return 0
            fi
        fi
    done
    return 1
}

PY=$(find_python) || {
    echo "[X] Python 3.10+ not found. Install it and re-run this script." >&2
    exit 1
}

if [ ! -x "$VENV_DIR/bin/python" ]; then
    echo "[*] Creating virtual environment in $VENV_DIR ..."
    "$PY" -m venv "$VENV_DIR"
fi

VPY="$VENV_DIR/bin/python"

echo "[*] Installing dependencies ..."
"$VPY" -m pip install --disable-pip-version-check -q --upgrade pip >/dev/null
if ! "$VPY" -m pip install --disable-pip-version-check -q -r requirements.txt; then
    echo "[!] PyPI install failed. Retrying via runflare mirror ..."
    "$VPY" -m pip install --disable-pip-version-check -q -r requirements.txt
fi

# No need to check config.json – the GUI will create a default one if missing.
# No separate setup wizard – everything is inside the GUI (including CA install).

echo
echo "[*] Starting DomainFront Tunnel GUI ..."
echo
exec "$VPY" gui.py "$@"