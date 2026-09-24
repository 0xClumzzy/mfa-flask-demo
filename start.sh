#!/usr/bin/env bash
set -e
cd "$(dirname "$0")"

echo "============================================"
echo "   MFA - setup and start"
echo "============================================"
echo

PYEXE=""
if command -v python3 >/dev/null 2>&1; then
  PYEXE="python3"
elif command -v python >/dev/null 2>&1; then
  PYEXE="python"
fi

if [ -z "$PYEXE" ]; then
  echo "[ERROR] Python not found."
  echo "  Debian/Ubuntu: sudo apt install python3 python3-venv"
  exit 1
fi

echo "[1/3] Python found ($($PYEXE --version 2>&1)). Creating virtual environment..."
if [ ! -x ".venv/bin/python" ]; then
  $PYEXE -m venv .venv
fi

echo "[2/3] Installing packages (needs internet once)..."
".venv/bin/python" -m pip install --quiet --disable-pip-version-check -r requirements.txt

echo "[3/3] Starting server - browser opens automatically..."
echo "      Keep this terminal open. Ctrl+C stops the server."
echo
exec ".venv/bin/python" app.py
