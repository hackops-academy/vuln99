#!/usr/bin/env bash
# setup.sh — one-command install + run for vuln99.
#
#   ./setup.sh            install deps (if needed) and start the app
#   ./setup.sh --install  install/refresh deps only, don't start
#   ./setup.sh --test     install dev deps and run the smoke test suite
#
# Safe by default: the app binds to 127.0.0.1 unless you export
# VULN99_HOST yourself before running this script. See vuln99/config.py.

set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")"

VENV_DIR="venv"
PY="${PYTHON:-python3}"

if [ ! -d "$VENV_DIR" ]; then
  echo "==> Creating virtual environment in ./$VENV_DIR"
  "$PY" -m venv "$VENV_DIR"
fi

# shellcheck disable=SC1091
source "$VENV_DIR/bin/activate"

MODE="${1:-run}"

case "$MODE" in
  --install)
    echo "==> Installing requirements"
    pip install --quiet --upgrade pip
    pip install --quiet -r requirements.txt
    echo "==> Done. Activate with: source $VENV_DIR/bin/activate"
    ;;
  --test)
    echo "==> Installing dev requirements"
    pip install --quiet --upgrade pip
    pip install --quiet -r requirements-dev.txt
    echo "==> Running smoke tests"
    pytest -q
    ;;
  run|*)
    echo "==> Installing requirements"
    pip install --quiet --upgrade pip
    pip install --quiet -r requirements.txt
    echo "==> Starting vuln99 (Ctrl+C to stop)"
    echo "    Host: ${VULN99_HOST:-127.0.0.1}   Port: ${VULN99_PORT:-5099}"
    exec python run.py
    ;;
esac
