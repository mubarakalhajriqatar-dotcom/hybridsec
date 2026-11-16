#!/usr/bin/env bash
# HybridSec launcher for Linux / macOS / WSL.
# Creates a virtual environment on first start, installs (or repairs) the dependencies on every start,
# then starts the server. Set PYTHON=/path/to/python3.x to use a specific interpreter.
set -euo pipefail
cd "$(dirname "$0")"

PYTHON="${PYTHON:-python3}"

# KEY=value from .env (the last occurrence wins; quotes and inline comments are removed).
env_file_value() {
  [ -f .env ] || return 0
  local line value
  line="$(grep -E "^[[:space:]]*$1[[:space:]]*=" .env | tail -n 1 || true)"
  [ -n "$line" ] || return 0
  value="${line#*=}"
  value="${value%%#*}"
  value="$(printf '%s' "$value" | sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//' -e "s/^['\"]//" -e "s/['\"]\$//")"
  printf '%s' "$value"
}

# 1. Python 3.10 or newer.
if ! command -v "$PYTHON" >/dev/null 2>&1; then
  echo "Python 3 was not found ('$PYTHON'). Install it, for example: sudo apt install python3 python3-venv" >&2
  exit 1
fi
if ! "$PYTHON" -c 'import sys; sys.exit(0 if sys.version_info >= (3, 10) else 1)'; then
  echo "HybridSec needs Python 3.10 or newer; '$PYTHON' is $("$PYTHON" --version 2>&1)." >&2
  echo "Install a newer Python or run:  PYTHON=python3.12 ./run.sh" >&2
  exit 1
fi

# 2. Virtual environment: created once, and created again if an earlier attempt was interrupted (no
#    interpreter or no pip inside); re-running venv on the folder keeps the packages already installed.
if [ ! -x ".venv/bin/python" ] || ! ./.venv/bin/python -m pip --version >/dev/null 2>&1; then
  echo "Creating virtual environment..."
  if ! "$PYTHON" -m venv .venv; then
    echo "Could not create .venv (on Debian/Ubuntu: sudo apt install python3-venv)" >&2
    exit 1
  fi
fi

# 3. Dependencies. pip finishes in about a second when everything is already installed, so running it on
#    every start costs little and repairs an install that was interrupted or ran without a network.
echo "Checking dependencies (the first install can take a minute)..."
if ! ./.venv/bin/python -m pip install --quiet --disable-pip-version-check -r requirements.txt; then
  echo "Installing the dependencies failed (is the machine online?). Fix the error above and run the script again." >&2
  exit 1
fi

if [ ! -f ".env" ]; then
  cp .env.example .env
  echo "Created .env from .env.example (edit it, or use the dashboard's Settings page, to add an API key or scope restrictions)."
fi

# 4. Bind address and port: the shell environment wins, then .env, then the safe defaults.
BIND="${HYBRIDSEC_HOST:-$(env_file_value HYBRIDSEC_HOST)}"
BIND="${BIND:-127.0.0.1}"
PORT="${HYBRIDSEC_PORT:-$(env_file_value HYBRIDSEC_PORT)}"
PORT="${PORT:-8000}"

echo
echo "HybridSec dashboard:  http://${BIND}:${PORT}/"
echo "API docs (Swagger):   http://${BIND}:${PORT}/docs"
echo "Stop the server with Ctrl+C."
echo
exec ./.venv/bin/python -m uvicorn app.main:app --host "$BIND" --port "$PORT"
