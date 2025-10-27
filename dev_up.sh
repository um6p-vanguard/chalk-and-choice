#!/usr/bin/env bash
set -euo pipefail

# --- 0) ensure we're in the repo root ---
cd "$(dirname "$0")"

# --- 1) create / activate venv in this shell ---
if [ ! -d .venv ]; then
  python3 -m venv .venv
fi

# activate into THIS shell; if the script is sourced, you’ll stay activated
# shellcheck disable=SC1091
source .venv/bin/activate

# --- 2) deps ---
python -m pip install --upgrade pip
if [ -f requirements.txt ]; then
  pip install -r requirements.txt
fi

# --- 3) ensure scripts/ is importable as a module ---
[ -d scripts ] || mkdir -p scripts
[ -f scripts/__init__.py ] || : > scripts/__init__.py

# --- 4) fresh DB + seed users (safe if DB absent) ---
rm -f dev.db 2>/dev/null || true
python -m scripts.dev_seed

echo "[dev] Seeded admin/mentor/student users:"
echo "  admin@example.com / admin123"
echo "  mentor@example.com / mentor123"
echo "  student@example.com / student123"
echo

# --- 5) if the script was 'sourced', just leave the venv active and return ---
# (This makes you 'fall into' the venv in your current shell.)
if [ "${BASH_SOURCE[0]:-}" != "$0" ]; then
  echo "[dev] Virtualenv is ACTIVE in this shell. Type 'deactivate' to exit."
  return 0 2>/dev/null || exit 0
fi

# --- 6) if executed (./dev_up.sh), drop you into a venv subshell ---
echo "[dev] Entering venv subshell (type 'exit' to leave)…"
# On Bash, this keeps venv active in the new interactive shell.
exec "${SHELL:-/bin/bash}" -i
