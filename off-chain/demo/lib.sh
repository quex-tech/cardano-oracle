# SPDX-License-Identifier: Apache-2.0
# Copyright 2025 Quex Technologies
#
# Shared helpers for the on-camera demo scripts.
# Sourced by 00..04. Not meant to be run directly.

set -uo pipefail

# Resolve paths: demo/ lives inside off-chain/. All off-chain scripts assume
# their cwd is off-chain/, so we always cd there before calling them.
DEMO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
OFFCHAIN_DIR="$(cd "$DEMO_DIR/.." && pwd -P)"
cd "$OFFCHAIN_DIR"

# Activate the project venv if present (README: `uv sync` creates .venv).
if [ -z "${VIRTUAL_ENV:-}" ] && [ -f "$OFFCHAIN_DIR/.venv/bin/activate" ]; then
  # shellcheck disable=SC1091
  . "$OFFCHAIN_DIR/.venv/bin/activate"
fi

# Colors (fall back to empty strings if the terminal has no tput).
if command -v tput >/dev/null 2>&1 && [ -t 1 ]; then
  BOLD="$(tput bold)"; DIM="$(tput dim)"; RESET="$(tput sgr0)"
  BLUE="$(tput setaf 4)"; GREEN="$(tput setaf 2)"; YELLOW="$(tput setaf 3)"; CYAN="$(tput setaf 6)"
else
  BOLD=""; DIM=""; RESET=""; BLUE=""; GREEN=""; YELLOW=""; CYAN=""
fi

# Cardanoscan base for the configured network.
scan_base() {
  case "${CARDANO_NETWORK:-mainnet}" in
    mainnet) echo "https://cardanoscan.io" ;;
    preprod) echo "https://preprod.cardanoscan.io" ;;
    *)       echo "https://preview.cardanoscan.io" ;;
  esac
}

# A big section banner, easy to read on a screen recording.
banner() {
  echo
  echo "${BOLD}${BLUE}==============================================================${RESET}"
  echo "${BOLD}${BLUE}  $*${RESET}"
  echo "${BOLD}${BLUE}==============================================================${RESET}"
  echo
}

# Print a command in bold, then run it verbatim. Viewers see exactly what runs.
run_cmd() {
  echo "${DIM}\$${RESET} ${BOLD}$*${RESET}"
  echo
  "$@"
}

link() { echo "${CYAN}$*${RESET}"; }
ok()   { echo "${GREEN}$*${RESET}"; }
warn() { echo "${YELLOW}$*${RESET}"; }

# Fail early with a readable message if required env vars are missing.
require_env() {
  local missing=0 var
  for var in "$@"; do
    if [ -z "${!var:-}" ]; then warn "Missing env var: $var"; missing=1; fi
  done
  if [ "$missing" -ne 0 ]; then
    warn "Set them in $OFFCHAIN_DIR/.env (see demo/.env.example) and retry."
    exit 1
  fi
}

# Load .env so the helper scripts see the same config the off-chain tools use.
if [ -f "$OFFCHAIN_DIR/.env" ]; then
  set -a
  # shellcheck disable=SC1091
  . "$OFFCHAIN_DIR/.env"
  set +a
fi
