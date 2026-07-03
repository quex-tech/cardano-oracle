#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2025 Quex Technologies
#
# Act 1b: submit an on-chain data request for the ADA/USDT price.
# The jq filter picks the field and scales it to an integer the contract can use.
# This is the exact command from mainnet-deployment.md, run live with --submit.
. "$(dirname "$0")/lib.sh"

require_env WALLET_MNEMONIC ORACLE_POOL_ID CARDANO_NETWORK

# Override any of these via the environment to demo a different API/field.
REQUEST_URL="${REQUEST_URL:-https://api.binance.com/api/v3/ticker/price?symbol=ADAUSDT}"
FILTER="${FILTER:-.price|tonumber*100000000|floor}"
SCHEMA="${SCHEMA:-uint}"
TTL_MIN="${TTL_MIN:-60}"
MAX_RESPONSE="${MAX_RESPONSE:-256}"

banner "Submit a data request  ·  ADA/USDT price"
echo "Source : ${REQUEST_URL}"
echo "Filter : ${FILTER}      (runs inside the enclave, on the JSON response)"
echo "Type   : ${SCHEMA}"
echo

tmp="$(mktemp)"
echo "${DIM}\$${RESET} ${BOLD}./pending_requests.py add \"${REQUEST_URL}\" --filter \"${FILTER}\" \"${SCHEMA}\" --ttl ${TTL_MIN} --max-response ${MAX_RESPONSE} --submit --wait${RESET}"
echo
# Full output goes to $tmp for parsing; the screen only shows the tx lifecycle
# (the request datum details duplicate the header above).
./pending_requests.py add "${REQUEST_URL}" \
  --filter "${FILTER}" \
  "${SCHEMA}" \
  --ttl "${TTL_MIN}" \
  --max-response "${MAX_RESPONSE}" \
  --passphrase "${PASSPHRASE:-}" \
  --submit --wait 2>&1 | tee "$tmp" | grep --line-buffered -E '^(Transaction ID:|Transaction submitted|Waiting for confirmation|Transaction confirmed|Traceback|\S*Error|\S*Exception)' || true

# Parse the exact fields the tool prints; do not grab arbitrary hex (Action ID
# and tracebacks also contain 64-hex strings).
txid="$(sed -n 's/^Transaction ID: \([0-9a-f]\{64\}\)$/\1/p' "$tmp" | head -1)"
pool_action_id="$(sed -n 's/^Pool Action ID:[[:space:]]*\([0-9a-f]\{64\}\)$/\1/p' "$tmp" | head -1)"
submitted="$(grep -c '^Transaction submitted\.$' "$tmp")"
rm -f "$tmp"

echo
if [ "$submitted" -ge 1 ] && [ -n "$txid" ]; then
  echo "$txid" > "$DEMO_DIR/.last_request"
  [ -n "$pool_action_id" ] && echo "$pool_action_id" > "$DEMO_DIR/.last_pool_action"
  ok "Request submitted on ${CARDANO_NETWORK}."
  link "  $(scan_base)/transaction/${txid}"
  echo "  (open this tab to show the request tx: inputs, outputs, request datum)"
else
  warn "Request was NOT submitted (see the error above). Nothing was spent."
  exit 1
fi

echo
ok "Next: ./demo/03-await.sh  (watch the TEE post the signed response)"
