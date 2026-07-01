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
./pending_requests.py add "${REQUEST_URL}" \
  --filter "${FILTER}" \
  "${SCHEMA}" \
  --ttl "${TTL_MIN}" \
  --max-response "${MAX_RESPONSE}" \
  --passphrase "${PASSPHRASE:-}" \
  --submit --wait 2>&1 | tee "$tmp"

txid="$(grep -oE '[0-9a-f]{64}' "$tmp" | head -1)"
rm -f "$tmp"

echo
if [ -n "$txid" ]; then
  echo "$txid" > "$DEMO_DIR/.last_request"
  ok "Request submitted on ${CARDANO_NETWORK}."
  link "  $(scan_base)/transaction/${txid}"
  echo "  (open this tab to show the request tx: inputs, outputs, request datum)"
else
  warn "Could not parse the request tx id from the output above."
fi

echo
ok "Next: ./demo/03-await.sh  (watch the TEE post the signed response)"
