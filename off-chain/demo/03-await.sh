#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2025 Quex Technologies
#
# Act 2: watch the chain until the TEE-signed response lands. The Quex relayer
# sees the request, the enclave fetches + signs, and posts the response on-chain.
# Fill this ~60-90s wait with verify.quex.tech and the architecture slide.
#
# Detection: 02-request.sh saved our Pool Action ID and the request tx id. We
# poll responses.py for a response with that Pool Action ID whose timestamp is
# not older than the request submission (mtime of .last_request). This is
# immune to the response landing before the first poll (the relayer can be
# faster than this script starts).
. "$(dirname "$0")/lib.sh"

TIMEOUT_S="${AWAIT_TIMEOUT:-240}"
POLL_S="${AWAIT_POLL:-8}"

pool_action_id="$(cat "$DEMO_DIR/.last_pool_action" 2>/dev/null || true)"
if [ -z "$pool_action_id" ]; then
  warn "No $DEMO_DIR/.last_pool_action found. Run ./demo/02-request.sh first."
  exit 1
fi
# The request tx id file was written right after submission; its mtime is our
# "not older than" cutoff for response freshness (60s slack for clock skew).
req_epoch="$(stat -f %m "$DEMO_DIR/.last_request" 2>/dev/null || stat -c %Y "$DEMO_DIR/.last_request" 2>/dev/null || echo 0)"
cutoff=$(( req_epoch - 60 ))

banner "Waiting for the TEE-signed response"
echo "Pool Action ID: ${pool_action_id}"
echo
echo "While we wait, the enclave (Intel TDX) is fetching the API and signing the"
echo "value in hardware. Anyone can verify that enclave at ${CYAN}https://verify.quex.tech${RESET}"
echo

# Print the matched response block, or exit non-zero (see match_response.py).
find_response() {
  ./responses.py 2>/dev/null | python3 "$DEMO_DIR/match_response.py" "$pool_action_id" "$cutoff"
}

spinner='⠿⠄⠤⠴⠶⠷'
start="$(date +%s)"
i=0
response=""
while :; do
  elapsed=$(( $(date +%s) - start ))
  if response="$(find_response)"; then break; fi
  if [ "$elapsed" -ge "$TIMEOUT_S" ]; then
    echo
    warn "No response for our Pool Action ID after ${TIMEOUT_S}s."
    warn "Check the relayer is running. Fallback (needs signer access via ORACLE_URL):"
    warn "  ./pending_requests.py list        # find your request UTxO"
    warn "  ./pending_requests.py fulfill <txid#idx> --submit --wait"
    exit 1
  fi
  printf "\r  ${YELLOW}%s${RESET} polling... %3ds elapsed " "${spinner:i++%${#spinner}:1}" "$elapsed"
  sleep "$POLL_S"
done

echo; echo
ok "TEE-signed response is on-chain:"
echo
echo "$response"
echo

txid="$(sed -n 's/^- UTxO:[[:space:]]*\([0-9a-f]\{64\}\)#.*$/\1/p' <<<"$response" | head -1)"
if [ -n "$txid" ]; then
  echo "$txid" > "$DEMO_DIR/.last_response"
  link "  $(scan_base)/transaction/${txid}"
  echo "  (open this tab: the TEE-signed value delivered and validated on-chain)"
fi

echo
ok "Request in, hardware-signed answer out. Next: ./demo/04-consumer.sh"
