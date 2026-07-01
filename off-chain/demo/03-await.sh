#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2025 Quex Technologies
#
# Act 2: watch the chain until the TEE-signed response lands. The Quex relayer
# sees the request, the enclave fetches + signs, and posts the response on-chain.
# Fill this ~60-90s wait with verify.quex.tech and the architecture slide.
. "$(dirname "$0")/lib.sh"

TIMEOUT_S="${AWAIT_TIMEOUT:-240}"
POLL_S="${AWAIT_POLL:-8}"

banner "Waiting for the TEE-signed response"
echo "While we wait, the enclave (Intel TDX) is fetching the API and signing the"
echo "value in hardware. Anyone can verify that enclave at ${CYAN}https://verify.quex.tech${RESET}"
echo

# Baseline = responses currently at the response address. We stop when a new one appears.
baseline="$(./responses.py 2>/dev/null || true)"

spinner='⠿⠄⠤⠴⠶⠷'
start="$(date +%s 2>/dev/null || echo 0)"
i=0
new_utxo=""
while :; do
  now="$(date +%s 2>/dev/null || echo 0)"; elapsed=$(( now - start ))
  cur="$(./responses.py 2>/dev/null || true)"
  # Any UTxO line present now that was not present in the baseline is our response.
  new_utxo="$(grep 'UTxO:' <<<"$cur" 2>/dev/null | grep -vFf <(grep 'UTxO:' <<<"$baseline" 2>/dev/null) 2>/dev/null | head -1 || true)"
  if [ -n "$new_utxo" ]; then break; fi
  if [ "$elapsed" -ge "$TIMEOUT_S" ]; then
    echo
    warn "No new response after ${TIMEOUT_S}s."
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
./responses.py 2>/dev/null | sed -n '1,12p'
echo

txid="$(grep -oE '[0-9a-f]{64}' <<<"$new_utxo" | head -1)"
if [ -n "$txid" ]; then
  echo "$txid" > "$DEMO_DIR/.last_response"
  link "  $(scan_base)/transaction/${txid}"
  echo "  (open this tab: the TEE-signed value delivered and validated on-chain)"
fi

echo
ok "Request in, hardware-signed answer out. Next: ./demo/04-consumer.sh"
