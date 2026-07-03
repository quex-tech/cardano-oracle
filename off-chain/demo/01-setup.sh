#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2025 Quex Technologies
#
# Step 1 (set the stage): network, oracle pool, protocol addresses, wallet.
# Read-only, no transactions. Output is trimmed to what the video narrates;
# run ./protocol.py and ./wallet.py show directly for the full picture.
. "$(dirname "$0")/lib.sh"

require_env CARDANO_NETWORK ORACLE_POOL_ID WALLET_MNEMONIC

banner "QUEX ORACLE DEMO  ·  network: ${CARDANO_NETWORK}"

protocol_out="$(./protocol.py 2>/dev/null)"
requests_addr="$(sed -n '/^Requests:/,/Address:/s/^ *Address: *//p' <<<"$protocol_out" | head -1)"
responses_addr="$(sed -n '/^Responses:/,/Address:/s/^ *Address: *//p' <<<"$protocol_out" | head -1)"
wallet_addr="$(./wallet.py show --passphrase "${PASSPHRASE:-}" 2>/dev/null | sed -n 's/^Treasury address: *//p')"

echo "Oracle pool:         ${ORACLE_POOL_ID:0:24}..."
echo "Requests validator:  ${requests_addr}"
echo "Responses validator: ${responses_addr}"
echo "Wallet (requester):  ${wallet_addr}"
echo
ok "Next: ./demo/02-request.sh"
