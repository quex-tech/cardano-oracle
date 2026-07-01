#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2025 Quex Technologies
#
# Step 1 (set the stage): show the network, the oracle pool, the on-chain
# protocol addresses, and the requester wallet. Read-only, no transactions.
# The actual Cardano calls start in 02.
. "$(dirname "$0")/lib.sh"

require_env CARDANO_NETWORK ORACLE_POOL_ID WALLET_MNEMONIC

banner "QUEX ORACLE DEMO  ·  network: ${CARDANO_NETWORK}"
echo "Oracle pool ID : ${ORACLE_POOL_ID}"
echo "Explorer       : $(scan_base)"

banner "Protocol addresses on this network"
# protocol.py prints the responses address + response currency symbol.
# On mainnet the currency symbol must be c093ca8bc5318cb767219cc1907aa03120ba696fb3293b48069e5edc.
run_cmd ./protocol.py

banner "Your wallet (the requester)"
# --passphrase is optional; pass PASSPHRASE from .env if you set one at generation.
run_cmd ./wallet.py show --passphrase "${PASSPHRASE:-}"

echo
warn "Top up the Treasury address with a few ADA before recording (~3-5 ADA is plenty)."
warn "This wallet is the only key on the machine; the oracle's signing key lives inside"
warn "the Intel TDX enclave, not here. That's the trust model: trust the hardware."
echo
ok "Stage is set. Next: ./demo/02-request.sh"
