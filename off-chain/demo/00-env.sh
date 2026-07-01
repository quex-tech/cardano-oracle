#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2025 Quex Technologies
#
# Act 0 (title card in the terminal): show the network, the oracle pool, and
# the on-chain protocol addresses this demo talks to. Read-only, no tx.
. "$(dirname "$0")/lib.sh"

banner "QUEX ORACLE DEMO  ·  network: ${CARDANO_NETWORK:-mainnet}"

require_env CARDANO_NETWORK ORACLE_POOL_ID

echo "Oracle pool ID : ${ORACLE_POOL_ID}"
echo "Explorer       : $(scan_base)"
echo

banner "Protocol addresses on this network"
# protocol.py prints the responses address + response currency symbol.
# On mainnet the currency symbol must be c093ca8bc5318cb767219cc1907aa03120ba696fb3293b48069e5edc.
run_cmd ./protocol.py

echo
ok "Ready. Next: ./demo/01-wallet.sh"
