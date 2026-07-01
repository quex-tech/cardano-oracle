#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2025 Quex Technologies
#
# Act 3 (cue card): a smart contract that CONSUMES the verified value.
# We narrate over the example consumer contract source + a confirmed spend tx
# in the explorer (produced once, off-camera). No live tx here.
. "$(dirname "$0")/lib.sh"

banner "A contract that trusts the value"

echo "The example consumer: on-chain/src/ExampleUserValidator.hs"
echo
echo "  type OracleResponse = Integer"
echo "  isResponseGood datum = datum > 25000000     # unlock only if ADA/USDT > \$0.25"
echo
echo "It reads the oracle response as a ${BOLD}reference input${RESET}, checks the response"
echo "NFT (proves it came from the enclave), that error == 0, that the value passes"
echo "the rule, and that the response has not expired. Only then can funds move."
echo
echo "Flow a developer runs:"
echo "  ./demo.py lock  <ada>            --submit   # lock funds behind the oracle"
echo "  ./demo.py spend <response addr>  --submit   # unlocks, referencing the response"
echo

if [ -n "${SPEND_TX:-}" ]; then
  banner "The consuming (spend) transaction"
  link "  $(scan_base)/transaction/${SPEND_TX}"
  echo "  (open this tab: note the oracle response as a reference input)"
else
  warn "Set SPEND_TX=<txid> in .env to print the cardanoscan link for the confirmed"
  warn "spend transaction. See demo/README.md > 'Act 3 prerequisite' to produce one."
fi

echo
ok "That's the full loop: request -> TEE-signed response -> a contract that trusts it."
