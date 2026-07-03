#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2025 Quex Technologies
#
# Act 3 (cue card): a contract that consumes the verified value. Narrated over
# the validator source + the confirmed spend tx (produced once, off-camera).
# No live tx here.
. "$(dirname "$0")/lib.sh"

banner "A contract that trusts the value"

echo "on-chain/src/ExampleUserValidator.hs:"
echo
echo "  isResponseGood datum = datum > 10000000    ${DIM}-- unlock only if ADA/USDT > \$0.10${RESET}"
echo
echo "Fresh, correctly signed response for this exact request -> spend allowed."
echo

if [ -n "${SPEND_TX:-}" ]; then
  link "  $(scan_base)/transaction/${SPEND_TX}"
  echo "  (the spend tx: note the oracle response as a reference input)"
else
  warn "Set SPEND_TX=<txid> in .env (see demo/README.md > 'Act 3 prerequisite')."
fi