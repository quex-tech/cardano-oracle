#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2025 Quex Technologies
#
# Act 1a: show the requester wallet. This is the only key on the machine;
# the TEE signing key never leaves the enclave. Read-only, no tx.
. "$(dirname "$0")/lib.sh"

banner "Your wallet (the requester)"

require_env WALLET_MNEMONIC

# --passphrase is optional; pass PASSPHRASE from .env if you set one at generation.
run_cmd ./wallet.py show --passphrase "${PASSPHRASE:-}"

echo
warn "Top up the Treasury address with a few ADA before recording (covers the"
warn "request budget + change; ~3-5 ADA is plenty). The signing key stays local;"
warn "the oracle's key lives inside the Intel TDX enclave, not here."
echo
ok "Next: ./demo/02-request.sh"
