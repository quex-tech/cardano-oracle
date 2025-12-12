#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2025 Quex Technologies
set -euo pipefail

ROOT_DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )

docker run \
  --rm \
  -v "$ROOT_DIR":/workspaces/quex-oracle \
  ghcr.io/input-output-hk/devx-devcontainer:x86_64-linux.ghc96-iog \
  bash -ic "cd /workspaces/quex-oracle/on-chain && cabal update && cabal test && cabal run gen-oracle-blueprint ../off-chain/plutus.json && cabal run gen-example-user-blueprint ../off-chain/plutus.user.json"
