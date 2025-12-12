# SPDX-License-Identifier: Apache-2.0
# Copyright 2025 Quex Technologies
import os
from blockfrost import ApiUrls
from pycardano import (
    BlockFrostChainContext,
    ChainContext,
    Network,
    OgmiosV6ChainContext,
)


def get_network() -> Network:
    network = os.environ.get("CARDANO_NETWORK", "preview")
    return Network.MAINNET if network == "mainnet" else Network.TESTNET


def get_chain_context() -> ChainContext:
    blockfrost_project = os.environ.get("BLOCKFROST_PROJECT", None)
    if not blockfrost_project:
        return OgmiosV6ChainContext(network=get_network())
    network = os.environ.get("CARDANO_NETWORK", "preview")
    return BlockFrostChainContext(blockfrost_project, base_url=ApiUrls[network].value)
