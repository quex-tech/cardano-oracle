#!/usr/bin/env python
# SPDX-License-Identifier: Apache-2.0
# Copyright 2025 Quex Technologies
import argparse
from dataclasses import dataclass
from operator import itemgetter
import os

from dotenv import load_dotenv
from pycardano import Address, Network, PlutusScript, ScriptHash, plutus_script_hash

from networks import get_network
from utils import blueprint_arg_parser, load_scripts


def main():
    load_dotenv()
    parser = argparse.ArgumentParser(
        parents=[blueprint_arg_parser], description="Shows general protocol information"
    )
    args = parser.parse_args()
    protocol = Protocol.load(args.plutus_blueprint)
    nw = get_network()
    print(
        "Network:            ",
        os.environ.get("CARDANO_NETWORK", "preview"),
    )
    print("Requests:")
    print("  Address:          ", protocol.request_addr(nw))
    print("  Script size:      ", len(protocol.request_validator))
    print("Responses:")
    print("  Address:          ", protocol.response_addr(nw))
    print("  Script size:      ", len(protocol.response_validator))
    print("  Currency symbol:  ", bytes(protocol.response_currency_symbol).hex())
    print("Single-oracle pools:")
    print("  Address:          ", protocol.single_oracle_pool_addr(nw))
    print("  Script size:      ", len(protocol.single_oracle_pool_validator))
    print(
        "  Currency symbol:  ", bytes(protocol.single_oracle_pool_currency_symbol).hex()
    )


@dataclass
class Protocol:
    response_validator: PlutusScript
    request_validator: PlutusScript
    single_oracle_pool_validator: PlutusScript

    @classmethod
    def load(cls, blueprint_path: str):
        response_validator, request_validator, single_oracle_pool_validator = (
            itemgetter(
                "Oracle Response Validator",
                "Oracle Request Validator",
                "Single Oracle Pool Validator",
            )(load_scripts(blueprint_path))
        )
        return cls(
            response_validator=response_validator,
            request_validator=request_validator,
            single_oracle_pool_validator=single_oracle_pool_validator,
        )

    def response_addr(self, nw: Network) -> Address:
        return Address(plutus_script_hash(self.response_validator), network=nw)

    def request_addr(self, nw: Network) -> Address:
        return Address(plutus_script_hash(self.request_validator), network=nw)

    def single_oracle_pool_addr(self, nw: Network) -> Address:
        return Address(
            plutus_script_hash(self.single_oracle_pool_validator), network=nw
        )

    @property
    def response_currency_symbol(self) -> ScriptHash:
        return plutus_script_hash(self.response_validator)

    @property
    def single_oracle_pool_currency_symbol(self) -> ScriptHash:
        return plutus_script_hash(self.single_oracle_pool_validator)


if __name__ == "__main__":
    main()
