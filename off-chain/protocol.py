#!/usr/bin/env python
# SPDX-License-Identifier: Apache-2.0
# Copyright 2025 Quex Technologies
import argparse
import os
from dataclasses import dataclass
from operator import itemgetter
from pathlib import Path

from dotenv import load_dotenv
from pycardano import Address, Network, PlutusScript, ScriptHash, plutus_script_hash

from networks import get_network
from utils import blueprint_arg_parser, load_scripts


def main() -> None:
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
    print("  Address:          ", protocol.request_validator.addr(nw))
    print("  Script size:      ", len(protocol.request_validator.script))
    print("Responses:")
    print("  Address:          ", protocol.response_validator.addr(nw))
    print("  Script size:      ", len(protocol.response_validator.script))
    print("  Currency symbol:  ", bytes(protocol.response_validator.currency_symbol).hex())
    print("Single-oracle pools:")
    print("  Address:          ", protocol.single_oracle_pool_validator.addr(nw))
    print("  Script size:      ", len(protocol.single_oracle_pool_validator.script))
    print(
        "  Currency symbol:  ",
        bytes(protocol.single_oracle_pool_validator.currency_symbol).hex(),
    )


@dataclass
class Validator:
    script: PlutusScript

    def addr(self, nw: Network) -> Address:
        return Address(self.currency_symbol, network=nw)

    @property
    def currency_symbol(self) -> ScriptHash:
        return plutus_script_hash(self.script)


@dataclass
class Protocol:
    response_validator: Validator
    request_validator: Validator
    single_oracle_pool_validator: Validator

    @classmethod
    def load(cls, blueprint_path: Path):
        response_validator, request_validator, single_oracle_pool_validator = itemgetter(
            "Oracle Response Validator",
            "Oracle Request Validator",
            "Single Oracle Pool Validator",
        )(load_scripts(blueprint_path))
        return cls(
            response_validator=Validator(response_validator),
            request_validator=Validator(request_validator),
            single_oracle_pool_validator=Validator(single_oracle_pool_validator),
        )


if __name__ == "__main__":
    main()
