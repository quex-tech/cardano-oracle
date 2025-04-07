#!/usr/bin/env python
import argparse
from dataclasses import dataclass

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
    print("Response address:                  ", protocol.response_addr(nw))
    print(
        "Response currency symbol:          ",
        bytes(protocol.response_currency_symbol).hex(),
    )
    print("Single-oracle pool address:        ", protocol.single_oracle_pool_addr(nw))
    print(
        "Single-oracle pool currency symbol:",
        bytes(protocol.single_oracle_pool_currency_symbol).hex(),
    )


@dataclass
class Protocol:
    minting_policy: PlutusScript
    spending_validator: PlutusScript
    single_oracle_pool_validator: PlutusScript

    @classmethod
    def load(cls, blueprint_path: str):
        minting_policy, validator, single_oracle_pool_validator = load_scripts(
            blueprint_path
        )
        return cls(
            minting_policy=minting_policy,
            spending_validator=validator,
            single_oracle_pool_validator=single_oracle_pool_validator,
        )

    def response_addr(self, nw: Network) -> Address:
        return Address(plutus_script_hash(self.spending_validator), network=nw)

    def single_oracle_pool_addr(self, nw: Network) -> Address:
        return Address(
            plutus_script_hash(self.single_oracle_pool_validator), network=nw
        )

    @property
    def response_currency_symbol(self) -> ScriptHash:
        return plutus_script_hash(self.minting_policy)

    @property
    def single_oracle_pool_currency_symbol(self) -> ScriptHash:
        return plutus_script_hash(self.single_oracle_pool_validator)


if __name__ == "__main__":
    main()
