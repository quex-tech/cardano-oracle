#!/usr/bin/env python
import argparse
from dataclasses import dataclass

from dotenv import load_dotenv
from pycardano import Address, Network, PlutusScript, ScriptHash, plutus_script_hash

from networks import get_network
from utils import blueprint_arg_parser, load_scripts


def main():
    load_dotenv()
    parser = argparse.ArgumentParser(parents=[blueprint_arg_parser])
    args = parser.parse_args()
    protocol = Protocol.load(args.plutus_blueprint)
    print("Responses address:       ", protocol.response_addr(get_network()))
    print("Response currency symbol:", bytes(protocol.response_currency_symbol).hex())


@dataclass
class Protocol:
    minting_policy: PlutusScript
    spending_validator: PlutusScript

    @classmethod
    def load(cls, blueprint_path: str):
        minting_policy, validator = load_scripts(blueprint_path)
        return cls(minting_policy=minting_policy, spending_validator=validator)

    def response_addr(self, nw: Network) -> Address:
        return Address(plutus_script_hash(self.spending_validator), network=nw)

    @property
    def response_currency_symbol(self) -> ScriptHash:
        return plutus_script_hash(self.minting_policy)


if __name__ == "__main__":
    main()
