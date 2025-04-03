#!/usr/bin/env python
import argparse
from dataclasses import dataclass
from datetime import timedelta
from hashlib import sha256
from typing import List, Optional, Iterable

from dotenv import load_dotenv
from eth_keys import keys

from pycardano import (
    ChainContext,
    DeserializeException,
    ExtendedVerificationKey,
    MultiAsset,
    PlutusData,
    ScriptPubkey,
    TransactionInput,
    Transaction,
    TransactionBuilder,
    TransactionOutput,
    Value,
)

from networks import get_chain_context
from signer_client import SignerClient
from utils import handle_tx, parse_tx_input, passphrase_arg_parser, tx_arg_parser
from wallet import OraclePoolOwnerWallet


def main():
    load_dotenv()
    parser = argparse.ArgumentParser(description="Manages oracles in the pool")
    subparsers = parser.add_subparsers(required=True)
    parser_list = subparsers.add_parser(
        "list",
        help="List oracles in the pool",
        description="Lists oracles in the pool",
        parents=[passphrase_arg_parser],
    )
    parser_list.set_defaults(func=list_oracles)
    parser_add = subparsers.add_parser(
        "add",
        help="Add an oracle to the pool",
        description="Adds an oracle to the pool",
        parents=[passphrase_arg_parser, tx_arg_parser],
    )
    parser_add.add_argument("url", help="Base URL of the Quex Signer API")
    parser_add.add_argument(
        "response_validity_period_minutes",
        type=int,
        help=(
            "How long a response is considered valid after creation, in minutes. "
            "After that it is not possible to post it on-chain"
        ),
    )
    parser_add.add_argument(
        "--name",
        default="TestRequestOraclePool",
        help="Pool name. Default: TestRequestOraclePool",
    )
    parser_add.set_defaults(func=add_oracle)
    parser_delete = subparsers.add_parser(
        "delete",
        help="Delete an oracle from the pool",
        description="Delets an oracle from the pool",
        parents=[passphrase_arg_parser, tx_arg_parser],
    )
    parser_delete.add_argument(
        "utxo",
        type=parse_tx_input,
        help="UTxO, that stores oracle data, to spend. Format: <transaction_id>#<index>",
    )
    parser_delete.set_defaults(func=delete_oracle)
    args = parser.parse_args()

    context = get_chain_context()
    repo = OracleRepository(
        wallet=OraclePoolOwnerWallet.from_env(args.passphrase), context=context
    )

    args.func(context, repo, args)


@dataclass
class PlutusOracle(PlutusData):
    CONSTR_ID = 0
    public_key: bytes
    response_validity_period_ms: int


@dataclass
class Oracle:
    public_key: keys.PublicKey
    response_validity_period: timedelta

    def to_plutus_data(self):
        return PlutusOracle(
            public_key=self.public_key.to_compressed_bytes(),
            response_validity_period_ms=int(
                self.response_validity_period.total_seconds() * 1000
            ),
        )

    @classmethod
    def from_plutus_data(cls, oracle: PlutusOracle):
        return cls(
            public_key=keys.PublicKey.from_compressed_bytes(oracle.public_key),
            response_validity_period=timedelta(
                milliseconds=oracle.response_validity_period_ms
            ),
        )


@dataclass
class OraclePoolOwner:
    vk: ExtendedVerificationKey

    def get_policy(self):
        return ScriptPubkey(self.vk.hash())

    def create_pool(self, name: str):
        return OraclePool(name=name, owner=self)

    def get_pools(self, assets: MultiAsset):
        asset_dict: dict = assets.to_primitive()
        name_dict: dict = asset_dict.get(bytes(self.get_policy().hash()), {})
        return [self.create_pool(k.decode()) for k in name_dict.keys()]


@dataclass
class OraclePool:
    name: str
    owner: OraclePoolOwner

    def get_assets(self):
        return MultiAsset.from_primitive(
            {bytes(self.owner.get_policy().hash()): {self.name.encode(): 1}}
        )

    def pool_id(self):
        return bytes(self.owner.get_policy().hash()) + self.name.encode()

    def pool_action_id(self, action_id: bytes) -> bytes:
        return sha256(self.pool_id() + action_id).digest()


@dataclass
class RegisteredOracle:
    input: TransactionInput
    pools: List[OraclePool]
    data: Oracle


@dataclass
class OracleRepository:
    wallet: OraclePoolOwnerWallet
    context: ChainContext

    def add_tx(self, oracle: Oracle, pool_name: str) -> Transaction:
        pool_owner = OraclePoolOwner(vk=self.wallet.treasury.vk)
        pool = pool_owner.create_pool(pool_name)
        assets = pool.get_assets()
        nw = self.context.network

        builder = TransactionBuilder(self.context)
        builder.add_input_address(self.wallet.treasury.addr(nw))
        builder.native_scripts = [pool_owner.get_policy()]

        builder.mint = assets
        builder.add_output(
            TransactionOutput(
                self.wallet.oracles.addr(nw),
                Value(2_000_000, assets),
                datum=oracle.to_plutus_data(),
            )
        )

        return builder.build_and_sign(
            [self.wallet.treasury.sk],
            change_address=self.wallet.treasury.addr(nw),
        )

    def delete_tx(self, tx_input: TransactionInput) -> Optional[Transaction]:
        pool_owner = OraclePoolOwner(vk=self.wallet.treasury.vk)
        nw = self.context.network
        utxo = next(
            (
                u
                for u in self.context.utxos(self.wallet.oracles.addr(nw))
                if u.input == tx_input
            ),
            None,
        )

        if not utxo:
            return None

        builder = TransactionBuilder(self.context)
        builder.add_input_address(self.wallet.treasury.addr(nw))
        builder.add_input(utxo)
        builder.native_scripts = [pool_owner.get_policy()]
        builder.mint = MultiAsset() - utxo.output.amount.multi_asset

        return builder.build_and_sign(
            [self.wallet.treasury.sk, self.wallet.oracles.sk],
            change_address=self.wallet.treasury.addr(nw),
        )

    def registered(self) -> Iterable[RegisteredOracle]:
        pool_owner = OraclePoolOwner(vk=self.wallet.treasury.vk)
        nw = self.context.network
        utxos = self.context.utxos(self.wallet.oracles.addr(nw))
        for utxo in utxos:
            pools = pool_owner.get_pools(utxo.output.amount.multi_asset)
            if not pools:
                continue

            if not utxo.output.datum:
                continue

            try:
                oracle = Oracle.from_plutus_data(
                    PlutusOracle.from_cbor(utxo.output.datum.cbor)
                )
            except DeserializeException:
                continue

            yield RegisteredOracle(utxo.input, pools, oracle)


def list_oracles(_, repo: OracleRepository, __):
    for oracle in repo.registered():
        pub_key = oracle.data.public_key.to_compressed_bytes().hex()
        utxo = f"{oracle.input.transaction_id}#{oracle.input.index}"
        pool_names = ", ".join([pool.name for pool in oracle.pools])
        print("- UTxO:                    ", utxo)
        print("  Pool:                    ", pool_names)
        print("  Public key:              ", pub_key)
        print("  Response validity period:", oracle.data.response_validity_period)


def add_oracle(context: ChainContext, repo: OracleRepository, args: argparse.Namespace):
    client = SignerClient(args.url)

    oracle = Oracle(
        public_key=client.public_key(),
        response_validity_period=timedelta(
            minutes=args.response_validity_period_minutes
        ),
    )

    signed_tx = repo.add_tx(oracle, args.name)

    handle_tx(signed_tx, context, args)


def delete_oracle(
    context: ChainContext, repo: OracleRepository, args: argparse.Namespace
):
    signed_tx = repo.delete_tx(args.utxo)

    if not signed_tx:
        print("Oracle is not registered")

    handle_tx(signed_tx, context, args)


if __name__ == "__main__":
    main()
