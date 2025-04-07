#!/usr/bin/env python
import argparse
from dataclasses import dataclass
from datetime import timedelta
from itertools import chain
from hashlib import sha256
from typing import List, Optional, Iterable

from dotenv import load_dotenv
from eth_keys import keys

from pycardano import (
    Address,
    ChainContext,
    DeserializeException,
    MultiAsset,
    NativeScript,
    PlutusData,
    Redeemer,
    SCRIPT_HASH_SIZE,
    ScriptHash,
    ScriptPubkey,
    TransactionInput,
    Transaction,
    TransactionBuilder,
    TransactionOutput,
    Value,
)

from networks import get_chain_context
from protocol import Protocol
from signer_client import SignerClient
from utils import (
    blueprint_arg_parser,
    handle_tx,
    parse_tx_input,
    passphrase_arg_parser,
    tx_arg_parser,
)
from wallet import OraclePoolOwnerWallet


def main():
    load_dotenv()
    parser = argparse.ArgumentParser(description="Manages oracles in pools")
    subparsers = parser.add_subparsers(required=True)
    parser_list = subparsers.add_parser(
        "list",
        help="List oracles in private and single-oracle pools",
        description="Lists oracles in private and single-oracle pools",
        parents=[passphrase_arg_parser, blueprint_arg_parser],
    )
    parser_list.set_defaults(func=list_oracles)
    parser_add = subparsers.add_parser(
        "add",
        help="Add an oracle to a pool",
        description="Adds an oracle to a pool",
        parents=[passphrase_arg_parser, tx_arg_parser, blueprint_arg_parser],
    )
    parser_add.add_argument("url", help="Base URL of the oracle")
    parser_add.add_argument(
        "response_validity_period_minutes",
        type=int,
        help=(
            "How long a response is considered valid after creation, in minutes. "
            "After that it is not possible to post it on-chain"
        ),
    )
    parser_add.add_argument(
        "--pool-name",
        default="TestRequestOraclePool",
        help="Pool name for private pools. Default: TestRequestOraclePool",
    )
    parser_add.add_argument(
        "--pool-type",
        choices=["private", "single-oracle"],
        default="private",
        help=(
            "private: owner can add arbitrary oracles, "
            "single-oracle: 1 fixed oracle per pool. "
            "Default: private"
        ),
    )
    parser_add.set_defaults(func=add_oracle)
    parser_delete = subparsers.add_parser(
        "delete",
        help="Delete an oracle from a private pool",
        description="Deletes an oracle from a private pool",
        parents=[passphrase_arg_parser, tx_arg_parser, blueprint_arg_parser],
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
        wallet=OraclePoolOwnerWallet.from_env(args.passphrase),
        context=context,
        protocol=Protocol.load(args.plutus_blueprint),
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
class OraclePool:
    currency_symbol: ScriptHash
    token_name: bytes

    @classmethod
    def from_script(cls, script: NativeScript, token_name: str):
        return cls(currency_symbol=script.hash(), token_name=token_name.encode())

    @classmethod
    def get_pools(cls, assets: MultiAsset):
        asset_dict: dict = assets.to_primitive()
        return [
            cls(currency_symbol=ScriptHash(payload=cs), token_name=tn)
            for cs in asset_dict.keys()
            for tn in asset_dict[cs].keys()
            if len(cs) == SCRIPT_HASH_SIZE
        ]

    @property
    def assets(self) -> MultiAsset:
        return MultiAsset.from_primitive(
            {bytes(self.currency_symbol): {self.token_name: 1}}
        )

    @property
    def id(self) -> bytes:
        return bytes(self.currency_symbol) + self.token_name

    def pool_action_id(self, action_id: bytes) -> bytes:
        return sha256(self.id + action_id).digest()


@dataclass
class RegisteredOracle:
    input: TransactionInput
    pools: List[OraclePool]
    data: Oracle


@dataclass
class OracleRepository:
    wallet: OraclePoolOwnerWallet
    context: ChainContext
    protocol: Protocol

    def add_private_tx(self, oracle: Oracle, pool_name: str) -> Transaction:
        policy = ScriptPubkey(self.wallet.treasury.vk.hash())
        pool = OraclePool.from_script(policy, pool_name)
        nw = self.context.network

        builder = TransactionBuilder(self.context)
        builder.add_input_address(self.wallet.treasury.addr(nw))
        builder.native_scripts = [policy]

        builder.mint = pool.assets
        builder.add_output(
            TransactionOutput(
                self.wallet.oracles.addr(nw),
                Value(2_000_000, pool.assets),
                datum=oracle.to_plutus_data(),
            )
        )

        return builder.build_and_sign(
            [self.wallet.treasury.sk],
            change_address=self.wallet.treasury.addr(nw),
        )

    def add_single_oracle_tx(self, oracle: Oracle) -> Transaction:
        plutus_oracle = oracle.to_plutus_data()
        pool = OraclePool(
            self.protocol.single_oracle_pool_currency_symbol,
            sha256(plutus_oracle.to_cbor()).digest(),
        )
        nw = self.context.network

        builder = TransactionBuilder(self.context)
        builder.add_input_address(self.wallet.treasury.addr(nw))
        builder.mint = pool.assets
        builder.add_minting_script(
            self.protocol.single_oracle_pool_validator,
            redeemer=Redeemer(data=plutus_oracle),
        )
        builder.add_output(
            TransactionOutput(
                self.protocol.single_oracle_pool_addr(nw),
                Value(2_000_000, pool.assets),
                datum=plutus_oracle,
            )
        )

        return builder.build_and_sign(
            [self.wallet.treasury.sk],
            change_address=self.wallet.treasury.addr(nw),
        )

    def delete_private_tx(self, tx_input: TransactionInput) -> Optional[Transaction]:
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
        builder.native_scripts = [ScriptPubkey(self.wallet.treasury.vk.hash())]
        builder.mint = MultiAsset() - utxo.output.amount.multi_asset

        return builder.build_and_sign(
            [self.wallet.treasury.sk, self.wallet.oracles.sk],
            change_address=self.wallet.treasury.addr(nw),
        )

    def registered(self) -> Iterable[RegisteredOracle]:
        return chain(
            self.registered_at(self.wallet.oracles.addr(self.context.network)),
            self.registered_at(
                self.protocol.single_oracle_pool_addr(self.context.network)
            ),
        )

    def registered_at(self, addr: Address) -> Iterable[RegisteredOracle]:
        for utxo in self.context.utxos(addr):
            pools = OraclePool.get_pools(utxo.output.amount.multi_asset)
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
        for pool in oracle.pools:
            pool_type = (
                "single-oracle"
                if pool.currency_symbol
                == repo.protocol.single_oracle_pool_currency_symbol
                else "private"
            )
            print("- UTxO:                 ", utxo)
            print(
                "  Pool:",
            )
            print("    ID:                 ", pool.id.hex())
            print("    Type:               ", pool_type)
            print("  Public key:           ", pub_key)
            print("  Resp. validity period:", oracle.data.response_validity_period)


def add_oracle(context: ChainContext, repo: OracleRepository, args: argparse.Namespace):
    client = SignerClient(args.url)

    oracle = Oracle(
        public_key=client.public_key(),
        response_validity_period=timedelta(
            minutes=args.response_validity_period_minutes
        ),
    )

    signed_tx = (
        repo.add_single_oracle_tx(oracle)
        if args.pool_type == "single-oracle"
        else repo.add_private_tx(oracle, args.pool_name)
    )

    handle_tx(signed_tx, context, args)


def delete_oracle(
    context: ChainContext, repo: OracleRepository, args: argparse.Namespace
):
    signed_tx = repo.delete_private_tx(args.utxo)

    if not signed_tx:
        print("Oracle is not registered in the private pool")

    handle_tx(signed_tx, context, args)


if __name__ == "__main__":
    main()
