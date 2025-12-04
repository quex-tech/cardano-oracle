#!/usr/bin/env python
# SPDX-License-Identifier: Apache-2.0
# Copyright 2025 Quex Technologies
import argparse
from dataclasses import dataclass
from typing import List

from pycardano import (
    ChainContext,
    MultiAsset,
    Redeemer,
    Transaction,
    TransactionBuilder,
    TransactionOutput,
    UTxO,
    Value,
    min_lovelace_post_alonzo,
)
from dotenv import load_dotenv

from models import DataItem, QuexResponse
from networks import get_chain_context
from oracles import RegisteredOracle
from protocol import Protocol, Validator
from utils import passphrase_arg_parser, blueprint_arg_parser, try_from_tx_output
from wallet import OperatorWallet


def main():
    load_dotenv()
    parser = argparse.ArgumentParser(
        parents=[passphrase_arg_parser, blueprint_arg_parser],
        description="Shows oracle responses stored on-chain",
    )
    args = parser.parse_args()

    repo = ResponseRepository(
        wallet=OperatorWallet.from_env(args.passphrase),
        context=get_chain_context(),
        validator=Protocol.load(args.plutus_blueprint).response_validator,
    )

    for response in repo.all():
        print(
            f"- UTxO:          {response.utxo.input.transaction_id}#{response.utxo.input.index}"
        )
        print("  PoolAction ID:", response.pool_action_id.hex())
        print("  Timestamp:    ", response.data.format_timestamp())
        print("  Error:        ", response.data.error)
        print("  Value:        ", response.data.format_value())


@dataclass
class StoredResponse:
    utxo: UTxO
    data: DataItem
    pool_action_id: bytes

    @classmethod
    def from_utxo(cls, utxo: UTxO):
        return cls(
            utxo=utxo,
            data=DataItem.from_cbor(utxo.output.datum.cbor),
            pool_action_id=next(
                iter(next(iter(utxo.output.amount.multi_asset.values())).keys())
            ).payload,
        )

    @classmethod
    def try_from_utxo(cls, utxo: UTxO):
        data = try_from_tx_output(DataItem, utxo.output)
        if not data:
            return None

        asset_name = next(
            iter(next(iter(utxo.output.amount.multi_asset.values()), {}).keys()), None
        )
        if not asset_name:
            return None

        return cls(
            utxo=utxo,
            data=data,
            pool_action_id=asset_name.payload,
        )


@dataclass
class ResponseTransactionBuilder:
    builder: TransactionBuilder
    context: ChainContext
    validator: Validator

    def add_token_inputs_and_outputs(
        self,
        existing_responses: List[StoredResponse],
        pool_action_id: bytes,
        response: QuexResponse,
    ):
        nw = self.context.network

        assets = MultiAsset.from_primitive(
            {bytes(self.validator.currency_symbol): {pool_action_id: 1}}
        )

        if existing_responses:
            for r in existing_responses:
                self.builder.add_script_input(
                    r.utxo,
                    self.validator.script,
                    redeemer=Redeemer(data=response),
                )
            tokens_to_burn = len(existing_responses) - 1
            if tokens_to_burn:
                self.builder.mint = MultiAsset.from_primitive(
                    {
                        bytes(self.validator.currency_symbol): {
                            pool_action_id: -tokens_to_burn
                        }
                    }
                )
                self.builder.add_minting_script(
                    self.validator.script,
                    redeemer=Redeemer(data=response),
                )
        else:
            self.builder.mint = assets
            self.builder.add_minting_script(
                self.validator.script,
                redeemer=Redeemer(data=response),
            )

        tx_out = TransactionOutput(
            self.validator.addr(nw),
            Value(2_000_000, assets),
            datum=response.message.data,
        )
        tx_out.amount.coin = min_lovelace_post_alonzo(tx_out, self.context)
        self.builder.add_output(tx_out)


@dataclass
class ResponseRepository:
    wallet: OperatorWallet
    context: ChainContext
    validator: Validator

    def all(self) -> List[StoredResponse]:
        return [
            sr
            for sr in (
                StoredResponse.try_from_utxo(utxo)
                for utxo in self.context.utxos(
                    self.validator.addr(self.context.network)
                )
                if self.validator.currency_symbol in utxo.output.amount.multi_asset
            )
            if sr
        ]

    def by_pool_action_id(self, pool_action_id: bytes):
        return [r for r in self.all() if r.pool_action_id == pool_action_id]

    def add_tx(self, response: QuexResponse, oracle: RegisteredOracle) -> Transaction:
        nw = self.context.network
        pool_action_id = oracle.pools[0].pool_action_id(response.message.action_id)

        builder = TransactionBuilder(self.context)
        builder.add_input_address(self.wallet.treasury.addr(nw))

        response_tx_builder = ResponseTransactionBuilder(
            builder=builder, context=self.context, validator=self.validator
        )

        response_tx_builder.add_token_inputs_and_outputs(
            self.by_pool_action_id(pool_action_id), pool_action_id, response
        )

        builder.reference_inputs.add(oracle.input)

        return builder.build_and_sign(
            [self.wallet.treasury.sk],
            change_address=self.wallet.treasury.addr(nw),
            collateral_change_address=self.wallet.treasury.addr(nw),
            auto_ttl_offset=min(
                int(oracle.data.response_validity_period.total_seconds() * 0.9), 10_000
            ),
        )


if __name__ == "__main__":
    main()
