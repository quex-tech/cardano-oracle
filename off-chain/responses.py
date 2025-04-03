#!/usr/bin/env python
import argparse
from dataclasses import dataclass
from typing import List

from pycardano import (
    ChainContext,
    MultiAsset,
    PlutusData,
    Redeemer,
    Transaction,
    TransactionBuilder,
    TransactionOutput,
    UTxO,
    Value,
)
from dotenv import load_dotenv

from models import DataItem, QuexResponse
from networks import get_chain_context
from oracles import RegisteredOracle
from protocol import Protocol
from utils import passphrase_arg_parser, blueprint_arg_parser
from wallet import OraclePoolOwnerWallet


def main():
    load_dotenv()
    parser = argparse.ArgumentParser(
        parents=[passphrase_arg_parser, blueprint_arg_parser]
    )
    args = parser.parse_args()

    repo = ResponseRepository(
        wallet=OraclePoolOwnerWallet.from_env(args.passphrase),
        context=get_chain_context(),
        protocol=Protocol.load(args.plutus_blueprint),
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


@dataclass
class ResponseRepository:
    wallet: OraclePoolOwnerWallet
    context: ChainContext
    protocol: Protocol

    def all(self) -> List[StoredResponse]:
        return [
            StoredResponse.from_utxo(utxo)
            for utxo in self.context.utxos(
                self.protocol.response_addr(self.context.network)
            )
            if self.protocol.response_currency_symbol in utxo.output.amount.multi_asset
        ]

    def add_tx(self, response: QuexResponse, oracle: RegisteredOracle) -> Transaction:
        nw = self.context.network
        pool_action_id = oracle.pools[0].pool_action_id(response.message.action_id)

        existing_responses = [
            r for r in self.all() if r.pool_action_id == pool_action_id
        ]

        builder = TransactionBuilder(self.context)
        builder.add_input_address(self.wallet.treasury.addr(nw))

        assets = MultiAsset.from_primitive(
            {bytes(self.protocol.response_currency_symbol): {pool_action_id: 1}}
        )

        if existing_responses:
            for r in existing_responses:
                builder.add_script_input(
                    r.utxo,
                    self.protocol.spending_validator,
                    redeemer=Redeemer(data=response),
                )
            tokens_to_burn = len(existing_responses) - 1
            if tokens_to_burn:
                builder.mint = MultiAsset.from_primitive(
                    {
                        bytes(self.protocol.response_currency_symbol): {
                            pool_action_id: -tokens_to_burn
                        }
                    }
                )
                builder.add_minting_script(
                    self.protocol.minting_policy,
                    redeemer=Redeemer(data=DeleteOracleResponseMintingRedeemer()),
                )
        else:
            builder.mint = assets
            builder.add_minting_script(
                self.protocol.minting_policy,
                redeemer=Redeemer(
                    data=CreateOracleResponseMintingRedeemer(signed_message=response)
                ),
            )

        builder.reference_inputs.add(oracle.input)
        builder.add_output(
            TransactionOutput(
                self.protocol.response_addr(nw),
                Value(2_000_000, assets),
                datum=response.message.data,
            )
        )

        return builder.build_and_sign(
            [self.wallet.treasury.sk],
            change_address=self.wallet.treasury.addr(nw),
            collateral_change_address=self.wallet.treasury.addr(nw),
            auto_ttl_offset=min(
                int(oracle.data.response_validity_period.total_seconds() * 0.9), 10_000
            ),
        )


@dataclass
class CreateOracleResponseMintingRedeemer(PlutusData):
    CONSTR_ID = 0
    signed_message: QuexResponse


@dataclass
class DeleteOracleResponseMintingRedeemer(PlutusData):
    CONSTR_ID = 1


if __name__ == "__main__":
    main()
