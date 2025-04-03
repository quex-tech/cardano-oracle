#!/usr/bin/env python
import argparse
from dataclasses import dataclass

from pycardano import (
    Address,
    ChainContext,
    MultiAsset,
    PlutusData,
    PlutusV3Script,
    Redeemer,
    Transaction,
    TransactionBuilder,
    TransactionOutput,
    UTxO,
    Value,
    plutus_script_hash,
)
from dotenv import load_dotenv

from oracles import RegisteredOracle
from models import DataItem, QuexResponse
from wallet import OraclePoolOwnerWallet
from networks import get_chain_context
from utils import load_scripts, passphrase_arg_parser, blueprint_arg_parser


def main():
    load_dotenv()
    parser = argparse.ArgumentParser(
        parents=[passphrase_arg_parser, blueprint_arg_parser]
    )
    args = parser.parse_args()
    minting_policy, validator = load_scripts(args.plutus_blueprint)

    repo = ResponseRepository(
        wallet=OraclePoolOwnerWallet.from_env(args.passphrase),
        context=get_chain_context(),
        minting_policy=minting_policy,
        validator=validator,
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
    minting_policy: PlutusV3Script
    validator: PlutusV3Script

    def all(self):
        validator_addr = Address(
            plutus_script_hash(self.validator), network=self.context.network
        )

        currency_symbol = plutus_script_hash(self.minting_policy)

        return [
            StoredResponse.from_utxo(utxo)
            for utxo in self.context.utxos(validator_addr)
            if currency_symbol in utxo.output.amount.multi_asset
        ]

    def add_tx(self, response: QuexResponse, oracle: RegisteredOracle) -> Transaction:
        nw = self.context.network
        validator_addr = Address(plutus_script_hash(self.validator), network=nw)
        currency_symbol = plutus_script_hash(self.minting_policy)
        pool_action_id = oracle.pools[0].pool_action_id(response.message.action_id)

        existing_responses = [
            r for r in self.all() if r.pool_action_id == pool_action_id
        ]

        builder = TransactionBuilder(self.context)
        builder.add_input_address(self.wallet.treasury.addr(nw))

        assets = MultiAsset.from_primitive(
            {bytes(currency_symbol): {pool_action_id: 1}}
        )

        if existing_responses:
            for r in existing_responses:
                builder.add_script_input(
                    r.utxo, self.validator, redeemer=Redeemer(data=response)
                )
            tokens_to_burn = len(existing_responses) - 1
            if tokens_to_burn:
                builder.mint = MultiAsset.from_primitive(
                    {bytes(currency_symbol): {pool_action_id: -tokens_to_burn}}
                )
                builder.add_minting_script(
                    self.minting_policy,
                    redeemer=Redeemer(data=DeleteOracleResponseMintingRedeemer()),
                )
        else:
            builder.mint = assets
            builder.add_minting_script(
                self.minting_policy,
                redeemer=Redeemer(
                    data=CreateOracleResponseMintingRedeemer(signed_message=response)
                ),
            )

        builder.reference_inputs.add(oracle.input)
        builder.add_output(
            TransactionOutput(
                validator_addr, Value(2_000_000, assets), datum=response.message.data
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
