#!/usr/bin/env python
import json
import base64
from hashlib import sha256
from pycardano import *
from pycardano.serialization import ByteString
from dataclasses import dataclass
import paths


def main():
    with open(paths.BLUEPRINT) as f:
        blueprint = json.load(f)

    mintingPolicy, spending_validator = blueprint["validators"]

    with open(paths.RESPONSE) as f:
        response_json = json.load(f)
        response = QuexResponse.parse(response_json)

    sk = PaymentSigningKey.load(paths.POOL_OWNER_SIGNER_KEY)
    vk = PaymentVerificationKey.from_signing_key(sk)

    with open(paths.POOL_ID, "rb") as f:
        pool_id = f.read()

    with open(paths.ORACLE_UTXO, "rb") as f:
        oracle_utxo = TransactionInput.from_cbor(f.read())

    nw = Network.TESTNET

    addr = Address(payment_part=vk.hash(),
                   network=nw)

    context = OgmiosV6ChainContext()

    pool_action_id = sha256(pool_id + response.message.action_id).digest()

    assets = MultiAsset.from_primitive(
        {
            bytes.fromhex(mintingPolicy["hash"]): {
                pool_action_id: 1
            }
        }
    )

    spending_validator_addr = Address(plutus_script_hash(
        PlutusV3Script.fromhex(spending_validator["compiledCode"])), network=nw)

    redeemer = Redeemer(
        data=CreateOracleResponseMintingRedeemer(signed_message=response))

    builder = TransactionBuilder(context)
    builder.mint = assets
    builder.add_input_address(addr)
    builder.add_minting_script(
        PlutusV3Script.fromhex(mintingPolicy["compiledCode"]),
        redeemer=redeemer)
    builder.reference_inputs.add(oracle_utxo)
    builder.add_output(TransactionOutput(spending_validator_addr, Value(
        2_000_000, assets), datum=response.message.data))
    signed_tx = builder.build_and_sign(
        [sk], change_address=addr, collateral_change_address=addr, auto_ttl_offset=200)
    print("Transaction", signed_tx)
    print("Transaction ID", signed_tx.id)


@dataclass
class DataItem(PlutusData):
    CONSTR_ID = 0
    timestamp: int
    error: int
    value: RawPlutusData

    @staticmethod
    def parse(value: dict):
        return DataItem(
            timestamp=value["timestamp"],
            error=value["error"],
            value=RawPlutusData.from_cbor(base64.b64decode(value["value"])),
        )


def parse_eth_signature(value: dict):
    r = base64.b64decode(value["r"])
    s = base64.b64decode(value["s"])
    return ByteString(r + s)


@dataclass
class QuexMessage(PlutusData):
    CONSTR_ID = 0
    action_id: bytes
    data: DataItem

    @staticmethod
    def parse(value: dict):
        return QuexMessage(action_id=base64.b64decode(value["action_id"]),
                           data=DataItem.parse(value["data_item"]))


@dataclass
class QuexResponse(PlutusData):
    CONSTR_ID = 0
    message: QuexMessage
    signature: ByteString

    @staticmethod
    def parse(value: dict):
        return QuexResponse(
            message=QuexMessage.parse(value["msg"]),
            signature=parse_eth_signature(value["sig"])
        )


@dataclass
class CreateOracleResponseMintingRedeemer(PlutusData):
    CONSTR_ID = 0
    signed_message: QuexResponse


@dataclass
class DeleteOracleResponseMintingRedeemer(PlutusData):
    CONSTR_ID = 1


if __name__ == '__main__':
    main()
