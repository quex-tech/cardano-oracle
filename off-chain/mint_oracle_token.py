#!/usr/bin/env python
import os
from pycardano import *
from dataclasses import dataclass
import paths


def main():
    vk = PaymentVerificationKey.from_signing_key(sk)
    os.unlink(paths.POOL_OWNER_VERIFICATION_KEY)
    vk.save(paths.POOL_OWNER_VERIFICATION_KEY)

    with open(paths.ORACLE_PUBLIC_KEY, "rb") as f:
        oracle_public_key = f.read()

    addr = Address(payment_part=vk.hash(),
                   network=Network.TESTNET)

    context = OgmiosV6ChainContext()

    policy = ScriptPubkey(vk.hash())
    policy_id = policy.hash()
    assets = MultiAsset.from_primitive(
        {
            bytes(policy_id): {
                b"TD": 1
            }
        }
    )

    with open(paths.POOL_ID, "wb") as f:
        f.write(bytes(policy_id) + b"TD")

    builder = TransactionBuilder(context)
    builder.add_input_address(addr)
    builder.mint = assets
    builder.native_scripts = [policy]

    oracle = Oracle(oracle_public_key, 5*60*1000)

    builder.add_output(TransactionOutput(addr, Value(
        2_000_000, assets), datum=oracle))
    signed_tx = builder.build_and_sign(
        [sk], change_address=addr, collateral_change_address=addr)
    print("Transaction", signed_tx)
    print("Transaction ID", signed_tx.id)

    with open(paths.ORACLE_UTXO, "wb") as f:
        f.write(TransactionInput(signed_tx.id, 0).to_cbor())

    context.submit_tx(signed_tx)


def get_or_create_signing_key():
    if os.path.exists(paths.POOL_OWNER_SIGNER_KEY):
        return PaymentSigningKey.load(paths.POOL_OWNER_SIGNER_KEY)
    else:
        sk = PaymentSigningKey.generate()
        sk.save(paths.POOL_OWNER_SIGNER_KEY)
        return sk


@dataclass
class Oracle(PlutusData):
    CONSTR_ID = 0
    public_key: bytes
    response_validity_period: int


if __name__ == '__main__':
    main()
