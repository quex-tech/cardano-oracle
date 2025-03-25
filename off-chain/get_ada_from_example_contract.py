#!/usr/bin/env python
import argparse
import json
from pycardano import *
import paths


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("blueprint", help="path to plutus.json",
                        type=argparse.FileType("r"))
    parser.add_argument("utxo", help="reference UTxO with oracle response")
    parser.add_argument(
        "--submit", help="submit transaction", action='store_true')
    args = parser.parse_args()

    nw = Network.TESTNET
    sk = PaymentSigningKey.load(paths.POOL_OWNER_SIGNER_KEY)
    vk = PaymentVerificationKey.from_signing_key(sk)
    to_addr = Address(payment_part=vk.hash(), network=nw)

    with args.blueprint as f:
        blueprint = json.load(f)

    script = PlutusV3Script.fromhex(blueprint["validators"][0]["compiledCode"])
    from_addr = Address(plutus_script_hash(script), network=nw)

    context = OgmiosV6ChainContext()
    utxo_to_spend = context.utxos(from_addr)[0]
    builder = TransactionBuilder(context)
    builder.add_input_address(to_addr)
    builder.add_script_input(utxo_to_spend, script, redeemer=Redeemer(Unit()))
    builder.reference_inputs.add(parse_tx_input(args.utxo))
    builder.add_output(TransactionOutput(to_addr, utxo_to_spend.output.amount))
    signed_tx = builder.build_and_sign([sk], change_address=to_addr)
    print("Transaction", signed_tx)
    print("Transaction ID", signed_tx.id)
    if args.submit:
        context.submit_tx(signed_tx)

def parse_tx_input(input: str):
    tx, idx = input.split("#")
    return TransactionInput.from_primitive([tx, int(idx)])

if __name__ == '__main__':
    main()
