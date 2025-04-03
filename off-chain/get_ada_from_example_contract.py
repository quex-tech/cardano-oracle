#!/usr/bin/env python
import argparse

from dotenv import load_dotenv
from pycardano import (
    Address,
    Redeemer,
    TransactionBuilder,
    TransactionOutput,
    Unit,
    plutus_script_hash,
)

from networks import get_chain_context
from utils import handle_tx, parse_tx_input, load_scripts, tx_arg_parser
from wallet import OraclePoolOwnerWallet


def main():
    load_dotenv()
    parser = argparse.ArgumentParser(parents=[tx_arg_parser])
    parser.add_argument(
        "blueprint",
        help="path to plutus.json",
    )
    parser.add_argument(
        "utxo", help="reference UTxO with oracle response", type=parse_tx_input
    )
    args = parser.parse_args()

    wallet = OraclePoolOwnerWallet.from_env(args.passphrase)

    (script,) = load_scripts(args.blueprint)

    context = get_chain_context()
    from_addr = Address(plutus_script_hash(script), network=context.network)
    to_addr = wallet.treasury.addr(context.network)

    utxo_to_spend = context.utxos(from_addr)[0]
    builder = TransactionBuilder(context)
    builder.add_input_address(to_addr)
    builder.add_script_input(utxo_to_spend, script, redeemer=Redeemer(Unit()))
    builder.reference_inputs.add(args.utxo)
    builder.add_output(TransactionOutput(to_addr, utxo_to_spend.output.amount))
    signed_tx = builder.build_and_sign([wallet.treasury.sk], change_address=to_addr)
    handle_tx(signed_tx, context, args)


if __name__ == "__main__":
    main()
