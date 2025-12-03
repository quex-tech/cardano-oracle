#!/usr/bin/env python
from argparse import ArgumentParser

from dotenv import load_dotenv
from pycardano import TransactionBuilder, TransactionOutput, Value

from networks import get_chain_context
from utils import handle_tx, passphrase_arg_parser, tx_arg_parser
from wallet import OperatorWallet


def main():
    load_dotenv()
    parser = ArgumentParser(
        parents=[
            tx_arg_parser,
            passphrase_arg_parser,
        ],
        description="Consolidates UTxO in a wallet",
    )
    args = parser.parse_args()

    context = get_chain_context()
    nw = context.network
    wallet = OperatorWallet.from_env(args.passphrase).request_treasury

    builder = TransactionBuilder(context)
    builder.add_input_address(wallet.addr(nw))

    utxos = context.utxos(wallet.addr(nw))
    utxos.sort(key=lambda x: x.output.amount)
    amount = Value()
    for utxo in utxos[0:-1]:
        builder.add_input(utxo)
        amount += utxo.output.amount

    builder.add_output(TransactionOutput(wallet.addr(nw), amount))

    signed_tx = builder.build_and_sign(
        [wallet.sk], change_address=wallet.addr(nw), merge_change=True
    )

    handle_tx(signed_tx, context, args)


if __name__ == "__main__":
    main()
