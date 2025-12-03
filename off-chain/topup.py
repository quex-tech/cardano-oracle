#!/usr/bin/env python
from argparse import ArgumentParser

from dotenv import load_dotenv
from pycardano import Address, TransactionBuilder, TransactionOutput, Value

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
        description="Tops up wallets",
    )
    parser.add_argument(
        "recipient",
        type=Address.decode,
        help="The adddress where oracle responses are stored",
    )
    parser.add_argument("ada", type=float, help="Amount of ADA to send")
    args = parser.parse_args()

    context = get_chain_context()
    nw = context.network
    wallet = OperatorWallet.from_env(args.passphrase)

    builder = TransactionBuilder(context)
    builder.add_input_address(wallet.treasury.addr(nw))

    builder.add_output(
        TransactionOutput(args.recipient, Value(int(args.ada * 1_000_000)))
    )

    signed_tx = builder.build_and_sign(
        [wallet.treasury.sk],
        change_address=wallet.treasury.addr(nw),
    )

    handle_tx(signed_tx, context, args)


if __name__ == "__main__":
    main()
