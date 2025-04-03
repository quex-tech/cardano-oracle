#!/usr/bin/env python
import argparse

from dotenv import load_dotenv
from pycardano import Address, TransactionBuilder, TransactionOutput, Value

from networks import get_chain_context
from utils import handle_tx, passphrase_arg_parser, tx_arg_parser
from wallet import OraclePoolOwnerWallet


def main():
    load_dotenv()
    parser = argparse.ArgumentParser(parents=[tx_arg_parser, passphrase_arg_parser])
    parser.add_argument("addr", help="recipient address", type=Address.decode)
    parser.add_argument("ada", help="amount of ada", type=int)
    args = parser.parse_args()

    wallet = OraclePoolOwnerWallet.from_env(args.passphrase)
    context = get_chain_context()

    from_addr = wallet.treasury.addr(context.network)
    to_addr = args.addr

    builder = TransactionBuilder(context)
    builder.add_input_address(from_addr)
    builder.add_output(TransactionOutput(to_addr, Value(args.ada * 1_000_000)))
    signed_tx = builder.build_and_sign([wallet.treasury.sk], change_address=from_addr)
    handle_tx(signed_tx, context, args)


if __name__ == "__main__":
    main()
