#!/usr/bin/env python
import argparse
from pycardano import *
import paths


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("addr", help="recipient address")
    parser.add_argument("ada", help="amount of ada", type=int)
    parser.add_argument(
        "--submit", help="submit transaction", action='store_true')
    args = parser.parse_args()

    nw = Network.TESTNET
    sk = PaymentSigningKey.load(paths.POOL_OWNER_SIGNER_KEY)
    vk = PaymentVerificationKey.from_signing_key(sk)
    from_addr = Address(payment_part=vk.hash(), network=nw)
    to_addr = Address.decode(args.addr)

    context = OgmiosV6ChainContext()
    builder = TransactionBuilder(context)
    builder.utxo_selectors = [LargestFirstSelector()]
    builder.add_input_address(from_addr)
    builder.add_output(TransactionOutput(to_addr, Value(args.ada * 1_000_000)))
    signed_tx = builder.build_and_sign([sk], change_address=from_addr)
    print("Transaction", signed_tx)
    print("Transaction ID", signed_tx.id)
    if args.submit:
        context.submit_tx(signed_tx)


if __name__ == '__main__':
    main()
