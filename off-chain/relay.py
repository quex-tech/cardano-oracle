#!/usr/bin/env python
# SPDX-License-Identifier: Apache-2.0
# Copyright 2025 Quex Technologies
import argparse
import os

from dotenv import load_dotenv
from ecdsa import SECP256k1, VerifyingKey

from http_action import http_action_arg_parser, parse_http_action_with_proof
from networks import get_chain_context
from oracles import get_registered_oracles_at
from protocol import Protocol
from responses import ResponseRepository
from signer_client import SignerClient
from utils import (
    blueprint_arg_parser,
    handle_tx,
    passphrase_arg_parser,
    tx_arg_parser,
)
from wallet import OperatorWallet


def main() -> None:
    load_dotenv()
    parser = argparse.ArgumentParser(
        parents=[
            tx_arg_parser,
            passphrase_arg_parser,
            blueprint_arg_parser,
            http_action_arg_parser,
        ],
        description="Initiates HTTPS requests and posts responses on-chain",
    )
    parser.add_argument(
        "--oracle-url",
        default=os.environ.get("ORACLE_URL"),
        required="ORACLE_URL" not in os.environ,
        help="Base URL of the oracle API",
    )
    parser.add_argument(
        "--oracle-pool-id",
        default=os.environ.get("ORACLE_POOL_ID"),
        type=bytes.fromhex,
        help="ID of the oracle pool in hex",
    )
    args = parser.parse_args()

    client = SignerClient(args.oracle_url)
    public_key = client.public_key()
    public_key_vk = VerifyingKey.from_string(public_key.to_bytes(), SECP256k1)

    action_with_proof = parse_http_action_with_proof(args, public_key_vk)

    wallet = OperatorWallet.from_env(args.passphrase)

    relayer = bytes(wallet.treasury.vk.hash())
    response = client.query(action_with_proof, relayer)

    print("Oracle Response:")
    print("  Action ID:", response.message.action_id.hex())
    print("  Timestamp:", response.message.data.format_timestamp())
    print("  Error:    ", response.message.data.error)
    print("  Value:    ", response.message.data.format_value())
    print("  Relayer:  ", response.message.relayer.value.hex())

    print("Oracle Info:")
    print("  Public key:", public_key.to_compressed_bytes().hex())

    context = get_chain_context()
    protocol = Protocol.load(args.plutus_blueprint)
    oracle = next(
        (
            o
            for o in get_registered_oracles_at(
                context,
                [wallet.oracles.vk.hash(), protocol.single_oracle_pool_validator.currency_symbol],
            )
            if o.data.public_key == public_key
            if not args.oracle_pool_id or o.pool.id == args.oracle_pool_id
        ),
        None,
    )
    if not oracle:
        print("  Oracle is not registered on-chain")
        return

    print("  UTxO:", f"{oracle.input.transaction_id}#{oracle.input.index}")
    pool = oracle.pool
    print("  Pool ID:", pool.id.hex())
    print("  Public key:", oracle.data.public_key.to_compressed_bytes().hex())
    print("  Resp. validity period:", oracle.data.response_validity_period)
    print("PoolAction ID:", pool.pool_action_id(response.message.action_id).hex())

    response_repo = ResponseRepository(context=context, validator=protocol.response_validator)

    handle_tx(
        signed_tx=response_repo.add_tx(response, oracle, wallet.treasury),
        context=context,
        args=args,
    )


if __name__ == "__main__":
    main()
