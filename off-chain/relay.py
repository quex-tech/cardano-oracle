#!/usr/bin/env python
import argparse
import os

from pycardano.serialization import ByteString
from dotenv import load_dotenv

from models import (
    HTTP_METHODS,
    HTTPAction,
    HTTPPrivatePatch,
    HTTPRequest,
)
from networks import get_chain_context
from oracles import OracleRepository
from protocol import Protocol
from responses import ResponseRepository
from signer_client import SignerClient
from utils import (
    handle_tx,
    tx_arg_parser,
    passphrase_arg_parser,
    blueprint_arg_parser,
)
from wallet import OraclePoolOwnerWallet


def main():
    load_dotenv()
    parser = argparse.ArgumentParser(
        parents=[tx_arg_parser, passphrase_arg_parser, blueprint_arg_parser]
    )
    parser.add_argument(
        "-X",
        "--request",
        help="HTTP method",
        choices=list(HTTP_METHODS.keys()),
        default="GET",
    )
    parser.add_argument(
        "-H",
        "--header",
        action="append",
        help='add an HTTP header. Example: --header "Content-Type: application/json"',
    )
    parser.add_argument("-d", "--data", help="HTTP body as plaintext")
    parser.add_argument(
        "-f",
        "--filter",
        default=".",
        help="jq filter to transfort response body. Default: .",
    )
    parser.add_argument(
        "--oracle-url",
        default=os.environ.get("ORACLE_URL"),
        required="ORACLE_URL" not in os.environ,
        help="Base URL of a QUEX Signer",
    )
    parser.add_argument("url", help="URL to fetch")
    parser.add_argument(
        "schema", help="Schema to encode response body, example: (string,(int,bool[]))"
    )
    args = parser.parse_args()
    request = HTTPRequest.from_parts(
        method=args.request, url=args.url, headers=args.header, body=args.data
    )
    action = HTTPAction(
        request=request,
        patch=HTTPPrivatePatch.empty(),
        filter=ByteString(args.filter.encode()),
        schema=ByteString(args.schema.encode()),
    )
    client = SignerClient(args.oracle_url)
    response = client.query(action)

    print("Oracle Response:")
    print("  Action ID:", response.message.action_id.hex())
    print("  Timestamp:", response.message.data.format_timestamp())
    print("  Error:", response.message.data.error)
    print("  Value:", response.message.data.format_value())

    public_key = client.public_key()

    print("Oracle Info:")
    print("  Public key:", public_key.to_compressed_bytes().hex())

    wallet = OraclePoolOwnerWallet.from_env(args.passphrase)
    context = get_chain_context()
    oracle_repo = OracleRepository(wallet=wallet, context=context)
    oracle = next(
        (o for o in oracle_repo.registered() if o.data.public_key == public_key), None
    )
    if not oracle:
        print("  Oracle is not registered on-chain")
        return

    print("  UTxO:", f"{oracle.input.transaction_id}#{oracle.input.index}")
    pool = oracle.pools[0]
    print("  Pool:")
    print("    Name:", pool.name)
    print("    ID:", pool.pool_id().hex())
    print("PoolAction ID:", pool.pool_action_id(response.message.action_id).hex())

    protocol = Protocol.load(args.plutus_blueprint)

    response_repo = ResponseRepository(
        wallet=wallet, context=context, protocol=protocol
    )

    handle_tx(
        signed_tx=response_repo.add_tx(response, oracle), context=context, args=args
    )


if __name__ == "__main__":
    main()
