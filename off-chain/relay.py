#!/usr/bin/env python
import argparse
import os

from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto.Protocol.KDF import HKDF
from dotenv import load_dotenv
from ecdsa import SECP256k1, SigningKey, VerifyingKey
from eth_keys import keys
from pycardano.serialization import ByteString

from models import (
    HTTP_METHODS,
    HTTPAction,
    HTTPRequest,
    UnencryptedHTTPPrivatePatch,
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
        parents=[tx_arg_parser, passphrase_arg_parser, blueprint_arg_parser],
        description="Initiates HTTPS requests and posts responses on-chain",
    )
    parser.add_argument(
        "-X",
        "--request",
        help="HTTP method",
        choices=list(HTTP_METHODS.keys()),
        default="GET",
    )
    parser.add_argument(
        "--enc-url-suffix",
        help=(
            "URL suffix to append and send encrypted. "
            "Examples: /mysecretpath, ?secret1=123&secret2=321, /mypath?secret=321"
        ),
    )
    parser.add_argument(
        "-H",
        "--header",
        action="append",
        help='add an HTTP header. Example: --header "Content-Type: application/json"',
    )
    parser.add_argument(
        "--enc-header",
        action="append",
        help='add an HTTP header to send encrypted. Example: --enc-header "Api-Key: abcdef123"',
    )
    parser.add_argument("-d", "--data", help="HTTP body as plaintext")
    parser.add_argument(
        "--enc-data", help="HTTP body as plaintext to send encrypted. Overrides --data"
    )
    parser.add_argument(
        "--td-address", default="0x0000000000000000000000000000000000000000"
    )
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
        help="Base URL of the oracle API",
    )
    parser.add_argument(
        "--oracle-pool-id",
        default=os.environ.get("ORACLE_POOL_ID"),
        type=bytes.fromhex,
        help="ID of the oracle pool in hex",
    )
    parser.add_argument("url", help="URL to fetch")
    parser.add_argument(
        "schema", help="Schema to encode response body, example: (string,(int,bool[]))"
    )
    args = parser.parse_args()
    request = HTTPRequest.from_parts(
        method=args.request, url=args.url, headers=args.header, body=args.data
    )
    patch = UnencryptedHTTPPrivatePatch.from_parts(
        url_suffix=args.enc_url_suffix,
        headers=args.enc_header,
        body=args.enc_data,
        td_address=args.td_address,
    )

    client = SignerClient(args.oracle_url)
    public_key = client.public_key()

    action = HTTPAction(
        request=request,
        patch=patch.encrypt(encrypt_func=lambda x: encrypt(x, public_key)),
        filter=ByteString(args.filter.encode()),
        schema=ByteString(args.schema.encode()),
    )
    response = client.query(action)

    print("Oracle Response:")
    print("  Action ID:", response.message.action_id.hex())
    print("  Timestamp:", response.message.data.format_timestamp())
    print("  Error:    ", response.message.data.error)
    print("  Value:    ", response.message.data.format_value())

    print("Oracle Info:")
    print("  Public key:", public_key.to_compressed_bytes().hex())

    wallet = OraclePoolOwnerWallet.from_env(args.passphrase)
    context = get_chain_context()
    protocol = Protocol.load(args.plutus_blueprint)
    oracle_repo = OracleRepository(wallet=wallet, context=context, protocol=protocol)
    oracle = next(
        (
            o
            for o in oracle_repo.registered()
            if o.data.public_key == public_key
            if not args.oracle_pool_id or o.pools[0].id == args.oracle_pool_id
        ),
        None,
    )
    if not oracle:
        print("  Oracle is not registered on-chain")
        return

    print("  UTxO:", f"{oracle.input.transaction_id}#{oracle.input.index}")
    pool = oracle.pools[0]
    print("  Pool ID:", pool.id.hex())
    print("  Public key:", oracle.data.public_key.to_compressed_bytes().hex())
    print("  Resp. validity period:", oracle.data.response_validity_period)
    print("PoolAction ID:", pool.pool_action_id(response.message.action_id).hex())

    response_repo = ResponseRepository(
        wallet=wallet, context=context, protocol=protocol
    )

    handle_tx(
        signed_tx=response_repo.add_tx(response, oracle), context=context, args=args
    )


def encrypt(message: bytes, recipient_pub_key: keys.PublicKey) -> bytes:
    ephemeral_private_key = SigningKey.generate(curve=SECP256k1)
    ephemeral_public_key = ephemeral_private_key.get_verifying_key().to_string()

    # Calculate the shared secret point using ECDH
    recipient_vk = VerifyingKey.from_string(recipient_pub_key.to_bytes(), SECP256k1)
    shared_point = (
        recipient_vk.pubkey.point * ephemeral_private_key.privkey.secret_multiplier
    )
    shared_key = shared_point.to_bytes()

    # Derive the symmetric key using HKDF with SHA-256
    hkdf_input = b"\x04" + ephemeral_public_key + b"\x04" + shared_key
    symm_key = HKDF(hkdf_input, 32, salt=None, hashmod=SHA256)

    # Encrypt the message using AES-GCM
    nonce = os.urandom(16)
    cipher = AES.new(symm_key, AES.MODE_GCM, nonce=nonce)
    ciphertext, tag = cipher.encrypt_and_digest(message)

    return ephemeral_public_key + nonce + tag + ciphertext


if __name__ == "__main__":
    main()
