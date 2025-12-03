from argparse import ArgumentParser, Namespace
import os
from typing import List, Optional

from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto.Protocol.KDF import HKDF
from ecdsa import SECP256k1, SigningKey, VerifyingKey
from eth_keys import keys
from pycardano.serialization import ByteString

from models import (
    HTTPAction,
    HTTPActionWithProof,
    HTTPRequest,
    UnencryptedHTTPPrivatePatch,
)

http_action_arg_parser = ArgumentParser(add_help=False)
http_action_arg_parser.add_argument(
    "-X",
    "--request",
    help="HTTP method",
    choices=["GET", "POST", "PATCH", "DELETE", "OPTIONS", "TRACE"],
    default="GET",
)
http_action_arg_parser.add_argument(
    "--enc-url-suffix",
    help=(
        "URL suffix to append and send encrypted. "
        "Examples: /mysecretpath, ?secret1=123&secret2=321, /mypath?secret=321"
    ),
)
http_action_arg_parser.add_argument(
    "-H",
    "--header",
    action="append",
    help='add an HTTP header. Example: --header "Content-Type: application/json"',
)
http_action_arg_parser.add_argument(
    "--enc-header",
    action="append",
    help='add an HTTP header to send encrypted. Example: --enc-header "Api-Key: abcdef123"',
)
http_action_arg_parser.add_argument("-d", "--data", help="HTTP body as plaintext")
http_action_arg_parser.add_argument(
    "--enc-data", help="HTTP body as plaintext to send encrypted. Overrides --data"
)
http_action_arg_parser.add_argument(
    "--td-address", default="0x0000000000000000000000000000000000000000"
)
http_action_arg_parser.add_argument(
    "-f",
    "--filter",
    default=".",
    help="jq filter to transfort response body. Default: .",
)
http_action_arg_parser.add_argument("url", help="URL to fetch")
http_action_arg_parser.add_argument(
    "schema", help="Schema to encode response body, example: (string,(int,bool[]))"
)


def parse_http_action_with_proof(
    args: Namespace, td_vk: Optional[VerifyingKey]
) -> HTTPActionWithProof:
    return create_http_action_with_proof(
        args.request,
        args.url,
        args.header,
        args.data,
        args.enc_url_suffix,
        args.enc_header,
        args.enc_data,
        td_vk,
        args.filter,
        args.schema,
    )


def create_http_action_with_proof(
    method: str,
    url: str,
    headers: List[str],
    body: Optional[str],
    enc_url_suffix: Optional[str],
    enc_headers: List[str],
    enc_body: Optional[str],
    td_vk: Optional[VerifyingKey],
    filter_: str,
    schema: str,
):
    request = HTTPRequest.from_parts(method=method, url=url, headers=headers, body=body)

    patch = UnencryptedHTTPPrivatePatch.from_parts(
        url_suffix=enc_url_suffix,
        headers=enc_headers,
        body=enc_body,
        td_address=(
            str(keys.PublicKey(td_vk.to_string()).to_checksum_address())
            if td_vk
            else "0x0000000000000000000000000000000000000000"
        ),
    )

    if not patch.empty() and not td_vk:
        raise Exception("Oracle public key is required")

    ephemeral_priv_key = SigningKey.generate(curve=SECP256k1)

    action = HTTPAction(
        request=request,
        patch=patch.encrypt(
            encrypt_func=lambda x: encrypt(x, td_vk, ephemeral_priv_key)
        ),
        filter=ByteString(filter_.encode()),
        schema=ByteString(schema.encode()),
    )

    proof = (
        encrypt(
            action.action_id(),
            td_vk,
            ephemeral_priv_key,
            include_ephemeral_public_key=True,
        )
        if td_vk and not patch.empty()
        else bytes()
    )

    return HTTPActionWithProof(
        action=action,
        proof=ByteString(proof),
    )


def encrypt(
    message: bytes,
    recipient_pub_key: VerifyingKey,
    priv_key: SigningKey,
    include_ephemeral_public_key=False,
) -> bytes:
    pub_key = priv_key.get_verifying_key()

    # Calculate the shared secret point using ECDH
    shared_point = recipient_pub_key.pubkey.point * priv_key.privkey.secret_multiplier
    shared_key = shared_point.to_bytes()

    # Derive the symmetric key using HKDF with SHA-256
    hkdf_input = b"\x04" + pub_key.to_string() + b"\x04" + shared_key
    symm_key = HKDF(hkdf_input, 32, salt=None, hashmod=SHA256)

    # Encrypt the message using AES-GCM
    nonce = os.urandom(16)
    cipher = AES.new(symm_key, AES.MODE_GCM, nonce=nonce)
    ciphertext, tag = cipher.encrypt_and_digest(message)

    if include_ephemeral_public_key:
        return pub_key.to_string() + nonce + tag + ciphertext

    return nonce + tag + ciphertext
