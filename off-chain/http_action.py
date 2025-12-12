# SPDX-License-Identifier: Apache-2.0
# Copyright 2025 Quex Technologies
import os
from argparse import ArgumentParser, Namespace

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from ecdsa import SECP256k1, SigningKey, VerifyingKey
from eth_keys import keys
from pycardano.serialization import ByteString

from models import (
    ANY_TD_ADDRESS,
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
    args: Namespace, td_vk: VerifyingKey | None
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


class MissingOracleKeyError(ValueError):
    pass


def create_http_action_with_proof(
    method: str,
    url: str,
    headers: list[str],
    body: str | None,
    enc_url_suffix: str | None,
    enc_headers: list[str],
    enc_body: str | None,
    td_vk: VerifyingKey | None,
    filter_: str,
    schema: str,
) -> HTTPActionWithProof:
    request = HTTPRequest.from_parts(method=method, url=url, headers=headers, body=body)

    patch = UnencryptedHTTPPrivatePatch.from_parts(
        url_suffix=enc_url_suffix,
        headers=enc_headers,
        body=enc_body,
        td_address=(
            str(keys.PublicKey(td_vk.to_string()).to_checksum_address())
            if td_vk
            else ANY_TD_ADDRESS
        ),
    )

    if not patch.empty() and not td_vk:
        raise MissingOracleKeyError

    ephemeral_priv_key = SigningKey.generate(curve=SECP256k1)

    encrypt_func = (lambda x: encrypt(x, td_vk, ephemeral_priv_key)) if td_vk else cannot_encrypt

    action = HTTPAction(
        request=request,
        patch=patch.encrypt(encrypt_func=encrypt_func),
        filter=ByteString(filter_.encode()),
        schema=ByteString(schema.encode()),
    )

    proof = (
        ephemeral_priv_key.get_verifying_key().to_string()
        + encrypt(
            action.action_id(),
            td_vk,
            ephemeral_priv_key,
        )
        if td_vk and not patch.empty()
        else b""
    )

    return HTTPActionWithProof(
        action=action,
        proof=ByteString(proof),
    )


def encrypt(
    message: bytes,
    recipient_pub_key: VerifyingKey,
    priv_key: SigningKey,
) -> bytes:
    pub_key = priv_key.get_verifying_key()

    # Calculate the shared secret point using ECDH
    shared_point = recipient_pub_key.pubkey.point * priv_key.privkey.secret_multiplier  # type: ignore
    shared_key = shared_point.to_bytes()

    # Derive the symmetric key using HKDF with SHA-256
    hkdf_input = b"\x04" + pub_key.to_string() + b"\x04" + shared_key
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b"",
    )
    symm_key = hkdf.derive(hkdf_input)

    # Encrypt the message using AES-GCM
    nonce = os.urandom(16)
    cipher = Cipher(algorithms.AES(symm_key), modes.GCM(nonce))
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(message) + encryptor.finalize()
    tag = encryptor.tag

    return nonce + tag + ciphertext


def cannot_encrypt(_: bytes) -> bytes:
    raise MissingOracleKeyError
