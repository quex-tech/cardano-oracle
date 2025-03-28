#!/usr/bin/env python
import argparse
import json
import os
from time import time

from eth_account import Account
from eth_keys import keys

from plutus.abi import encoder
from signer.models import OracleResponse, OracleMessage, DataItem, b64dict
import paths


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("value", help="oracle response value as JSON")
    parser.add_argument("schema", help="solidity-like ABI schema")
    args = parser.parse_args()
    account = get_or_create_account()

    msg = OracleMessage(
        action_id="action".encode("ascii"),
        data_item=DataItem(
            timestamp=round(time()),
            error=0,
            value=encoder.encode([args.schema], [json.loads(args.value)]),
        ),
    )

    sig = msg.sign_with_account(account)

    response = OracleResponse(msg=msg, sig=sig)

    print(json.dumps(b64dict(response)))


def get_or_create_account():
    if os.path.exists(paths.ORACLE_PRIVATE_KEY):
        with open(paths.ORACLE_PRIVATE_KEY, "rb") as f:
            account = Account.from_key(f.read())
    else:
        account = Account.create()
        with open(paths.ORACLE_PRIVATE_KEY, "wb") as f:
            f.write(bytes(account.key))

    with open(paths.ORACLE_PUBLIC_KEY, "wb") as f:
        f.write(keys.PrivateKey(bytes(account.key)
                                ).public_key.to_compressed_bytes())
    return account


if __name__ == '__main__':
    main()
