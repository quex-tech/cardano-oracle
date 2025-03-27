#!/usr/bin/env python
import argparse
from base64 import b64encode
from dataclasses import dataclass, asdict
import json
import os
from time import time

from eth_account import Account
from eth_account.messages import encode_defunct
from eth_keys import keys
from eth_utils import keccak

from plutus_encoding import PlutusRawData, PlutusTuple, encode_by_schema, encode_primitive
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
            value=encode_by_schema(json.loads(args.value), args.schema),
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


@dataclass
class ETHSignature:
    r: bytes
    s: bytes
    v: int

    def fromETH(sig):
        return ETHSignature(
            r=sig.r.to_bytes(32, 'big'),
            s=sig.s.to_bytes(32, 'big'),
            v=sig.v
        )


@dataclass
class DataItem():
    timestamp: int
    error: int
    value: bytes

    def to_primitive(self):
        return PlutusTuple(self.timestamp, self.error, PlutusRawData(self.value))


@dataclass
class OracleMessage():
    action_id: bytes
    data_item: DataItem

    def to_primitive(self):
        return PlutusTuple(self.action_id, self.data_item.to_primitive())

    def sign_with_account(self, account: Account):
        msg = encode_primitive(self.to_primitive())
        msghash = keccak(msg)
        return ETHSignature.fromETH(account.unsafe_sign_hash(msghash))


@dataclass
class OracleResponse:
    msg: OracleMessage
    sig: ETHSignature


def b64dict(obj):
    return asdict(obj,
                  dict_factory=lambda fields: {
                      key: (b64encode(value).decode() if type(
                          value) == bytes else value)
                      for (key, value) in fields
                  }
                  )


if __name__ == '__main__':
    main()
