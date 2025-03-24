#!/usr/bin/env python
from base64 import b64encode
from dataclasses import dataclass, asdict
import json
import os
from time import time

from eth_account import Account
from eth_account.messages import encode_defunct
from eth_keys import keys
from eth_utils import keccak

from pycardano.serialization import CBORSerializable, RawCBOR
from pycardano.plutus import PlutusData, RawPlutusData

import paths


def main():
    account = get_or_create_account()

    msg = OracleMessage(
        data_item=DataItem(
            timestamp=round(time()),
            error=0,
            value=RawPlutusData.from_primitive(123),
        ),
        action_id="action".encode("ascii")
    )

    sig = msg.sign_with_account(account)

    msg.data_item.value = msg.data_item.value.to_cbor()

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
class DataItem(PlutusData):
    CONSTR_ID = 0
    timestamp: int
    error: int
    value: RawPlutusData


@dataclass
class OracleMessage(PlutusData):
    CONSTR_ID = 0
    action_id: bytes
    data_item: DataItem

    def sign_with_account(self, account: Account):
        msg = self.to_cbor()
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
