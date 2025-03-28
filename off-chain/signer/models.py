from base64 import b64encode, b64decode
from dataclasses import dataclass, asdict, fields
from enum import IntEnum
from typing import List
from urllib.parse import urljoin

from eth_account import Account
from eth_utils import keccak
import eth_abi

from plutus.cbor import PlutusRawData, PlutusTuple
from plutus.mixins import PlutusEncodable, PlutusDecodable


def b64dict(obj):
    return asdict(obj,
                  dict_factory=lambda fields: {
                      key: (b64encode(value).decode() if type(
                          value) == bytes else value)
                      for (key, value) in fields
                  }
                  )


def from_nested_tuple(t, class_constructor):
    if '_name' in dir(class_constructor) and class_constructor._name == 'List':
        return [from_nested_tuple(x, class_constructor.__args__[0]) for x in t]
    elif type(t) == tuple:
        return class_constructor(*(
            from_nested_tuple(x, y.type)
            for x, y in zip(t, fields(class_constructor))))
    else:
        return class_constructor(t)


class RequestMethod(IntEnum):
    GET = 0
    POST = 1
    PUT = 2
    PATCH = 3
    DELETE = 4
    OPTIONS = 5
    TRACE = 6


@dataclass
class RequestHeader(PlutusEncodable, PlutusDecodable):
    key: str
    value: str

    @staticmethod
    def obj_schema() -> str:
        return '(string,string)'


# QueryParameter structure
@dataclass
class QueryParameter(PlutusEncodable, PlutusDecodable):
    key: str
    value: str

    @staticmethod
    def obj_schema() -> str:
        return '(string,string)'


# QueryParameterPatch structure (encrypted value in base64)
@dataclass
class QueryParameterPatch(PlutusEncodable, PlutusDecodable):
    key: str
    ciphertext: bytes  # Encrypted value

    @staticmethod
    def obj_schema() -> str:
        return "(string,bytes)"


# RequestHeaderPatch structure (encrypted value in base64)
@dataclass
class RequestHeaderPatch(PlutusEncodable, PlutusDecodable):
    key: str
    ciphertext: bytes  # Encrypted value

    @staticmethod
    def obj_schema() -> str:
        return "(string,bytes)"


# HTTPPrivatePatch structure
@dataclass
class HTTPPrivatePatch(PlutusEncodable, PlutusDecodable):
    path_suffix: bytes
    headers: List[RequestHeaderPatch]
    parameters: List[QueryParameterPatch]
    body: bytes
    td_address: str

    @staticmethod
    def obj_schema() -> str:
        return f"(bytes,{RequestHeaderPatch.obj_schema()}[],{QueryParameterPatch.obj_schema()}[],bytes,address)"


# HTTPRequest structure
@dataclass
class HTTPRequest(PlutusEncodable, PlutusDecodable):
    method: RequestMethod
    host: str
    path: str
    headers: List[RequestHeader]
    parameters: List[QueryParameter]
    body: bytes

    @staticmethod
    def obj_schema() -> str:
        return f'(uint8,string,string,{RequestHeader.obj_schema()}[],{QueryParameter.obj_schema()}[],bytes)'

    def build_url(self) -> str:
        # Ensure that the host starts with the correct protocol
        protocol = "https://"
        host = f"{protocol}{self.host}"

        # Use urljoin to properly concatenate host and path
        return urljoin(host, self.path)

    def get_parameters(self):
        params = {}
        for p in self.parameters:
            params[p.key] = p.value
        return params

    def get_headers(self):
        headers = {}
        for p in self.headers:
            headers[p.key] = p.value
        return headers

    def get_body(self):
        return self.body


@dataclass
class HTTPAction(PlutusEncodable, PlutusDecodable):
    request: HTTPRequest
    patch: HTTPPrivatePatch
    schema: str  # ResultSchema as a string for now
    filter: str  # JqFilter as a string for now

    @staticmethod
    def parse_eth_b64(data: str):
        data_bytes = b64decode(data)
        data_tuple, = eth_abi.decode([HTTPAction.obj_schema()], data_bytes)
        return from_nested_tuple(data_tuple, HTTPAction)

    @staticmethod
    def parse_plutus_b64(data: str):
        data_bytes = b64decode(data)
        return HTTPAction.from_plutus_bytes(data_bytes)

    @staticmethod
    def obj_schema() -> str:
        return f"({HTTPRequest.obj_schema()},{HTTPPrivatePatch.obj_schema()},string,string)"

    # def action_id(self) -> bytes:
        # return keccak(self.bytes())

    def action_id_plutus(self) -> bytes:
        return keccak(self.to_plutus_bytes())


@dataclass
class ETHSignature:
    r: bytes
    s: bytes
    v: int

    @staticmethod
    def fromETH(sig):
        return ETHSignature(
            r=sig.r.to_bytes(32, 'big'),
            s=sig.s.to_bytes(32, 'big'),
            v=sig.v
        )


@dataclass
class DataItem(PlutusEncodable):
    timestamp: int
    error: int
    value: bytes

    def to_plutus(self):
        return PlutusTuple([self.timestamp, self.error, PlutusRawData(self.value)])


@dataclass
class OracleMessage(PlutusEncodable):
    action_id: bytes
    data_item: DataItem

    def sign_with_account(self, account: Account):
        msg = self.to_plutus_bytes()
        msghash = keccak(msg)
        return ETHSignature.fromETH(account.unsafe_sign_hash(msghash))


@dataclass
class OracleResponse:
    msg: OracleMessage
    sig: ETHSignature
