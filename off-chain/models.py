# SPDX-License-Identifier: Apache-2.0
# Copyright 2025 Quex Technologies
from base64 import b64decode
from collections.abc import Callable
from dataclasses import dataclass, fields
from hashlib import sha256
from time import gmtime, strftime
from types import UnionType
from typing import Any, ClassVar, List, Union, get_args, get_origin
from urllib.parse import parse_qsl, urlencode, urlparse

import eth_utils
from pycardano import (
    SCRIPT_HASH_SIZE,
    VERIFICATION_KEY_HASH_SIZE,
    IndefiniteList,
    PlutusData,
    Primitive,
    RawPlutusData,
)
from pycardano.serialization import ByteString, CBORTag

from utils import format_plutus_dict

HTTP_METHODS = {
    "GET": CBORTag(121, []),
    "POST": CBORTag(122, []),
    "PATCH": CBORTag(123, []),
    "DELETE": CBORTag(124, []),
    "OPTIONS": CBORTag(125, []),
    "TRACE": CBORTag(126, []),
}

CBOR_TAG_EXTENDED_CONSTR = 102

ANY_TD_ADDRESS = "0x0000000000000000000000000000000000000000"


class FixedPlutusData(PlutusData):
    def __post_init__(self) -> None:
        super().__post_init__()

        for f in fields(self):
            ann = f.type

            if not _is_indef_list(ann):
                continue

            value = getattr(self, f.name)

            if isinstance(value, list) and not isinstance(value, IndefiniteList) and value:
                setattr(self, f.name, IndefiniteList(value))


def _is_indef_list(tp: Any) -> bool:
    if tp is IndefiniteList:
        return True

    origin = get_origin(tp)

    if origin is IndefiniteList:
        return True

    if origin is Union or origin is UnionType:
        for arg in get_args(tp):
            if arg is IndefiniteList:
                return True
            if get_origin(arg) is IndefiniteList:
                return True

    return False


@dataclass
class RequestHeader(FixedPlutusData):
    CONSTR_ID: ClassVar[int] = 0
    key: ByteString
    value: ByteString

    @classmethod
    def from_str(cls, header: str):
        key, value = header.split(":", 1)
        return cls(
            key=ByteString(key.strip().encode()),
            value=ByteString(value.strip().encode()),
        )


@dataclass
class QueryParameter(FixedPlutusData):
    CONSTR_ID: ClassVar[int] = 0
    key: ByteString
    value: ByteString


@dataclass
class QueryParameterPatch(FixedPlutusData):
    CONSTR_ID: ClassVar[int] = 0
    key: ByteString
    ciphertext: ByteString


@dataclass
class RequestHeaderPatch(FixedPlutusData):
    CONSTR_ID: ClassVar[int] = 0
    key: ByteString
    ciphertext: ByteString


@dataclass
class HTTPPrivatePatch(FixedPlutusData):
    CONSTR_ID: ClassVar[int] = 0
    path_suffix: ByteString
    headers: IndefiniteList[RequestHeaderPatch] | List[RequestHeaderPatch]
    parameters: IndefiniteList[QueryParameterPatch] | List[QueryParameterPatch]
    body: ByteString
    td_address: ByteString


@dataclass
class UnencryptedHTTPPrivatePatch:
    path_suffix: bytes | None
    headers: list[RequestHeader]
    parameters: list[QueryParameter]
    body: bytes | None
    td_address: bytes

    @classmethod
    def from_parts(
        cls,
        url_suffix: str | None,
        headers: list[str],
        body: str | None,
        td_address: str,
    ):
        parsed_url_suffix = urlparse(url_suffix or "")
        parsed_headers = [RequestHeader.from_str(header) for header in (headers or [])]

        parameters = [
            QueryParameter(key=ByteString(k.encode()), value=ByteString(v.encode()))
            for k, v in parse_qsl(parsed_url_suffix.query)
        ]

        return cls(
            path_suffix=(parsed_url_suffix.path.encode() if parsed_url_suffix.path else None),
            headers=parsed_headers,
            parameters=parameters,
            body=body.encode() if body else None,
            td_address=td_address.encode(),
        )

    def encrypt(self, encrypt_func: Callable[[bytes | None], bytes]) -> HTTPPrivatePatch:
        headers = [
            RequestHeaderPatch(h.key, ByteString(encrypt_func(h.value.value))) for h in self.headers
        ]
        parameters = [
            QueryParameterPatch(p.key, ByteString(encrypt_func(p.value.value)))
            for p in self.parameters
        ]
        return HTTPPrivatePatch(
            path_suffix=ByteString(encrypt_func(self.path_suffix) if self.path_suffix else b""),
            headers=headers,
            parameters=parameters,
            body=ByteString(encrypt_func(self.body) if self.body else b""),
            td_address=ByteString(self.td_address),
        )

    def empty(self) -> bool:
        return not (self.path_suffix or self.headers or self.parameters or self.body)


@dataclass
class HTTPRequest(FixedPlutusData):
    CONSTR_ID: ClassVar[int] = 0
    method: RawPlutusData
    host: ByteString
    path: ByteString
    headers: IndefiniteList[RequestHeader] | List[RequestHeader]
    parameters: IndefiniteList[QueryParameter] | List[QueryParameter]
    body: ByteString

    @classmethod
    def from_parts(cls, method: str, url: str, headers: list[str], body: str | None):
        parsed_url = urlparse(url)
        host = parsed_url.hostname.encode() if parsed_url.hostname else b""
        path = parsed_url.path.encode() if parsed_url.path else b"/"

        parsed_headers = [RequestHeader.from_str(header) for header in (headers or [])]

        parameters = [
            QueryParameter(key=ByteString(k.encode()), value=ByteString(v.encode()))
            for k, v in parse_qsl(parsed_url.query)
        ]

        return cls(
            method=RawPlutusData.from_primitive(HTTP_METHODS[method]),
            host=ByteString(host),
            path=ByteString(path),
            headers=parsed_headers,
            parameters=parameters,
            body=ByteString(body.encode() if body else b""),
        )

    def format_url(self) -> str:
        base_url = f"https://{self.host.value.decode()}{self.path.value.decode()}"

        query_items = [
            (param.key.value.decode(), param.value.value.decode()) for param in self.parameters
        ]
        if not query_items:
            return base_url

        return f"{base_url}?{urlencode(query_items)}"


@dataclass
class HTTPAction(FixedPlutusData):
    CONSTR_ID: ClassVar[int] = 0
    request: HTTPRequest
    patch: HTTPPrivatePatch
    schema: ByteString
    filter: ByteString

    def action_id(self) -> bytes:
        return eth_utils.keccak(self.to_cbor())


@dataclass
class HTTPActionWithProof(FixedPlutusData):
    CONSTR_ID: ClassVar[int] = 0
    action: HTTPAction
    proof: ByteString


@dataclass
class FixedRawPlutusData(RawPlutusData):
    def to_primitive(self) -> Primitive:
        def _dfs(obj: object) -> Any:
            if isinstance(obj, list) and obj:
                return IndefiniteList([_dfs(item) for item in obj])
            if isinstance(obj, dict):
                return {_dfs(k): _dfs(v) for k, v in obj.items()}
            if isinstance(obj, CBORTag) and isinstance(obj.value, list) and obj.value:
                if obj.tag != CBOR_TAG_EXTENDED_CONSTR:
                    value = IndefiniteList([_dfs(item) for item in obj.value])
                else:
                    value = [_dfs(item) for item in obj.value]
                return CBORTag(tag=obj.tag, value=value)
            if isinstance(obj, bytes):
                return ByteString(obj)
            return obj

        return _dfs(self.data)


@dataclass
class DataItem(FixedPlutusData):
    CONSTR_ID: ClassVar[int] = 0
    timestamp: int
    error: int
    value: FixedRawPlutusData

    @staticmethod
    def parse(value: dict):
        return DataItem(
            timestamp=value["timestamp"],
            error=value["error"],
            value=FixedRawPlutusData.from_cbor(b64decode(value["value"])),
        )

    def format_timestamp(self) -> str:
        return format_unixtime_seconds(self.timestamp)

    def format_value(self) -> str:
        return format_plutus_dict(self.value.to_dict())


@dataclass
class QuexMessage(FixedPlutusData):
    CONSTR_ID: ClassVar[int] = 0
    action_id: bytes
    data: DataItem
    relayer: ByteString

    @staticmethod
    def parse(value: dict):
        return QuexMessage(
            action_id=b64decode(value["action_id"]),
            data=DataItem.parse(value["data_item"]),
            relayer=ByteString(bytes.fromhex(str(value["relayer"]).removeprefix("0x"))),
        )


def parse_eth_signature(value: dict) -> ByteString:
    r = b64decode(value["r"])
    s = b64decode(value["s"])
    return ByteString(r + s)


@dataclass
class QuexResponse(FixedPlutusData):
    CONSTR_ID: ClassVar[int] = 0
    message: QuexMessage
    signature: ByteString

    @staticmethod
    def parse(value: dict):
        return QuexResponse(
            message=QuexMessage.parse(value["msg"]),
            signature=parse_eth_signature(value["sig"]),
        )


@dataclass
class OracleRequest(FixedPlutusData):
    CONSTR_ID: ClassVar[int] = 0
    action: HTTPActionWithProof
    pool_id: ByteString
    pool_action_id: ByteString
    after: int
    before: int
    owner_pkh: ByteString
    reward: int
    coins_per_utxo_byte: int
    max_cost: int

    def is_valid(self) -> bool:
        if self.after < 0 or self.before < 0 or self.after >= self.before:
            return False
        if self.max_cost < 0:
            return False
        if len(self.pool_id.value) < SCRIPT_HASH_SIZE:
            return False

        td_address = self.action.action.patch.td_address.value
        if not td_address.isascii() or not eth_utils.is_hex_address(td_address.decode()):
            return False

        if len(self.owner_pkh.value) != VERIFICATION_KEY_HASH_SIZE:
            return False

        action_id = self.action.action.action_id()
        expected_pool_action_id = sha256(self.pool_id.value + action_id).digest()
        return self.pool_action_id == expected_pool_action_id

    def format_after(self) -> str:
        return format_unixtime_seconds(self.after)

    def format_before(self) -> str:
        return format_unixtime_seconds(self.before)


def format_unixtime_seconds(sec: int) -> str:
    return strftime("%Y-%m-%dT%H:%M:%SZ", gmtime(sec))
