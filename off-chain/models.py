# SPDX-License-Identifier: Apache-2.0
# Copyright 2025 Quex Technologies
from base64 import b64decode
from dataclasses import dataclass
from time import gmtime, strftime
from typing import List, Optional
from urllib.parse import urlparse, parse_qsl

from eth_utils import keccak
from pycardano.serialization import ByteString, CBORTag, IndefiniteList
from pycardano.plutus import PlutusData, RawPlutusData

from utils import format_plutus_dict

HTTP_METHODS = {
    "GET": CBORTag(121, []),
    "POST": CBORTag(122, []),
    "PATCH": CBORTag(123, []),
    "DELETE": CBORTag(124, []),
    "OPTIONS": CBORTag(125, []),
    "TRACE": CBORTag(126, []),
}


@dataclass
class RequestHeader(PlutusData):
    CONSTR_ID = 0
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
class QueryParameter(PlutusData):
    CONSTR_ID = 0
    key: ByteString
    value: ByteString


@dataclass
class QueryParameterPatch(PlutusData):
    CONSTR_ID = 0
    key: ByteString
    ciphertext: ByteString


@dataclass
class RequestHeaderPatch(PlutusData):
    CONSTR_ID = 0
    key: ByteString
    ciphertext: ByteString


@dataclass
class UnencryptedHTTPPrivatePatch:
    path_suffix: Optional[bytes]
    headers: List[RequestHeader]
    parameters: List[QueryParameter]
    body: Optional[bytes]
    td_address: bytes

    @classmethod
    def from_parts(
        cls,
        url_suffix: Optional[str],
        headers: List[str],
        body: Optional[str],
        td_address: str,
    ):
        parsed_url_suffix = urlparse(url_suffix)
        parsed_headers = [RequestHeader.from_str(header) for header in (headers or [])]

        parameters = [
            QueryParameter(key=ByteString(k.encode()), value=ByteString(v.encode()))
            for k, v in parse_qsl(parsed_url_suffix.query)
        ]

        return cls(
            path_suffix=(
                parsed_url_suffix.path.encode() if parsed_url_suffix.path else None
            ),
            headers=parsed_headers,
            parameters=parameters,
            body=body.encode() if body else None,
            td_address=td_address.encode(),
        )

    def encrypt(self, encrypt_func):
        headers = [
            RequestHeaderPatch(h.key, ByteString(encrypt_func(h.value.value)))
            for h in self.headers
        ]
        parameters = [
            QueryParameterPatch(p.key, ByteString(encrypt_func(p.value.value)))
            for p in self.parameters
        ]
        return HTTPPrivatePatch(
            path_suffix=ByteString(
                encrypt_func(self.path_suffix) if self.path_suffix else b""
            ),
            headers=_to_plutus_list(headers),
            parameters=_to_plutus_list(parameters),
            body=ByteString(encrypt_func(self.body) if self.body else b""),
            td_address=ByteString(self.td_address),
        )


@dataclass
class HTTPPrivatePatch(PlutusData):
    CONSTR_ID = 0
    path_suffix: ByteString
    headers: IndefiniteList[RequestHeaderPatch] | List[RequestHeaderPatch]
    parameters: IndefiniteList[QueryParameterPatch] | List[QueryParameterPatch]
    body: ByteString
    td_address: ByteString


@dataclass
class HTTPRequest(PlutusData):
    CONSTR_ID = 0
    method: RawPlutusData
    host: ByteString
    path: ByteString
    headers: IndefiniteList[RequestHeader] | List[RequestHeader]
    parameters: IndefiniteList[QueryParameter] | List[QueryParameter]
    body: ByteString

    @classmethod
    def from_parts(cls, method: str, url: str, headers: List[str], body: Optional[str]):
        parsed_url = urlparse(url)
        host = parsed_url.hostname.encode()
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
            headers=_to_plutus_list(parsed_headers),
            parameters=_to_plutus_list(parameters),
            body=ByteString(body.encode() if body else b""),
        )


def _to_plutus_list(items):
    return IndefiniteList(items) if items else []


@dataclass
class HTTPAction(PlutusData):
    CONSTR_ID = 0
    request: HTTPRequest
    patch: HTTPPrivatePatch
    schema: ByteString
    filter: ByteString

    def action_id(self) -> bytes:
        return keccak(self.to_cbor())


@dataclass
class HTTPActionWithProof(PlutusData):
    CONSTR_ID = 0
    action: HTTPAction
    proof: ByteString


@dataclass
class DataItem(PlutusData):
    CONSTR_ID = 0
    timestamp: int
    error: int
    value: RawPlutusData

    @staticmethod
    def parse(value: dict):
        return DataItem(
            timestamp=value["timestamp"],
            error=value["error"],
            value=RawPlutusData.from_cbor(b64decode(value["value"])),
        )

    def format_timestamp(self):
        return strftime("%Y-%m-%dT%H:%M:%SZ", gmtime(self.timestamp))

    def format_value(self):
        return format_plutus_dict(self.value.to_dict())


@dataclass
class QuexMessage(PlutusData):
    CONSTR_ID = 0
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
class QuexResponse(PlutusData):
    CONSTR_ID = 0
    message: QuexMessage
    signature: ByteString

    @staticmethod
    def parse(value: dict):
        return QuexResponse(
            message=QuexMessage.parse(value["msg"]),
            signature=parse_eth_signature(value["sig"]),
        )
