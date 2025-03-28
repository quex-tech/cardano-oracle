from dataclasses import dataclass

from pycardano.serialization import ByteString, CBORTag, IndefiniteList
from pycardano.plutus import PlutusData, RawPlutusData, get_tag

from signer.models import (
    HTTPAction,
    HTTPPrivatePatch,
    HTTPRequest,
    RequestHeader,
    QueryParameter,
    QueryParameterPatch,
    RequestHeaderPatch
)


@dataclass
class PlutusRequestHeader(PlutusData):
    CONSTR_ID = 0
    key: ByteString
    value: ByteString

    @classmethod
    def from_vanilla(cls, header: RequestHeader):
        return cls(
            key=ByteString(header.key.encode()),
            value=ByteString(header.value.encode())
        )


@dataclass
class PlutusQueryParameter(PlutusData):
    CONSTR_ID = 0
    key: ByteString
    value: ByteString

    @classmethod
    def from_vanilla(cls, parameter: QueryParameter):
        return cls(
            key=ByteString(parameter.key.encode()),
            value=ByteString(parameter.value.encode())
        )


@dataclass
class PlutusQueryParameterPatch(PlutusData):
    CONSTR_ID = 0
    key: ByteString
    ciphertext: ByteString

    @classmethod
    def from_vanilla(cls, parameter: QueryParameterPatch):
        return cls(
            key=ByteString(parameter.key.encode()),
            ciphertext=ByteString(parameter.ciphertext)
        )


@dataclass
class PlutusRequestHeaderPatch(PlutusData):
    CONSTR_ID = 0
    key: ByteString
    ciphertext: ByteString

    @classmethod
    def from_vanilla(cls, header: RequestHeaderPatch):
        return cls(
            key=ByteString(header.key.encode()),
            ciphertext=ByteString(header.ciphertext)
        )


@dataclass
class PlutusHTTPPrivatePatch(PlutusData):
    CONSTR_ID = 0
    path_suffix: ByteString
    headers: IndefiniteList[PlutusRequestHeaderPatch]
    parameters: IndefiniteList[PlutusQueryParameterPatch]
    body: ByteString
    td_address: ByteString

    @classmethod
    def from_vanilla(cls, patch: HTTPPrivatePatch):
        return cls(
            path_suffix=ByteString(patch.path_suffix),
            headers=IndefiniteList(
                map(PlutusRequestHeaderPatch.from_vanilla, patch.headers)),
            parameters=IndefiniteList(
                map(PlutusQueryParameterPatch.from_vanilla, patch.parameters)),
            body=ByteString(patch.body),
            td_address=ByteString(patch.td_address.encode()),
        )


@dataclass
class PlutusHTTPRequest(PlutusData):
    CONSTR_ID = 0
    method: RawPlutusData
    host: ByteString
    path: ByteString
    headers: IndefiniteList[PlutusRequestHeader]
    parameters: IndefiniteList[PlutusQueryParameter]
    body: ByteString

    @classmethod
    def from_vanilla(cls, request: HTTPRequest):
        return cls(
            method=RawPlutusData.from_primitive(
                CBORTag(get_tag(request.method.value), [])),
            host=ByteString(request.host.encode()),
            path=ByteString(request.path.encode()),
            headers=IndefiniteList(
                map(PlutusRequestHeader.from_vanilla, request.headers)),
            parameters=IndefiniteList(
                map(PlutusQueryParameter.from_vanilla, request.parameters)),
            body=ByteString(request.body),
        )


@dataclass
class PlutusHTTPAction(PlutusData):
    CONSTR_ID = 0
    request: PlutusHTTPRequest
    patch: PlutusHTTPPrivatePatch
    schema: ByteString
    filter: ByteString

    @classmethod
    def from_vanilla(cls, action: HTTPAction):
        return cls(
            request=PlutusHTTPRequest.from_vanilla(action.request),
            patch=PlutusHTTPPrivatePatch.from_vanilla(action.patch),
            schema=ByteString(action.schema.encode()),
            filter=ByteString(action.filter.encode()),
        )
