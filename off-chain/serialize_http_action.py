#!/usr/bin/env python
from base64 import b64decode
from signer.models import (
    HTTPAction,
    HTTPPrivatePatch,
    HTTPRequest,
    RequestHeader,
    RequestMethod,
    QueryParameter,
    QueryParameterPatch,
    RequestHeaderPatch
)
from plutus_models import PlutusHTTPAction


action = HTTPAction(
    request=HTTPRequest(
        method=RequestMethod.OPTIONS,
        host="pro-api.coinmarketcap.com",
        path="/v2/cryptocurrency/quotes/latest",
        headers=[
            RequestHeader(key="Accept", value="application/json")
        ],
        parameters=[
            QueryParameter(key="id", value="1")
        ],
        body=b64decode("AAECAw==")),
    patch=HTTPPrivatePatch(
        path_suffix=b64decode("AQIBAgECAQIBAgEC"),
        headers=[
            RequestHeaderPatch(key="X-CMC_PRO_API_KEY",
                                   ciphertext=b64decode("ABEiM0Q=")),
        ],
        parameters=[
            QueryParameterPatch(key="param_patch",
                                ciphertext=b64decode("/+7dzLuq")),
            QueryParameterPatch(key="param_patch2",
                                ciphertext=b64decode("CgsMDQ4P")),
        ],
        body=b64decode("qrur/wAAAA=="),
        td_address="td_address"
    ),
    schema="(int256,int256)",
    filter="data.\"1\".quote.USD.price*1000000|round"
)

bb = PlutusHTTPAction.from_vanilla(action).to_cbor()
action2 = HTTPAction.from_plutus_bytes(
    (HTTPAction.from_plutus_bytes(bb)).to_plutus_bytes())

print(action == action2)
