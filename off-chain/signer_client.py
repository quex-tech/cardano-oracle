from base64 import b64encode
from dataclasses import dataclass
from urllib.parse import urljoin
import requests
from eth_keys import keys
from models import HTTPActionWithProof, QuexResponse

TIMEOUT = 30


@dataclass
class SignerClient:
    url: str

    def query(self, action: HTTPActionWithProof, relayer: bytes) -> QuexResponse:
        response = requests.post(
            urljoin(self.url, "query"),
            json={"action": b64encode(action.to_cbor()).decode(), "relayer": relayer.hex()},
            timeout=TIMEOUT,
        )
        response.raise_for_status()
        return QuexResponse.parse(response.json())

    def public_key(self) -> keys.PublicKey:
        response = requests.get(urljoin(self.url, "/pubkey"), timeout=TIMEOUT)
        response.raise_for_status()
        return keys.PublicKey(bytes.fromhex(response.text.replace("0x", "")))
