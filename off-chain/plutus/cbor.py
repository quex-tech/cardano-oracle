from typing import Any, List
from dataclasses import dataclass
from abc import ABC, abstractmethod
from cbor2 import CBOREncoder, dumps as cbor2_dumps

CBOR_CONSTR0 = b"\xd8\x79"
CBOR_BYTES_INDEF = b"\x5f"
CBOR_ARRAY_INDEF = b"\x9f"
CBOR_BREAK = b"\xff"
BYTES_MAX_CHUNK_SIZE = 64


def dumps(value: Any) -> bytes:
    return cbor2_dumps(value, default=_encode_primitive)


class PlutusPrimitive(ABC):
    @abstractmethod
    def encode(self, encoder: CBOREncoder) -> None:
        pass


@dataclass
class PlutusRawData(PlutusPrimitive):
    data: bytes

    def encode(self, encoder: CBOREncoder) -> None:
        encoder.write(self.data)


@dataclass
class PlutusByteString(PlutusPrimitive):
    value: bytes

    def encode(self, encoder: CBOREncoder) -> None:
        if len(self.value) > BYTES_MAX_CHUNK_SIZE:
            encoder.write(CBOR_BYTES_INDEF)
            for i in range(0, len(self.value), BYTES_MAX_CHUNK_SIZE):
                chunk = self.value[i:i+BYTES_MAX_CHUNK_SIZE]
                encoder.encode(chunk)
            encoder.write(CBOR_BREAK)
        else:
            encoder.encode(self.value)


@dataclass
class PlutusList(PlutusPrimitive):
    items: List[Any]

    def encode(self, encoder: CBOREncoder) -> None:
        _write_indef_list(self.items, encoder)


@dataclass
class PlutusTuple(PlutusPrimitive):
    items: List[Any]

    def encode(self, encoder: CBOREncoder) -> None:
        encoder.write(CBOR_CONSTR0)
        _write_indef_list(self.items, encoder)


def _write_indef_list(items: List[Any], encoder: CBOREncoder) -> None:
    if items:
        encoder.write(CBOR_ARRAY_INDEF)
        for item in items:
            encoder.encode(item)
        encoder.write(CBOR_BREAK)
    else:
        encoder.encode([])


def _encode_primitive(encoder: CBOREncoder, value: Any) -> None:
    if not isinstance(value, PlutusPrimitive):
        raise TypeError(
            f"Expected PlutusPrimitive, got {type(value)} instead.")
    value.encode(encoder)
