from abc import ABC
from dataclasses import fields
from enum import IntEnum
from typing import get_origin, get_args
from cbor2 import CBORTag, loads as cbor2_loads
from plutus.cbor import (
    PlutusTuple,
    PlutusList,
    PlutusByteString,
    dumps as plutus_dumps,
    get_tag,
    get_constr_idx
)


class PlutusEncodable(ABC):
    def to_plutus(self):
        encoded_fields = [to_plutus(getattr(self, f.name))
                          for f in fields(self)]
        return PlutusTuple(encoded_fields)

    def to_plutus_bytes(self) -> bytes:
        return plutus_dumps(self.to_plutus())


class PlutusDecodable(ABC):
    @classmethod
    def from_plutus(cls, tag: CBORTag):
        values = tag.value
        cls_fields = fields(cls)
        if len(values) != len(cls_fields):
            raise ValueError(
                f"Expected {len(cls_fields)} constructor fields")

        kwargs = {}
        for f, value in zip(cls_fields, values):
            kwargs[f.name] = from_plutus(value, f.type)
        return cls(**kwargs)

    @classmethod
    def from_plutus_bytes(cls, b):
        return cls.from_plutus(cbor2_loads(b))


def to_plutus(value):
    if isinstance(value, PlutusEncodable):
        return value.to_plutus()
    if isinstance(value, bytes):
        return PlutusByteString(value)
    if isinstance(value, str):
        return PlutusByteString(value.encode())
    if isinstance(value, list):
        return PlutusList([to_plutus(v) for v in value])
    if isinstance(value, IntEnum):
        return CBORTag(get_tag(value.value), [])
    return value


def from_plutus(value, target_type):
    if target_type is bytes:
        return value
    if target_type is str:
        return value.decode()
    if isinstance(target_type, type) and issubclass(target_type, PlutusDecodable):
        return target_type.from_plutus(value)
    if isinstance(target_type, type) and issubclass(target_type, IntEnum):
        return target_type(get_constr_idx(value))
    if get_origin(target_type) is list:
        inner_type = get_args(target_type)[0]
        return [from_plutus(v, inner_type) for v in value]
    return value
