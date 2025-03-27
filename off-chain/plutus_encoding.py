from dataclasses import dataclass
import cbor2
from eth_abi.base import parse_type_str, parse_tuple_type_str
from eth_abi.encoding import BaseEncoder
from eth_abi.codec import ABIEncoder
from eth_abi.registry import ABIRegistry, is_base_tuple, has_arrlist, BaseEquals


def encode_by_schema(value, schema):
    return _encoder.encode([schema], [value])


def encode_primitive(value):
    return cbor2.dumps(value, default=_encode_custom)


class _PlutusPrimitive:
    def encode(self, encoder: cbor2.CBOREncoder):
        raise NotImplementedError


@dataclass
class PlutusByteString(_PlutusPrimitive):
    value: bytes

    def encode(self, encoder: cbor2.CBOREncoder):
        if len(self.value) > 64:
            encoder.write(b"\x5f")
            for i in range(0, len(self.value), 64):
                imax = min(i + 64, len(self.value))
                encoder.encode(self.value[i:imax])
            encoder.write(b"\xff")
        else:
            encoder.encode(self.value)


@dataclass
class PlutusRawData(_PlutusPrimitive):
    data: bytes

    def encode(self, encoder: cbor2.CBOREncoder):
        encoder.write(self.data)


@dataclass
class PlutusList(_PlutusPrimitive):
    items: list

    def encode(self, encoder: cbor2.CBOREncoder):
        _write_plutus_list(self.items, encoder)


class PlutusTuple(_PlutusPrimitive):
    def __init__(self, *args):
        self.items = args

    def encode(self, encoder: cbor2.CBOREncoder):
        encoder.write(b"\xd8\x79")  # tag 121
        _write_plutus_list(self.items, encoder)


def _write_plutus_list(items, encoder: cbor2.CBOREncoder):
    if len(items) > 0:
        encoder.write(b"\x9f")
        for item in items:
            encoder.encode(item)
        encoder.write(b"\xff")
    else:
        encoder.encode([])


def _encode_custom(encoder: cbor2.CBOREncoder, value):
    assert isinstance(value, _PlutusPrimitive), (
        f"Type of input value is not _PlutusEncodable, " f"got {type(value)} instead.")
    value.encode(encoder)


class _PlutusBaseEncoder(BaseEncoder):
    def encode(self, value) -> bytes:
        self.validate_value(value)
        return encode_primitive(self.to_primitive(value))

    def to_primitive(self, value):
        raise NotImplementedError

    def validate_value(self, value) -> None:
        raise NotImplementedError


class _IntegerEncoder(_PlutusBaseEncoder):
    def validate_value(self, value) -> None:
        if not isinstance(value, int):
            type(self).invalidate_value(value, msg="Expected an integer.")

    def to_primitive(self, value):
        return value

    @parse_type_str("int")
    def from_type_str(cls, type_obj, registry):
        return cls()

class _UnsignedIntegerEncoder(_PlutusBaseEncoder):
    def validate_value(self, value) -> None:
        if not isinstance(value, int):
            type(self).invalidate_value(value, msg="Expected an integer.")
        if value < 0:
            type(self).invalidate_value(value, msg="Expected a non-negative integer.")

    def to_primitive(self, value):
        return value

    @parse_type_str("uint")
    def from_type_str(cls, type_obj, registry):
        return cls()


class _BoolEncoder(_PlutusBaseEncoder):
    def validate_value(self, value) -> None:
        if not isinstance(value, bool):
            type(self).invalidate_value(value, msg="Expected a boolean.")

    def to_primitive(self, value):
        return cbor2.CBORTag(122 if value else 121, [])

    @parse_type_str("bool")
    def from_type_str(cls, type_obj, registry):
        return cls()


class _StringEncoder(_PlutusBaseEncoder):
    def validate_value(self, value) -> None:
        if not isinstance(value, str):
            type(self).invalidate_value(value, msg="Expected a string.")

    def to_primitive(self, value):
        return PlutusByteString(value.encode("utf-8"))

    @parse_type_str("string")
    def from_type_str(cls, type_obj, registry):
        return cls()


class _TupleEncoder(_PlutusBaseEncoder):
    def __init__(self, *, encoders):
        self.encoders = encoders

    def validate_value(self, value) -> None:
        if not isinstance(value, (tuple, list)):
            type(self).invalidate_value(
                value, msg="Tuple value must be a tuple or list")

        expected = len(self.encoders)
        if len(value) != expected:
            type(self).invalidate_value(
                value,
                msg=f"Expected {expected} fields, got {len(value)}"
            )
        fields = value

        for field, encoder in zip(fields, self.encoders):
            encoder.validate_value(field)

    def to_primitive(self, value):
        primitives = [
            encoder.to_primitive(field) for field, encoder in zip(value, self.encoders)
        ]
        return PlutusTuple(*primitives)

    @parse_tuple_type_str
    def from_type_str(cls, type_obj, registry):
        encoders = tuple(registry.get_encoder(comp.to_type_str())
                         for comp in type_obj.components)
        return cls(encoders=encoders)


class _ArrayEncoder(_PlutusBaseEncoder):
    def __init__(self, *, item_encoder, array_size=None):
        self.item_encoder = item_encoder
        self.array_size = array_size

    def validate_value(self, value) -> None:
        if not isinstance(value, (list, tuple)):
            type(self).invalidate_value(
                value, msg="Array value must be a list or tuple")
        if self.array_size is not None and len(value) != self.array_size:
            type(self).invalidate_value(
                value,
                msg=f"Expected array of length {self.array_size}, got {len(value)}"
            )
        for item in value:
            self.item_encoder.validate_value(item)

    def to_primitive(self, value):
        return PlutusList([self.item_encoder.to_primitive(item) for item in value])

    @parse_type_str(with_arrlist=True)
    def from_type_str(cls, type_obj, registry):
        item_encoder = registry.get_encoder(type_obj.item_type.to_type_str())
        array_spec = type_obj.arrlist[-1]
        if len(array_spec) == 1:
            return cls(item_encoder=item_encoder, array_size=array_spec[0])
        else:
            return cls(item_encoder=item_encoder)


_registry = ABIRegistry()
_registry.register_encoder(BaseEquals("int"), _IntegerEncoder)
_registry.register_encoder(BaseEquals("uint"), _UnsignedIntegerEncoder)
_registry.register_encoder(BaseEquals("bool"), _BoolEncoder)
_registry.register_encoder(BaseEquals("string"), _StringEncoder)
_registry.register_encoder(is_base_tuple, _TupleEncoder)
_registry.register_encoder(has_arrlist, _ArrayEncoder)
_encoder = ABIEncoder(_registry)
