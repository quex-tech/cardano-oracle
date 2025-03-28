from abc import abstractmethod

from cbor2 import CBORTag
from eth_abi.base import parse_type_str, parse_tuple_type_str
from eth_abi.encoding import BaseEncoder
from eth_abi.exceptions import ValueOutOfBounds
from eth_abi.codec import ABIEncoder
from eth_abi.registry import ABIRegistry, is_base_tuple, has_arrlist, BaseEquals

from plutus.cbor import PlutusByteString, PlutusList, PlutusTuple, dumps


class PlutusBaseEncoder(BaseEncoder):
    def encode(self, value) -> bytes:
        self.validate_value(value)
        return dumps(self.to_primitive(value))

    @abstractmethod
    def to_primitive(self, value):
        pass


class IntegerEncoder(PlutusBaseEncoder):
    def validate_value(self, value) -> None:
        if not isinstance(value, int):
            type(self).invalidate_value(value, msg="must be an integer")

    def to_primitive(self, value):
        return value

    @parse_type_str("int")
    def from_type_str(cls, type_str, registry):
        return cls()


class UnsignedIntegerEncoder(PlutusBaseEncoder):
    def validate_value(self, value) -> None:
        if not isinstance(value, int):
            type(self).invalidate_value(value, msg="must be an integer")
        if value < 0:
            type(self).invalidate_value(
                value, msg="must be non-negative")

    def to_primitive(self, value):
        return value

    @parse_type_str("uint")
    def from_type_str(cls, type_str, registry):
        return cls()


class BoolEncoder(PlutusBaseEncoder):
    def validate_value(self, value) -> None:
        if not isinstance(value, bool):
            type(self).invalidate_value(value, msg="must be a boolean")

    def to_primitive(self, value):
        return CBORTag(122 if value else 121, [])

    @parse_type_str("bool")
    def from_type_str(cls, type_str, registry):
        return cls()


class StringEncoder(PlutusBaseEncoder):
    def validate_value(self, value) -> None:
        if not isinstance(value, str):
            type(self).invalidate_value(value, msg="must be a string")

    def to_primitive(self, value):
        return PlutusByteString(value.encode("utf-8"))

    @parse_type_str("string")
    def from_type_str(cls, type_str, registry):
        return cls()


class TupleEncoder(PlutusBaseEncoder):
    def __init__(self, encoders):
        super().__init__()
        self.encoders = encoders

    def validate_value(self, value) -> None:
        if not isinstance(value, (tuple, list)):
            type(self).invalidate_value(
                value, msg="must be a tuple or list")

        if len(value) != len(self.encoders):
            self.invalidate_value(
                value,
                exc=ValueOutOfBounds,
                msg=f"value has {len(value)} items when {len(self.encoders)} were "
                "expected",
            )

        for item, encoder in zip(value, self.encoders):
            encoder.validate_value(item)

    def to_primitive(self, value):
        primitives = [
            encoder.to_primitive(field) for field, encoder in zip(value, self.encoders)
        ]
        return PlutusTuple(primitives)

    @parse_tuple_type_str
    def from_type_str(cls, type_str, registry):
        encoders = tuple(registry.get_encoder(comp.to_type_str())
                         for comp in type_str.components)
        return cls(encoders=encoders)


class ArrayEncoder(PlutusBaseEncoder):
    def __init__(self, item_encoder, array_size=None):
        super().__init__()
        self.item_encoder = item_encoder
        self.array_size = array_size

    def validate_value(self, value) -> None:
        if not isinstance(value, list):
            type(self).invalidate_value(value, msg="must be a list")

        if self.array_size is not None and len(value) != self.array_size:
            self.invalidate_value(
                value,
                exc=ValueOutOfBounds,
                msg=f"value has {len(value)} items when {self.array_size} were "
                "expected",
            )

        for item in value:
            self.item_encoder.validate_value(item)

    def to_primitive(self, value):
        return PlutusList([self.item_encoder.to_primitive(item) for item in value])

    @parse_type_str(with_arrlist=True)
    def from_type_str(cls, type_str, registry):
        item_encoder = registry.get_encoder(type_str.item_type.to_type_str())
        array_spec = type_str.arrlist[-1]

        return cls(
            item_encoder=item_encoder,
            array_size=array_spec[0] if len(array_spec) == 1 else None
        )


registry = ABIRegistry()
registry.register_encoder(BaseEquals("int"), IntegerEncoder)
registry.register_encoder(BaseEquals("uint"), UnsignedIntegerEncoder)
registry.register_encoder(BaseEquals("bool"), BoolEncoder)
registry.register_encoder(BaseEquals("string"), StringEncoder)
registry.register_encoder(is_base_tuple, TupleEncoder)
registry.register_encoder(has_arrlist, ArrayEncoder)

encoder = ABIEncoder(registry)
