from enum import IntEnum
from dataclasses import dataclass
from typing import List
import unittest

from cbor2 import CBORTag

from plutus.cbor import PlutusByteString, PlutusList, PlutusTuple
from plutus.mixins import to_plutus, from_plutus, PlutusEncodable, PlutusDecodable


class MyEnum(IntEnum):
    A = 0
    B = 1


@dataclass
class MyClass(PlutusEncodable, PlutusDecodable):
    a: int
    b: str


class TestToPlutus(unittest.TestCase):
    def test_to_plutus(self):
        cases = [
            (1, 1),
            ("Hello", PlutusByteString(b"Hello")),
            (b"Hello", PlutusByteString(b"Hello")),
            ([1, 2, 3], PlutusList([1, 2, 3])),
            (MyEnum.A, CBORTag(121, [])),
            (MyEnum.B, CBORTag(122, [])),
            ([1, 2], PlutusList([1, 2])),
            (MyClass(1, "Hello"), PlutusTuple([1, PlutusByteString(b"Hello")]))
        ]

        for input_value, expected in cases:
            with self.subTest(input_value=input_value, expected=expected):
                actual = to_plutus(input_value)
                self.assertEqual(actual, expected)


class TestFromPlutus(unittest.TestCase):
    def test_from_plutus(self):
        cases = [
            (b"Hello", bytes, b"Hello"),
            (b"Hello", str, "Hello"),
            ([1, 2], List[int], [1, 2]),
            (CBORTag(122, []), MyEnum, MyEnum.B),
            (CBORTag(121, [1, b"Hello"]), MyClass, MyClass(1, "Hello")),
        ]

        for value, target_type, expected in cases:
            with self.subTest(input_value=value, target_type=target_type, expected=expected):
                actual = from_plutus(value, target_type)
                self.assertEqual(actual, expected)

    def test_from_plutus_invalid(self):
        cases = [
            (1, bytes),
            ("Hello", str),
        ]

        for value, target_type in cases:
            with self.subTest(input_value=value, target_type=target_type):
                with self.assertRaises(TypeError):
                    from_plutus(value, target_type)


if __name__ == "__main__":
    unittest.main()
