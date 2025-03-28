import json
import unittest
from pycardano.plutus import RawPlutusData
from pycardano.serialization import default_encoder, ByteString, IndefiniteList
from cbor2 import dumps, CBORTag
from plutus.abi import encoder

class TestEncode(unittest.TestCase):
    def test_encode(self):
        cases = [
            ("0", "int", 0),
            ("1", "int", 1),
            ("2147483647", "int", 2147483647),
            ("2147483648", "int", 2147483648),
            ("4294967295", "int", 4294967295),
            ("4294967296", "int", 4294967296),
            ("9223372036854775807", "int", 9223372036854775807),
            ("9223372036854775808", "int", 9223372036854775808),
            ("18446744073709551615", "int", 18446744073709551615),
            ("18446744073709551616", "int", 18446744073709551616),
            ("-2147483648", "int", -2147483648),
            ("-2147483649", "int", -2147483649),
            ("-9223372036854775808", "int", -9223372036854775808),
            ("-9223372036854775809", "int", -9223372036854775809),
            ('"Hello, 世界"', "string", "Hello, 世界".encode()),
            ('"Exactly 64 bytes世界世界世界世界世界世界世界世界"', "string",
             ByteString("Exactly 64 bytes世界世界世界世界世界世界世界世界".encode())),
            ('"Exactly 65 bytes 世界世界世界世界世界世界世界世界"', "string",
             ByteString("Exactly 65 bytes 世界世界世界世界世界世界世界世界".encode())),
            ("true", "bool", CBORTag(122, [])),
            ("false", "bool", CBORTag(121, [])),
            ("[]", "int[]", []),
            ("[1]", "int[]", IndefiniteList([1])),
            ("[1]", "(int)", CBORTag(121, IndefiniteList([1]))),
            ("[1,2]", "(int,int)", CBORTag(121, IndefiniteList([1, 2]))),
            ("[1,[2]]", "(int,(int))", CBORTag(121, IndefiniteList([1, CBORTag(121, IndefiniteList([2]))]))),
            ("[1,[2]]", "(int,int[])", CBORTag(121, IndefiniteList([1, IndefiniteList([2])]))),
            ("[[1,[2]],[3,[4,5]]]", "(int,int[])[]", IndefiniteList([CBORTag(121, IndefiniteList([1, IndefiniteList([2])])), CBORTag(121, IndefiniteList([3, IndefiniteList([4, 5])]))])),
            ("[[1,[2]],[3,[4]]]", "(int,(int))[]", IndefiniteList([CBORTag(121, IndefiniteList([1, CBORTag(121, IndefiniteList([2]))])), CBORTag(121, IndefiniteList([3, CBORTag(121, IndefiniteList([4]))]))])),
            ("[1,2,3,4,5,6]", "(uint,uint8,uint256,int,int8,int256)", CBORTag(121, IndefiniteList([1, 2, 3, 4, 5, 6]))),
        ]

        for json_str, schema, expected_primitive in cases:
            with self.subTest(json=json_str, schema=schema, expected_primitive=expected_primitive):
                actual = encoder.encode([schema], [json.loads(json_str)])
                expected = dumps(expected_primitive, default=default_encoder)
                print(json_str, "::", schema, "=", expected.hex())
                self.assertEqual(actual.hex(), expected.hex())


if __name__ == "__main__":
    unittest.main()
