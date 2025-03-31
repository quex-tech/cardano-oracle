import json
import unittest
from plutus.abi import encoder


class TestEncoder(unittest.TestCase):
    def test_encode(self):
        cases = [
            ("1", "int", "01"),
            ('"Hello, 世界"', "string", "4d" "48656c6c6f2c20e4b896e7958c"),
            ("true", "bool", "d87a" "80"),
            ("false", "bool", "d879" "80"),
            ("[]", "int[]", "80"),
            ("[1]", "int[]", "9f" "01" "ff"),
            ("[1]", "(int)", "d879" "9f" "01" "ff"),
            ("[1,2]", "(int,int)", "d879" "9f" "0102" "ff"),
            ("[1,[2]]", "(int,(int))", "d879" "9f" "01" "d879" "9f" "02ff" "ff"),
            ("[1,[2]]", "(int,int[])", "d879" "9f" "01" "9f" "02" "ff" "ff"),
            ("[[1,[2]],[3,[4,5]]]", "(int,int[])[]",
             "9f"
             "d879" "9f" "01" "9f" "02" "ff" "ff"
             "d879" "9f" "03" "9f" "0405" "ff" "ff"
             "ff"),
            ("[[1,[2]],[3,[4]]]", "(int,(int))[]",
             "9f"
             "d879" "9f" "01" "d879" "9f" "02" "ff" "ff"
             "d879" "9f" "03" "d879" "9f" "04" "ff" "ff"
             "ff"),
            ("[1,2,3,4,5,6]", "(uint,uint8,uint256,int,int8,int256)",
             "d879" "9f" "010203040506" "ff"),
        ]

        for json_str, schema, expected_hex in cases:
            with self.subTest(json=json_str, schema=schema, expected_primitive=expected_hex):
                actual = encoder.encode([schema], [json.loads(json_str)])
                self.assertEqual(actual.hex(), expected_hex)


if __name__ == "__main__":
    unittest.main()
