import unittest
from cbor2 import CBORTag
from plutus.cbor import PlutusList, PlutusRawData, PlutusByteString, get_tag, get_constr_idx, dumps
from plutus.cbor import PlutusTuple


class TestGetTag(unittest.TestCase):
    def test_get_tag(self):
        cases = [
            (0, 121),
            (1, 122),
            (6, 127),
            (7, 1280),
            (127, 1400),
        ]

        for constr_idx, expected in cases:
            with self.subTest(constr_idx=constr_idx, expected=expected):
                actual = get_tag(constr_idx)
                self.assertEqual(actual, expected)

    def test_get_tag_out_of_range(self):
        for constr_idx in [-1, 128]:
            with self.subTest(constr_idx=constr_idx):
                with self.assertRaises(ValueError):
                    get_tag(constr_idx)


class TestGetConstrIdx(unittest.TestCase):
    def test_get_constr_idx_returns_constr_idx(self):
        cases = [
            (CBORTag(121, []), 0),
            (CBORTag(122, []), 1),
            (CBORTag(127, []), 6),
            (CBORTag(1280, []), 7),
            (CBORTag(1400, []), 127),
        ]

        for tag, expected in cases:
            with self.subTest(tag=tag, expected=expected):
                actual = get_constr_idx(tag)
                self.assertEqual(actual, expected)

    def test_get_constr_idx_out_of_range(self):
        with self.assertRaises(ValueError):
            get_constr_idx(CBORTag(128, []))


class TestDumps(unittest.TestCase):
    def test_dumps(self):
        cases = [
            (PlutusRawData(bytes.fromhex("123456789a")), "123456789a"),
            (PlutusByteString(bytes(64)), (
                "5840"
                "00000000000000000000000000000000"
                "00000000000000000000000000000000"
                "00000000000000000000000000000000"
                "00000000000000000000000000000000"
            )),
            (PlutusByteString(bytes(65)), (
                "5f" "5840"
                "00000000000000000000000000000000"
                "00000000000000000000000000000000"
                "00000000000000000000000000000000"
                "00000000000000000000000000000000"
                "4100" "ff")),
            (PlutusList([1, 2, 3]), "9f" "010203" "ff"),
            (PlutusTuple([1, 2, 3]), "d879" "9f" "010203" "ff"),
        ]

        for value, expected in cases:
            with self.subTest(value=value, expected=expected):
                actual = dumps(value)
                self.assertEqual(actual.hex(), expected)


if __name__ == "__main__":
    unittest.main()
