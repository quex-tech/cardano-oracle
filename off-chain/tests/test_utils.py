# SPDX-License-Identifier: Apache-2.0
# Copyright 2025 Quex Technologies
import unittest

from pycardano.serialization import ByteString

from models import RequestHeader
from utils import try_from_cbor


class TryFromCborTests(unittest.TestCase):
    def test_none_when_empty(self) -> None:
        print(RequestHeader(ByteString(b"Key"), ByteString(b"Value")).to_cbor_hex())
        self.assertIsNone(try_from_cbor(RequestHeader, b""))

    def test_non_none_when_good(self) -> None:
        header = try_from_cbor(RequestHeader, bytes.fromhex("d8799f434b65794556616c7565ff"))
        self.assertIsNotNone(header)
