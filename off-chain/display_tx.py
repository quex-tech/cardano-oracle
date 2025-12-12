#!/usr/bin/env python
# SPDX-License-Identifier: Apache-2.0
# Copyright 2025 Quex Technologies
import sys
from pathlib import Path

from pycardano import Transaction


def main() -> None:
    with Path(sys.argv[1]).open("rb") as file:
        print(Transaction.from_cbor(file.read()))


if __name__ == "__main__":
    main()
