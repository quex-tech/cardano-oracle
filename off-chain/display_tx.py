#!/usr/bin/env python
import sys

from pycardano import Transaction


def main():
    with open(sys.argv[1], "rb") as file:
        print(Transaction.from_cbor(file.read()))


if __name__ == "__main__":
    main()
