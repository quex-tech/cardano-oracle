#!/usr/bin/env python
import argparse
import json
from pycardano import *


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("path", help="path to plutus.json",
                        type=argparse.FileType("r"))
    args = parser.parse_args()

    with args.path as f:
        blueprint = json.load(f)

    nw = Network.TESTNET

    for validator in blueprint["validators"]:
        print(validator["title"], Address(
            ScriptHash(bytes.fromhex(validator["hash"])), network=nw))


if __name__ == '__main__':
    main()
