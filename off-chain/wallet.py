#!/usr/bin/env python
# SPDX-License-Identifier: Apache-2.0
# Copyright 2025 Quex Technologies
import argparse
from dataclasses import dataclass
import os

from pycardano import (
    Address,
    ExtendedSigningKey,
    ExtendedVerificationKey,
    HDWallet,
    Network,
)
from dotenv import load_dotenv

from networks import get_network
from utils import passphrase_arg_parser


def main():
    load_dotenv()
    parser = argparse.ArgumentParser(
        description="Generates wallets and displays addresses",
    )
    subparsers = parser.add_subparsers(required=True)
    parser_generate = subparsers.add_parser(
        "generate",
        help="Generate a new wallet",
        description="Generates a new wallet",
        parents=[passphrase_arg_parser],
    )
    parser_generate.set_defaults(func=generate)
    parser_show = subparsers.add_parser(
        "show",
        help=(
            "Show current wallet from WALLET_MNEMONIC environment variable; "
            "treasury and oracle storage addresses"
        ),
        description=(
            "Shows current wallet from WALLET_MNEMONIC environment variable; "
            "treasury and oracle storage addresses"
        ),
        parents=[passphrase_arg_parser],
    )
    parser_show.set_defaults(func=show)
    args = parser.parse_args()
    args.func(args)


def generate(args):
    mnemonic = HDWallet.generate_mnemonic()
    wallet = OperatorWallet(
        HDWallet.from_mnemonic(mnemonic=mnemonic, passphrase=args.passphrase)
    )
    print(f'WALLET_MNEMONIC="{mnemonic}"')
    print_wallet(wallet=wallet)


def show(args):
    wallet = OperatorWallet.from_env(args.passphrase)
    if not wallet:
        print("No wallet in WALLET_MNEMONIC environment variables")
        return
    print_wallet(wallet)


@dataclass
class Wallet:
    wallet: HDWallet

    @classmethod
    def from_env(cls, passphrase: str):
        mnemonic = os.environ.get("WALLET_MNEMONIC", None)
        if not mnemonic:
            return None
        return cls(HDWallet.from_mnemonic(mnemonic, passphrase=passphrase))

    @property
    def sk(self) -> ExtendedSigningKey:
        return ExtendedSigningKey.from_hdwallet(self.wallet)

    @property
    def vk(self) -> ExtendedVerificationKey:
        return self.sk.to_verification_key()

    def addr(self, nw: Network) -> Address:
        return Address(payment_part=self.vk.hash(), network=nw)


@dataclass
class OperatorWallet(Wallet):
    @property
    def treasury(self) -> Wallet:
        return Wallet(self.wallet.derive(0))

    @property
    def oracles(self) -> Wallet:
        return Wallet(self.wallet.derive(1))

    @property
    def library(self) -> Wallet:
        return Wallet(self.wallet.derive(2))


def print_wallet(wallet: OperatorWallet):
    print("Verification key:", wallet.vk.hash())
    nw = get_network()
    print("Treasury address:", wallet.treasury.addr(nw))
    print("Oracles address: ", wallet.oracles.addr(nw))


if __name__ == "__main__":
    main()
