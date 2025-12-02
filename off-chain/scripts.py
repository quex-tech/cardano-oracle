#!/usr/bin/env python
from argparse import ArgumentParser, Namespace
from dataclasses import dataclass
from typing import List, Optional, Union
import warnings

from dotenv import load_dotenv
from pycardano import (
    ChainContext,
    NativeScript,
    PlutusScript,
    Transaction,
    TransactionBuilder,
    TransactionOutput,
    UTxO,
    Value,
    min_lovelace_post_alonzo,
    script_hash,
)

from networks import get_chain_context
from protocol import Protocol
from utils import blueprint_arg_parser, passphrase_arg_parser, handle_tx, tx_arg_parser
from wallet import OperatorWallet


def main():
    load_dotenv()
    parser = ArgumentParser(
        description="Manage reference scripts stored on-chain",
    )
    subparsers = parser.add_subparsers(required=True)
    parser_list = subparsers.add_parser(
        "list",
        help="List scripts",
        description="Lists scripts",
        parents=[passphrase_arg_parser, blueprint_arg_parser],
    )
    parser_list.set_defaults(func=list_scripts)
    parser_add_all = subparsers.add_parser(
        "addall",
        help="Add all oracle scripts on-chain for reference",
        description="Adds all oracle scripts on-chain for reference",
        parents=[passphrase_arg_parser, blueprint_arg_parser, tx_arg_parser],
    )
    parser_add_all.set_defaults(func=add_all_scripts)
    parser_clear = subparsers.add_parser(
        "clear",
        help="Remove all oracle scripts from on-chain library",
        description="Removes all oracle oracle scripts from on-chain library",
        parents=[passphrase_arg_parser, blueprint_arg_parser, tx_arg_parser],
    )
    parser_clear.set_defaults(func=clear_scripts)

    args = parser.parse_args()

    context = get_chain_context()
    repo = ScriptRepository(
        wallet=OperatorWallet.from_env(args.passphrase),
        context=context,
        protocol=Protocol.load(args.plutus_blueprint),
    )

    warnings.filterwarnings(
        "ignore",
        message=".*__init__ failed to validate.*",
        category=UserWarning,
    )

    args.func(context, repo, args)


def try_refer_to_script(
    context: ChainContext,
    wallet: OperatorWallet,
    script: Union[NativeScript, PlutusScript],
) -> Union[NativeScript, PlutusScript, UTxO]:
    return next(
        (
            u
            for u in context.utxos(wallet.library.addr(context.network))
            if u.output.script == script
        ),
        script,
    )


@dataclass
class ScriptRepository:
    wallet: OperatorWallet
    context: ChainContext
    protocol: Protocol

    def all(self) -> List[UTxO]:
        nw = self.context.network
        utxos = self.context.utxos(self.wallet.library.addr(nw))
        return [u for u in utxos if u.output.script]

    def add_tx(self, scripts: [PlutusScript]) -> Optional[Transaction]:
        existing = [u.output.script for u in self.all()]
        scripts_to_add = [s for s in scripts if s not in existing]
        if not scripts_to_add:
            return None

        nw = self.context.network

        builder = TransactionBuilder(self.context)
        builder.add_input_address(self.wallet.treasury.addr(nw))

        for script in scripts_to_add:
            tx_out = TransactionOutput(
                self.wallet.library.addr(nw), Value(2_000_000), script=script
            )
            tx_out.amount.coin = min_lovelace_post_alonzo(tx_out, self.context)
            builder.add_output(tx_out)

        return builder.build_and_sign(
            [self.wallet.treasury.sk],
            change_address=self.wallet.treasury.addr(nw),
        )

    def clear_tx(self):
        nw = self.context.network

        builder = TransactionBuilder(self.context)
        builder.add_input_address(self.wallet.treasury.addr(nw))

        val = Value()

        scripts = self.all()
        if not scripts:
            return None

        for script in scripts:
            builder.add_input(script)
            val += script.output.amount

        builder.add_output(TransactionOutput(self.wallet.treasury.addr(nw), amount=val))

        return builder.build_and_sign(
            [self.wallet.treasury.sk, self.wallet.library.sk],
            change_address=self.wallet.treasury.addr(nw),
            merge_change=True,
        )


def list_scripts(context: ChainContext, repo: ScriptRepository, args: Namespace):
    for utxo in repo.all():
        print(f"- UTxO:  {utxo.input.transaction_id}#{utxo.input.index}")
        print("  Type: ", type(utxo.output.script).__name__)
        print("  Hash: ", script_hash(utxo.output.script))


def add_all_scripts(context: ChainContext, repo: ScriptRepository, args: Namespace):
    tx = repo.add_tx(
        [
            repo.protocol.request_validator,
            repo.protocol.response_validator,
            repo.protocol.single_oracle_pool_validator,
        ]
    )

    if not tx:
        print("All scripts are already added")
        return

    handle_tx(tx, context, args)


def clear_scripts(context: ChainContext, repo: ScriptRepository, args: Namespace):
    tx = repo.clear_tx()

    if not tx:
        print("No scripts on-chain")
        return

    handle_tx(tx, context, args)


if __name__ == "__main__":
    main()
