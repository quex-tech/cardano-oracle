# SPDX-License-Identifier: Apache-2.0
# Copyright 2025 Quex Technologies
import json
from argparse import ArgumentParser, Namespace
from collections.abc import Mapping
from pathlib import Path
from time import sleep

from cbor2 import CBORDecodeError
from pycardano import (
    ChainContext,
    PlutusScript,
    Transaction,
    TransactionInput,
    TransactionOutput,
)
from pycardano.serialization import CBORBase, DeserializeException, RawCBOR


def handle_tx(signed_tx: Transaction, context: ChainContext, args: Namespace) -> None:
    show_tx = "view_tx" not in args or args.view_tx
    submit_tx = "submit" in args and args.submit
    wait_tx = "wait" not in args or args.wait

    if show_tx:
        print("Transaction:", signed_tx)

    print("Transaction ID:", signed_tx.id)

    if submit_tx:
        context.submit_tx(signed_tx)
        print("Transaction submitted.")

        if wait_tx and signed_tx.transaction_body.outputs:
            print("Waiting for confirmation...")
            first_output = signed_tx.transaction_body.outputs[0]
            utxo = None
            tick = 0
            while not utxo:
                utxo = next(
                    (
                        u
                        for u in context.utxos(first_output.address)
                        if u.input.transaction_id == signed_tx.id
                    ),
                    None,
                )
                sleep(5)
                tick += 1
                dots = tick % 6
                if dots != 1:
                    print("\b", end="", flush=True)
                print("⠿⠄⠤⠴⠶⠷"[dots], end="", flush=True)
            print()
            print("Transaction confirmed.")
        return

    print()
    if not show_tx:
        print("Add --view-tx to preview the transaction")
    print(
        "Add --submit to submit the transaction (add --wait to wait for transaction confirmation)"
    )


def parse_tx_input(tx_input: str) -> TransactionInput:
    tx, idx = tx_input.split("#")
    return TransactionInput.from_primitive([tx, int(idx)])


def load_scripts(path: Path) -> Mapping[str, PlutusScript]:
    with path.open(encoding="utf-8") as f:
        blueprint = json.load(f)

    version = int(blueprint["preamble"]["plutusVersion"].strip("v"))

    return {
        validator["title"]: PlutusScript.from_version(
            version, bytes.fromhex(validator["compiledCode"])
        )
        for validator in blueprint["validators"]
    }


tx_arg_parser = ArgumentParser(add_help=False)
tx_arg_parser.add_argument("--view-tx", action="store_true", help="View transaction contents")
tx_arg_parser.add_argument(
    "--submit",
    action="store_true",
    help="Submit the transaction on-chain",
)
tx_arg_parser.add_argument(
    "--wait",
    action="store_true",
    help="Wait for the transaction confirmation",
)

passphrase_arg_parser = ArgumentParser(add_help=False)
passphrase_arg_parser.add_argument("--passphrase", help="Passphrase for the wallet", default="")

blueprint_arg_parser = ArgumentParser(add_help=False)
blueprint_arg_parser.add_argument(
    "--plutus-blueprint",
    default="plutus.json",
    type=Path,
    help=(
        "Path to a Plutus blueprint JSON file containing compiled contracts code. "
        "Default: plutus.json"
    ),
)


def format_plutus_dict(data: dict) -> str:
    if "int" in data:
        return str(data["int"])
    if "bytes" in data:
        try:
            return f'"{bytes.fromhex(data["bytes"]).decode()}"'
        except UnicodeDecodeError:
            return data["bytes"]
    if "list" in data:
        return f"[{','.join([format_plutus_dict(item) for item in data['list']])}]"
    if "constructor" in data:
        return format_plutus_constr(data)
    return "UNKNOWN"


def format_plutus_constr(data: dict) -> str:
    fields = data["fields"]
    if fields:
        return f"({','.join([format_plutus_dict(field) for field in fields])})"

    return {0: "False", 1: "True"}.get(data["constructor"], "()")


def try_from_cbor(cls: type[CBORBase], payload: str | bytes) -> CBORBase | None:
    try:
        return cls.from_cbor(payload)
    except CBORDecodeError:
        return None
    except DeserializeException:
        return None


def try_from_tx_output(cls: type[CBORBase], output: TransactionOutput) -> CBORBase | None:
    if not output.datum:
        return None

    if not isinstance(output.datum, RawCBOR):
        return None

    return try_from_cbor(cls, output.datum.cbor)
