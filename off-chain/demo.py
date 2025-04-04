#!/usr/bin/env python
import argparse
import json
from datetime import datetime, timedelta, timezone

from dotenv import load_dotenv
from pycardano import (
    Address,
    ChainContext,
    Redeemer,
    ScriptHash,
    TransactionBuilder,
    TransactionOutput,
    Unit,
    Value,
    plutus_script_hash,
)

from networks import get_chain_context
from responses import StoredResponse
from wallet import OraclePoolOwnerWallet
from utils import handle_tx, load_scripts, passphrase_arg_parser, tx_arg_parser

TX_TTL_OFFSET = timedelta(minutes=10)
RESPONSE_VALIDITY_PERIOD = timedelta(minutes=30)


def main():
    load_dotenv()
    parser = argparse.ArgumentParser(
        description="Locks and unlocks funds at the demo contract"
    )
    user_blueprint_arg_parser = argparse.ArgumentParser(add_help=False)
    user_blueprint_arg_parser.add_argument(
        "--user-plutus-blueprint",
        default="plutus.user.json",
        help=(
            "Path to a Plutus blueprint JSON file containing compiled user contract code. "
            "Default: plutus.user.json"
        ),
    )
    subparsers = parser.add_subparsers(required=True)
    parser_show = subparsers.add_parser("show", parents=[user_blueprint_arg_parser])
    parser_show.set_defaults(func=show)
    parser_lock = subparsers.add_parser(
        "lock",
        parents=[passphrase_arg_parser, tx_arg_parser, user_blueprint_arg_parser],
    )
    parser_lock.add_argument("ada", help="ADA amount to lock", type=int)
    parser_lock.set_defaults(func=lock)
    parser_spend = subparsers.add_parser(
        "spend",
        parents=[passphrase_arg_parser, tx_arg_parser, user_blueprint_arg_parser],
    )
    parser_spend.add_argument(
        "response_address",
        type=Address.decode,
        help="The adddress where oracle responses are stored",
    )
    parser_spend.set_defaults(func=spend)
    args = parser.parse_args()
    context = get_chain_context()
    args.func(context, args)


def show(context: ChainContext, args):
    (user_script,) = load_scripts(args.user_plutus_blueprint)
    currency_symbol, pool_action_id = load_asset_class(args.user_plutus_blueprint)
    addr = Address(plutus_script_hash(user_script), network=context.network)
    print("Contract address:                 ", addr)
    print("Expected response currency symbol:", currency_symbol)
    print("Expected PoolAction ID:           ", pool_action_id.hex())
    lovelace = sum((utxo.output.amount.coin for utxo in context.utxos(addr)))
    print("Locked Lovelace:                  ", lovelace)


def lock(context: ChainContext, args):
    wallet = OraclePoolOwnerWallet.from_env(args.passphrase)
    (user_script,) = load_scripts(args.user_plutus_blueprint)

    from_addr = wallet.treasury.addr(context.network)
    to_addr = Address(plutus_script_hash(user_script), network=context.network)

    builder = TransactionBuilder(context)
    builder.add_input_address(from_addr)
    builder.add_output(TransactionOutput(to_addr, Value(args.ada * 1_000_000)))
    signed_tx = builder.build_and_sign([wallet.treasury.sk], change_address=from_addr)
    handle_tx(signed_tx, context, args)


def spend(context: ChainContext, args):
    wallet = OraclePoolOwnerWallet.from_env(args.passphrase)
    (user_script,) = load_scripts(args.user_plutus_blueprint)
    currency_symbol, pool_action_id = load_asset_class(args.user_plutus_blueprint)
    from_addr = Address(plutus_script_hash(user_script), network=context.network)

    print("Contract address:                 ", from_addr)
    print("Response address:                 ", args.response_address)
    print("Expected response currency symbol:", currency_symbol)
    print("Expected PoolAction ID:           ", pool_action_id.hex())
    lovelace = sum((utxo.output.amount.coin for utxo in context.utxos(from_addr)))
    print("Locked Lovelace:                  ", lovelace)
    if not lovelace:
        return

    responses = [
        StoredResponse.from_utxo(utxo)
        for utxo in context.utxos(args.response_address)
        if currency_symbol in utxo.output.amount.multi_asset
    ]
    print("Responses found:                  ", len(responses))
    if not responses:
        return
    action_responses = [r for r in responses if r.pool_action_id == pool_action_id]
    print("- with this PoolAction ID:        ", len(action_responses))
    if not action_responses:
        return
    successful_action_responses = [r for r in action_responses if r.data.error == 0]
    print("- successful:                     ", len(successful_action_responses))
    response = max(
        (r for r in successful_action_responses),
        key=lambda x: x.data.timestamp,
        default=None,
    )
    print("Latest value:                     ", response.data.format_value())
    print("Latest timestamp:                 ", response.data.format_timestamp())

    expires_at = (
        datetime.fromtimestamp(response.data.timestamp, timezone.utc)
        + RESPONSE_VALIDITY_PERIOD
    )
    transaction_valid_to = datetime.now(timezone.utc) + TX_TTL_OFFSET
    time_remaining = expires_at - transaction_valid_to
    print("Time before expiration:           ", max(timedelta(), time_remaining))
    if time_remaining < timedelta():
        return

    to_addr = wallet.treasury.addr(context.network)

    builder = TransactionBuilder(context)
    builder.add_input_address(to_addr)
    amount = Value()

    for utxo in context.utxos(from_addr):
        builder.add_script_input(utxo, user_script, redeemer=Redeemer(Unit()))
        amount += utxo.output.amount

    builder.reference_inputs.add(response.utxo)
    builder.add_output(TransactionOutput(to_addr, amount))
    signed_tx = builder.build_and_sign(
        [wallet.treasury.sk],
        change_address=to_addr,
        auto_ttl_offset=TX_TTL_OFFSET.total_seconds(),
    )

    handle_tx(signed_tx, context, args)


def load_asset_class(path: str) -> (ScriptHash, bytes):
    with open(path, "r", encoding="utf-8") as f:
        blueprint = json.loads(f.read())

    (validator,) = blueprint["validators"]
    (parameter,) = validator["parameters"]
    currency_symbol, pool_action_id = parameter["description"].split(".")

    return (
        ScriptHash(payload=bytes.fromhex(currency_symbol)),
        bytes.fromhex(pool_action_id),
    )


if __name__ == "__main__":
    main()
