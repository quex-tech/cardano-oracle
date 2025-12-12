#!/usr/bin/env python
# SPDX-License-Identifier: Apache-2.0
# Copyright 2025 Quex Technologies
import json
import random
from argparse import ArgumentParser, Namespace
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from time import sleep
from typing import Mapping

import eth_keys
import eth_utils
from dotenv import load_dotenv
from pycardano import (
    SCRIPT_HASH_SIZE,
    Address,
    ChainContext,
    PyCardanoException,
    ScriptHash,
    Transaction,
    VerificationKeyHash,
)

from models import ANY_TD_ADDRESS, HTTPActionWithProof, OracleRequest, QuexResponse
from networks import get_chain_context
from oracles import RegisteredOracle, get_registered_oracles_at
from pending_requests import (
    InsufficientFundsError,
    InsufficientRewardError,
    RequestRepository,
    StoredRequest,
    fulfill_request,
)
from protocol import Protocol
from signer_client import SignerClient
from utils import (
    blueprint_arg_parser,
    passphrase_arg_parser,
)
from wallet import OperatorWallet


@dataclass
class Config:
    pkhs_by_cs: Mapping[bytes, list[VerificationKeyHash | ScriptHash]]
    urls_by_pk: Mapping[bytes, list[str]]
    relayer_reward: int

    def get_pkhs(self, pool_id: bytes) -> list[VerificationKeyHash | ScriptHash]:
        currency_symbol = pool_id[:SCRIPT_HASH_SIZE]
        return self.pkhs_by_cs.get(currency_symbol, [])

    def get_urls(self, key: eth_keys.keys.PublicKey) -> list[str]:
        return self.urls_by_pk.get(key.to_compressed_bytes(), [])

    @classmethod
    def load(cls, path: Path):
        with path.open(encoding="utf-8") as f:
            config = json.load(f)

        pkhs_by_cs = {
            bytes.fromhex(cs_hex): [
                h for h in (Address.decode(addr).payment_part for addr in addrs) if h
            ]
            for cs_hex, addrs in config["addressesByCurrencySymbol"].items()
        }

        urls_by_pk: Mapping[bytes, list[str]] = {
            bytes.fromhex(k): v for k, v in config["urlsByPublicKey"].items()
        }

        relayer_reward = config["relayerReward"]

        return cls(pkhs_by_cs, urls_by_pk, relayer_reward)


class RequestHandlingError(Exception):
    pass


class InvalidRequestError(RequestHandlingError):
    pass


def main() -> None:
    load_dotenv()
    parser = ArgumentParser(
        description="Fulfills all valid requests",
        parents=[
            blueprint_arg_parser,
            passphrase_arg_parser,
        ],
    )
    parser.add_argument(
        "--config",
        default="config.json",
        type=Path,
        help="Path to the JSON file containing oracle data. Default: config.json",
    )
    parser.add_argument(
        "--dry-run", action="store_true", help="Do not actually submit any transactions"
    )

    args = parser.parse_args()
    context = get_chain_context()
    wallet = OperatorWallet.from_env(args.passphrase)
    protocol = Protocol.load(args.plutus_blueprint)
    config = Config.load(args.config)

    repo = RequestRepository(
        context=context,
        validator=protocol.request_validator,
    )
    relayer = bytes(wallet.treasury.vk.hash())
    requests = repo.all()
    requests.sort(key=lambda x: x.request.before)

    for request in requests:
        request_id = f"{request.utxo.input.transaction_id}#{request.utxo.input.index}"
        try:
            handle_request(
                context=context,
                wallet=wallet,
                protocol=protocol,
                args=args,
                relayer=relayer,
                config=config,
                request=request,
            )
        except RequestHandlingError as err:
            print(f"{request_id}: Could not handle: {err}")
            continue
        print(f"{request_id}: Handled")


def handle_request(
    context: ChainContext,
    wallet: OperatorWallet,
    protocol: Protocol,
    args: Namespace,
    relayer: bytes,
    config: Config,
    request: StoredRequest,
) -> None:
    validate_request(request.request, context, config)

    oracles = get_suitable_oracles(context, request.request, config)
    if not oracles:
        reason = "No suitable oracles found"
        raise RequestHandlingError(reason)

    oracle = random.choice(oracles)
    response = obtain_response(
        oracle.data.public_key,
        request.request.action,
        relayer,
        config,
    )

    try:
        signed_tx = fulfill_request(
            context,
            wallet.treasury,
            protocol.response_validator,
            protocol.request_validator,
            oracle,
            request,
            response,
            config.relayer_reward,
            library_pkh=wallet.library.vk.hash(),
        )
    except InsufficientFundsError as err:
        reason = "Insufficient funds in request"
        raise RequestHandlingError(reason) from err
    except InsufficientRewardError as err:
        reason = "Insufficient reward"
        raise RequestHandlingError(reason) from err
    except PyCardanoException as err:
        reason = "Could not build transaction"
        raise RequestHandlingError(reason) from err

    if not args.dry_run:
        try:
            context.submit_tx(signed_tx)
            wait_tx(context, signed_tx)
        except PyCardanoException as err:
            reason = "Could not submit transaction"
            raise RequestHandlingError(reason) from err


def validate_request(request: OracleRequest, context: ChainContext, config: Config) -> None:
    if not request.is_valid():
        reason = "Invalid request"
        raise InvalidRequestError(reason)

    if request.coins_per_utxo_byte < context.protocol_param.coins_per_utxo_byte:
        reason = "coins_per_utxo_byte is too small"
        raise InvalidRequestError(reason)

    if request.reward < config.relayer_reward:
        reason = "Reward is too small"
        raise InvalidRequestError(reason)

    now = int(datetime.now(UTC).timestamp())
    if request.after > now:
        reason = "Too early"
        raise InvalidRequestError(reason)

    if request.before < now:
        reason = "Too late"
        raise InvalidRequestError(reason)


def get_suitable_oracles(
    context: ChainContext,
    request: OracleRequest,
    config: Config,
) -> list[RegisteredOracle]:
    pkhs = config.get_pkhs(request.pool_id.value)
    if not pkhs:
        return []

    oracles: list[RegisteredOracle] = [
        o
        for o in get_registered_oracles_at(context, pkhs)
        if o.pool.id == request.pool_id.value
        if config.get_urls(o.data.public_key)
    ]

    td_address = (
        request.action.action.patch.td_address.value.decode()
        if request.action.action.patch.td_address.value
        else ANY_TD_ADDRESS
    )

    if td_address != ANY_TD_ADDRESS:
        oracles = [
            o
            for o in oracles
            if eth_utils.is_same_address(o.data.public_key.to_checksum_address(), td_address)
        ]

    return oracles


def obtain_response(
    public_key: eth_keys.keys.PublicKey,
    action: HTTPActionWithProof,
    relayer: bytes,
    config: Config,
) -> QuexResponse:
    urls = config.get_urls(public_key)
    if not urls:
        reason = "Oracle urls are not found"
        raise RequestHandlingError(reason)

    client = SignerClient(random.choice(urls))
    try:
        if client.public_key() != public_key:
            reason = "Wrong public key"
            raise RequestHandlingError(reason)
        return client.query(action, relayer)
    except OSError as err:
        reason = "Could not reach the oracle"
        raise RequestHandlingError(reason) from err


def wait_tx(context: ChainContext, tx: Transaction, timeout_secs: int = 600) -> None:
    first_output = tx.transaction_body.outputs[0]
    deadline = datetime.now(UTC).timestamp() + timeout_secs

    while datetime.now(UTC).timestamp() < deadline:
        try:
            utxo = next(
                (u for u in context.utxos(first_output.address) if u.input.transaction_id == tx.id),
                None,
            )
        except PyCardanoException:
            utxo = None

        if utxo:
            return

        sleep(5)

    reason = "Transaction not confirmed within timeout"
    raise RequestHandlingError(reason)


if __name__ == "__main__":
    main()
