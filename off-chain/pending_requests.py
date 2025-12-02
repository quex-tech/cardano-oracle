#!/usr/bin/env python
from argparse import ArgumentParser, Namespace
from base64 import b64encode
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from hashlib import sha256
from math import ceil, floor
import os
from typing import List, Optional

from dotenv import load_dotenv
from ecdsa import SECP256k1, VerifyingKey
from pycardano import (
    Address,
    ChainContext,
    MultiAsset,
    Network,
    PlutusData,
    ProtocolParameters,
    Redeemer,
    Transaction,
    TransactionBuilder,
    TransactionInput,
    TransactionOutput,
    Unit,
    UTxO,
    Value,
    VerificationKeyHash,
    min_lovelace_post_alonzo,
    fee,
)
from pycardano.serialization import ByteString, default_encoder

from http_action import http_action_arg_parser, parse_http_action_with_proof
from models import OracleRequest, HTTPActionWithProof, QuexResponse
from networks import get_chain_context
from oracles import OracleRepository, RegisteredOracle
from protocol import Protocol
from responses import ResponseRepository, ResponseTransactionBuilder
from scripts import try_refer_to_script
from signer_client import SignerClient
from utils import (
    blueprint_arg_parser,
    handle_tx,
    passphrase_arg_parser,
    tx_arg_parser,
    parse_tx_input,
)
from wallet import OperatorWallet

RELAYER_FEE = 50_000


def main():
    load_dotenv()
    parser = ArgumentParser(
        description="Manage pending oracle requests stored on-chain",
    )
    subparsers = parser.add_subparsers(required=True)
    parser_list = subparsers.add_parser(
        "list",
        help="List pending oracle requests",
        description="Lists pending oracle requests",
        parents=[passphrase_arg_parser, blueprint_arg_parser],
    )
    parser_list.set_defaults(func=list_requests)
    parser_add = subparsers.add_parser(
        "add",
        help="Add a request",
        description="Adds a request",
        parents=[
            blueprint_arg_parser,
            http_action_arg_parser,
            passphrase_arg_parser,
            tx_arg_parser,
        ],
    )
    parser_add.add_argument(
        "--oracle-pub-key",
        type=lambda x: VerifyingKey.from_string(
            bytes.fromhex(x.removeprefix("0x")), SECP256k1
        ),
        help="Public key of the oracle. Needed for encryption",
    )
    parser_add.add_argument(
        "--oracle-pool-id",
        default=os.environ.get("ORACLE_POOL_ID"),
        type=bytes.fromhex,
        help="ID of the oracle pool in hex",
    )
    parser_add.add_argument(
        "--ttl",
        default=timedelta(hours=1),
        type=lambda s: timedelta(minutes=int(s)),
        help="TTL of the request in minutes. After it expires, author can reclaim funds. Default: 60",
    )
    parser_add.add_argument(
        "--max-response",
        default=256,
        type=int,
        help="Maximum response size in bytes. Default: 256",
    )
    parser_add.set_defaults(func=run_add_request_command)
    parser_recycle = subparsers.add_parser(
        "recycle",
        help="Recycle an expired request",
        description="Recycles an expired request",
        parents=[
            blueprint_arg_parser,
            passphrase_arg_parser,
            tx_arg_parser,
        ],
    )
    parser_recycle.add_argument(
        "utxo",
        type=parse_tx_input,
        help="UTxO, that stores the request. Format: <transaction_id>#<index>",
    )
    parser_recycle.set_defaults(func=recycle_request)
    parser_recycle_all = subparsers.add_parser(
        "recycleall",
        help="Recycle all expired requests",
        description="Recycles all expired requests",
        parents=[
            blueprint_arg_parser,
            passphrase_arg_parser,
            tx_arg_parser,
        ],
    )
    parser_recycle_all.add_argument(
        "--limit",
        type=int,
        help="Maximum number of requests to recycle",
    )
    parser_recycle_all.set_defaults(func=recycle_all_requests)
    parser_fulfill = subparsers.add_parser(
        "fulfill",
        help="Fulfill a request",
        description="Fulfills a request",
        parents=[
            blueprint_arg_parser,
            passphrase_arg_parser,
            tx_arg_parser,
        ],
    )
    parser_fulfill.add_argument(
        "--oracle-url",
        default=os.environ.get("ORACLE_URL"),
        required="ORACLE_URL" not in os.environ,
        help="Base URL of the oracle API",
    )
    parser_fulfill.add_argument(
        "utxo",
        type=parse_tx_input,
        help="UTxO, that stores the request. Format: <transaction_id>#<index>",
    )
    parser_fulfill.set_defaults(func=run_fulfill_request_command)

    args = parser.parse_args()
    args.func(
        get_chain_context(),
        OperatorWallet.from_env(args.passphrase),
        Protocol.load(args.plutus_blueprint),
        args,
    )


@dataclass
class StoredRequest:
    utxo: UTxO
    request: OracleRequest

    @classmethod
    def from_utxo(cls, utxo: UTxO):
        return cls(
            utxo=utxo,
            request=OracleRequest.from_cbor(utxo.output.datum.cbor),
        )


@dataclass
class RequestRepository:
    wallet: OperatorWallet
    context: ChainContext
    protocol: Protocol

    def all(self) -> List[StoredRequest]:
        return [
            StoredRequest.from_utxo(utxo)
            for utxo in self.context.utxos(
                self.protocol.request_addr(self.context.network)
            )
        ]

    def find(self, tx_input: TransactionInput) -> Optional[StoredRequest]:
        return next(
            (
                StoredRequest.from_utxo(u)
                for u in self.context.utxos(
                    self.protocol.request_addr(self.context.network)
                )
                if u.input == tx_input
            ),
            None,
        )

    def add_tx(
        self,
        request: OracleRequest,
    ) -> Transaction:
        nw = self.context.network
        builder = TransactionBuilder(self.context)
        builder.add_input_address(self.wallet.request_treasury.addr(nw))

        min_lovelace_change_utxo = min_lovelace_post_alonzo(
            TransactionOutput(self.wallet.request_treasury.addr(nw), Value()),
            self.context,
        )
        min_lovelace_request_utxo = min_lovelace_post_alonzo(
            TransactionOutput(self.protocol.request_addr(nw), Value(), datum=request),
            self.context,
        )
        tx_out = TransactionOutput(
            self.protocol.request_addr(nw),
            Value(
                max(
                    min_lovelace_change_utxo + request.max_fee,
                    min_lovelace_request_utxo,
                )
            ),
            datum=request,
        )
        builder.add_output(tx_out)

        return builder.build_and_sign(
            [self.wallet.request_treasury.sk],
            change_address=self.wallet.request_treasury.addr(nw),
            collateral_change_address=self.wallet.request_treasury.addr(nw),
        )

    def recycle_tx(self, tx_input: TransactionInput):
        nw = self.context.network
        utxo = next(
            (
                u
                for u in self.context.utxos(self.protocol.request_addr(nw))
                if u.input == tx_input
            ),
            None,
        )

        if not utxo:
            return None

        builder = TransactionBuilder(self.context)
        builder.add_input_address(self.wallet.request_treasury.addr(nw))
        builder.add_script_input(
            utxo,
            try_refer_to_script(
                self.context, self.wallet, self.protocol.request_validator
            ),
            redeemer=Redeemer(data=Unit()),
        )

        builder.add_output(
            TransactionOutput(
                self.wallet.request_treasury.addr(nw),
                utxo.output.amount,
            )
        )

        return builder.build_and_sign(
            [self.wallet.request_treasury.sk],
            change_address=self.wallet.request_treasury.addr(nw),
            collateral_change_address=self.wallet.request_treasury.addr(nw),
            merge_change=True,
        )

    def recycle_all_tx(self, limit: int):
        nw = self.context.network

        now = int((datetime.now(timezone.utc)).timestamp())

        owner_pkh = bytes(self.wallet.request_treasury.vk.hash())
        requests = [
            r
            for r in self.all()
            if r.request.before < now and r.request.owner_pkh.value == owner_pkh
        ][0:limit]

        if not requests:
            return None

        builder = TransactionBuilder(self.context)
        builder.add_input_address(self.wallet.request_treasury.addr(nw))
        script = try_refer_to_script(
            self.context, self.wallet, self.protocol.request_validator
        )

        amount = Value(0)

        for r in requests:
            builder.add_script_input(
                r.utxo,
                script,
                redeemer=Redeemer(data=Unit()),
            )

            amount += r.utxo.output.amount

        builder.add_output(
            TransactionOutput(
                self.wallet.request_treasury.addr(nw),
                amount,
            )
        )

        return builder.build_and_sign(
            [self.wallet.request_treasury.sk],
            change_address=self.wallet.request_treasury.addr(nw),
            merge_change=True,
            auto_validity_start_offset=0,
        )


def list_requests(
    context: ChainContext,
    wallet: OperatorWallet,
    protocol: Protocol,
    args: Namespace,
):
    repo = RequestRepository(wallet=wallet, context=context, protocol=protocol)
    for request in repo.all():
        action_id = request.request.action.action.action_id()
        print(
            f"- UTxO:              {request.utxo.input.transaction_id}#{request.utxo.input.index}"
        )
        print_request(request.request, context.network, indent="  ")
        print("  Locked Lovelace:  ", request.utxo.output.amount.coin)


def run_add_request_command(
    context: ChainContext,
    wallet: OperatorWallet,
    protocol: Protocol,
    args: Namespace,
):
    request = create_request(
        context,
        wallet,
        protocol,
        parse_http_action_with_proof(args, args.oracle_pub_key),
        args.oracle_pool_id,
        args.oracle_pub_key,
        args.max_response,
        args.ttl,
    )

    print_request(request, context.network)

    repo = RequestRepository(wallet=wallet, context=context, protocol=protocol)
    signed_tx = repo.add_tx(request)

    handle_tx(
        signed_tx=signed_tx,
        context=context,
        args=args,
    )


def create_request(
    context: ChainContext,
    wallet: OperatorWallet,
    protocol: Protocol,
    action: HTTPActionWithProof,
    pool_id: bytes,
    oracle_pub_key: Optional[bytes],
    max_response_size: int,
    ttl: timedelta,
) -> OracleRequest:
    response_repo = ResponseRepository(
        wallet=wallet, context=context, protocol=protocol
    )
    pool_action_id = sha256(pool_id + action.action.action_id()).digest()

    after = datetime.now(timezone.utc)

    fee_response_slope = get_fee_slope(context.protocol_param)
    fee_intercept = get_fee_intercept(context.protocol_param)
    datum_intercept = get_datum_intercept(context.protocol_param)

    base_fee = fee_intercept + datum_intercept + RELAYER_FEE
    max_fee = fee_intercept + RELAYER_FEE + max_response_size * fee_response_slope
    if not response_repo.by_pool_action_id(pool_action_id):
        max_fee += datum_intercept

    return OracleRequest(
        action,
        ByteString(pool_id),
        ByteString(pool_action_id),
        int(after.timestamp()),
        int((after + ttl).timestamp()),
        ByteString(bytes(wallet.request_treasury.vk.hash())),
        ceil(base_fee),
        ceil(fee_response_slope),
        ceil(max_fee),
    )


def recycle_request(
    context: ChainContext,
    wallet: OperatorWallet,
    protocol: Protocol,
    args: Namespace,
):
    repo = RequestRepository(wallet=wallet, context=context, protocol=protocol)
    signed_tx = repo.recycle_tx(args.utxo)
    if not signed_tx:
        print("Request is not found")
        return

    handle_tx(signed_tx=signed_tx, context=context, args=args)


def recycle_all_requests(
    context: ChainContext,
    wallet: OperatorWallet,
    protocol: Protocol,
    args: Namespace,
):
    repo = RequestRepository(wallet=wallet, context=context, protocol=protocol)
    signed_tx = repo.recycle_all_tx(args.limit)
    if not signed_tx:
        print("No expired requests are found")
        return

    handle_tx(signed_tx=signed_tx, context=context, args=args)


def run_fulfill_request_command(
    context: ChainContext,
    wallet: OperatorWallet,
    protocol: Protocol,
    args: Namespace,
):
    repo = RequestRepository(wallet=wallet, context=context, protocol=protocol)
    request = repo.find(args.utxo)
    if not request:
        print("Request is not found")
        return

    client = SignerClient(args.oracle_url)
    oracle = find_oracle(
        context, wallet, protocol, client, request.request.pool_id.value
    )
    if not oracle:
        print("Oracle is not registered on-chain")
        return

    relayer = bytes(wallet.treasury.vk.hash())
    response = client.query(request.request.action, relayer)

    response_size = len(response.message.data.to_cbor())
    print("Oracle Response:")
    print("  Action ID:     ", response.message.action_id.hex())
    print("  Timestamp:     ", response.message.data.format_timestamp())
    print("  Error:         ", response.message.data.error)
    print("  Value:         ", response.message.data.format_value())
    print("  Relayer:       ", response.message.relayer.value.hex())
    print("  Data CBOR size:", response_size)

    signed_tx = fulfill_request(context, wallet, protocol, oracle, request, response)

    spent_ada = sum(
        utxo.output.amount.coin
        for utxo in builder.inputs
        if utxo.output.address == wallet.treasury.addr(nw)
    )
    received_ada = sum(
        out.amount.coin
        for out in signed_tx.transaction_body.outputs
        if out.address == wallet.treasury.addr(nw)
    )
    change = next(
        (
            out.amount.coin
            for out in signed_tx.transaction_body.outputs
            if out.address == wallet.request_treasury.addr(nw)
        ),
        0,
    )
    print("User spent:      ", request.utxo.output.amount.coin - change)
    print("User change:     ", change)

    print("Cardano tx fee:  ", signed_tx.transaction_body.fee)
    print("Relayer profit:  ", received_ada - spent_ada)

    handle_tx(signed_tx=signed_tx, context=context, args=args)


def find_oracle(
    context: ChainContext,
    wallet: OperatorWallet,
    protocol: Protocol,
    client: SignerClient,
    pool_id: bytes,
) -> Optional[RegisteredOracle]:
    public_key = client.public_key()
    oracle_repo = OracleRepository(wallet=wallet, context=context, protocol=protocol)
    return next(
        (
            o
            for o in oracle_repo.registered()
            if o.data.public_key == public_key
            if o.pools[0].id == pool_id
        ),
        None,
    )


def fulfill_request(
    context: ChainContext,
    wallet: OperatorWallet,
    protocol: Protocol,
    oracle: RegisteredOracle,
    request: StoredRequest,
    response: QuexResponse,
) -> Transaction:
    nw = context.network
    pool_action_id = oracle.pools[0].pool_action_id(response.message.action_id)

    builder = TransactionBuilder(context)
    builder.add_input_address(wallet.treasury.addr(nw))

    response_repo = ResponseRepository(
        wallet=wallet, context=context, protocol=protocol
    )

    response_tx_builder = ResponseTransactionBuilder(
        builder=builder, context=context, protocol=protocol
    )

    existing_responses = response_repo.by_pool_action_id(pool_action_id)

    response_tx_builder.add_token_inputs_and_outputs(
        existing_responses, pool_action_id, response
    )

    builder.reference_inputs.add(oracle.input)

    builder.add_script_input(
        request.utxo,
        try_refer_to_script(context, wallet, protocol.request_validator),
        redeemer=Redeemer(data=Unit()),
    )

    response_size = len(response.message.data.to_cbor())

    fee_response_slope = get_fee_slope(context.protocol_param)
    fee_intercept = get_fee_intercept(context.protocol_param)
    datum_intercept = get_datum_intercept(context.protocol_param)

    base_fee = fee_intercept + datum_intercept + RELAYER_FEE
    actual_fee = max(
        0,
        floor(
            base_fee
            + fee_response_slope * response_size
            - sum((r.utxo.output.amount.coin for r in existing_responses))
        ),
    )

    change = request.utxo.output.amount - Value(actual_fee)
    if change > 0:
        builder.add_output(
            TransactionOutput(
                wallet.request_treasury.addr(nw),
                change,
            )
        )

    return builder.build_and_sign(
        [wallet.treasury.sk],
        change_address=wallet.treasury.addr(nw),
        merge_change=True,
        collateral_change_address=wallet.treasury.addr(nw),
        auto_ttl_offset=min(
            int(oracle.data.response_validity_period.total_seconds() * 0.9), 10_000
        ),
    )


def print_request(request: OracleRequest, network: Network, indent: str = ""):
    action_id = request.action.action.action_id()
    print(f"{indent}Action ID:         {action_id.hex()}")
    print(f"{indent}Pool ID:           {request.pool_id.value.hex()}")
    print(f"{indent}Pool Action ID:    {request.pool_action_id.value.hex()}")
    print(f"{indent}URL:               {request.action.action.request.format_url()}")

    if request.action.action.request.headers:
        print(f"{indent}Headers:")
        for h in request.action.action.request.headers:
            print(f"{indent}  {h.key.value.decode()}: {h.value.value.decode()}")

    print(f"{indent}Filter:            {request.action.action.filter.value.decode()}")
    print(f"{indent}Schema:            {request.action.action.schema.value.decode()}")
    print(f"{indent}Valid After:       {request.format_after()}")
    print(f"{indent}Valid Before:      {request.format_before()}")
    print(
        f"{indent}Fee:               min({request.fee_per_response_byte} * size(response) + {request.base_fee}, {request.max_fee})"
    )
    print(
        f"{indent}Owner:             {Address(VerificationKeyHash(request.owner_pkh.value), network=network)}"
    )


REQUEST_VALIDATOR_MEM_RESPONSE_SLOPE = 0.26862522318578114
REQUEST_VALIDATOR_MEM_INTERCEPT = 2444955.1270897575
REQUEST_VALIDATOR_STEPS_RESPONSE_SLOPE = 28376.961085864274
REQUEST_VALIDATOR_STEPS_INTERCEPT = 607304434.1903505
RESPONSE_VALIDATOR_MEM_RESPONSE_SLOPE = 0.2662717091419963
RESPONSE_VALIDATOR_MEM_INTERCEPT = 1031963.3169128388
RESPONSE_VALIDATOR_STEPS_RESPONSE_SLOPE = 41384.99833630961
RESPONSE_VALIDATOR_STEPS_INTERCEPT = 310053093.94453
TRANSACTION_SIZE_RESPONSE_SLOPE = 2
TRANSACTION_SIZE_INTERCEPT = 10435
RESPONSE_DATUM_SIZE_INTERCEPT = 274


def get_fee_slope(pp: ProtocolParameters) -> float:
    return (
        pp.min_fee_coefficient * TRANSACTION_SIZE_RESPONSE_SLOPE
        + pp.coins_per_utxo_byte
        + pp.price_mem
        * (REQUEST_VALIDATOR_MEM_RESPONSE_SLOPE + RESPONSE_VALIDATOR_MEM_RESPONSE_SLOPE)
        + pp.price_step
        * (
            REQUEST_VALIDATOR_STEPS_RESPONSE_SLOPE
            + RESPONSE_VALIDATOR_STEPS_RESPONSE_SLOPE
        )
    )


def get_fee_intercept(pp: ProtocolParameters) -> float:
    return (
        pp.min_fee_coefficient * TRANSACTION_SIZE_INTERCEPT
        + pp.min_fee_constant
        + pp.price_mem
        * (REQUEST_VALIDATOR_MEM_INTERCEPT + RESPONSE_VALIDATOR_MEM_INTERCEPT)
        + pp.price_step
        * (REQUEST_VALIDATOR_STEPS_INTERCEPT + RESPONSE_VALIDATOR_STEPS_INTERCEPT)
    )


def get_datum_intercept(pp: ProtocolParameters) -> float:
    return pp.coins_per_utxo_byte * RESPONSE_DATUM_SIZE_INTERCEPT


if __name__ == "__main__":
    main()
