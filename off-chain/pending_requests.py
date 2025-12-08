#!/usr/bin/env python
import os
from argparse import ArgumentParser, Namespace
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from hashlib import sha256
from math import ceil

from dotenv import load_dotenv
from ecdsa import SECP256k1, VerifyingKey
from pycardano import (
    Address,
    ChainContext,
    Network,
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
)
from pycardano.serialization import ByteString

from http_action import http_action_arg_parser, parse_http_action_with_proof
from models import (
    HTTPActionWithProof,
    OracleRequest,
    QuexResponse,
)
from networks import get_chain_context
from oracles import RegisteredOracle, find_oracle_by_pk_pool_id
from protocol import Protocol, Validator
from responses import ResponseRepository, ResponseTransactionBuilder
from scripts import try_refer_to_script
from signer_client import SignerClient
from utils import (
    blueprint_arg_parser,
    handle_tx,
    parse_tx_input,
    passphrase_arg_parser,
    try_from_tx_output,
    tx_arg_parser,
)
from wallet import OperatorWallet, Wallet

CARDANO_FEE_BUFFER = 1_000_000
RELAYER_REWARD = 50_000
RESPONSE_DATUM_SIZE_INTERCEPT = 274


def main() -> None:
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
        type=lambda x: VerifyingKey.from_string(bytes.fromhex(x.removeprefix("0x")), SECP256k1),
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
        help="TTL of the request in minutes."
        " After it expires, author can reclaim funds. Default: 60",
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
    def try_from_utxo(cls, utxo: UTxO):
        request = try_from_tx_output(OracleRequest, utxo.output)
        if not request:
            return None

        return cls(
            utxo=utxo,
            request=request,
        )


@dataclass
class RequestRepository:
    context: ChainContext
    validator: Validator

    def all(self) -> list[StoredRequest]:
        return [
            sr
            for sr in (
                StoredRequest.try_from_utxo(utxo)
                for utxo in self.context.utxos(self.validator.addr(self.context.network))
            )
            if sr
        ]

    def find(self, tx_input: TransactionInput) -> StoredRequest | None:
        return next(
            (
                StoredRequest.try_from_utxo(u)
                for u in self.context.utxos(self.validator.addr(self.context.network))
                if u.input == tx_input
            ),
            None,
        )

    def add_tx(self, request: OracleRequest, wallet: Wallet) -> Transaction:
        nw = self.context.network
        builder = TransactionBuilder(self.context)
        builder.add_input_address(wallet.addr(nw))

        min_lovelace_change_utxo = min_lovelace_post_alonzo(
            TransactionOutput(wallet.addr(nw), Value()),
            self.context,
        )
        min_lovelace_request_utxo = min_lovelace_post_alonzo(
            TransactionOutput(self.validator.addr(nw), Value(), datum=request),
            self.context,
        )
        tx_out = TransactionOutput(
            self.validator.addr(nw),
            Value(
                max(
                    min_lovelace_change_utxo + request.max_cost,
                    min_lovelace_request_utxo,
                )
            ),
            datum=request,
        )
        builder.add_output(tx_out)

        return builder.build_and_sign(
            [wallet.sk],
            change_address=wallet.addr(nw),
            collateral_change_address=wallet.addr(nw),
        )

    def recycle_tx(
        self,
        tx_input: TransactionInput,
        wallet: Wallet,
        library_pkh: VerificationKeyHash | None = None,
    ) -> Transaction | None:
        nw = self.context.network
        utxo = next(
            (u for u in self.context.utxos(self.validator.addr(nw)) if u.input == tx_input),
            None,
        )

        if not utxo:
            return None

        builder = TransactionBuilder(self.context)
        builder.add_input_address(wallet.addr(nw))
        builder.add_script_input(
            utxo,
            try_refer_to_script(self.context, library_pkh, self.validator.script),
            redeemer=Redeemer(data=Unit()),
        )

        builder.add_output(
            TransactionOutput(
                wallet.addr(nw),
                utxo.output.amount,
            )
        )

        return builder.build_and_sign(
            [wallet.sk],
            change_address=wallet.addr(nw),
            collateral_change_address=wallet.addr(nw),
            merge_change=True,
        )

    def recycle_all_tx(
        self,
        limit: int,
        wallet: Wallet,
        library_pkh: VerificationKeyHash | None = None,
    ) -> Transaction | None:
        nw = self.context.network

        now = int((datetime.now(UTC)).timestamp())

        owner_pkh = bytes(wallet.vk.hash())
        requests = [
            r
            for r in self.all()
            if r.request.before < now and r.request.owner_pkh.value == owner_pkh
        ][0:limit]

        if not requests:
            return None

        builder = TransactionBuilder(self.context)
        builder.add_input_address(wallet.addr(nw))
        script = try_refer_to_script(self.context, library_pkh, self.validator.script)

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
                wallet.addr(nw),
                amount,
            )
        )

        return builder.build_and_sign(
            [wallet.sk],
            change_address=wallet.addr(nw),
            collateral_change_address=wallet.addr(nw),
            merge_change=True,
            auto_validity_start_offset=0,
        )


def list_requests(
    context: ChainContext,
    _: OperatorWallet,
    protocol: Protocol,
    __: Namespace,
) -> None:
    repo = RequestRepository(
        context=context,
        validator=protocol.request_validator,
    )
    for request in repo.all():
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
) -> None:
    request = create_request(
        context,
        protocol.response_validator,
        parse_http_action_with_proof(args, args.oracle_pub_key),
        args.oracle_pool_id,
        args.max_response,
        args.ttl,
        wallet.request_treasury.vk.hash(),
    )

    print_request(request, context.network)

    repo = RequestRepository(
        context=context,
        validator=protocol.request_validator,
    )
    signed_tx = repo.add_tx(request, wallet.request_treasury)

    handle_tx(
        signed_tx=signed_tx,
        context=context,
        args=args,
    )


def create_request(
    context: ChainContext,
    response_validator: Validator,
    action: HTTPActionWithProof,
    pool_id: bytes,
    max_response_size: int,
    ttl: timedelta,
    owner_pkh: VerificationKeyHash,
) -> OracleRequest:
    response_repo = ResponseRepository(context=context, validator=response_validator)
    pool_action_id = sha256(pool_id + action.action.action_id()).digest()

    after = datetime.now(UTC)

    max_cost = (
        CARDANO_FEE_BUFFER
        + RELAYER_REWARD
        + max_response_size * context.protocol_param.coins_per_utxo_byte
    )
    if not response_repo.by_pool_action_id(pool_action_id):
        max_cost += RESPONSE_DATUM_SIZE_INTERCEPT * context.protocol_param.coins_per_utxo_byte

    return OracleRequest(
        action,
        ByteString(pool_id),
        ByteString(pool_action_id),
        int(after.timestamp()),
        int((after + ttl).timestamp()),
        ByteString(bytes(owner_pkh)),
        RELAYER_REWARD,
        context.protocol_param.coins_per_utxo_byte,
        ceil(max_cost),
    )


def recycle_request(
    context: ChainContext,
    wallet: OperatorWallet,
    protocol: Protocol,
    args: Namespace,
) -> None:
    repo = RequestRepository(
        context=context,
        validator=protocol.request_validator,
    )
    signed_tx = repo.recycle_tx(
        args.utxo, wallet.request_treasury, library_pkh=wallet.library.vk.hash()
    )
    if not signed_tx:
        print("Request is not found")
        return

    handle_tx(signed_tx=signed_tx, context=context, args=args)


def recycle_all_requests(
    context: ChainContext,
    wallet: OperatorWallet,
    protocol: Protocol,
    args: Namespace,
) -> None:
    repo = RequestRepository(
        context=context,
        validator=protocol.request_validator,
    )
    signed_tx = repo.recycle_all_tx(
        args.limit, wallet.request_treasury, library_pkh=wallet.library.vk.hash()
    )
    if not signed_tx:
        print("No expired requests are found")
        return

    handle_tx(signed_tx=signed_tx, context=context, args=args)


def run_fulfill_request_command(
    context: ChainContext,
    wallet: OperatorWallet,
    protocol: Protocol,
    args: Namespace,
) -> None:
    repo = RequestRepository(
        context=context,
        validator=protocol.request_validator,
    )
    request = repo.find(args.utxo)
    if not request:
        print("Request is not found")
        return

    client = SignerClient(args.oracle_url)
    public_key = client.public_key()
    oracle = find_oracle_by_pk_pool_id(
        context,
        public_key,
        request.request.pool_id.value,
        [wallet.oracles.vk.hash(), protocol.single_oracle_pool_validator.currency_symbol],
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

    signed_tx = fulfill_request(
        context,
        wallet.treasury,
        protocol.response_validator,
        oracle,
        request,
        response,
        library_pkh=wallet.library.vk.hash(),
    )

    change = next(
        (
            out.amount.coin
            for out in signed_tx.transaction_body.outputs
            if out.address == wallet.request_treasury.addr(context.network)
        ),
        0,
    )
    print("User spent:      ", request.utxo.output.amount.coin - change)
    print("User change:     ", change)

    print("Cardano tx fee:  ", signed_tx.transaction_body.fee)

    handle_tx(signed_tx=signed_tx, context=context, args=args)


def fulfill_request(
    context: ChainContext,
    wallet: Wallet,
    response_validator: Validator,
    oracle: RegisteredOracle,
    request: StoredRequest,
    response: QuexResponse,
    library_pkh: VerificationKeyHash | None = None,
) -> Transaction:
    nw = context.network
    pool_action_id = oracle.pool.pool_action_id(response.message.action_id)

    builder = TransactionBuilder(context)
    builder.add_input_address(wallet.addr(nw))

    response_repo = ResponseRepository(context=context, validator=response_validator)

    response_tx_builder = ResponseTransactionBuilder(
        builder=builder, context=context, validator=response_validator
    )

    existing_responses = response_repo.by_pool_action_id(pool_action_id)

    response_tx_builder.add_token_inputs_and_outputs(existing_responses, pool_action_id, response)

    builder.reference_inputs.add(oracle.input)

    builder.add_script_input(
        request.utxo,
        try_refer_to_script(context, library_pkh, response_validator.script),
        redeemer=Redeemer(data=Unit()),
    )

    response_size = len(response.message.data.to_cbor())

    min_cost = (
        RELAYER_REWARD
        + 0
        + context.protocol_param.coins_per_utxo_byte
        * (RESPONSE_DATUM_SIZE_INTERCEPT + response_size)
        - sum(r.utxo.output.amount.coin for r in existing_responses)
    )
    capped_min_cost = max(0, min(request.request.max_cost, min_cost))
    max_change = request.utxo.output.amount.coin - capped_min_cost
    owner_addr = Address(
        payment_part=VerificationKeyHash(request.request.owner_pkh.value), network=nw
    )
    builder.add_output(
        TransactionOutput(
            owner_addr,
            Value(max_change),
        )
    )

    tx = builder.build_and_sign(
        [wallet.sk],
        change_address=wallet.addr(nw),
        merge_change=True,
        collateral_change_address=wallet.addr(nw),
        auto_ttl_offset=min(
            int(oracle.data.response_validity_period.total_seconds() * 0.9), 10_000
        ),
    )

    real_cost = min_cost + tx.transaction_body.fee
    capped_real_cost = max(0, real_cost)
    real_change = request.utxo.output.amount.coin - capped_real_cost
    change_output = next(o for o in builder.outputs if o.address == owner_addr)
    change_output.amount = Value(real_change)

    builder._should_estimate_execution_units = False

    return builder.build_and_sign(
        [wallet.sk],
        change_address=wallet.addr(nw),
        merge_change=True,
        collateral_change_address=wallet.addr(nw),
        auto_ttl_offset=min(
            int(oracle.data.response_validity_period.total_seconds() * 0.9), 10_000
        ),
    )


def print_request(request: OracleRequest, network: Network, indent: str = "") -> None:
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
        f"{indent}Fee:               min("
        f"({request.coin_per_utxo_byte} * ({RESPONSE_DATUM_SIZE_INTERCEPT} + size(response))"
        f" + {request.reward} + fee"
        f", {request.max_cost})"
    )
    owner = Address(VerificationKeyHash(request.owner_pkh.value), network=network)
    print(f"{indent}Owner:             {owner}")


if __name__ == "__main__":
    main()
