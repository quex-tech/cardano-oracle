#!/usr/bin/env python
from argparse import ArgumentParser, Namespace
from base64 import b64encode
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import os
from typing import List, Optional

from dotenv import load_dotenv
from ecdsa import SECP256k1, VerifyingKey
from pycardano import (
    ChainContext,
    MultiAsset,
    PlutusData,
    Redeemer,
    Transaction,
    TransactionBuilder,
    TransactionInput,
    TransactionOutput,
    Unit,
    UTxO,
    Value,
)
from pycardano.serialization import ByteString, default_encoder

from http_action import http_action_arg_parser, parse_http_action_with_proof
from models import (
    OracleRequest,
    HTTPActionWithProof,
    OracleRequestParameters,
    AssetClass,
    TimeRange,
)
from networks import get_chain_context
from oracles import OracleRepository
from protocol import Protocol
from responses import ResponseRepository, ResponseTransactionBuilder
from signer_client import SignerClient
from utils import (
    blueprint_arg_parser,
    handle_tx,
    passphrase_arg_parser,
    tx_arg_parser,
    parse_tx_input,
)
from wallet import OraclePoolOwnerWallet


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
    parser_add.set_defaults(func=add_request)
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
    parser_fulfill.set_defaults(func=fulfill_request)

    args = parser.parse_args()
    args.func(
        get_chain_context(),
        OraclePoolOwnerWallet.from_env(args.passphrase),
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
    wallet: OraclePoolOwnerWallet
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
        action: HTTPActionWithProof,
        pool_id: bytes,
        after: datetime,
        before: datetime,
    ) -> Transaction:
        nw = self.context.network
        builder = TransactionBuilder(self.context)
        builder.add_input_address(self.wallet.treasury.addr(nw))

        params = OracleRequestParameters(
            pool_id=AssetClass.from_bytes(pool_id),
            time_range=TimeRange(
                start=int(after.timestamp()), end=int(before.timestamp())
            ),
            pub_key_hash=ByteString(bytes(self.wallet.treasury.vk.hash())),
        )

        request = OracleRequest(action, params)

        builder.add_output(
            TransactionOutput(
                self.protocol.request_addr(nw),
                Value(3_000_000),
                datum=request,
            )
        )

        return builder.build_and_sign(
            [self.wallet.treasury.sk],
            change_address=self.wallet.treasury.addr(nw),
            collateral_change_address=self.wallet.treasury.addr(nw),
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
        builder.add_input_address(self.wallet.treasury.addr(nw))
        builder.add_script_input(
            utxo, self.protocol.request_validator, redeemer=Redeemer(data=Unit())
        )
        builder.add_output(
            TransactionOutput(
                self.wallet.treasury.addr(nw),
                utxo.output.amount,
            )
        )

        return builder.build_and_sign(
            [self.wallet.treasury.sk],
            change_address=self.wallet.treasury.addr(nw),
        )


def list_requests(
    context: ChainContext,
    wallet: OraclePoolOwnerWallet,
    protocol: Protocol,
    args: Namespace,
):
    repo = RequestRepository(wallet=wallet, context=context, protocol=protocol)
    for request in repo.all():
        action_id = request.request.action.action.action_id()
        pool_id = request.request.parameters.pool_id
        print(
            f"- UTxO:             {request.utxo.input.transaction_id}#{request.utxo.input.index}"
        )
        print("  Action ID:       ", action_id.hex())
        print("  Pool ID:         ", bytes(pool_id).hex())
        print(
            "  Pool Action ID:  ",
            pool_id.pool_action_id(action_id).hex(),
        )
        print("  URL:             ", request.request.action.action.request.format_url())
        print(
            "  Filter:          ", request.request.action.action.filter.value.decode()
        )
        print(
            "  Schema:          ", request.request.action.action.schema.value.decode()
        )
        print(
            "  Valid After:     ", request.request.parameters.time_range.format_start()
        )
        print("  Valid Before:    ", request.request.parameters.time_range.format_end())
        print(
            "  Owner:           ", request.request.parameters.pub_key_hash.value.hex()
        )
        print("  Locked Lovelace: ", request.utxo.output.amount.coin)


def add_request(
    context: ChainContext,
    wallet: OraclePoolOwnerWallet,
    protocol: Protocol,
    args: Namespace,
):
    repo = RequestRepository(wallet=wallet, context=context, protocol=protocol)
    action = parse_http_action_with_proof(args, args.oracle_pub_key)

    after = datetime.now(timezone.utc)

    signed_tx = repo.add_tx(
        action, args.oracle_pool_id, after, after + timedelta(hours=1)
    )

    handle_tx(
        signed_tx=signed_tx,
        context=context,
        args=args,
    )


def recycle_request(
    context: ChainContext,
    wallet: OraclePoolOwnerWallet,
    protocol: Protocol,
    args: Namespace,
):
    repo = RequestRepository(wallet=wallet, context=context, protocol=protocol)
    signed_tx = repo.recycle_tx(args.utxo)
    if not signed_tx:
        print("Request is not found")
        return

    handle_tx(signed_tx=signed_tx, context=context, args=args)


def fulfill_request(
    context: ChainContext,
    wallet: OraclePoolOwnerWallet,
    protocol: Protocol,
    args: Namespace,
):
    repo = RequestRepository(wallet=wallet, context=context, protocol=protocol)
    request = repo.find(args.utxo)
    if not request:
        print("Request is not found")
        return

    client = SignerClient(args.oracle_url)
    public_key = client.public_key()

    oracle_repo = OracleRepository(wallet=wallet, context=context, protocol=protocol)
    oracle = next(
        (
            o
            for o in oracle_repo.registered()
            if o.data.public_key == public_key
            if o.pools[0].id == bytes(request.request.parameters.pool_id)
        ),
        None,
    )
    if not oracle:
        print("Oracle is not registered on-chain")
        return

    relayer = bytes(wallet.treasury.vk.hash())
    response = client.query(request.request.action, relayer)

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

    response_tx_builder.add_token_inputs_and_outputs(
        response_repo.by_pool_action_id(pool_action_id), pool_action_id, response
    )

    builder.reference_inputs.add(oracle.input)

    builder.add_script_input(
        request.utxo, protocol.request_validator, redeemer=Redeemer(data=Unit())
    )

    builder.add_output(
        TransactionOutput(
            wallet.treasury.addr(nw),
            request.utxo.output.amount,
        )
    )

    signed_tx = builder.build_and_sign(
        [wallet.treasury.sk],
        change_address=wallet.treasury.addr(nw),
        collateral_change_address=wallet.treasury.addr(nw),
        auto_ttl_offset=min(
            int(oracle.data.response_validity_period.total_seconds() * 0.9), 10_000
        ),
    )

    handle_tx(signed_tx=signed_tx, context=context, args=args)


if __name__ == "__main__":
    main()
