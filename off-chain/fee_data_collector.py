#!/usr/bin/env python
from datetime import timedelta
import os
import sys
from time import sleep

from dotenv import load_dotenv
from pycardano import ExecutionUnits, ChainContext, Transaction, TransactionInput, Unit

from http_action import create_http_action_with_proof
from models import QuexResponse
from networks import get_chain_context
from pending_requests import (
    create_request,
    find_oracle,
    fulfill_request,
    RequestRepository,
)
from protocol import Protocol
from signer_client import SignerClient
from wallet import OperatorWallet

SIZES = [
    0,
    16,
    32,
    48,
    64,
]

FILL = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"


def main():
    load_dotenv()
    context = get_chain_context()
    wallet = OperatorWallet.from_env("")
    protocol = Protocol.load("plutus.json")
    client = SignerClient(os.environ.get("ORACLE_URL"))
    pool_id = bytes.fromhex(
        "96dc3580d31151f2e8e50203f67e5c53f4eb630620cd695501339ba954657374526571756573744f7261636c65506f6f6c"
    )
    relayer = bytes(wallet.treasury.vk.hash())
    request_repo = RequestRepository(wallet=wallet, context=context, protocol=protocol)
    oracle = find_oracle(context, wallet, protocol, client, pool_id)
    if not oracle:
        print("No oracle", file=sys.stderr)
        return

    for s in SIZES:
        f = f'"{FILL[0:s]}"'
        action = create_http_action_with_proof(
            "GET",
            "https://api.binance.com/api/v3/ticker/price?symbol=ADAUSDT",
            headers=[],
            body=None,
            enc_url_suffix=None,
            enc_headers=[],
            enc_body=None,
            td_vk=None,
            filter_=f,
            schema="string",
        )

        request = create_request(
            context,
            wallet,
            protocol,
            action,
            pool_id,
            max_response_size=128,
            ttl=timedelta(minutes=5),
        )
        add_tx = request_repo.add_tx(request)
        context.submit_tx(add_tx)
        wait_tx(context, add_tx)
        stored_request = request_repo.find(TransactionInput(add_tx.id, 0))
        if not stored_request:
            print("ERROR: Request is not found after creation", file=sys.stderr)
            continue

        response = client.query(action, relayer)
        fulfill_tx = fulfill_request(
            context, wallet, protocol, oracle, stored_request, response
        )

        rv = fulfill_tx.transaction_witness_set.redeemer.values()
        request_ex_units = next(
            (v.ex_units for v in rv if isinstance(v.data, Unit)),
            ExecutionUnits(0, 0),
        )
        response_ex_units = next(
            (v.ex_units for v in rv if isinstance(v.data, QuexResponse)),
            ExecutionUnits(0, 0),
        )
        response_coin = next(
            (
                out.amount.coin
                for out in fulfill_tx.transaction_body.outputs
                if out.address == protocol.response_addr(context.network)
            ),
            0,
        )

        print(
            ",".join(
                [
                    str(x)
                    for x in [
                        len(response.message.data.to_cbor()),
                        fulfill_tx.transaction_body.fee,
                        response_coin,
                        request_ex_units.mem,
                        request_ex_units.steps,
                        response_ex_units.mem,
                        response_ex_units.steps,
                        len(fulfill_tx.to_cbor()),
                    ]
                ]
            )
        )

        with open(f"{len(response.message.data.to_cbor())}_tx.bin", "wb") as file:
            file.write(fulfill_tx.to_cbor())

        # context.submit_tx(fulfill_tx)
        # wait_tx(context, fulfill_tx)


def wait_tx(context: ChainContext, tx: Transaction):
    first_output = tx.transaction_body.outputs[0]
    utxo = None
    while not utxo:
        utxo = next(
            (
                u
                for u in context.utxos(first_output.address)
                if u.input.transaction_id == tx.id
            ),
            None,
        )
        sleep(5)


if __name__ == "__main__":
    main()
