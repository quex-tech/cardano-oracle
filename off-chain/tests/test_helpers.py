# SPDX-License-Identifier: Apache-2.0
# Copyright 2025 Quex Technologies
import secrets
import unittest
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import timedelta
from fractions import Fraction
from typing import DefaultDict, TypeVar, cast, override

from eth_keys import keys
from pycardano import (
    Address,
    AssetName,
    ChainContext,
    Datum,
    ExecutionUnits,
    HDWallet,
    Network,
    PlutusData,
    PlutusScript,
    ProtocolParameters,
    RawCBOR,
    RedeemerMap,
    ScriptHash,
    Transaction,
    TransactionId,
    TransactionInput,
    TransactionOutput,
    UTxO,
    Value,
    VerificationKeyHash,
)

from oracles import Oracle, OraclePool
from protocol import Validator
from wallet import OperatorWallet


def gen_tx_in() -> TransactionInput:
    return TransactionInput(TransactionId(secrets.token_bytes(32)), 0)


def gen_sk() -> keys.PrivateKey:
    return keys.PrivateKey(secrets.token_bytes(32))


def gen_pk() -> keys.PublicKey:
    return gen_sk().public_key


def gen_cs() -> ScriptHash:
    return ScriptHash(secrets.token_bytes(28))


def gen_tn() -> AssetName:
    return AssetName(secrets.token_bytes(32))


def gen_oracle() -> Oracle:
    return Oracle(gen_pk(), timedelta(minutes=15))


def gen_pool() -> OraclePool:
    return OraclePool(gen_cs(), gen_tn())


def gen_plutus_script() -> PlutusScript:
    return PlutusScript.from_version(3, secrets.token_bytes(64))


def gen_validator() -> Validator:
    return Validator(gen_plutus_script())


def to_raw_cbor(data: PlutusData) -> RawCBOR:
    return RawCBOR(data.to_cbor())


def ada(amount: int) -> int:
    return amount * 1_000_000


PROTOCOL_PARAMS = ProtocolParameters(
    min_fee_constant=155381,
    min_fee_coefficient=44,
    max_block_size=90112,
    max_tx_size=16384,
    max_block_header_size=1100,
    key_deposit=2000000,
    pool_deposit=500000000,
    pool_influence=Fraction(5404319552844595, 18014398509481984),
    monetary_expansion=Fraction(3458764513820541, 1152921504606846976),
    treasury_expansion=Fraction(3602879701896397, 18014398509481984),
    decentralization_param=None,  # type: ignore[arg-type]
    extra_entropy=None,  # type: ignore[arg-type]
    protocol_major_version=10,
    protocol_minor_version=0,
    min_utxo=None,  # type: ignore[arg-type]
    min_pool_cost=170000000,
    price_mem=Fraction(2078861587994221, 36028797018963968),
    price_step=Fraction(5320040990857835, 73786976294838206464),
    max_tx_ex_mem=16500000,
    max_tx_ex_steps=10000000000,
    max_block_ex_mem=72000000,
    max_block_ex_steps=20000000000,
    max_val_size=5000,
    collateral_percent=150,
    max_collateral_inputs=3,
    coins_per_utxo_word=34482,
    coins_per_utxo_byte=4310,
    cost_models={
        "PlutusV3": {
            "066": 38,
            "152": 213312,
            "154": 2,
            "156": 22588,
            "236": 64571,
        },
    },
    maximum_reference_scripts_size={"bytes": 204800},
    min_fee_reference_scripts={"base": 15.0, "range": 25600, "multiplier": 1.2},
)


@dataclass
class FakeChainContext(ChainContext):
    utxos_by_addr: DefaultDict[str, dict[TransactionInput, UTxO]] = field(
        default_factory=lambda: defaultdict(dict)
    )
    addr_by_tx_input: dict[TransactionInput, str] = field(default_factory=dict)

    @property
    def protocol_param(self) -> ProtocolParameters:
        return PROTOCOL_PARAMS

    @property
    def network(self) -> Network:
        return Network.MAINNET

    @property
    def epoch(self) -> int:
        return 1000

    @property
    def last_block_slot(self) -> int:
        return 100_000_000

    def _utxos(self, address: str) -> list[UTxO]:
        return list(self.utxos_by_addr.get(address, {}).values())

    def submit_tx(self, tx: Transaction) -> None:
        for tx_input in tx.transaction_body.inputs:
            addr = self.addr_by_tx_input[tx_input]
            del self.utxos_by_addr[addr][tx_input]
            del self.addr_by_tx_input[tx_input]

        for i, tx_out in enumerate(tx.transaction_body.outputs):
            self.add_utxo(tx_out.address, UTxO(TransactionInput(tx.id, i), tx_out))

    @override
    def evaluate_tx(self, tx: Transaction) -> dict[str, ExecutionUnits]:
        if not isinstance(tx.transaction_witness_set.redeemer, RedeemerMap):
            return {}
        return {
            f"{k.tag.name.lower()}:{k.index}": ExecutionUnits(1, 1)
            for k, v in tx.transaction_witness_set.redeemer.items()
        }

    def add_tx_out(self, address: Address, amount: Value, datum: Datum | None = None) -> None:
        self.add_utxo(address, UTxO(gen_tx_in(), TransactionOutput(address, amount, datum=datum)))

    def add_utxo(self, address: Address, utxo: UTxO) -> None:
        fix_datum(utxo.output)
        self.utxos_by_addr[str(address)][utxo.input] = utxo
        self.addr_by_tx_input[utxo.input] = str(address)


def fix_datum(tx_out: TransactionOutput) -> None:
    if isinstance(tx_out.datum, PlutusData):
        tx_out.datum = RawCBOR(tx_out.datum.to_cbor())


T = TypeVar("T")


class CardanoTestCase(unittest.TestCase):
    def setUp(self) -> None:
        self.context = FakeChainContext()
        self.wallet = OperatorWallet(HDWallet.from_mnemonic(mnemonic=HDWallet.generate_mnemonic()))
        self.nw = self.context.network
        self.context.add_tx_out(self.wallet.treasury.addr(self.nw), Value(ada(100)))

    def assertIsNotNoneT(self, value: T | None, msg: str | None = None) -> T:  # noqa: N802
        self.assertIsNotNone(value, msg)
        return cast("T", value)

    def to_addr(self, payment_part: VerificationKeyHash | ScriptHash) -> Address:
        return Address(payment_part, network=self.nw)
