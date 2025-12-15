# SPDX-License-Identifier: Apache-2.0
# Copyright 2025 Quex Technologies
import unittest

from pycardano import Value

from oracles import (
    Oracle,
    OraclePool,
    PlutusOracle,
    PrivateOracleRepository,
    SingleOracleRepository,
    find_oracle_by_pk_pool_id,
    get_registered_oracles_at,
)
from tests.test_helpers import (
    CardanoTestCase,
    ada,
    gen_cs,
    gen_oracle,
    gen_pk,
    gen_pool,
    gen_tn,
    gen_validator,
    to_raw_cbor,
)


class TryFromPlutusDataTests(unittest.TestCase):
    def test_round_trip(self) -> None:
        oracle = gen_oracle()

        plutus_oracle = oracle.to_plutus_data()
        reconstructed = Oracle.try_from_plutus_data(plutus_oracle)

        self.assertIsNotNone(reconstructed)
        self.assertEqual(
            reconstructed.public_key.to_compressed_bytes(),
            oracle.public_key.to_compressed_bytes(),
        )
        self.assertEqual(reconstructed.response_validity_period, oracle.response_validity_period)

    def test_when_invalid_public_key_returns_none(self) -> None:
        invalid_plutus_oracle = PlutusOracle(
            public_key=b"\x02",
            response_validity_period_ms=1234,
        )

        self.assertIsNone(Oracle.try_from_plutus_data(invalid_plutus_oracle))


class PrivateOracleRepositoryTests(CardanoTestCase):
    def test_add_tx_registers_oracle(self) -> None:
        repo = PrivateOracleRepository(self.context)
        oracle = gen_oracle()
        self.context.submit_tx(
            repo.add_tx(
                oracle,
                "PoolName",
                self.wallet.treasury,
                self.wallet.oracles.vk.hash(),
            )
        )
        registered = list(
            get_registered_oracles_at(self.context, [self.wallet.oracles.addr(self.nw)])
        )
        self.assertEqual(len(registered), 1)
        self.assertEqual(registered[0].data, oracle)

    def test_delete_tx_removes_oracle(self) -> None:
        repo = PrivateOracleRepository(self.context)
        oracle = gen_oracle()
        self.context.submit_tx(
            repo.add_tx(oracle, "PoolName", self.wallet.treasury, self.wallet.oracles.vk.hash())
        )
        registered = list(
            get_registered_oracles_at(self.context, [self.wallet.oracles.addr(self.nw)])
        )
        self.assertEqual(len(registered), 1)
        delete_tx = repo.delete_tx(registered[0].input, self.wallet.treasury, self.wallet.oracles)
        delete_tx = self.assertIsNotNoneT(delete_tx)
        self.context.submit_tx(delete_tx)
        registered = list(
            get_registered_oracles_at(self.context, [self.wallet.oracles.addr(self.nw)])
        )
        self.assertEqual(len(registered), 0)


class SingleOracleRepositoryTests(CardanoTestCase):
    def test_add_tx_registers_oracle(self) -> None:
        validator = gen_validator()
        repo = SingleOracleRepository(self.context, validator)
        oracle = gen_oracle()
        self.context.submit_tx(repo.add_tx(oracle, self.wallet.treasury))
        registered = list(get_registered_oracles_at(self.context, [validator.addr(self.nw)]))
        self.assertEqual(len(registered), 1)
        self.assertEqual(registered[0].data, oracle)


class GetRegisteredOraclesAtTests(CardanoTestCase):
    def test_returns_oracles(self) -> None:
        oracle = gen_oracle()
        private_pool = gen_pool()
        validator_hash = gen_cs()
        single_pool = OraclePool(currency_symbol=validator_hash, token_name=gen_tn())

        self.context.add_tx_out(
            self.to_addr(self.wallet.oracles.vk.hash()),
            Value(ada(2), private_pool.assets),
            datum=to_raw_cbor(oracle.to_plutus_data()),
        )

        self.context.add_tx_out(
            self.to_addr(validator_hash),
            Value(ada(2), single_pool.assets),
            datum=to_raw_cbor(oracle.to_plutus_data()),
        )

        registered = list(
            get_registered_oracles_at(
                self.context,
                [self.wallet.oracles.addr(self.nw), self.to_addr(validator_hash)],
            )
        )

        self.assertEqual(len(registered), 2)
        pool_ids = {r.pool.id for r in registered}
        self.assertSetEqual(pool_ids, {private_pool.id, single_pool.id})
        for entry in registered:
            self.assertEqual(
                entry.data.public_key.to_compressed_bytes(),
                oracle.public_key.to_compressed_bytes(),
            )
            self.assertEqual(entry.data.response_validity_period, oracle.response_validity_period)

    def test_skips_invalid_utxos(self) -> None:
        oracle = gen_oracle()
        pool = gen_pool()
        address = self.wallet.oracles.addr(self.nw)

        self.context.add_tx_out(
            address,
            Value(ada(3)),
            datum=to_raw_cbor(oracle.to_plutus_data()),
        )

        self.context.add_tx_out(
            address,
            Value(ada(3), pool.assets),
            datum=oracle.to_plutus_data().to_cbor(),
        )

        registered = list(
            get_registered_oracles_at(
                self.context,
                [self.wallet.oracles.addr(self.nw)],
            )
        )

        self.assertEqual(registered, [])


class FindOracleByPkPoolIdTests(CardanoTestCase):
    def test_return_oracle_when_exists(self) -> None:
        oracle = gen_oracle()
        pool = gen_pool()
        address = self.to_addr(self.wallet.oracles.vk.hash())
        self.context.add_tx_out(
            address, Value(ada(2), pool.assets), datum=to_raw_cbor(oracle.to_plutus_data())
        )

        result = find_oracle_by_pk_pool_id(
            self.context,
            oracle.public_key,
            pool.id,
            [self.wallet.oracles.addr(self.nw)],
        )

        result = self.assertIsNotNoneT(result)
        self.assertEqual(result.pool.id, pool.id)
        self.assertEqual(result.data, oracle)

    def test_returns_none_when_no_oracle(self) -> None:
        oracle = gen_oracle()
        pool = gen_pool()
        address = self.to_addr(self.wallet.oracles.vk.hash())
        self.context.add_tx_out(
            address, Value(ada(2), pool.assets), datum=to_raw_cbor(oracle.to_plutus_data())
        )

        addrs = [self.wallet.oracles.addr(self.nw)]

        self.assertIsNone(
            find_oracle_by_pk_pool_id(self.context, oracle.public_key, gen_pool().id, addrs)
        )

        self.assertIsNone(find_oracle_by_pk_pool_id(self.context, gen_pk(), pool.id, addrs))
