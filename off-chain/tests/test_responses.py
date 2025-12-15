# SPDX-License-Identifier: Apache-2.0
# Copyright 2025 Quex Technologies
import secrets
import unittest

from pycardano import (
    MultiAsset,
    TransactionBuilder,
    TransactionOutput,
    UTxO,
    Value,
)
from pycardano.serialization import ByteString, RawCBOR

from models import DataItem, FixedRawPlutusData, QuexMessage, QuexResponse
from responses import ResponseTransactionBuilder, StoredResponse
from tests.test_helpers import CardanoTestCase, ada, gen_tx_in, gen_validator


class ResponseTransactionBuilderTests(CardanoTestCase):
    def setUp(self) -> None:
        super().setUp()
        self.validator = gen_validator()
        self.builder = TransactionBuilder(self.context)
        self.response_builder = ResponseTransactionBuilder(
            builder=self.builder,
            context=self.context,
            validator=self.validator,
        )
        self.response = QuexResponse(
            message=QuexMessage(
                action_id=secrets.token_bytes(32),
                data=DataItem(
                    timestamp=0,
                    error=0,
                    value=FixedRawPlutusData.from_cbor(b"\xa0"),
                ),
                relayer=ByteString(bytes(self.wallet.treasury.vk.hash())),
            ),
            signature=ByteString(secrets.token_bytes(64)),
        )
        self.pool_action_id = secrets.token_bytes(32)
        self.assets = MultiAsset.from_primitive(
            {bytes(self.validator.currency_symbol): {self.pool_action_id: 1}}
        )

    def test_mints_token_and_adds_output_when_no_existing_responses(self) -> None:
        self.response_builder.add_token_inputs_and_outputs([], self.pool_action_id, self.response)

        self.assertEqual(self.builder.mint, self.assets)
        self.assertEqual(len(self.builder.outputs), 1)
        tx_out = self.builder.outputs[0]
        self.assertEqual(tx_out.address, self.validator.addr(self.nw))
        self.assertEqual(tx_out.amount.multi_asset, self.assets)
        self.assertEqual(tx_out.datum, self.response.message.data)

    def test_consumes_single_existing_response_without_mint(self) -> None:
        existing = [self._stored_response()]

        self.response_builder.add_token_inputs_and_outputs(
            existing, self.pool_action_id, self.response
        )

        self.assertIsNone(self.builder.mint)
        self.assertEqual(len(self.builder._inputs_to_scripts), 1)
        self.assertEqual(len(self.builder.outputs), 1)

    def test_burns_extra_tokens_when_multiple_responses_exist(self) -> None:
        existing = [self._stored_response(), self._stored_response()]

        self.response_builder.add_token_inputs_and_outputs(
            existing, self.pool_action_id, self.response
        )

        expected_burn = MultiAsset.from_primitive(
            {bytes(self.validator.currency_symbol): {self.pool_action_id: -1}}
        )
        self.assertEqual(self.builder.mint, expected_burn)
        self.assertEqual(len(self.builder._inputs_to_scripts), 2)

    def _stored_response(self) -> StoredResponse:
        return StoredResponse(
            utxo=UTxO(
                gen_tx_in(),
                TransactionOutput(
                    self.validator.addr(self.nw),
                    Value(ada(2), self.assets),
                    datum=RawCBOR(self.response.message.data.to_cbor()),
                ),
            ),
            data=self.response.message.data,
            pool_action_id=self.pool_action_id,
        )


if __name__ == "__main__":
    unittest.main()
