-- SPDX-License-Identifier: Apache-2.0
-- Copyright 2025 Quex Technologies
{-# LANGUAGE ImportQualifiedPost #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE NoImplicitPrelude #-}

module Main where

import PlutusLedgerApi.V1.Crypto qualified as Crypto
import PlutusTx.Builtins (mkB, mkConstr, mkI, mkList, serialiseData)
import PlutusTx.Builtins.HasOpaque (stringToBuiltinByteStringHex)
import PlutusTx.IsData (UnsafeFromData, toBuiltinData, unsafeFromBuiltinData)
import PlutusTx.Prelude
import System.Exit (exitFailure, exitSuccess)
import Test.HUnit
import Prelude qualified as Haskell

serialiseCases :: [(BuiltinData, Haskell.String)]
serialiseCases =
  [ (mkI 0, "00"),
    (mkI 1, "01"),
    (mkI 2147483647, "1a7fffffff"),
    (mkI 2147483648, "1a80000000"),
    (mkI 4294967295, "1affffffff"),
    (mkI 4294967296, "1b0000000100000000"),
    (mkI 9223372036854775807, "1b7fffffffffffffff"),
    (mkI 9223372036854775808, "1b8000000000000000"),
    (mkI 18446744073709551615, "1bffffffffffffffff"),
    (mkI 18446744073709551616, "c249010000000000000000"),
    (mkI (-2147483648), "3a7fffffff"),
    (mkI (-2147483649), "3a80000000"),
    (mkI (-9223372036854775808), "3b7fffffffffffffff"),
    (mkI (-9223372036854775809), "3b8000000000000000"),
    (mkB $ encodeUtf8 $ "Hello, 世界", "4d48656c6c6f2c20e4b896e7958c"),
    (mkB $ encodeUtf8 $ "Exactly 64 bytes世界世界世界世界世界世界世界世界", "584045786163746c79203634206279746573e4b896e7958ce4b896e7958ce4b896e7958ce4b896e7958ce4b896e7958ce4b896e7958ce4b896e7958ce4b896e7958c"),
    (mkB $ encodeUtf8 $ "Exactly 65 bytes 世界世界世界世界世界世界世界世界", "5f584045786163746c7920363520627974657320e4b896e7958ce4b896e7958ce4b896e7958ce4b896e7958ce4b896e7958ce4b896e7958ce4b896e7958ce4b896e795418cff"),
    (mkConstr 1 [], "d87a80"),
    (mkConstr 0 [], "d87980"),
    (mkList [], "80"),
    (mkList [mkI 1], "9f01ff"),
    (mkConstr 0 [mkI 1], "d8799f01ff"),
    (mkConstr 0 [mkI 1, mkI 2], "d8799f0102ff"),
    (mkConstr 0 [mkI 1, mkConstr 0 [mkI 2]], "d8799f01d8799f02ffff"),
    (mkConstr 0 [mkI 1, mkList [mkI 2]], "d8799f019f02ffff"),
    (mkList [mkConstr 0 [mkI 1, mkList [mkI 2]], mkConstr 0 [mkI 3, mkList [mkI 4, mkI 5]]], "9fd8799f019f02ffffd8799f039f0405ffffff"),
    (mkList [mkConstr 0 [mkI 1, mkConstr 0 [mkI 2]], mkConstr 0 [mkI 3, mkConstr 0 [mkI 4]]], "9fd8799f01d8799f02ffffd8799f03d8799f04ffffff")
  ]

serialiseTests :: Test
serialiseTests = TestList $ map mkSerialiseTest serialiseCases

mkSerialiseTest :: (BuiltinData, Haskell.String) -> Test
mkSerialiseTest (d, expectedHex) =
  TestCase $ assertEqual label (stringToBuiltinByteStringHex expectedHex) (serialiseData d)
  where
    label = Haskell.show d ++ " must serialise to 0x" ++ expectedHex

unsafeFromBuiltinDataTests :: Test
unsafeFromBuiltinDataTests =
  TestList
    [ mkUnsafeFromBuiltinDataTest (mkConstr 1 []) True,
      mkUnsafeFromBuiltinDataTest (mkConstr 0 []) False,
      mkUnsafeFromBuiltinDataTest (mkConstr 0 [mkI 1, mkI 2]) (1 :: Integer, 2 :: Integer),
      mkUnsafeFromBuiltinDataTest (mkB $ encodeUtf8 $ "Hello, 世界") (encodeUtf8 "Hello, 世界")
    ]

mkUnsafeFromBuiltinDataTest :: (UnsafeFromData a, Haskell.Eq a, Haskell.Show a) => BuiltinData -> a -> Test
mkUnsafeFromBuiltinDataTest d expected =
  TestCase $ assertEqual label expected (unsafeFromBuiltinData d)
  where
    label = Haskell.show d ++ " must unsafeFromBuiltinData to " ++ Haskell.show expected

verifyEcdsaSecp256k1SignatureTests :: Test
verifyEcdsaSecp256k1SignatureTests =
  mkVerifyEcdsaSecp256k1SignatureTest "02792bb2ae2b769acf2b971f368d7d5cbed9d54a889c30ae7cd2e6a0321bfbcfee" "d886efed2048a920b411d5d9b25bffdd75dbdfc00c606ef21917be2483f60939" "c1c19c195fb499e8b562ff14f8d620a56ad9108a9978b15747c46e68f7410f1a75828cff2ae1d9a631585febf5985cfbd4e62f887f9d9db799b194a43e9d3f63"

mkVerifyEcdsaSecp256k1SignatureTest :: Haskell.String -> Haskell.String -> Haskell.String -> Test
mkVerifyEcdsaSecp256k1SignatureTest pubKeyHex hashHex signatureHex =
  TestCase $ assertBool "must be valid" (verifyEcdsaSecp256k1Signature pubKey hash signature)
  where
    pubKey = stringToBuiltinByteStringHex pubKeyHex
    hash = stringToBuiltinByteStringHex hashHex
    signature = stringToBuiltinByteStringHex signatureHex

main = runTestTT $ TestList [serialiseTests, unsafeFromBuiltinDataTests]
