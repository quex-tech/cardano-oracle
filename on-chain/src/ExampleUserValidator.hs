-- SPDX-License-Identifier: Apache-2.0
-- Copyright 2025 Quex Technologies
{-# LANGUAGE DataKinds #-}
{-# LANGUAGE DerivingStrategies #-}
{-# LANGUAGE FlexibleInstances #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE ImportQualifiedPost #-}
{-# LANGUAGE MultiParamTypeClasses #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE PatternSynonyms #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE Strict #-}
{-# LANGUAGE TemplateHaskell #-}
{-# LANGUAGE TypeApplications #-}
{-# LANGUAGE UndecidableInstances #-}
{-# LANGUAGE ViewPatterns #-}
{-# LANGUAGE NoImplicitPrelude #-}
{-# OPTIONS_GHC -fno-full-laziness #-}
{-# OPTIONS_GHC -fno-ignore-interface-pragmas #-}
{-# OPTIONS_GHC -fno-omit-interface-pragmas #-}
{-# OPTIONS_GHC -fno-spec-constr #-}
{-# OPTIONS_GHC -fno-specialise #-}
{-# OPTIONS_GHC -fno-strictness #-}
{-# OPTIONS_GHC -fno-unbox-small-strict-fields #-}
{-# OPTIONS_GHC -fno-unbox-strict-fields #-}
{-# OPTIONS_GHC -fplugin-opt PlutusTx.Plugin:target-version=1.1.0 #-}

module ExampleUserValidator where

import PlutusCore.Version (plcVersion110)
import PlutusLedgerApi.V1
  ( AssetClass,
    DiffMilliSeconds (..),
    after,
    assetClassValueOf,
    fromMilliSeconds,
  )
import PlutusLedgerApi.V3
  ( OutputDatum (..),
    ScriptContext (ScriptContext),
    TxInfo (txInfoReferenceInputs),
    TxOut (..),
    getDatum,
    txInInfoResolved,
    txInfoValidRange,
  )
import PlutusTx
import PlutusTx.Prelude

type OracleResponse = Integer

{-# INLINEABLE isResponseGood #-}
isResponseGood :: OracleResponse -> Bool
isResponseGood datum = datum > 50000000

{-# INLINEABLE exampleUserTypedValidator #-}
exampleUserTypedValidator :: AssetClass -> ScriptContext -> Bool
exampleUserTypedValidator assetClass (ScriptContext txInfo _ _) =
  traceIfFalse "Error != 0" (err == 0)
    && traceIfFalse "Response is bad" (isResponseGood oracleData)
    && traceIfFalse "Response has expired" notExpired
  where
    (posixTimeSeconds, err, oracleData) = getOracleResponse txInfo assetClass
    notExpired = after responseExpiresAt (txInfoValidRange txInfo)
    responseExpiresAt = fromMilliSeconds (DiffMilliSeconds (1000 * posixTimeSeconds) + validityPeriod)
    validityPeriod = DiffMilliSeconds (30 * 60 * 1000)

{-# INLINEABLE getOracleResponse #-}
getOracleResponse :: TxInfo -> AssetClass -> (Integer, Integer, OracleResponse)
getOracleResponse txInfo assetClass =
  case map txInInfoResolved $ txInfoReferenceInputs txInfo of
    [TxOut _ value (OutputDatum datum) _]
      | assetClassValueOf value assetClass == 1 -> unsafeFromBuiltinData (getDatum datum)
    _ -> traceError "Response is not found"

exampleUserUntypedValidator :: AssetClass -> BuiltinData -> BuiltinUnit
exampleUserUntypedValidator params ctx =
  check (exampleUserTypedValidator params (unsafeFromBuiltinData ctx))

exampleUserSpendingValidatorScript :: AssetClass -> CompiledCode (BuiltinData -> BuiltinUnit)
exampleUserSpendingValidatorScript params =
  $$(compile [||exampleUserUntypedValidator||])
    `unsafeApplyCode` liftCode plcVersion110 params
