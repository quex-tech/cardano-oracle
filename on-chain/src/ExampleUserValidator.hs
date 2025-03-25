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
    ScriptContext (scriptContextTxInfo),
    TxInfo (txInfoReferenceInputs),
    TxOut (..),
    getDatum,
    txInInfoResolved,
    txInfoValidRange,
  )
import PlutusTx
import PlutusTx.Prelude

type ExampleUserValidatorParams = (AssetClass, BuiltinData, DiffMilliSeconds)

{-# INLINEABLE exampleUserTypedValidator #-}
exampleUserTypedValidator :: ExampleUserValidatorParams -> ScriptContext -> Bool
exampleUserTypedValidator (poolActionID, expectedOracleData, validityPeriodMs) scriptContext =
  case (findOracleData txInfo poolActionID) of
    Just (posixTimeSeconds, err, oracleData) ->
      (err == 0)
        && (oracleData == expectedOracleData)
        && notExpired
      where
        notExpired = after responseExpiresAt (txInfoValidRange txInfo)
        responseExpiresAt = fromMilliSeconds (DiffMilliSeconds (1000 * posixTimeSeconds) + validityPeriodMs)
    Nothing -> False
  where
    txInfo = scriptContextTxInfo scriptContext

findOracleData :: TxInfo -> AssetClass -> Maybe (Integer, Integer, BuiltinData)
findOracleData txInfo poolActionID =
  case (map txInInfoResolved $ txInfoReferenceInputs txInfo) of
    [(TxOut _ value (OutputDatum datum) _)]
      | (assetClassValueOf value poolActionID) == 1 -> Just (unsafeFromBuiltinData (getDatum datum))
    _ -> Nothing

exampleUserUntypedValidator :: ExampleUserValidatorParams -> BuiltinData -> BuiltinUnit
exampleUserUntypedValidator params ctx =
  check (exampleUserTypedValidator params (unsafeFromBuiltinData ctx))

exampleUserSpendingValidatorScript :: ExampleUserValidatorParams -> CompiledCode (BuiltinData -> BuiltinUnit)
exampleUserSpendingValidatorScript params =
  $$(compile [||exampleUserUntypedValidator||])
    `unsafeApplyCode` liftCode plcVersion110 params
