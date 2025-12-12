-- SPDX-License-Identifier: Apache-2.0
-- Copyright 2025 Quex Technologies
{-# LANGUAGE DataKinds #-}
{-# LANGUAGE DeriveAnyClass #-}
{-# LANGUAGE DeriveGeneric #-}
{-# LANGUAGE DerivingStrategies #-}
{-# LANGUAGE FlexibleInstances #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE ImportQualifiedPost #-}
{-# LANGUAGE MultiParamTypeClasses #-}
{-# LANGUAGE NamedFieldPuns #-}
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

module SingleOraclePoolValidator (singleOraclePoolValidatorScript) where

import PlutusLedgerApi.V1
  ( DiffMilliSeconds,
    currencySymbolValueOf,
    symbols,
    valueOf,
  )
import PlutusLedgerApi.V3
  ( Datum (Datum),
    OutputDatum (OutputDatum),
    Redeemer (Redeemer),
    ScriptContext (..),
    TokenName (TokenName),
    TxInfo (TxInfo, txInfoInputs, txInfoOutputs),
    TxOut (TxOut),
    adaSymbol,
  )
import PlutusTx
  ( CompiledCode,
    UnsafeFromData (unsafeFromBuiltinData),
    compile,
  )
import PlutusTx.Builtins (serialiseData)
import PlutusTx.Prelude
import Validator (storageScriptInfo)

{-# INLINEABLE singleOraclePoolTypedValidator #-}
singleOraclePoolTypedValidator :: (BuiltinByteString, DiffMilliSeconds) -> ScriptContext -> Bool
singleOraclePoolTypedValidator
  (pubKey, responseValidityPeriod)
  (ScriptContext (TxInfo {txInfoInputs, txInfoOutputs}) (Redeemer rawRedeemer) scriptInfo) =
    let tokenName = TokenName . sha2_256 . serialiseData $ rawRedeemer
        (currencySymbol, ownAddress, maybeOldDatum, spentTokenNames) = storageScriptInfo scriptInfo txInfoInputs
        hasCurrency (TxOut _ value _ _) = currencySymbol `elem` symbols value
     in (lengthOfByteString pubKey == 33)
          && (responseValidityPeriod > 0)
          && case filter hasCurrency txInfoOutputs of
            [TxOut address value (OutputDatum (Datum newDatum)) _] ->
              (address == ownAddress)
                && (newDatum == rawRedeemer)
                && (valueOf value currencySymbol tokenName == 1)
                && (currencySymbolValueOf value currencySymbol == 1)
                && (symbols value == [adaSymbol, currencySymbol])
                && ( case spentTokenNames of
                       [tn] -> tn == tokenName
                       _ -> True
                   )
                && ( case maybeOldDatum of
                       Just (Datum oldDatum) -> oldDatum == rawRedeemer
                       Nothing -> True
                   )
            _ -> False

singleOraclePoolUntypedValidator :: BuiltinData -> BuiltinUnit
singleOraclePoolUntypedValidator rawCtx =
  let ctx = unsafeFromBuiltinData rawCtx
      ScriptContext {scriptContextRedeemer = Redeemer rawRedeemer} = ctx
      redeemer = unsafeFromBuiltinData rawRedeemer
   in check (singleOraclePoolTypedValidator redeemer ctx)

singleOraclePoolValidatorScript :: CompiledCode (BuiltinData -> BuiltinUnit)
singleOraclePoolValidatorScript =
  $$(compile [||singleOraclePoolUntypedValidator||])