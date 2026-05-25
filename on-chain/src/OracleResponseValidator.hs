-- SPDX-License-Identifier: Apache-2.0
-- Copyright 2025 Quex Technologies
{-# LANGUAGE DataKinds #-}
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
{-# OPTIONS_GHC -fplugin-opt PlutusTx.Plugin:conservative-optimisation #-}

module OracleResponseValidator (oracleResponseValidatorScript, ETHSignedMessage) where

import PlutusLedgerApi.V1
  ( AssetClass (AssetClass),
    DiffMilliSeconds (DiffMilliSeconds),
    POSIXTimeRange,
    PubKeyHash,
    after,
    currencySymbolValueOf,
    flattenValue,
    fromMilliSeconds,
    symbols,
    valueOf,
  )
import PlutusLedgerApi.V3
  ( CurrencySymbol (CurrencySymbol),
    Datum (Datum),
    OutputDatum (OutputDatum),
    Redeemer (Redeemer),
    ScriptContext (ScriptContext, scriptContextRedeemer),
    TokenName (TokenName),
    TxInInfo (txInInfoResolved),
    TxInfo (TxInfo, txInfoInputs, txInfoOutputs, txInfoReferenceInputs, txInfoSignatories, txInfoValidRange),
    TxOut (TxOut),
    Value,
    adaSymbol,
  )
import PlutusTx
import PlutusTx.Builtins (serialiseData)
import PlutusTx.Prelude
import Validator (storageScriptInfo)

type ActionID = BuiltinByteString

type DataItem = (POSIXTimeSeconds, Integer, BuiltinData)

type POSIXTimeSeconds = Integer

type PoolID = AssetClass

type PoolActionID = TokenName

type Oracle = (PoolID, OracleDatum)

type OracleDatum = (ETHCompressedPubKey, DiffMilliSeconds)

type ETHSignature = BuiltinByteString

type ETHCompressedPubKey = BuiltinByteString

type ETHSignedMessage = (BuiltinData, ETHSignature)

oracleResponseTypedValidator :: ETHSignedMessage -> ScriptContext -> Bool
oracleResponseTypedValidator
  signedOracleMessage@(oracleMessage, _)
  (ScriptContext txInfo@(TxInfo {txInfoInputs, txInfoOutputs, txInfoValidRange, txInfoSignatories}) _ scriptInfo) =
    let (poolID, oracleDatum) = getOracle txInfo
        (actionID, rawDataItem, relayer) = unsafeFromBuiltinData oracleMessage :: (ActionID, BuiltinData, PubKeyHash)
        (newTimestamp, _, _) = unsafeFromBuiltinData rawDataItem :: DataItem
        poolActionID = mkPoolActionID poolID actionID
        (currencySymbol, ownAddress, maybeOldDatum, spentTokenNames) = storageScriptInfo scriptInfo txInfoInputs
        hasCurrency (TxOut _ value _ _) = currencySymbol `elem` symbols value
     in lengthOfByteString (serialiseData rawDataItem) <= maxResponseDataItemBytes
          && verifyOracleMessage signedOracleMessage oracleDatum txInfoValidRange
          && (relayer `elem` txInfoSignatories)
          && case filter hasCurrency txInfoOutputs of
            [TxOut address value (OutputDatum (Datum newDatum)) _] ->
              address == ownAddress
                && newDatum == rawDataItem
                && valueOf value currencySymbol poolActionID == 1
                && currencySymbolValueOf value currencySymbol == 1
                && symbols value == [adaSymbol, currencySymbol]
                && ( case spentTokenNames of
                       [tn] -> tn == poolActionID
                       _ -> True
                   )
                && ( case maybeOldDatum of
                       Just (Datum rawOldDatum) -> newTimestamp > oldTimestamp
                         where
                           (oldTimestamp, _, _) = unsafeFromBuiltinData rawOldDatum :: DataItem
                       Nothing -> True
                   )
            _ -> False

{-# INLINEABLE getInlineDatum #-}
getInlineDatum :: OutputDatum -> BuiltinData
getInlineDatum (OutputDatum (Datum datum)) = datum
getInlineDatum _ = error ()

{-# INLINEABLE getOracle #-}
getOracle :: TxInfo -> Oracle
getOracle TxInfo {txInfoReferenceInputs}
  | [oracle] <- mapMaybe (findOracle . txInInfoResolved) txInfoReferenceInputs = oracle
  | otherwise = error ()

{-# INLINEABLE findOracle #-}
findOracle :: TxOut -> Maybe Oracle
findOracle (TxOut _ value (OutputDatum (Datum datum)) _) =
  case findPoolID value of
    Just poolID -> Just (poolID, unsafeFromBuiltinData datum)
    Nothing -> Nothing
findOracle _ = Nothing

{-# INLINEABLE findPoolID #-}
findPoolID :: Value -> Maybe PoolID
findPoolID value =
  case filter (\(cs, _, _) -> cs /= adaSymbol) (flattenValue value) of
    [(cs, tn, v)] | v == 1 -> Just $ AssetClass (cs, tn)
    _ -> Nothing

{-# INLINEABLE maxResponseDataItemBytes #-}
maxResponseDataItemBytes :: Integer
maxResponseDataItemBytes = 4096

{-# INLINEABLE mkPoolActionID #-}
mkPoolActionID :: PoolID -> ActionID -> PoolActionID
mkPoolActionID (AssetClass (CurrencySymbol cs, TokenName tn)) actionID =
  TokenName . sha2_256 $ cs `appendByteString` tn `appendByteString` actionID

{-# INLINEABLE verifyOracleMessage #-}
verifyOracleMessage :: ETHSignedMessage -> OracleDatum -> POSIXTimeRange -> Bool
verifyOracleMessage signedOracleMessage@(oracleMessage, _) (pubKey, responseValidityPeriodMs) validRange =
  responseSignatureIsValid && responseIsNotExpired
  where
    responseSignatureIsValid = verifyETHSignature pubKey signedOracleMessage
    responseIsNotExpired = after responseExpiresAt validRange
    responseExpiresAt = fromMilliSeconds (DiffMilliSeconds (1000 * posixTimeSeconds) + responseValidityPeriodMs)
    (_, (posixTimeSeconds, _, _), _) = unsafeFromBuiltinData oracleMessage :: (ActionID, DataItem, PubKeyHash)

{-# INLINEABLE verifyETHSignature #-}
verifyETHSignature :: ETHCompressedPubKey -> ETHSignedMessage -> Bool
verifyETHSignature pubKey (message, signature) =
  verifyEcdsaSecp256k1Signature pubKey hash signature
  where
    hash = keccak_256 (serialiseData message)

oracleResponseUntypedValidator :: BuiltinData -> BuiltinUnit
oracleResponseUntypedValidator rawCtx =
  let ctx = unsafeFromBuiltinData rawCtx
      ScriptContext {scriptContextRedeemer = Redeemer rawRedeemer} = ctx
      redeemer = unsafeFromBuiltinData rawRedeemer
   in check (oracleResponseTypedValidator redeemer ctx)

oracleResponseValidatorScript :: CompiledCode (BuiltinData -> BuiltinUnit)
oracleResponseValidatorScript =
  $$(compile [||oracleResponseUntypedValidator||])
