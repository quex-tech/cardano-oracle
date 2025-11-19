{-# LANGUAGE DataKinds #-}
{-# LANGUAGE DerivingStrategies #-}
{-# LANGUAGE FlexibleInstances #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE ImportQualifiedPost #-}
{-# LANGUAGE ImpredicativeTypes #-}
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

module OracleRequestValidator (oracleRequestValidatorScript, OracleRequest) where

import PlutusCore.Version (plcVersion110)
import PlutusLedgerApi.V1
  ( DiffMilliSeconds (DiffMilliSeconds),
    PubKeyHash,
    before,
    fromMilliSeconds,
  )
import PlutusLedgerApi.V1.Value
  ( AssetClass (AssetClass),
    TokenName (TokenName),
    assetClassValueOf,
  )
import PlutusLedgerApi.V3
  ( CurrencySymbol (..),
    Datum (Datum),
    OutputDatum (..),
    ScriptContext (..),
    ScriptInfo (SpendingScript),
    TxInfo,
    TxOut (txOutDatum, txOutValue),
    txInfoOutputs,
    txInfoValidRange,
  )
import PlutusLedgerApi.V3.Contexts (txSignedBy)
import PlutusTx
import PlutusTx.Builtins (serialiseData)
import PlutusTx.Builtins.Internal (unitval)
import PlutusTx.Prelude

type OracleActionWithProof = (OracleAction, BuiltinByteString)

type OracleAction = BuiltinData

type PoolID = AssetClass

type POSIXTimeSeconds = Integer

type TimeRange = (POSIXTimeSeconds, POSIXTimeSeconds)

type OracleRequestParameters = (PoolID, TimeRange, PubKeyHash)

type OracleRequest = (OracleActionWithProof, OracleRequestParameters)

{-# INLINEABLE oracleRequestTypedValidator #-}
oracleRequestTypedValidator :: CurrencySymbol -> OracleRequest -> ScriptContext -> Bool
oracleRequestTypedValidator currencySymbol ((oracleAction, _), (poolId, reqRange@(_, end), owner)) (ScriptContext txInfo _ _) =
  let requestExpiresAt = fromMilliSeconds (DiffMilliSeconds (1000 * end))
      requestExpired = requestExpiresAt `before` txInfoValidRange txInfo
   in if requestExpired
        then txSignedBy txInfo owner
        else existsValidOracleOutput currencySymbol oracleAction poolId reqRange txInfo

{-# INLINEABLE existsValidOracleOutput #-}
existsValidOracleOutput ::
  CurrencySymbol ->
  OracleAction ->
  PoolID ->
  TimeRange ->
  TxInfo ->
  Bool
existsValidOracleOutput currencySymbol oracleAction poolId reqRange info =
  let poolActionID = mkPoolActionID poolId oracleAction
      responseAssetClass = AssetClass (currencySymbol, poolActionID)
   in any (isValidOracleOutput responseAssetClass reqRange) (txInfoOutputs info)

{-# INLINEABLE mkPoolActionID #-}
mkPoolActionID :: PoolID -> OracleAction -> TokenName
mkPoolActionID (AssetClass (CurrencySymbol cs, TokenName tn)) oracleAction =
  let actionID = keccak_256 (serialiseData oracleAction)
   in TokenName . sha2_256 $ cs `appendByteString` tn `appendByteString` actionID

{-# INLINEABLE isValidOracleOutput #-}
isValidOracleOutput :: AssetClass -> TimeRange -> TxOut -> Bool
isValidOracleOutput responseAssetClass (start, end) out =
  let hasToken = assetClassValueOf (txOutValue out) responseAssetClass > 0
      outputDatumIsValid =
        case txOutDatum out of
          OutputDatum (Datum d) ->
            let (createdAt, _, _) = unsafeFromBuiltinData d :: (POSIXTimeSeconds, Integer, BuiltinData)
             in (createdAt >= start) && (createdAt <= end)
          _ -> False
   in hasToken && outputDatumIsValid

oracleRequestUntypedValidator :: CurrencySymbol -> BuiltinData -> BuiltinUnit
oracleRequestUntypedValidator responseCurrencySymbol ctx =
  let scriptContext@(ScriptContext _ _ scriptInfo) = unsafeFromBuiltinData ctx
   in case scriptInfo of
        SpendingScript _ (Just (Datum datum)) ->
          check (oracleRequestTypedValidator responseCurrencySymbol (unsafeFromBuiltinData datum) scriptContext)
        SpendingScript _ Nothing -> unitval
        _ -> error ()

oracleRequestValidatorScript :: CurrencySymbol -> CompiledCode (BuiltinData -> BuiltinUnit)
oracleRequestValidatorScript responseCurrencySymbol =
  $$(compile [||oracleRequestUntypedValidator||])
    `unsafeApplyCode` liftCode plcVersion110 responseCurrencySymbol
