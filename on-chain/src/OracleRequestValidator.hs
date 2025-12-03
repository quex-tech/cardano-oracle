{-# LANGUAGE DataKinds #-}
{-# LANGUAGE DeriveAnyClass #-}
{-# LANGUAGE DeriveGeneric #-}
{-# LANGUAGE DerivingStrategies #-}
{-# LANGUAGE FlexibleInstances #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE ImportQualifiedPost #-}
{-# LANGUAGE InstanceSigs #-}
{-# LANGUAGE MultiParamTypeClasses #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE PatternSynonyms #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE Strict #-}
{-# LANGUAGE TemplateHaskell #-}
{-# LANGUAGE TypeApplications #-}
{-# LANGUAGE TypeFamilies #-}
{-# LANGUAGE UndecidableInstances #-}
{-# LANGUAGE ViewPatterns #-}
{-# LANGUAGE NoImplicitPrelude #-}
{-# OPTIONS_GHC -Wno-orphans #-}
{-# OPTIONS_GHC -fno-full-laziness #-}
{-# OPTIONS_GHC -fno-ignore-interface-pragmas #-}
{-# OPTIONS_GHC -fno-omit-interface-pragmas #-}
{-# OPTIONS_GHC -fno-spec-constr #-}
{-# OPTIONS_GHC -fno-specialise #-}
{-# OPTIONS_GHC -fno-strictness #-}
{-# OPTIONS_GHC -fno-unbox-small-strict-fields #-}
{-# OPTIONS_GHC -fno-unbox-strict-fields #-}
{-# OPTIONS_GHC -fplugin-opt PlutusTx.Plugin:conservative-optimisation #-}
{-# OPTIONS_GHC -fplugin-opt PlutusTx.Plugin:target-version=1.1.0 #-}

module OracleRequestValidator (oracleRequestValidatorScript, OracleRequest) where

import GHC.Generics (Generic)
import PlutusCore.Version (plcVersion110)
import PlutusLedgerApi.V1
  ( DiffMilliSeconds (DiffMilliSeconds),
    Lovelace (Lovelace),
    PubKeyHash,
    before,
    fromMilliSeconds,
    lovelaceValueOf,
  )
import PlutusLedgerApi.V1.Value
  ( AssetClass (AssetClass),
    TokenName,
    assetClassValueOf,
  )
import PlutusLedgerApi.V3
  ( Address (..),
    Credential (..),
    CurrencySymbol (..),
    Datum (Datum),
    OutputDatum (..),
    ScriptContext (..),
    ScriptInfo (SpendingScript),
    TxInInfo (txInInfoResolved),
    TxOut (txOutAddress, txOutDatum, txOutValue),
    txInfoFee,
    txInfoInputs,
    txInfoOutputs,
    txInfoValidRange,
  )
import PlutusLedgerApi.V3.Contexts (findOwnInput, txSignedBy)
import PlutusTx
import PlutusTx.Blueprint (HasBlueprintDefinition (..), definitionRef)
import PlutusTx.Builtins (serialiseData)
import PlutusTx.Builtins.Internal (unitval)
import PlutusTx.Prelude

type OracleActionWithProof = (OracleAction, BuiltinByteString)

type OracleAction = BuiltinData

type POSIXTimeSeconds = Integer

data OracleRequest = MkOracleRequest
  { reqAction :: OracleActionWithProof,
    reqPoolID :: BuiltinByteString,
    reqPoolActionID :: TokenName,
    reqAfter :: POSIXTimeSeconds,
    reqBefore :: POSIXTimeSeconds,
    reqOwner :: PubKeyHash,
    reqReward :: Lovelace,
    reqCoinPerUTxOByte :: Lovelace,
    reqMaxCost :: Lovelace
  }
  deriving stock (Generic)
  deriving anyclass (HasBlueprintDefinition)

$(makeIsDataSchemaIndexed ''OracleRequest [('MkOracleRequest, 0)])

{-# INLINEABLE oracleRequestTypedValidator #-}
oracleRequestTypedValidator :: CurrencySymbol -> OracleRequest -> ScriptContext -> Bool
oracleRequestTypedValidator currencySymbol (MkOracleRequest _ _ poolActionID start end owner reward coinPerUTxOByte maxCost) ctx@(ScriptContext txInfo _ _) =
  let requestExpiresAt = fromMilliSeconds (DiffMilliSeconds (1000 * end))
      requestExpired = requestExpiresAt `before` txInfoValidRange txInfo
   in if requestExpired
        then txSignedBy txInfo owner
        else
          let txOutputs = txInfoOutputs txInfo
              responseAssetClass = AssetClass (currencySymbol, poolActionID)
              mResponseDatum = findValidResponseDatum responseAssetClass start end txOutputs
              requestCoin =
                case findOwnInput ctx of
                  Nothing -> error ()
                  Just input -> lovelaceValueOf (txOutValue (txInInfoResolved input))
           in case mResponseDatum of
                Nothing -> False
                Just responseDatum -> existsChangeOutput responseDatum responseAssetClass coinPerUTxOByte reward maxCost requestCoin (txInfoFee txInfo) owner (txInfoInputs txInfo) txOutputs

{-# INLINEABLE existsChangeOutput #-}
existsChangeOutput ::
  BuiltinData ->
  AssetClass ->
  Lovelace ->
  Lovelace ->
  Lovelace ->
  Lovelace ->
  Lovelace ->
  PubKeyHash ->
  [TxInInfo] ->
  [TxOut] ->
  Bool
existsChangeOutput newResponseDatum assetClass (Lovelace coinPerUTxOByte) reward maxCost requestCoin txFee owner txInputs txOutputs =
  let oldResponseCoin = adaSpentWithAsset assetClass txInputs
      responseBytes = lengthOfByteString (serialiseData newResponseDatum)
      realCost = reward + txFee + Lovelace (coinPerUTxOByte * (274 + responseBytes)) - oldResponseCoin
      cappedCost = max 0 (min maxCost realCost)
      minChange = requestCoin - cappedCost
      isOwners out =
        case txOutAddress out of
          Address (PubKeyCredential pkh) _ -> pkh == owner
          _ -> False
   in minChange <= 0 || any (\o -> isOwners o && lovelaceValueOf (txOutValue o) >= minChange) txOutputs

{-# INLINEABLE adaSpentWithAsset #-}
adaSpentWithAsset :: AssetClass -> [TxInInfo] -> Lovelace
adaSpentWithAsset ac txInfo =
  let totalVal =
        foldMap
          ( \input ->
              let v = txOutValue (txInInfoResolved input)
               in if assetClassValueOf v ac > 0
                    then v
                    else mempty
          )
          txInfo
   in lovelaceValueOf totalVal

{-# INLINEABLE isValidOracleOutput #-}
isValidOracleOutput :: AssetClass -> POSIXTimeSeconds -> POSIXTimeSeconds -> TxOut -> Bool
isValidOracleOutput responseAssetClass start end out =
  let hasToken = assetClassValueOf (txOutValue out) responseAssetClass > 0
      outputDatumIsValid =
        case txOutDatum out of
          OutputDatum (Datum d) ->
            let (createdAt, _, _) = unsafeFromBuiltinData d :: (POSIXTimeSeconds, Integer, BuiltinData)
             in (createdAt >= start) && (createdAt <= end)
          _ -> False
   in hasToken && outputDatumIsValid

{-# INLINEABLE findValidResponseDatum #-}
findValidResponseDatum ::
  AssetClass ->
  POSIXTimeSeconds ->
  POSIXTimeSeconds ->
  [TxOut] ->
  Maybe BuiltinData
findValidResponseDatum responseAssetClass start end = foldr go Nothing
  where
    go _ (Just d) = Just d
    go out Nothing =
      let v = txOutValue out
       in if assetClassValueOf v responseAssetClass <= 0
            then Nothing
            else case txOutDatum out of
              OutputDatum (Datum d) ->
                let (createdAt, _, _) =
                      unsafeFromBuiltinData d :: (POSIXTimeSeconds, Integer, BuiltinData)
                 in if createdAt >= start && createdAt <= end
                      then Just d
                      else Nothing
              _ -> Nothing

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
