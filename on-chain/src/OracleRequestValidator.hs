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
import PlutusLedgerApi.Data.V3 ()
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
    txInfoInputs,
    txInfoOutputs,
    txInfoValidRange,
  )
import PlutusLedgerApi.V3.Contexts (txInInfoOutRef, txSignedBy)
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
    reqBaseFee :: Lovelace,
    reqFeePerResponseByte :: Lovelace,
    reqMaxFee :: Lovelace
  }
  deriving stock (Generic)
  deriving anyclass (HasBlueprintDefinition)

$(makeIsDataSchemaIndexed ''OracleRequest [('MkOracleRequest, 0)])

{-# INLINEABLE oracleRequestTypedValidator #-}
oracleRequestTypedValidator :: CurrencySymbol -> OracleRequest -> ScriptContext -> Bool
oracleRequestTypedValidator currencySymbol (MkOracleRequest _ _ poolActionID start end owner baseFee feePerResponseByte maxFee) ctx@(ScriptContext txInfo _ _) =
  let requestExpiresAt = fromMilliSeconds (DiffMilliSeconds (1000 * end))
      requestExpired = requestExpiresAt `before` txInfoValidRange txInfo
   in if requestExpired
        then txSignedBy txInfo owner
        else
          let txOutputs = txInfoOutputs txInfo
              responseAssetClass = AssetClass (currencySymbol, poolActionID)
              mResponseDatum = findValidResponseDatum responseAssetClass start end txOutputs
              requestAda =
                case findOwnInputConst ctx of
                  Nothing -> error ()
                  Just input -> lovelaceValueOf (txOutValue (txInInfoResolved input))
           in case mResponseDatum of
                Nothing -> False
                Just responseDatum -> existsChangeOutput responseDatum responseAssetClass feePerResponseByte baseFee maxFee requestAda owner (txInfoInputs txInfo) txOutputs

{-# INLINEABLE existsChangeOutput #-}
existsChangeOutput ::
  BuiltinData ->
  AssetClass ->
  Lovelace ->
  Lovelace ->
  Lovelace ->
  Lovelace ->
  PubKeyHash ->
  [TxInInfo] ->
  [TxOut] ->
  Bool
existsChangeOutput newResponseDatum assetClass (Lovelace feePerResponseByte) baseFee maxFee requestAda owner txInputs txOutputs =
  let oldResponseAda = adaSpentWithAsset assetClass txInputs
      responseBytes = lengthOfByteString (serialiseData newResponseDatum)
      realFee = max 0 (min maxFee (baseFee + Lovelace (feePerResponseByte * responseBytes) - oldResponseAda))
      minChange = requestAda - realFee
      isOwners out =
        case txOutAddress out of
          Address (PubKeyCredential pkh) _ -> pkh == owner
          _ -> False
      changeOutputExists =
        -- to avoid short-circuit
        case (minChange <= 0, any (\o -> isOwners o && lovelaceValueOf (txOutValue o) >= minChange) txOutputs) of
          (False, False) -> False
          _ -> True
   in changeOutputExists

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

{-# INLINEABLE findOwnInputConst #-}
findOwnInputConst :: ScriptContext -> Maybe TxInInfo
findOwnInputConst (ScriptContext txInfo _ (SpendingScript ownRef _)) =
  let -- We *always* traverse the whole list, even after we found a match.
      go :: [TxInInfo] -> Maybe TxInInfo -> Maybe TxInInfo
      go [] acc = acc
      go (i : is) acc =
        let matches = txInInfoOutRef i == ownRef
            -- If this one matches, remember it, but still continue.
            newAcc = if matches then Just i else acc
         in go is newAcc
   in go (txInfoInputs txInfo) Nothing
findOwnInputConst _ = Nothing

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
