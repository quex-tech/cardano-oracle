{-# LANGUAGE DataKinds #-}
{-# LANGUAGE DeriveAnyClass #-}
{-# LANGUAGE DeriveGeneric #-}
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

module OracleResponseMintingPolicy where

import GHC.Generics (Generic)
import Oracle
import PlutusCore.Version (plcVersion110)
import PlutusLedgerApi.V1
  ( isZero,
    symbols,
  )
import PlutusLedgerApi.V3
  ( Address,
    OutputDatum (..),
    Redeemer (getRedeemer),
    ScriptContext (..),
    TxOut (..),
    adaSymbol,
    getDatum,
    mintValueMinted,
    singleton,
    txInfoMint,
    txInfoOutputs,
    txOutValue,
  )
import PlutusLedgerApi.V3.Contexts (ownCurrencySymbol)
import PlutusTx
import PlutusTx.Blueprint
import PlutusTx.Prelude

data OracleResponseMintingRedeemer
  = Create ETHSignedMessage
  | Delete
  deriving stock (Generic)
  deriving anyclass (HasBlueprintDefinition)

makeIsDataSchemaIndexed ''OracleResponseMintingRedeemer [('Create, 0), ('Delete, 1)]

{-# INLINEABLE oracleResponseTypedMintingPolicy #-}
oracleResponseTypedMintingPolicy :: Address -> OracleResponseMintingRedeemer -> ScriptContext -> Bool
oracleResponseTypedMintingPolicy destinationAddress redeemer scriptContext =
  case redeemer of
    (Create signedOracleMessage@(oracleMessage, _)) -> case findOracle txInfo of
      Just oracle@(poolID, _, _) ->
        mintedSingleCorrectToken && oracleMessageIsValid && outputIsValid
        where
          mintedSingleCorrectToken = mintedValue == singleton ownCS (mkPoolActionID poolID actionID) 1
          oracleMessageIsValid = verifyOracleMessage txInfo oracle signedOracleMessage
          outputIsValid = case outputsWithMintedToken of
            [TxOut address value (OutputDatum responseDatum) _] ->
              address == destinationAddress && getDatum responseDatum == dataItem && noOtherTokens
              where
                noOtherTokens = symbols value == [adaSymbol, ownCS]
            _ -> False
          outputsWithMintedToken = filter (\o -> ownCS `elem` (symbols . txOutValue $ o)) (txInfoOutputs txInfo)
          (actionID, dataItem) = unsafeFromBuiltinData oracleMessage :: (ActionID, BuiltinData)
      Nothing -> False
    Delete -> isZero mintedValue
  where
    mintedValue = mintValueMinted (txInfoMint txInfo)
    ownCS = ownCurrencySymbol scriptContext
    txInfo = scriptContextTxInfo scriptContext

oracleResponseUntypedMintingPolicy :: Address -> BuiltinData -> BuiltinUnit
oracleResponseUntypedMintingPolicy destinationAddress ctx =
  check (oracleResponseTypedMintingPolicy destinationAddress redeemer scriptContext)
  where
    scriptContext = unsafeFromBuiltinData ctx
    redeemer = unsafeFromBuiltinData $ getRedeemer $ scriptContextRedeemer scriptContext

oracleResponseMintingPolicyScript :: Address -> CompiledCode (BuiltinData -> BuiltinUnit)
oracleResponseMintingPolicyScript destinationAddress =
  $$(compile [||oracleResponseUntypedMintingPolicy||])
    `unsafeApplyCode` liftCode plcVersion110 destinationAddress
