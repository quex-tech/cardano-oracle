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

module OracleResponseSpendingValidator where

import Oracle
import PlutusLedgerApi.V1
  ( currencySymbolValueOf,
    lovelaceValueOf,
    symbols,
    valueOf,
  )
import PlutusLedgerApi.V3
  ( OutputDatum (..),
    Redeemer (getRedeemer),
    ScriptContext (..),
    ScriptInfo (SpendingScript),
    TxInInfo (..),
    TxOut (..),
    adaSymbol,
    getDatum,
    txOutValue,
  )
import PlutusLedgerApi.V3.Contexts
  ( findOwnInput,
    getContinuingOutputs,
    valueProduced,
  )
import PlutusTx
import PlutusTx.Prelude

{-# INLINEABLE oracleResponseTypedValidator #-}
oracleResponseTypedValidator :: DataItem -> ETHSignedMessage -> ScriptContext -> Bool
oracleResponseTypedValidator (oldTimestamp, _, _) signedOracleMessage@(oracleMessage, _) scriptContext =
  case (findOracle txInfo) of
    Just oracle@(poolID, _, _) ->
      newTimestamp > oldTimestamp && oracleMessageIsValid && inputsAndOutputsAreValid
      where
        (newTimestamp, _, _) = unsafeFromBuiltinData dataItem :: DataItem
        oracleMessageIsValid = verifyOracleMessage txInfo oracle signedOracleMessage
        inputsAndOutputsAreValid = case (findOwnInput scriptContext) of
          Just (TxInInfo _ ownInput) -> case (symbols ownInputValue) of
            [a, ownCS] -> inputHasSinglePoolActionToken && outputIsValid && noTokensLeaked
              where
                inputHasSinglePoolActionToken = a == adaSymbol && valueOf ownInputValue ownCS poolActionID == 1
                outputIsValid = case (getContinuingOutputs scriptContext) of
                  [(TxOut _ outputValue (OutputDatum responseDatum) _)] ->
                    (getDatum responseDatum == dataItem)
                      && (valueOf outputValue ownCS poolActionID == 1)
                      && (lovelaceValueOf outputValue >= lovelaceValueOf ownInputValue)
                      && noOtherTokens
                    where
                      noOtherTokens = symbols outputValue == [adaSymbol, ownCS]
                  _ -> False
                noTokensLeaked = currencySymbolValueOf (valueProduced txInfo) ownCS == 1
                poolActionID = mkPoolActionID poolID actionID
            _ -> False
            where
              ownInputValue = txOutValue ownInput
          Nothing -> False
        (actionID, dataItem) = unsafeFromBuiltinData oracleMessage :: (ActionID, BuiltinData)
    Nothing -> False
  where
    txInfo = scriptContextTxInfo scriptContext

oracleResponseUntypedValidator :: BuiltinData -> BuiltinUnit
oracleResponseUntypedValidator ctx =
  check (oracleResponseTypedValidator datum redeemer scriptContext)
  where
    scriptContext = unsafeFromBuiltinData ctx
    datum :: DataItem
    datum = case scriptContextScriptInfo scriptContext of
      SpendingScript _TxOutRef (Just d) -> unsafeFromBuiltinData (getDatum d)
      _ -> traceError "Expected SpendingScript with a datum"
    redeemer = unsafeFromBuiltinData $ getRedeemer $ scriptContextRedeemer scriptContext

oracleResponseSpendingValidatorScript :: CompiledCode (BuiltinData -> BuiltinUnit)
oracleResponseSpendingValidatorScript =
  $$(compile [||oracleResponseUntypedValidator||])
