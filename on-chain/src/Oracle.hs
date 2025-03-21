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

module Oracle
  ( ActionID,
    ETHCompressedPubKey,
    ETHSignature,
    ETHSignedMessage,
    DataItem,
    OracleMessage,
    PoolID,
    TDParams,
    mkPoolActionID,
    verifyETHSignature,
    verifyOracleMessage,
  )
where

import PlutusLedgerApi.V1
  ( AssetClass (..),
    CurrencySymbol (..),
    DiffMilliSeconds,
    POSIXTime,
    TokenName (..),
    after,
    assetClassValueOf,
    fromMilliSeconds,
  )
import PlutusLedgerApi.V3
  ( OutputDatum (..),
    TxInfo,
    TxOut (..),
    getDatum,
    txInInfoResolved,
    txInfoReferenceInputs,
    txInfoValidRange,
    txOutValue,
  )
import PlutusTx
import PlutusTx.Builtins (serialiseData)
import PlutusTx.Prelude

type OracleMessage = (ActionID, DataItem)

type ActionID = BuiltinByteString

type DataItem = (POSIXTime, Error, BuiltinData)

type Error = Integer

type PoolID = AssetClass

type PoolActionID = TokenName

type TDParams = (ETHCompressedPubKey, DiffMilliSeconds)

type ETHSignature = BuiltinByteString

type ETHCompressedPubKey = BuiltinByteString

type ETHSignedMessage = (BuiltinData, ETHSignature)

{-# INLINEABLE verifyETHSignature #-}
verifyETHSignature :: ETHCompressedPubKey -> ETHSignedMessage -> Bool
verifyETHSignature pubKey (message, signature) =
  verifyEcdsaSecp256k1Signature pubKey (keccak_256 . serialiseData $ message) signature

{-# INLINEABLE mkPoolActionID #-}
mkPoolActionID :: PoolID -> ActionID -> PoolActionID
mkPoolActionID (AssetClass (CurrencySymbol poolCS, TokenName poolTN)) actionID =
  TokenName . sha2_256 $ poolCS `appendByteString` poolTN `appendByteString` actionID

{-# INLINEABLE verifyOracleMessage #-}
verifyOracleMessage :: TxInfo -> PoolID -> ETHSignedMessage -> Bool
verifyOracleMessage txInfo poolID signedOracleMessage@(oracleMessage, _) =
  case referenceOutputsWithPoolToken of
    [(TxOut _ _ (OutputDatum tdDatum) _)] ->
      and [responseSignatureIsValid, responseIsNotExpired]
      where
        responseSignatureIsValid = verifyETHSignature tdPubKey signedOracleMessage
        responseIsNotExpired = after responseExpiresAt (txInfoValidRange txInfo)
        responseExpiresAt = timestamp + fromMilliSeconds responseValidityPeriod
        (tdPubKey, responseValidityPeriod) = unsafeFromBuiltinData . getDatum $ tdDatum :: TDParams
        (_, (timestamp, _, _)) = unsafeFromBuiltinData oracleMessage :: (ActionID, DataItem)
    _ -> False
  where
    referenceOutputsWithPoolToken =
      filter (\i -> assetClassValueOf (txOutValue i) poolID > 0)
        . map txInInfoResolved
        $ txInfoReferenceInputs txInfo
