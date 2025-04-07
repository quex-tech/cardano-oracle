{-# LANGUAGE DataKinds #-}
{-# LANGUAGE DerivingStrategies #-}
{-# LANGUAGE FlexibleInstances #-}
{-# LANGUAGE MultiParamTypeClasses #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE Strict #-}
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
    ETHSignedMessage,
    DataItem,
    findOracle,
    mkPoolActionID,
    verifyOracleMessage,
  )
where

import PlutusLedgerApi.V1
  ( AssetClass (..),
    CurrencySymbol (..),
    DiffMilliSeconds (..),
    TokenName (..),
    after,
    flattenValue,
    fromMilliSeconds,
  )
import PlutusLedgerApi.V3
  ( OutputDatum (..),
    TxInfo,
    TxOut (..),
    Value (..),
    adaSymbol,
    getDatum,
    txInInfoResolved,
    txInfoReferenceInputs,
    txInfoValidRange,
  )
import PlutusTx
import PlutusTx.Builtins (serialiseData)
import PlutusTx.Prelude

type ActionID = BuiltinByteString

type DataItem = (POSIXTimeSeconds, Integer, BuiltinData)

type POSIXTimeSeconds = Integer

type PoolID = AssetClass

type PoolActionID = TokenName

type Oracle = (PoolID, ETHCompressedPubKey, DiffMilliSeconds)

type ETHSignature = BuiltinByteString

type ETHCompressedPubKey = BuiltinByteString

type ETHSignedMessage = (BuiltinData, ETHSignature)

{-# INLINEABLE mkPoolActionID #-}
mkPoolActionID :: PoolID -> ActionID -> PoolActionID
mkPoolActionID (AssetClass (CurrencySymbol poolCS, TokenName poolTN)) actionID =
  TokenName . sha2_256 $ poolCS `appendByteString` poolTN `appendByteString` actionID

{-# INLINEABLE findOracle #-}
findOracle :: TxInfo -> Maybe Oracle
findOracle txInfo =
  case referenceInputs of
    [TxOut _ value (OutputDatum datum) _] ->
      case findPoolID value of
        Just poolID -> Just (poolID, pubKey, responseValidityPeriodMs)
          where
            (pubKey, responseValidityPeriodMs) = unsafeFromBuiltinData . getDatum $ datum :: (ETHCompressedPubKey, DiffMilliSeconds)
        Nothing -> Nothing
    _ -> Nothing
  where
    referenceInputs =
      map txInInfoResolved
        $ txInfoReferenceInputs txInfo

{-# INLINEABLE findPoolID #-}
findPoolID :: Value -> Maybe PoolID
findPoolID value =
  case filter (\(cs, _, _) -> cs /= adaSymbol) (flattenValue value) of
    [(cs, tn, v)] | v == 1 -> Just $ AssetClass (cs, tn)
    _ -> Nothing

{-# INLINEABLE verifyOracleMessage #-}
verifyOracleMessage :: TxInfo -> Oracle -> ETHSignedMessage -> Bool
verifyOracleMessage txInfo (_, pubKey, responseValidityPeriodMs) signedOracleMessage@(oracleMessage, _) =
  responseSignatureIsValid && responseIsNotExpired
  where
    responseSignatureIsValid = verifyETHSignature pubKey signedOracleMessage
    responseIsNotExpired = after responseExpiresAt (txInfoValidRange txInfo)
    responseExpiresAt = fromMilliSeconds (DiffMilliSeconds (1000 * posixTimeSeconds) + responseValidityPeriodMs)
    (_, (posixTimeSeconds, _, _)) = unsafeFromBuiltinData oracleMessage :: (ActionID, DataItem)

{-# INLINEABLE verifyETHSignature #-}
verifyETHSignature :: ETHCompressedPubKey -> ETHSignedMessage -> Bool
verifyETHSignature pubKey (message, signature) =
  verifyEcdsaSecp256k1Signature pubKey hash signature
  where
    hash = keccak_256 (serialiseData message)
