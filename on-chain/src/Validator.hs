-- SPDX-License-Identifier: Apache-2.0
-- Copyright 2025 Quex Technologies
{-# LANGUAGE DataKinds #-}
{-# LANGUAGE DerivingStrategies #-}
{-# LANGUAGE FlexibleInstances #-}
{-# LANGUAGE MultiParamTypeClasses #-}
{-# LANGUAGE NamedFieldPuns #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE Strict #-}
{-# LANGUAGE UndecidableInstances #-}
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

module Validator (storageScriptInfo) where

import PlutusLedgerApi.V1
  ( CurrencySymbol (CurrencySymbol),
    ScriptHash (ScriptHash),
    TokenName,
    scriptHashAddress,
  )
import PlutusLedgerApi.V3
  ( Address (Address),
    Credential (ScriptCredential),
    Datum,
    ScriptInfo (MintingScript, SpendingScript),
    TxInInfo (TxInInfo),
    TxOut (TxOut),
    Value (Value),
    txInInfoOutRef,
  )
import PlutusTx.AssocMap (keys, lookup)
import PlutusTx.Prelude

type StorageScriptInfo = (CurrencySymbol, Address, Maybe Datum, [TokenName])

{-# INLINEABLE storageScriptInfo #-}
storageScriptInfo :: ScriptInfo -> [TxInInfo] -> StorageScriptInfo
storageScriptInfo (MintingScript cs@(CurrencySymbol rawCS)) _ =
  (cs, scriptHashAddress (ScriptHash rawCS), Nothing, [])
storageScriptInfo (SpendingScript outRef datum) txInfoInputs =
  let input = find (\TxInInfo {txInInfoOutRef} -> txInInfoOutRef == outRef) txInfoInputs
   in case input of
        Just (TxInInfo _ (TxOut address@(Address (ScriptCredential (ScriptHash hash)) _) (Value value) _ _)) ->
          let currencySymbol = CurrencySymbol hash
              tokenNames = maybe [] keys (lookup currencySymbol value)
           in (currencySymbol, address, datum, tokenNames)
        _ -> error ()
storageScriptInfo _ _ = error ()
