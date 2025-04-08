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
    scriptHashAddress,
  )
import PlutusLedgerApi.V3
  ( Address (Address),
    Credential (ScriptCredential),
    Datum,
    ScriptInfo (MintingScript, SpendingScript),
    TxInInfo (TxInInfo),
    TxOut (TxOut),
    txInInfoOutRef,
  )
import PlutusTx.Prelude

type StorageScriptInfo = (CurrencySymbol, Address, Maybe Datum)

{-# INLINEABLE storageScriptInfo #-}
storageScriptInfo :: ScriptInfo -> [TxInInfo] -> StorageScriptInfo
storageScriptInfo (MintingScript cs@(CurrencySymbol rawCS)) _ =
  (cs, scriptHashAddress (ScriptHash rawCS), Nothing)
storageScriptInfo (SpendingScript outRef datum) txInfoInputs
  | (Just (TxInInfo _ (TxOut address@(Address (ScriptCredential (ScriptHash hash)) _) _ _ _))) <-
      find (\TxInInfo {txInInfoOutRef} -> txInInfoOutRef == outRef) txInfoInputs =
      (CurrencySymbol hash, address, datum)
storageScriptInfo _ _ = error ()
