{-# LANGUAGE ImportQualifiedPost #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE NoImplicitPrelude #-}

module Main where

import PlutusLedgerApi.V1.Crypto qualified as Crypto
import PlutusTx.Builtins.HasOpaque (stringToBuiltinByteString, stringToBuiltinByteStringHex)
import PlutusTx.Prelude
import System.Exit (exitFailure, exitSuccess)
import Prelude qualified as Haskell

main :: Haskell.IO ()
main = do
  let pubKey = stringToBuiltinByteStringHex "02792bb2ae2b769acf2b971f368d7d5cbed9d54a889c30ae7cd2e6a0321bfbcfee"
      hash = stringToBuiltinByteStringHex "d886efed2048a920b411d5d9b25bffdd75dbdfc00c606ef21917be2483f60939"
      signature = stringToBuiltinByteStringHex "c1c19c195fb499e8b562ff14f8d620a56ad9108a9978b15747c46e68f7410f1a75828cff2ae1d9a631585febf5985cfbd4e62f887f9d9db799b194a43e9d3f63"
      valid = verifyEcdsaSecp256k1Signature pubKey hash signature

  if valid
    then exitSuccess
    else exitFailure
