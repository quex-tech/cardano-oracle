{-# LANGUAGE DataKinds #-}
{-# LANGUAGE DeriveAnyClass #-}
{-# LANGUAGE DeriveGeneric #-}
{-# LANGUAGE DerivingStrategies #-}
{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE FlexibleInstances #-}
{-# LANGUAGE GADTs #-}
{-# LANGUAGE ImportQualifiedPost #-}
{-# LANGUAGE LambdaCase #-}
{-# LANGUAGE MultiParamTypeClasses #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE StandaloneDeriving #-}
{-# LANGUAGE TypeApplications #-}
{-# LANGUAGE UndecidableInstances #-}
{-# LANGUAGE ViewPatterns #-}

module Main where

import Data.ByteString.Short qualified as Short
import Data.Set qualified as Set
import ExampleUserValidator
import PlutusLedgerApi.Common (serialiseCompiledCode)
import PlutusLedgerApi.V1
  ( AssetClass (..),
    CurrencySymbol (..),
    DiffMilliSeconds (..),
    TokenName (..),
    toBuiltinData,
  )
import PlutusTx.Blueprint
import PlutusTx.Builtins.HasOpaque (stringToBuiltinByteStringHex)
import System.Environment (getArgs)

myContractBlueprint :: ContractBlueprint
myContractBlueprint =
  MkContractBlueprint
    { contractId = Just "quex-oracle-user-example",
      contractPreamble = myPreamble,
      contractValidators = Set.fromList [validator],
      contractDefinitions = deriveDefinitions @'[ExampleUserValidatorParams]
    }

myPreamble :: Preamble
myPreamble =
  MkPreamble
    { preambleTitle = "QUEX Oracle User Example",
      preambleDescription = Nothing,
      preambleVersion = "0.0.1",
      preamblePlutusVersion = PlutusV3,
      preambleLicense = Nothing
    }

validator :: ValidatorBlueprint referencedTypes
validator =
  MkValidatorBlueprint
    { validatorTitle = "Oracle Response Example User Spending Validator",
      validatorDescription = Nothing,
      validatorParameters = [],
      validatorRedeemer =
        MkArgumentBlueprint
          { argumentTitle = Just "Redeemer for the validator",
            argumentDescription = Just "The validator does not use a redeemer, hence ()",
            argumentPurpose = Set.fromList [Spend],
            argumentSchema = definitionRef @()
          },
      validatorDatum = Nothing,
      validatorCompiled = do
        let quexCS = CurrencySymbol (stringToBuiltinByteStringHex "efd558979b0e353faa8ec7098d5ffd65d3b1bb6e1ca2daa16287400b")
        let poolActionID = stringToBuiltinByteStringHex "422d2f78b2cd55b635de0b9d822e597030523176feb8490e17cea8a58a36e29b"
        let assetClass = AssetClass (quexCS, (TokenName poolActionID))
        let params = (assetClass, toBuiltinData (321 :: Integer), DiffMilliSeconds (24 * 60 * 60 * 1000))
        let code = Short.fromShort (serialiseCompiledCode (exampleUserSpendingValidatorScript params))
        Just (compiledValidator PlutusV3 code)
    }

writeBlueprintToFile :: FilePath -> IO ()
writeBlueprintToFile path = writeBlueprint path myContractBlueprint

main :: IO ()
main =
  getArgs >>= \case
    [arg] -> writeBlueprintToFile arg
    args -> fail $ "Expects one argument, got " <> show (length args)
