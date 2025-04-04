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
import Data.Text (pack)
import ExampleUserValidator
import PlutusLedgerApi.Common (serialiseCompiledCode)
import PlutusLedgerApi.V1
  ( AssetClass (..),
    CurrencySymbol (..),
    TokenName (..)
  )
import PlutusTx.Blueprint
import PlutusTx.Builtins.HasOpaque (stringToBuiltinByteStringHex)
import System.Environment (getArgs)

currencySymbol :: String
currencySymbol = "56a571005b437f87a01367984b29d50900a50adfcbd2a39136f3d931"

poolActionID :: String
poolActionID = "48a82f43395f4ea4be50f4da6360058fa8cd12a113524cab63ae14dba205a29b"
-- "https://api.binance.com/api/v3/ticker/price?symbol=ADAUSDT" --filter ".price|tonumber*100000000|floor" "uint"

myContractBlueprint :: ContractBlueprint
myContractBlueprint =
  MkContractBlueprint
    { contractId = Just "quex-oracle-user-example",
      contractPreamble = myPreamble,
      contractValidators = Set.fromList [validator],
      contractDefinitions = deriveDefinitions @'[AssetClass]
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
      validatorParameters =
        [ MkParameterBlueprint
            { parameterTitle = Just "Oracle Response token asset class",
              parameterDescription = Just . pack $ currencySymbol ++ "." ++ poolActionID,
              parameterPurpose = Set.singleton Spend,
              parameterSchema = definitionRef @AssetClass
            }
        ],
      validatorRedeemer =
        MkArgumentBlueprint
          { argumentTitle = Just "Redeemer for the validator",
            argumentDescription = Just "The validator does not use a redeemer, hence ()",
            argumentPurpose = Set.fromList [Spend],
            argumentSchema = definitionRef @()
          },
      validatorDatum = Nothing,
      validatorCompiled = do
        let cs = CurrencySymbol (stringToBuiltinByteStringHex currencySymbol)
        let paID = stringToBuiltinByteStringHex poolActionID
        let assetClass = AssetClass (cs, (TokenName paID))
        let code = Short.fromShort (serialiseCompiledCode (exampleUserSpendingValidatorScript assetClass))
        Just (compiledValidator PlutusV3 code)
    }

writeBlueprintToFile :: FilePath -> IO ()
writeBlueprintToFile path = writeBlueprint path myContractBlueprint

main :: IO ()
main =
  getArgs >>= \case
    [arg] -> writeBlueprintToFile arg
    args -> fail $ "Expects one argument, got " <> show (length args)
