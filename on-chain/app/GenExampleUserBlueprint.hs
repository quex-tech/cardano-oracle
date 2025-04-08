{-# LANGUAGE DataKinds #-}
{-# LANGUAGE DerivingStrategies #-}
{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE FlexibleInstances #-}
{-# LANGUAGE GADTs #-}
{-# LANGUAGE ImportQualifiedPost #-}
{-# LANGUAGE LambdaCase #-}
{-# LANGUAGE MultiParamTypeClasses #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE TypeApplications #-}
{-# LANGUAGE UndecidableInstances #-}

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
currencySymbol = "4057d367339745c83dbd613f3fd641a74f076879f533b7cfa6eaad2a"

poolActionID :: String
poolActionID = "4928cea39057bfd8bc4cbc3d11a5ebc8cdaa4eb67064227e65dd8d64521d696f"

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
        let assetClass = AssetClass (cs, TokenName paID)
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
