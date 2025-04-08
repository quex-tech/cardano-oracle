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
import OracleResponseValidator
import PlutusLedgerApi.Common (BuiltinByteString, serialiseCompiledCode)
import PlutusLedgerApi.V1 (DiffMilliSeconds)
import PlutusTx.Blueprint
import SingleOraclePoolValidator (singleOraclePoolValidatorScript)
import System.Environment (getArgs)

myContractBlueprint :: ContractBlueprint
myContractBlueprint =
  MkContractBlueprint
    { contractId = Just "quex-oracle",
      contractPreamble = myPreamble,
      contractValidators = Set.fromList [validator, singleOraclePoolValidator],
      contractDefinitions = deriveDefinitions @[ETHSignedMessage, (BuiltinByteString, DiffMilliSeconds)]
    }

myPreamble :: Preamble
myPreamble =
  MkPreamble
    { preambleTitle = "QUEX Oracle",
      preambleDescription = Nothing,
      preambleVersion = "0.0.1",
      preamblePlutusVersion = PlutusV3,
      preambleLicense = Nothing
    }

validator :: ValidatorBlueprint referencedTypes
validator =
  MkValidatorBlueprint
    { validatorTitle = "Oracle Response Validator",
      validatorDescription = Nothing,
      validatorParameters = [],
      validatorRedeemer =
        MkArgumentBlueprint
          { argumentTitle = Just "Redeemer for the response validator",
            argumentDescription = Nothing,
            argumentPurpose = Set.fromList [Spend, Mint],
            argumentSchema = definitionRef @ETHSignedMessage
          },
      validatorDatum = Nothing,
      validatorCompiled = do
        let code = Short.fromShort (serialiseCompiledCode oracleResponseValidatorScript)
        Just (compiledValidator PlutusV3 code)
    }

singleOraclePoolValidator :: ValidatorBlueprint referencedTypes
singleOraclePoolValidator =
  MkValidatorBlueprint
    { validatorTitle = "Single Oracle Pool Validator",
      validatorDescription = Nothing,
      validatorParameters = [],
      validatorRedeemer =
        MkArgumentBlueprint
          { argumentTitle = Just "Redeemer for the single oracle pool validator",
            argumentDescription = Nothing,
            argumentPurpose = Set.fromList [Spend, Mint],
            argumentSchema = definitionRef @(BuiltinByteString, DiffMilliSeconds)
          },
      validatorDatum =
        Just
          MkArgumentBlueprint
            { argumentTitle = Just "Datum for the single oracle pool validator",
              argumentDescription = Nothing,
              argumentPurpose = Set.singleton Spend,
              argumentSchema = definitionRef @(BuiltinByteString, DiffMilliSeconds)
            },
      validatorCompiled = do
        let code = Short.fromShort (serialiseCompiledCode singleOraclePoolValidatorScript)
        Just (compiledValidator PlutusV3 code)
    }

writeBlueprintToFile :: FilePath -> IO ()
writeBlueprintToFile path = writeBlueprint path myContractBlueprint

main :: IO ()
main =
  getArgs >>= \case
    [arg] -> writeBlueprintToFile arg
    args -> fail $ "Expects one argument, got " <> show (length args)
