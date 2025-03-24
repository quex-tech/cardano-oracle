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
import Oracle (ETHSignedMessage)
import OracleResponseMintingPolicy
import OracleResponseSpendingValidator
import PlutusLedgerApi.Common (serialiseCompiledCode)
import PlutusLedgerApi.V1 (Address, ScriptHash (..), SerialisedScript, scriptHashAddress)
import PlutusTx.Blueprint
import PlutusTx.Prelude (toBuiltin)
import System.Environment (getArgs)

myContractBlueprint :: ContractBlueprint
myContractBlueprint =
  MkContractBlueprint
    { contractId = Just "quex-oracle",
      contractPreamble = myPreamble,
      contractValidators = Set.fromList [mintingPolicy, validator],
      contractDefinitions = deriveDefinitions @[Address, OracleResponseMintingRedeemer, ETHSignedMessage]
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

mintingPolicy :: ValidatorBlueprint referencedTypes
mintingPolicy =
  MkValidatorBlueprint
    { validatorTitle = "Oracle Response Minting Validator",
      validatorDescription = Nothing,
      validatorParameters =
        [ MkParameterBlueprint
            { parameterTitle = Just "Oracle Response Spending Validator Address",
              parameterDescription = Nothing,
              parameterPurpose = Set.singleton Mint,
              parameterSchema = definitionRef @Address
            }
        ],
      validatorRedeemer =
        MkArgumentBlueprint
          { argumentTitle = Just "Redeemer for the minting policy",
            argumentDescription = Nothing,
            argumentPurpose = Set.singleton Mint,
            argumentSchema = definitionRef @OracleResponseMintingRedeemer
          },
      validatorDatum = Nothing,
      validatorCompiled = do
        let script = oracleResponseMintingPolicyScript . toAddress . serialiseCompiledCode $ oracleResponseSpendingValidatorScript
        let code = Short.fromShort (serialiseCompiledCode script)
        Just (compiledValidator PlutusV3 code)
    }

validator :: ValidatorBlueprint referencedTypes
validator =
  MkValidatorBlueprint
    { validatorTitle = "Oracle Response Spending Validator",
      validatorDescription = Nothing,
      validatorParameters = [],
      validatorRedeemer =
        MkArgumentBlueprint
          { argumentTitle = Just "Redeemer for the spending validator",
            argumentDescription = Nothing,
            argumentPurpose = Set.singleton Spend,
            argumentSchema = definitionRef @ETHSignedMessage
          },
      validatorDatum = Nothing,
      validatorCompiled = do
        let code = Short.fromShort (serialiseCompiledCode oracleResponseSpendingValidatorScript)
        Just (compiledValidator PlutusV3 code)
    }

toAddress :: SerialisedScript -> Address
toAddress =
  scriptHashAddress
    . ScriptHash
    . toBuiltin
    . compiledValidatorHash
    . compiledValidator PlutusV3
    . Short.fromShort

writeBlueprintToFile :: FilePath -> IO ()
writeBlueprintToFile path = writeBlueprint path myContractBlueprint

main :: IO ()
main =
  getArgs >>= \case
    [arg] -> writeBlueprintToFile arg
    args -> fail $ "Expects one argument, got " <> show (length args)
