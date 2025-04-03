# QUEX Cardano Oracle

## Structure

+ `on-chain/`: contains on-chain contracts in Plinth (Plutus Tx) language
+ `off-chain/`: contains off-chain Python scripts. See [the off-chain README](./off-chain/README.md)

## Building on-chain contracts

Ensure you have `docker` installed.

Run:

```sh
./compile-contracts.sh
```

This script builds the contracts inside a Docker container, and puts Plutus blueprint .json files into the `off-chain` directory to be used by off-chain Python scripts.

It takes a long time to run. You can take advantage of incremental builds by running an interactive container with:

```sh
docker run \
  -v .:/workspaces/quex-oracle \
  -it \
  ghcr.io/input-output-hk/devx-devcontainer:x86_64-linux.ghc96-iog
```

Inside the container, do once:

```sh
cd /workspaces/quex-oracle/on-chain
cabal update
```

After that, build the contracts with:

```sh
cabal run gen-oracle-blueprint ../off-chain/plutus.json
cabal run gen-example-user-blueprint ../off-chain/plutus.user.json
```

Run tests with:

```sh
cabal test
```
