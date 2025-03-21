#!/bin/bash

docker run \
  -v .:/workspaces/quex-oracle \
  -it \
  ghcr.io/input-output-hk/devx-devcontainer:x86_64-linux.ghc96-iog
