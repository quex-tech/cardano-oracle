# Quex Cardano oracle — on-camera demo

A small, reproducible walkthrough that drives the real off-chain scripts, live on
Cardano mainnet, for a developer-facing video. Everything runs from this repo; the
only tab outside it is the explorer (cardanoscan) to show the request/response/spend.

The loop it demonstrates:

1. **Request** — you submit an on-chain data request for a web API value.
2. **Response** — the Quex relayer + Intel TDX enclave fetch, sign in hardware, and post the value back on-chain.
3. **Consume** — an example Plutus contract unlocks funds only against that verified value.

## Scripts

Run from `off-chain/` (the helpers `cd` there themselves):

| Step | Script | What it does | On-chain? |
|------|--------|--------------|-----------|
| 1 | `./demo/01-setup.sh` | Set the stage: network, pool, protocol addresses, requester wallet | read-only |
| 2 | `./demo/02-request.sh` | Submit the ADA/USDT request, print the request tx | **submits** |
| 3 | `./demo/03-await.sh` | Poll until the TEE-signed response lands, print the response tx | read-only |
| 4 | `./demo/04-consumer.sh` | Cue card: consumer contract + confirmed spend tx link | read-only |

Step 1 sets the stage locally; from step 2 on, each script is an actual Cardano interaction.

Each script prints the exact command it runs, so if a take fails you re-run just that step.

## Setup

```sh
uv sync                          # once, creates .venv
cp demo/.env.example .env        # then edit .env (it is gitignored)
```

Fill `.env` (see `.env.example`). The only secret is `WALLET_MNEMONIC`; the oracle's
signing key lives inside the enclave, never here.

## Pre-record checklist

- [ ] `.env` filled; `WALLET_MNEMONIC` Treasury address topped up with ~3-5 ADA.
- [ ] `CARDANO_NETWORK=mainnet` and `ORACLE_POOL_ID` set to the mainnet pool.
- [ ] `./protocol.py` prints response currency symbol `c093ca8bc5318cb767219cc1907aa03120ba696fb3293b48069e5edc` (confirms this checkout matches the mainnet deploy).
- [ ] **Relayer is running** on mainnet. Do a full dry run: `02` then `03` should complete in ~1-2 min. If not, the relayer is down; see fallback in `03`.
- [ ] Browser tabs pre-opened: request tx, response tx, spend tx, `verify.quex.tech`, the repo, the audit PDF, `plutus-auditor`.
- [ ] Terminal zoomed to ~125%, cursor highlight on.

## Act 3 prerequisite (the confirmed spend tx)

The video shows Act 3 as an already-confirmed spend transaction in the explorer, not a
live run. That tx must exist first. The committed `plutus.user.json` is compiled for a
non-mainnet deployment, so producing a mainnet spend needs a one-time rebuild:

1. In `on-chain/app/GenExampleUserBlueprint.hs` set:
   - `currencySymbol = "c093ca8bc5318cb767219cc1907aa03120ba696fb3293b48069e5edc"`
   - `poolActionID = "64b526bad78de161682bea9782c4c28ac641d9ab5bf0957bcdd688366d8a13ed"` (the ADA/USDT request above; printed by `./responses.py`)
   Also check the unlock rule in `on-chain/src/ExampleUserValidator.hs`: `isResponseGood datum = datum > 25000000` means ADA/USDT > $0.25. With ADA below that (e.g. $0.17 as of 2026-07-03, response value 16850000) the spend will fail; lower the threshold (e.g. `> 10000000`).
2. Rebuild into a separate blueprint (keeps the repo default intact):
   ```sh
   ../compile-contracts.sh    # docker; on Apple Silicon the x86 GHC image runs emulated (slow, one-time)
   mv ../off-chain/plutus.user.json ../off-chain/plutus.user.mainnet.json
   ```
3. Produce the spend, off-camera:
   ```sh
   ./demo.py lock 5 --user-plutus-blueprint plutus.user.mainnet.json --submit
   ./protocol.py                              # note the responses address
   ./demo.py spend <responses addr> --user-plutus-blueprint plutus.user.mainnet.json --submit
   ```
4. Put the resulting spend tx id in `.env` as `SPEND_TX=...`; `04-consumer.sh` prints its link.

If you skip the rebuild, keep Act 3 to narrating `ExampleUserValidator.hs` on screen
(the `isResponseGood` rule) and describe consumption without a live spend tx.
