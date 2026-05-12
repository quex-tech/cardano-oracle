# Audit — Quex Cardano Oracle

**Subject:** [quex-tech/cardano-oracle](https://github.com/quex-tech/cardano-oracle) — TEE-attested HTTPS data oracle for Cardano (Catalyst Fund 14, project 1400103).

**Commit audited:** `11d13a56` on branch `audit/plutus-skill`, forked from `main`.

**Auditor:** AI-assisted walk-through using the `plutus-audit` skill (MLabs Plutus Pitfalls + Plutonomicon Vulnerabilities + CIP-52 Audit Best Practice Guidelines). This is **not** a substitute for a human-expert audit; see [§12. Disclosures](#12-disclosures).

**Audit date:** 2026-05-12.

**Skill version:** `plutus-audit@0.1.0` (`tee-audit` plugin, local).

---

## 1. Scope

### 1.1 Repository layout

```
on-chain/                Plinth (PlutusTx) validators, GHC 9.6, plutus-core ^>=1.42
├── src/
│   ├── OracleRequestValidator.hs        request escrow + payout
│   ├── OracleResponseValidator.hs       response storage + signature check
│   ├── SingleOraclePoolValidator.hs     immutable single-oracle pool registry
│   ├── ExampleUserValidator.hs          demo consumer (not production)
│   └── Validator.hs                     shared storage helper
├── app/
│   ├── GenOracleBlueprint.hs            CIP-57 blueprint generation
│   └── GenExampleUserBlueprint.hs       (demo)
└── test/Main.hs                         CBOR + ECDSA fixtures only

off-chain/               PyCardano + Blockfrost/Ogmios, Python 3.12
├── oracles.py           pool registration (mint authority NFT)
├── relay.py / responses.py   build response txs
├── pending_requests.py  build/fulfill request txs
├── scripts.py           reference-script library (CIP-33)
├── protocol.py / wallet.py / models.py / utils.py   plumbing
└── tests/               unit tests for off-chain TX builders only
```

### 1.2 In scope

| File | Script-purpose | Parameter | Datum type | Redeemer type |
|---|---|---|---|---|
| `OracleRequestValidator.hs` | Spending only (returns `unitval` on other purposes via `oracleRequestUntypedValidator` fallback — **see Finding [REQ-A](#req-a-validator-trivially-passes-for-purposes-without-an-inline-datum)**) | `CurrencySymbol` (responses currency, applied at compile-time via `unsafeApplyCode`) | `OracleRequest` (9-field record: action+proof, pool ID, pool-action ID, time window, owner, reward, cost-per-byte, max cost) | `BuiltinData` (ignored — only datum + script context used) |
| `OracleResponseValidator.hs` | Spending **and** Minting (script-hash doubles as authority currency symbol, no purpose check) | none | response payload `(POSIXTimeSeconds, Integer, BuiltinData)` as inline datum | `ETHSignedMessage = (BuiltinData, ETHSignature)` |
| `SingleOraclePoolValidator.hs` | Spending **and** Minting (same dual-purpose pattern) | none | `(ETHCompressedPubKey, DiffMilliSeconds)` (oracle pubkey + response TTL) | `(BuiltinByteString, DiffMilliSeconds)` (same shape) |
| `ExampleUserValidator.hs` | Spending | `AssetClass` (expected oracle response identity) | (none consumed — script ignores its own datum) | (none consumed) |
| `Validator.hs` | helper (not a script) — `storageScriptInfo` | — | — | — |

### 1.3 Out of scope

- Off-chain Python — covered for **TX-construction parity** with on-chain (CIP-52 §7) but not for OWASP, dependency CVEs, key custody, or wallet UX. Use the generic `security-auditor` agent in `coding-skills` for those passes.
- TEE attestation layer (Intel TDX measurements, quote verification, enclave key management). The on-chain code currently verifies an **ECDSA signature** over the oracle message; there is **no on-chain TDX-attestation verification**. See Finding [P7B-1](#p7b-1-no-on-chain-tee-attestation-trust-collapses-to-ecdsa-key-custody).
- The `developer-docs` MkDocs site.
- The `unboundedmarket` Catalyst-F12 scanner integration that lives on `audit/unboundedmarket-scan`; that is an instrumentation branch, not part of the protocol.

### 1.4 Out-of-band components

| Component | Coverage |
|---|---|
| TEE (Intel TDX) signing enclave | **Trusted as black box.** No attestation verification on-chain (P7B-1). |
| Off-chain Python relayer | TX-format conformance only (CIP-52 §7). |
| Blockfrost / Ogmios | API endpoints assumed honest. Standard caveat for any indexer-backed off-chain. |
| HTTPS data sources (Binance, etc.) | Single-source per request — no multi-source agreement (P7A-1). |

---

## 2. Methodology

### 2.1 Standards walked

- **[MLabs — Common Plutus Security Vulnerabilities](https://www.mlabs.city/blog/common-plutus-security-vulnerabilities)** — 11 categories.
- **[Plutonomicon — Vulnerabilities](https://plutonomicon.github.io/plutonomicon/vulnerabilities)** — 9 categories.
- **[CIP-52 — Cardano Audit Best Practice Guidelines](https://cips.cardano.org/cip/CIP-52)** — 12 sections.

Each validator is walked against **every** category. Categories that don't apply are recorded with a one-line reason rather than skipped silently — that's how CIP-52 expects thoroughness to be documented (§10–11).

### 2.2 Tools

- Manual code review with frontier-model reasoning (Claude Opus 4.7, 1M context).
- `rg`, `git grep`, `git diff` for evidence-gathering.
- **Not run:** `cabal build`, `cabal test`, `cabal outdated` — would require a Linux build container (devx-devcontainer image) that is out of scope for this session. The README claims `compile-contracts.sh` builds successfully; the test suite at `on-chain/test/Main.hs` covers CBOR serialisation + ECDSA fixtures only and is documented as a CIP-52 §8 finding.

### 2.3 Severity rubric (CIP-52 §11)

| Severity | Definition |
|---|---|
| Critical | Direct loss of funds; attacker can drain or freeze the contract. |
| High | Funds at risk under realistic conditions; or contract unusable for legitimate users. |
| Medium | Funds at risk under unusual conditions; UX / DoS issues with no fund loss. |
| Low | Best-practice violations; subtle issues with limited impact. |
| Informational | No security impact; observation only. |

---

## 3. Threat model

### 3.1 Actors

| Actor | Capabilities | Trust level |
|---|---|---|
| **Requester** | Builds a request tx that locks reward at the request validator with a pool-action-ID; later signs the expiry-refund. | Untrusted (anyone). |
| **Relayer** (TEE enclave key holder) | Signs an oracle message (`ActionID, DataItem, PubKeyHash`) with an ETH-compatible secp256k1 key; submits the response tx that mints the response NFT and stores the datum. | Trusted to be honest *and* available. No on-chain attestation. |
| **Pool operator** | Mints/burns oracle-pool NFTs (`SingleOraclePoolValidator` for single-oracle pools, native `ScriptPubkey` for private pools). | Trusted for the pool config; for *single-oracle* pools the pool token is immutable. |
| **Library operator** (off-chain `wallet.library`) | Holds the reference-script library address (CIP-33). Can spend the reference-script UTxOs. | Trusted not to delete or front-run reference scripts. |
| **Consumer contract** (e.g., `ExampleUserValidator`) | Pulls oracle response as a reference input; gates its own spending logic on the response payload. | Trusted to validate the response against the expected `AssetClass`. |

### 3.2 Asset model

The protocol uses **script-hash-as-authority-currency**:

- For `OracleResponseValidator` and `SingleOraclePoolValidator`, the validator's own script hash *is* the currency symbol of its authority NFT (`storageScriptInfo` derives `CurrencySymbol cs = CurrencySymbol rawCS` where `rawCS` is the script hash).
- This means a single script doubles as a minting policy. **There is no separate one-shot mint policy** to enforce uniqueness; uniqueness is enforced by the validator itself on every spend (`symbols value == [adaSymbol, currencySymbol]`, `currencySymbolValueOf value currencySymbol == 1`).
- Pool tokens (`AssetName`) are constructed deterministically:
  - For `SingleOraclePoolValidator`: `tokenName = sha2_256 (serialiseData rawRedeemer)` — hash of the redeemer that names the pool's config.
  - For `OracleResponseValidator`: `poolActionID = sha2_256 (poolCurrency ++ poolToken ++ actionID)` — hash of the oracle-pool identity plus the per-action ID.

### 3.3 Trust boundaries

| Boundary | On-chain enforced? |
|---|---|
| "The relayer holds the TEE-issued signing key, not an arbitrary user." | **No** — only ECDSA signature is checked. TDX attestation is not bound to the signature on-chain. |
| "The oracle pubkey in the pool datum matches the actual TEE enclave that signed the response." | Yes (via signature verify); but the pubkey was set at pool-registration time and is trusted to have been issued by a TDX enclave. The chain has no independent proof of that. |
| "The pool-config UTxO is the canonical one." | **Partially.** Validator enforces NFT-uniqueness *at the time of spend* — but the **consumer must select the right reference input**. For consumers using only `AssetClass` to identify the response (like `ExampleUserValidator`), an attacker who mints a duplicate token under the *same script* cannot succeed (the minting check prevents it); but an off-chain caller still has to find the right UTxO. |
| "The expired request refunds to the original owner." | Yes (`txSignedBy txInfo owner`). |
| "Off-chain cannot forge a reference-script substitution attack." | Library scripts at `wallet.library.addr` are at a pubkey-only address: the library-key holder can spend any reference UTxO. If the library key is compromised, an attacker can delete or replace reference scripts. See [LIB-1](#lib-1-reference-script-library-is-key-controlled-not-script-controlled). |

### 3.4 Authority-token uniqueness — how it is enforced

This is the cornerstone of the protocol, so it deserves a paragraph in the threat model.

Rather than minting a one-shot NFT and trusting later spends, Quex uses an inductive uniqueness argument:

1. **At mint time**, the script runs in `MintingScript` purpose. `storageScriptInfo` returns `(cs, scriptHashAddress cs, Nothing, [])`. The validator then requires the **single** new output at the script address to carry `valueOf value currencySymbol tokenName == 1`, `currencySymbolValueOf value currencySymbol == 1`, and `symbols value == [adaSymbol, currencySymbol]`. So one and only one token is created per mint tx.
2. **At spend time**, the validator runs in `SpendingScript` purpose. `storageScriptInfo` retrieves the spent token name from the current input. The new continuation output again must carry exactly one such token. The `spentTokenNames` check enforces that if the old UTxO had one token of name `T`, the new one carries `T` as well.

This is elegant — uniqueness is preserved transitively without any one-shot policy. But it depends on **the mint check being airtight**, and the responseValidator has a known weak point (see [RESP-1](#resp-1-response-mint-can-include-arbitrary-other-tokens-via-the-spend-then-mint-path)). See finding for details.

### 3.5 Off-chain invariants the on-chain code does not enforce

The validator delegates these to the off-chain relayer. If the relayer misbehaves, the chain provides no defence.

| Off-chain invariant | Validator behaviour if violated |
|---|---|
| Relayer queries `≥N` independent data sources, takes a threshold (Plutonomicon-7a). | Single-source price is happily signed and accepted. |
| Relayer rate-limits price volatility (TWAP, outlier rejection). | Validator accepts any price the relayer signs. |
| Relayer enforces a sensible `coinPerUTxOByte` / `reward` / `maxCost` in `OracleRequest`. | These are user-set in the datum (Finding [REQ-B](#req-b-coinperutxobyte-and-maxcost-are-attacker-controlled-in-the-request-datum)). |
| Off-chain wallet picks "clean" UTxOs (no dust tokens) when feeding the script. | The validator's `Value` operations remain bounded (MLabs-5) because the response UTxO is **constructed** by the relayer, not the user; risk is shifted. |

These belong in the report's [§4. Findings](#4-findings) as Informational, plus in the off-chain relayer's documentation as required operational rules.
