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

---

## 4. Findings

Each finding is graded per [§2.3](#23-severity-rubric-cip-52-11) and cites the originating category (`MLabs-N`, `Plutonomicon-N`, `CIP-52-§N`, or `TEE-N` for the TEE-attestation-specific class added by the `plutus-audit` skill).

Summary table:

| ID | Severity | Title | Category |
|---|---|---|---|
| [REQ-C](#req-c-multiple-satisfaction-in-existschangeoutput) | **Critical** | Multiple satisfaction in `existsChangeOutput` lets a relayer steal owner funds when bundling requests | MLabs-7 |
| [P7B-1](#p7b-1-no-on-chain-tee-attestation-trust-collapses-to-ecdsa-key-custody) | **High** | No on-chain TEE attestation; trust collapses to ECDSA key custody | Plutonomicon-7b / TEE-1 |
| [REQ-A](#req-a-validator-trivially-passes-for-purposes-without-an-inline-datum) | **High** | Request validator trivially passes on hash-only datums (`SpendingScript _ Nothing -> unitval`) | MLabs-3 / Plutonomicon-6 |
| [RESP-2](#resp-2-getoracle-trusts-any-reference-input-with-a-single-non-ada-token) | **Medium** | `getOracle` trusts any reference input with a single non-ada token, no address pinning | MLabs-8 / Plutonomicon-9 |
| [REQ-D](#req-d-minchange--0-short-circuits-the-owner-payment-check) | **Medium** | `minChange ≤ 0` short-circuits the owner-payment check entirely | CIP-52-§4 |
| [LIB-1](#lib-1-reference-script-library-is-key-controlled-not-script-controlled) | **Medium** | Reference-script library is at a pubkey address, not a script address | CIP-52-§7 |
| [REQ-B](#req-b-request-datum-fields-not-validated) | **Low** | `coinPerUTxOByte`, `reward`, `maxCost` are owner-controlled with no on-chain bounds | MLabs-4 / Plutonomicon-6 |
| [RESP-A](#resp-a-untyped-validator-does-not-discriminate-script-purpose) | **Low** | `oracleResponseUntypedValidator` runs the same logic for every script-purpose | CIP-52-§6 |
| [SOPV-1](#sopv-1-no-upper-bound-on-response-validity-period) | **Low** | `responseValidityPeriod` has no upper bound in `SingleOraclePoolValidator` | CIP-52-§4 |
| [REQ-MAGIC-1](#req-magic-1-magic-number-274-uxto-overhead) | **Low** | Magic number `274` for UTxO entry overhead — should be named and sourced | CIP-52-§3 |
| [TEST-1](#test-1-test-suite-has-no-validator-level-tests) | **Low** | Test suite covers CBOR + ECDSA fixtures only; no validator tests | CIP-52-§8 |
| [EUS-1](#eus-1-exampleuservalidator-uses-unsafefrombuiltindata-on-reference-input) | **Informational** | `ExampleUserValidator` uses `unsafeFromBuiltinData` on a reference-input datum | MLabs-3 |
| [RESP-B](#resp-b-relayer-pkh-check-excludes-multisig-and-script-witnesses) | **Informational** | `relayer ∈ txInfoSignatories` rules out script-credentialled relayers (multisig wallets) | MLabs anti-pattern |
| [REQ-ERR](#req-err-error--in-mid-validator-paths-produces-no-trace) | **Informational** | `error ()` paths in `findOwnInput`, `getOracle`, `storageScriptInfo` produce empty traces | CIP-52-§6 |
| [P9-1](#p9-1-reqpoolid-in-the-request-datum-is-unused-on-chain) | **Informational** | `reqPoolID` field exists in the request datum but is never read by the validator | Plutonomicon-9 |
| [DOC-1](#doc-1-architecture-document-and-state-machine-diagrams-missing) | **Informational** | No architecture document or state-machine diagrams in `on-chain/` | CIP-52-§2 |

### Critical

#### REQ-C — Multiple satisfaction in `existsChangeOutput`

**Severity:** Critical
**Category:** MLabs-7
**Location:** `on-chain/src/OracleRequestValidator.hs:131–135`

`existsChangeOutput` checks that *some* output going to the request owner carries at least `minChange` lovelace:

```haskell
isOwners out =
  case txOutAddress out of
    Address (PubKeyCredential pkh) _ -> pkh == owner
    _ -> False
in minChange <= 0 || any (\o -> isOwners o && lovelaceValueOf (txOutValue o) >= minChange) txOutputs
```

When a relayer bundles **two** of the same owner's requests into one transaction, both validator instances see the same `TxInfo` and both apply the same `any … >= minChange` predicate. A **single** output paying `max(minChange₁, minChange₂)` lovelace to the owner satisfies *both* instances.

**Attack vector:** A self-interested relayer fulfills requests R₁ and R₂ from owner `O`, both with `requestCoin = 5 ADA` and `maxCost = 1 ADA` (so `minChange = 4 ADA` each). The relayer constructs one tx that:

1. Spends both request UTxOs.
2. Mints the two corresponding response NFTs.
3. Stores both response UTxOs at the response validator.
4. Pays a **single** `4 ADA` output to `O`.

Each `existsChangeOutput` invocation finds the same 4 ADA output and returns `True`. The relayer pockets `(5 + 5) − 4 = 6 ADA`. `O` expected to receive 8 ADA; receives 4. The 4 ADA loss is direct, and the protocol gives `O` no on-chain remedy.

**Recommendation:** Tag the refund output with a per-request marker. Two clean fixes:

1. **Output-index pinning** — extend the datum with an expected `OutputIndex` and require `txInfoOutputs !! ix` to be the refund. (Fails if the off-chain reorders outputs; needs careful off-chain spec.)
2. **One-shot refund token** — mint a `1`-unit token at request creation under a parameter-bound minting policy, included in the request UTxO; spend requires the refund output to carry that token. The token effectively forces a dedicated output per request. This is the standard Cardano fix for MLabs-7 in payout-style validators.

**Test required:** Build a tx that consumes two request UTxOs from the same owner with one merged refund output equal to `max(minChange₁, minChange₂)` and assert the script fails. There is currently no such test; this is the most important regression to add.

---

### High

#### P7B-1 — No on-chain TEE attestation; trust collapses to ECDSA key custody

**Severity:** High
**Category:** Plutonomicon-7b / TEE-1
**Location:** `on-chain/src/OracleResponseValidator.hs:144–159`, `SingleOraclePoolValidator.hs:60–67`

The `verifyOracleMessage` chain verifies a secp256k1 ECDSA signature against a pubkey stored in the pool datum:

```haskell
verifyOracleMessage signedOracleMessage (pubKey, _) _ =
  verifyEcdsaSecp256k1Signature pubKey hash signature
```

The pubkey is set at pool-registration time. On-chain, **nothing binds this pubkey to a TEE-resident private key.** If the operator's signing key escapes the TEE (extraction, exfiltration from a misconfigured enclave, or registration of a non-TEE key), an attacker producing valid signatures is indistinguishable from the legitimate TEE.

The project's value proposition — and the Catalyst Fund 14 deliverable framing — claims TEE-attested oracle data. On-chain this claim reduces to "trust whoever holds the registered key." The TEE matters only in the off-chain pool-registration ceremony, which is a one-time event with no on-chain footprint.

**Attack vector:** An adversary who compromises the relayer's signing key (post-exfiltration, supply-chain compromise of the enclave runtime, social engineering, or operator key-management failure) can post arbitrary oracle responses indistinguishable from genuine ones. Consumers that gate their funds on the response datum lose those funds.

**Recommendation:** Either (a) downgrade the public claim to "operationally TEE-signed" and document the trust model as ECDSA-key-custody, or (b) extend the on-chain protocol with one of:

1. **Bind the pool's registered pubkey to a TDX quote.** The pool datum stores the quote alongside the pubkey, and pool minting verifies the quote. Pool registration becomes a public, anyone-can-verify operation. Quex's existing TEE infrastructure makes this feasible.
2. **Per-response TDX attestation.** Each response carries a TDX quote over the message; the validator verifies the quote (requires on-chain quote-verifier — costly in ex-units, but precedent exists in IOG's `cardano-tee` experiments).
3. **Threshold of TEEs.** Require `≥ M` signatures from `N` registered TEE pubkeys per response. Mitigates single-key compromise without on-chain attestation verification.

Option (1) is the lowest-cost honest fix.

**Test required:** Document the threat model in the user-facing spec and reference it from this finding. No code test catches this — it is an architectural gap.

#### REQ-A — Validator trivially passes for purposes without an inline datum

**Severity:** High
**Category:** MLabs-3 / Plutonomicon-6
**Location:** `on-chain/src/OracleRequestValidator.hs:186–193`

```haskell
oracleRequestUntypedValidator responseCurrencySymbol ctx =
  let scriptContext@(ScriptContext _ _ scriptInfo) = unsafeFromBuiltinData ctx
   in case scriptInfo of
        SpendingScript _ (Just (Datum datum)) ->
          check (oracleRequestTypedValidator responseCurrencySymbol (unsafeFromBuiltinData datum) scriptContext)
        SpendingScript _ Nothing -> unitval
        _ -> error ()
```

The `SpendingScript _ Nothing -> unitval` branch returns success **without running any check**. `Nothing` corresponds to a script-locked UTxO whose datum is present only as a hash (legacy V1 mode); in Conway, hash-only datums are still legal for script-locked outputs as long as the datum preimage is supplied in the witness set.

**Attack vector:** Anyone can pay to the request-validator address with a chosen datum-hash. If a legitimate user, or the off-chain relayer, ever creates a request UTxO with a datum-hash output (instead of an inline datum), the funds are spendable by *anyone*: the attacker constructs a spend with the `Nothing` branch and no inline datum, and the validator passes unconditionally.

`pending_requests.py`'s `TransactionBuilder.add_output(...)` defaults in PyCardano produce inline datums today, so the current off-chain code is not exploitable. The validator's defensive posture should not depend on that choice — a future off-chain refactor, or a misconfigured wallet, could move to hash-only and silently re-enable the bypass.

**Recommendation:** Replace `SpendingScript _ Nothing -> unitval` with `SpendingScript _ Nothing -> error ()`. There is no legitimate flow that creates a request UTxO without an inline datum; treating that shape as a failure denies the bypass.

**Test required:** Build a tx that creates a request UTxO with `DatumHash` (no inline), then a tx that spends it with no inline datum and arbitrary redeemer; assert the spend fails.

---

### Medium

#### RESP-2 — `getOracle` trusts any reference input with a single non-ada token

**Severity:** Medium
**Category:** MLabs-8 / Plutonomicon-9
**Location:** `on-chain/src/OracleResponseValidator.hs:118–137`

```haskell
getOracle TxInfo {txInfoReferenceInputs}
  | [oracle] <- mapMaybe (findOracle . txInInfoResolved) txInfoReferenceInputs = oracle
  | otherwise = error ()

findOracle (TxOut _ value (OutputDatum (Datum datum)) _) =
  case findPoolID value of
    Just poolID -> Just (poolID, unsafeFromBuiltinData datum)
    Nothing -> Nothing
```

The response validator extracts its pool config from whatever reference input contains exactly one non-ada token. It does **not** check:

- The reference input's address (must be the `SingleOraclePoolValidator` or a private-pool authority).
- The currency symbol of the token (no whitelist of acceptable pool-NFT policies).
- The structural validity of the datum before `unsafeFromBuiltinData`.

In the current flow this is contained because the response's `poolActionID = sha256(poolID ++ actionID)` is included in the response NFT's `tokenName`, and consumers look up responses by an `AssetClass` they trust. So an attacker who plants a fake pool reference can only produce responses with token names not matched by any legitimate consumer — they cannot impersonate a real pool's response stream.

That said, this is a defense-in-depth gap. Any future consumer that selects responses by `poolID` (not by full `(currency, poolActionID)` AssetClass) becomes trivially deceivable.

**Attack vector:** Attacker mints a token of their own currency, builds a reference UTxO with `(attackerToken, fakeDatum = (attackerPubKey, hugeTTL))`, signs an oracle message with their own key, posts a "response" with `actionID` of their choosing. The response NFT's `tokenName = sha256(attackerToken ++ actionID)`. Any consumer querying by this exact `(responseCurrency, sha256(attackerToken ++ actionID))` reads the attacker's signed garbage. (A naive "search responses by `actionID` only" consumer is the realistic victim.)

**Recommendation:** In `findOracle`, restrict reference inputs to those at a known set of addresses — either the `SingleOraclePoolValidator` script-hash address or a list of authorised private-pool minting-policy script addresses. Equivalently, restrict the accepted `CurrencySymbol` to the script hash of `SingleOraclePoolValidator` (plus the known private-pool policy hashes).

**Test required:** Submit a response tx using a reference input at a non-pool script address; assert validator rejects.

#### REQ-D — `minChange ≤ 0` short-circuits the owner-payment check

**Severity:** Medium
**Category:** CIP-52-§4 (specification compliance)
**Location:** `on-chain/src/OracleRequestValidator.hs:135`

```haskell
in minChange <= 0 || any (\o -> isOwners o && lovelaceValueOf (txOutValue o) >= minChange) txOutputs
```

When `minChange ≤ 0`, the entire change-output presence check is skipped. The protocol-level meaning is "the owner doesn't need a refund" but the validator interprets it as "the owner does not need to receive *anything*". A relayer can then take 100 % of `requestCoin` without producing any output to the owner.

This is exploitable any time the request datum's `(reward, coinPerUTxOByte, maxCost)` and the on-chain `(txFee, responseBytes, oldResponseCoin)` combine so that `cappedCost ≥ requestCoin`. The user-set parameters bound the situation: with `maxCost = 0`, `cappedCost = 0` and `minChange = requestCoin`, the relayer must return everything; with `maxCost ≥ requestCoin`, the relayer can take everything.

This is partly intentional — users may want "all-in" requests where they trade the entire `requestCoin` for the response service. But the validator does not document this and the off-chain `pending_requests.py` does not sanity-check it. A user setting `maxCost = 1 ADA` for a 1-ADA request silently authorises the relayer to keep their entire deposit if `realCost` happens to round up to 1 ADA.

**Attack vector:** Relayer constructs a response that makes `cappedCost` equal `requestCoin`. Since `realCost` depends on `txFee`, the relayer (who builds the tx) can drive fee/cost combinations that maximise `cappedCost`. Owner expects up to `maxCost` loss; loses up to `requestCoin`.

**Recommendation:** Either (a) document that `maxCost` is the maximum payout to the relayer and the user must accept the worst case; (b) require `minChange > 0` (enforce a strict positive change, even tiny — e.g., `requestCoin - cappedCost ≥ minUTxOLovelace`); or (c) enforce `cappedCost ≤ reward + storageOverhead` and reject relayers who inflate `txFee` artificially.

**Test required:** Build a tx where `cappedCost == requestCoin` and there is no output to the owner; assert validator behaviour matches the documented spec.

#### LIB-1 — Reference-script library is key-controlled, not script-controlled

**Severity:** Medium
**Category:** CIP-52-§7 (off-chain) / operational
**Location:** `off-chain/scripts.py:115`, `off-chain/wallet.py` (library credential derivation)

The off-chain `ScriptRepository.add_tx` deposits each Plutus reference script at `wallet.library.addr(nw)` — a payment-pubkey-only address. The library wallet's private key holder can spend, replace, or burn any reference UTxO at that address.

**Attack vector:**

- **Loss of availability** — if the library key is lost, the scripts must be re-published and every off-chain tooling that pinned reference inputs by `(txId, ix)` must be updated.
- **Replacement** — the library-key holder can spend the existing reference UTxO and pay a *different* Plutus script (same hash, different bytecode? — no, the hash is content-addressed; but they can publish a new UTxO with the same script and let consumers race the UTxO selection). More realistically: they could delete the reference and force every consumer back to inline scripts.
- **Off-chain MITM** — a compromised library wallet allows an attacker to delete reference scripts, breaking the relayer's ability to build txs.

**Recommendation:** Move the library to a multisig or script address — e.g., a 2-of-3 native script with the operator key plus two cold keys. Or use a known-immutable script-locked UTxO with a "never-spendable" validator (`\_ -> False`) so reference scripts can be published but never removed. The latter trades a small ada deposit for true immutability.

**Test required:** Operational runbook test, not on-chain.

---

### Low

#### REQ-B — Request datum fields not validated

**Severity:** Low
**Category:** MLabs-4 (size) / Plutonomicon-6 (unauthorised data modification)
**Location:** `on-chain/src/OracleRequestValidator.hs:77–87`, `95`

The `OracleRequest` datum has nine fields, several of which influence the payout math:

- `reqCoinPerUTxOByte` — multiplied into `realCost`.
- `reqReward` — added into `realCost`.
- `reqMaxCost` — caps `cappedCost`.
- `reqAfter` / `reqBefore` — define the request's validity window.
- `reqAction` / `reqPoolID` / `reqPoolActionID` — not bounded; arbitrary `BuiltinByteString` / `TokenName`.

The validator never bounds these. A malformed request (e.g., `reqMaxCost = -2⁶⁴`, `reqCoinPerUTxOByte = -1`, `reqAfter > reqBefore`) reaches the on-chain code; some combinations are exploitable, most are just DoS to the off-chain relayer (it wastes evaluation effort on impossible-to-fulfil requests). Plinth `Integer` is arbitrary-precision so there is no overflow, but there is also no sanity check.

Combined with [REQ-D](#req-d-minchange--0-short-circuits-the-owner-payment-check) above, the `reqMaxCost` / `reqCoinPerUTxOByte` levers let the request creator define a deliberately self-damaging request that loses all `requestCoin` to whichever relayer picks it up.

**Recommendation:** Add validator-level bounds: `reqMaxCost ≥ 0`, `reqMaxCost ≤ reqReward + safeUpperBound`, `reqCoinPerUTxOByte > 0`, `reqAfter < reqBefore`, `lengthOfByteString reqAction ≤ N` for some protocol cap `N` (Plutus `serialiseData` cost grows linearly in input size). Update `pending_requests.py` to enforce the same.

**Test required:** For each bound, build a request datum that violates it; assert validator rejects.

#### RESP-A — Untyped validator does not discriminate script-purpose

**Severity:** Low
**Category:** CIP-52-§6 / `plutus-audit` anti-pattern "missing script-purpose check"
**Location:** `on-chain/src/OracleResponseValidator.hs:161–166`, `SingleOraclePoolValidator.hs:85–90`

```haskell
oracleResponseUntypedValidator rawCtx =
  let ctx = unsafeFromBuiltinData rawCtx
      ScriptContext {scriptContextRedeemer = Redeemer rawRedeemer} = ctx
      redeemer = unsafeFromBuiltinData rawRedeemer
   in check (oracleResponseTypedValidator redeemer ctx)
```

Neither response- nor single-pool-validator untyped wrappers branch on `scriptContextScriptInfo`. They run the same `typedValidator` for **every** purpose: Spending, Minting, Rewarding, Certifying, Voting, Proposing. The dispatch happens inside `storageScriptInfo`, which `error ()`s on non-Spending / non-Minting purposes — but the failure mode is opaque (empty trace).

This works today (the protocol uses only Spending+Minting). The risk is forward-compatibility: future Plutus releases or governance features could introduce new purposes that `storageScriptInfo` does not anticipate; the validator's behaviour becomes implementation-defined.

**Recommendation:** In each untyped wrapper, explicitly pattern-match on `scriptContextScriptInfo` and `error ()` (or `check False`) for purposes the contract does not support. The `plutus-audit` skill's anti-pattern list calls this out as a defensive requirement.

**Test required:** Submit a tx invoking the script under `RewardingScript`, `CertifyingScript`, `VotingScript`, and `ProposingScript`; assert each fails with a meaningful trace.

#### SOPV-1 — No upper bound on response validity period

**Severity:** Low
**Category:** CIP-52-§4
**Location:** `on-chain/src/SingleOraclePoolValidator.hs:66–67`

```haskell
(lengthOfByteString pubKey == 33)
  && (responseValidityPeriod > 0)
```

The single-oracle pool's `responseValidityPeriod` is constrained to positive, with no upper bound. A pool created with `responseValidityPeriod = 2⁶³ - 1` (a year-plus, in milliseconds) signs responses that the on-chain `OracleResponseValidator.verifyOracleMessage` accepts as "not expired" effectively forever — at least until the tx's `validRange` upper bound is reached.

Consumers that don't apply their own freshness check (see `ExampleUserValidator.responseExpiresAt`, which *does* hardcode 30 minutes) inherit the pool's choice. This is a "consumer beware" pattern; it would be safer for the pool validator to clamp to a protocol-wide maximum.

**Recommendation:** Add `responseValidityPeriod ≤ MAX_TTL_MS` where `MAX_TTL_MS` is, e.g., 24 hours.

**Test required:** Attempt pool registration with `responseValidityPeriod = MAX_TTL_MS + 1`; assert validator rejects.

#### REQ-MAGIC-1 — Magic number `274` for UTxO entry overhead

**Severity:** Low
**Category:** CIP-52-§3 (source-code quality)
**Location:** `on-chain/src/OracleRequestValidator.hs:128`

```haskell
realCost = reward + txFee + Lovelace (coinPerUTxOByte * (274 + responseBytes)) - oldResponseCoin
```

`274` is the constant UTxO-entry overhead in bytes used by Cardano's `minUTxOLovelace` formula (post-Alonzo). It is a protocol-level constant; if it changes (it has changed historically — `160` in Alonzo, `192` in Babbage, `274` in Conway-era for inline-datum outputs), this validator becomes incorrect.

`responses.py:120` uses `min_lovelace_post_alonzo(tx_out, context)` (PyCardano's own implementation) for the off-chain side, so the *off-chain* tracks the live protocol parameter. The *on-chain* validator does not.

**Recommendation:** Extract as a named constant with a citation:

```haskell
-- Cardano Conway-era UTxO entry overhead per CIP-XXX; update when the
-- ledger parameter `utxoCostPerByte` changes how minUTxO is computed.
utxoEntryOverheadBytes :: Integer
utxoEntryOverheadBytes = 274
```

If the protocol-parameter source ever changes, this can be parameterised at compile-time (`unsafeApplyCode`) and the deployment manifest updated.

**Test required:** None per se; this is hygiene. Add to the deployment runbook.

#### TEST-1 — Test suite has no validator-level tests

**Severity:** Low
**Category:** CIP-52-§8 (test coverage)
**Location:** `on-chain/test/Main.hs`

The on-chain test suite contains:

- 29 CBOR serialisation fixtures (`serialiseData`).
- 4 `unsafeFromBuiltinData` round-trip fixtures.
- 1 `verifyEcdsaSecp256k1Signature` fixture.

It does **not** exercise any validator. No `plutus-simple-model` integration. No property-based tests via `quickcheck-dynamic` or `quickcheck-contractmodel`. The mint path, the multiple-satisfaction scenario, the hash-only-datum bypass, the relayer-fraud and consumer-attack paths flagged above are all untested.

CIP-52 §8 says every audit finding should be paired with a regression test. None of the findings here have one — they cannot, because the test infrastructure does not invoke the validators.

**Recommendation:** Adopt `plutus-simple-model` (or `cardano-cli`-based golden-tx tests) and add at minimum one happy-path and one failure-path test per validator. The findings above each list a "Test required" — that's the prioritised backlog.

**Test required:** This finding is itself a meta-finding about tests.

---

### Informational

#### EUS-1 — `ExampleUserValidator` uses `unsafeFromBuiltinData` on reference input

**Severity:** Informational
**Category:** MLabs-3 (arbitrary datum)
**Location:** `on-chain/src/ExampleUserValidator.hs:73`

```haskell
| assetClassValueOf value assetClass == 1 -> unsafeFromBuiltinData (getDatum datum)
```

The consumer validator decodes the response datum with `unsafeFromBuiltinData`. The reference UTxO is gated by the authority-NFT check (`assetClassValueOf == 1`), and the response NFT is mintable only by the response validator's own logic — so the datum here is implicitly authenticated. Defensive coding still prefers `fromBuiltinData :: BuiltinData -> Maybe a` to surface a typed `traceIfFalse "malformed response datum" ...` rather than crash with an empty trace.

This is a demo validator (per `README.md`); the same advice applies to any production consumer the team writes against the oracle.

**Recommendation:** Use `fromBuiltinData` with explicit `Maybe` handling.

#### RESP-B — Relayer pkh check excludes multisig and script witnesses

**Severity:** Informational
**Category:** MLabs anti-pattern "treating `txInfoSignatories` as exhaustive"
**Location:** `on-chain/src/OracleResponseValidator.hs:93`

```haskell
(relayer `elem` txInfoSignatories)
```

`txInfoSignatories` lists only pubkey-witness signers. If a relayer is operated under a multisig (native or Plutus-script credential), the multisig signers appear in the witness set but `relayer ∈ txInfoSignatories` returns False unless the relayer is the multisig's root pubkey. This is intentional in the current design but should be documented as a constraint on relayer custody models.

**Recommendation:** Document explicitly. If multisig relayers become desirable in future, add a `txInfoWdrl` / `txInfoCerts` check or migrate to a script-credential validator.

#### REQ-ERR — `error ()` in mid-validator paths produces no trace

**Severity:** Informational
**Category:** CIP-52-§6 (failure-mode trace quality)
**Locations:**
- `on-chain/src/OracleRequestValidator.hs:106` (`findOwnInput` fallback)
- `on-chain/src/OracleResponseValidator.hs:116, 122, 130` (datum / getOracle / findOracle fallbacks)
- `on-chain/src/Validator.hs:56–57` (`storageScriptInfo` non-match)

Multiple paths use bare `error ()` to fail. The empty argument produces no trace string, so debug output on validator failure says only "script evaluation failed" — debuggers cannot tell *which* path tripped.

**Recommendation:** Replace each `error ()` with `traceError "<short identifier>"`. The Plinth `traceError` is cheap (the string is replaced with an integer at compile time when `-fplugin-opt PlutusTx.Plugin:trace-context` is set) and dramatically improves diagnosability.

#### P9-1 — `reqPoolID` in the request datum is unused on-chain

**Severity:** Informational
**Category:** Plutonomicon-9 (parameterisation oversight)
**Location:** `on-chain/src/OracleRequestValidator.hs:79, 95`

The `reqPoolID :: BuiltinByteString` field is in the datum but the validator destructure discards it (`MkOracleRequest _ _ poolActionID …`). It is used off-chain (e.g., by the relayer) to know which pool the request is bound to. Leaving it on-chain unused is harmless but expands the datum size and the validator's serialisation surface for no benefit.

**Recommendation:** Either remove it from the on-chain datum and keep it only off-chain (e.g., in tx metadata), or add a sanity assertion that `mkPoolActionID poolID actionID == reqPoolActionID` to tie the two together on-chain. The latter is the stronger choice — it removes a class of off-chain bugs where the wrong poolID is paired with a poolActionID.

#### DOC-1 — Architecture document and state-machine diagrams missing

**Severity:** Informational
**Category:** CIP-52-§2 (documentation review)
**Location:** repo root

The `README.md` covers build instructions and high-level off-chain usage. There is no:

- Architecture document mapping the four-validator topology and the request/response state machine.
- Per-validator spec listing datum / redeemer schemas and the invariants each enforces.
- Threat model document (this audit's §3 is the first one).
- TEE-attestation trust-model description (relevant to [P7B-1](#p7b-1-no-on-chain-tee-attestation-trust-collapses-to-ecdsa-key-custody)).

CIP-52 §2 expects all four to exist as a prerequisite to a competent audit. Their absence is itself an Informational finding.

**Recommendation:** Add `docs/ARCHITECTURE.md` covering the points above. The threat model in §3 of this audit can seed it.
