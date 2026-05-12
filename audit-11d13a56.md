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

---

## 5. Test evidence

### 5.1 What was run

**Nothing.** No on-chain tests were executed during this audit because the build requires the IOG `devx-devcontainer:x86_64-linux.ghc96-iog` Docker image and `cabal` toolchain that fall outside this session's scope. The existing test suite (`on-chain/test/Main.hs`) covers only `serialiseData` fixtures (29 cases), `unsafeFromBuiltinData` round-trips (4 cases), and a single ECDSA signature fixture; none of these exercise the validators audited above.

`cabal outdated` and a comparison of `cabal.project.freeze` against [IntersectMBO/plutus security advisories](https://github.com/IntersectMBO/plutus/security/advisories) were not performed for the same reason — re-run before the next release-candidate build.

### 5.2 Required regression suite

Per CIP-52 §8, every finding requires a paired test. Consolidated below:

| Finding | Test required |
|---|---|
| [REQ-C](#req-c-multiple-satisfaction-in-existschangeoutput) | Bundle 2 same-owner requests with one merged refund output; assert spend fails. **Highest priority.** |
| [P7B-1](#p7b-1-no-on-chain-tee-attestation-trust-collapses-to-ecdsa-key-custody) | Architectural; document in spec rather than gate via test. |
| [REQ-A](#req-a-validator-trivially-passes-for-purposes-without-an-inline-datum) | Create request UTxO with datum-hash (no inline); attempt spend with arbitrary redeemer; assert fails. |
| [RESP-2](#resp-2-getoracle-trusts-any-reference-input-with-a-single-non-ada-token) | Build response tx with reference input at non-pool address; assert validator rejects. |
| [REQ-D](#req-d-minchange--0-short-circuits-the-owner-payment-check) | `cappedCost == requestCoin` with no owner output; document or reject per spec choice. |
| [LIB-1](#lib-1-reference-script-library-is-key-controlled-not-script-controlled) | Operational; runbook test, not on-chain. |
| [REQ-B](#req-b-request-datum-fields-not-validated) | Per-field: violate each bound (`maxCost < 0`, `coinPerUTxOByte ≤ 0`, `after > before`, oversize action); assert validator rejects. |
| [RESP-A](#resp-a-untyped-validator-does-not-discriminate-script-purpose) | Submit tx under Rewarding / Certifying / Voting / Proposing purposes; assert each fails. |
| [SOPV-1](#sopv-1-no-upper-bound-on-response-validity-period) | Pool registration with `responseValidityPeriod = MAX_TTL_MS + 1`; assert validator rejects. |
| [REQ-MAGIC-1](#req-magic-1-magic-number-274-uxto-overhead) | Style; no test (add to release runbook). |
| [TEST-1](#test-1-test-suite-has-no-validator-level-tests) | Meta — adopt `plutus-simple-model`. |
| [EUS-1](#eus-1-exampleuservalidator-uses-unsafefrombuiltindata-on-reference-input) | Spend example-user UTxO with malformed response datum; assert validator's failure trace is informative. |
| [RESP-B](#resp-b-relayer-pkh-check-excludes-multisig-and-script-witnesses) | Documentation only. |
| [REQ-ERR](#req-err-error--in-mid-validator-paths-produces-no-trace) | After fix: assert each failure path emits a distinct trace string. |
| [P9-1](#p9-1-reqpoolid-in-the-request-datum-is-unused-on-chain) | If fix adopted: build request with mismatched `(reqPoolID, reqPoolActionID)`; assert rejects. |
| [DOC-1](#doc-1-architecture-document-and-state-machine-diagrams-missing) | Documentation only. |

### 5.3 Recommended test infrastructure

Add `plutus-simple-model ^>=3.0` to `quex-oracle.cabal`'s `test-suite quex-oracle-test`. Re-organise `on-chain/test/Main.hs` into:

```
test/
├── Main.hs                          -- runner + existing fixtures
├── Unit/
│   ├── OracleRequestSpec.hs         -- per-finding tests
│   ├── OracleResponseSpec.hs
│   ├── SingleOraclePoolSpec.hs
│   └── ExampleUserSpec.hs
└── Property/
    └── ContractModelSpec.hs         -- quickcheck-contractmodel
```

Each `Unit/*Spec.hs` runs the validator in a mock chain with crafted tx contexts. The `Property/ContractModelSpec.hs` exercises the request → response → refund state machine under random schedules.

`cabal test` should be wired into the `compile-contracts.sh` driver so the test gate runs on every script regeneration.

---

## 6. Off-chain TX-format conformance (CIP-52 §5, §7)

A best-effort check that the off-chain Python TX builders construct transactions matching the on-chain expectations.

| Validator expectation | Off-chain enforcement | Status |
|---|---|---|
| Request UTxO carries **inline** datum (`SpendingScript _ Just`) | `pending_requests.py` builds `TransactionOutput(..., datum=...)` which PyCardano serialises as inline by default. | OK *(conditional on PyCardano version; see REQ-A)* |
| Response output address == `OracleResponseValidator` script address | `responses.py:115` uses `self.validator.addr(nw)` derived from `plutus_script_hash`. | OK |
| Response output asset name == `sha256(poolID ++ actionID)` | `oracles.py:163` `pool_action_id = sha256(self.id + action_id)`. | OK |
| Response output contains exactly `(ada, currency:poolActionID)` | `responses.py:117` `Value(2_000_000, assets)` with `assets` containing only `{currency: {tn: 1}}`. | OK |
| Reference input for `getOracle` is a single pool NFT | `responses.py:160` `builder.reference_inputs.add(oracle.input)`. | OK *(but see RESP-2 — no on-chain address check)* |
| Relayer's pkh ∈ `txInfoSignatories` | `responses.py:163` `build_and_sign([wallet.sk], ...)` includes the relayer's signing key. | OK |
| Request expiry refund branch needs `owner` signature | `pending_requests.py recycle …` signs with `wallet.treasury.sk`; assumed to match `reqOwner`. | OK *(needs explicit assertion in code)* |
| `Validator.addr()` constructs script-only address | `protocol.py:50` `Address(self.currency_symbol, network=nw)` — no staking part. | **Gap: MLabs-11 / Plutonomicon-3 staking control** |

### 6.1 New finding from TX-format review

#### STAKE-1 — Script addresses have no staking credential

**Severity:** Low
**Category:** MLabs-11 / Plutonomicon-3
**Location:** `off-chain/protocol.py:50`, `off-chain/oracles.py` and similar

```python
def addr(self, nw: Network) -> Address:
    return Address(self.currency_symbol, network=nw)
```

`Address(payment_part, network=…)` with no `staking_part` builds a script address whose staking part is `None`. ADA locked at these addresses earns no staking rewards. For an MVP this is acceptable, but as TVL grows the lost rewards become non-trivial.

Adding a stake credential creates two follow-on questions:

1. **Whose stake credential?** A pubkey credential under the operator's control concentrates reward extraction in the operator. A script credential that delegates programmatically (always delegate to pool X) is the safer pattern but requires another validator.
2. **Stake-key withdrawal authority** — if the stake credential is a *pubkey*, rewards can be withdrawn by that key independent of the spending logic. Document and audit this separately.

**Recommendation:** Decide the policy explicitly. For the v1 launch, document "script addresses currently have no stake delegation — locked ADA earns no rewards." For v2, introduce a stake-credential strategy.

---

## 7. Build reproducibility (CIP-52 §9)

- `on-chain/cabal.project` pins `index-state` to `2025-03-05T09:09:31Z` for both `hackage.haskell.org` and `cardano-haskell-packages`. **OK.**
- `quex-oracle.cabal` pins `plutus-core ^>=1.42.0.0`, `plutus-ledger-api ^>=1.42.0.0`, `plutus-tx ^>=1.42.0.0`. **OK** (^>= caret is consistent with IOG's release cadence).
- `cabal.project.freeze` — **not present in the repo**. Adding it would make the build fully reproducible byte-for-byte.
- `compile-contracts.sh` runs in `ghcr.io/input-output-hk/devx-devcontainer:x86_64-linux.ghc96-iog`. The image tag is *not* version-pinned (`ghc96-iog`, no digest). A future image rebuild upstream could change the script hash silently.

#### BUILD-1 — `cabal.project.freeze` missing; devcontainer tag not digest-pinned

**Severity:** Informational
**Category:** CIP-52-§9
**Recommendation:** Generate `cabal.project.freeze` and commit it. Pin the devcontainer to a digest (`ghcr.io/input-output-hk/devx-devcontainer@sha256:…`). Add a CI check that re-builds and asserts the four validator hashes are unchanged.

---

## 8. CIP-52 coverage matrix

How this audit covered each section of CIP-52:

| CIP-52 § | Section | Coverage in this report |
|---|---|---|
| §1 | Scope | [§1](#1-scope) |
| §2 | Documentation review | [DOC-1](#doc-1-architecture-document-and-state-machine-diagrams-missing) |
| §3 | Source-code quality review | [REQ-MAGIC-1](#req-magic-1-magic-number-274-uxto-overhead), [REQ-ERR](#req-err-error--in-mid-validator-paths-produces-no-trace), no HLint run |
| §4 | Specification compliance | [REQ-D](#req-d-minchange--0-short-circuits-the-owner-payment-check), [REQ-B](#req-b-request-datum-fields-not-validated), [SOPV-1](#sopv-1-no-upper-bound-on-response-validity-period) |
| §5 | Transaction format | [§6](#6-off-chain-tx-format-conformance-cip-52-5-7) |
| §6 | On-chain vulnerability assessment | [§4](#4-findings) — full MLabs + Plutonomicon walkthrough |
| §7 | Off-chain code review | [§6](#6-off-chain-tx-format-conformance-cip-52-5-7) (TX-format only); OWASP / dep-CVE out of scope this pass |
| §8 | Test coverage | [TEST-1](#test-1-test-suite-has-no-validator-level-tests), [§5](#5-test-evidence) |
| §9 | Build reproducibility | [BUILD-1](#build-1-cabalprojectfreeze-missing-devcontainer-tag-not-digest-pinned) |
| §10 | Findings format | [§4](#4-findings) uses the CIP-52 finding template |
| §11 | Severity classification | [§2.3](#23-severity-rubric-cip-52-11) |
| §12 | Disclosures and disclaimers | [§9](#9-disclosures) below |

---

## 9. Disclosures

This audit was performed by Claude Opus 4.7 (1M-context) operating as an AI agent under the `plutus-audit` skill (`tee-audit@0.1.0` plugin). **It is not a substitute for a human-expert audit.**

Specifically:

1. **AI-assisted, not AI-certified.** Claude is a capable code reviewer for Plutus, but it can hallucinate findings (we explicitly identified one hallucinated finding from the parallel UnboundedMarket scanner — see `audit/unboundedmarket-scan.md`). Every finding above should be independently verified by a human auditor against the live commit `11d13a56` before any of it informs an external publication or close-out artefact.
2. **No code executed.** The audit is static. `cabal build`, `cabal test`, and property-test runs were not performed in this session. The findings have not been demonstrated end-to-end on-chain.
3. **Point-in-time.** Audit reflects the state of `cardano-oracle` at commit `11d13a56` on `2026-05-12`. Subsequent changes are not covered. Re-run on every release-candidate.
4. **Scope-limited.** Off-chain Python is covered only for TX-format conformance (CIP-52 §5/§7). It is **not** covered for OWASP, dependency CVEs, key custody, wallet UX, or operator-side runbooks. The TEE attestation layer (Intel TDX measurement, quote verification, enclave key management) is **explicitly out of scope** and is the single largest gap in the trust model — see [P7B-1](#p7b-1-no-on-chain-tee-attestation-trust-collapses-to-ecdsa-key-custody).
5. **Parallel-tool corroboration.** The Catalyst F12 UnboundedMarket fine-tuned scanner (`unboundedmarket/vulnerabilities-openllama-3b`) was run on this codebase in parallel (branch `audit/unboundedmarket-scan`). It produced one finding on `OracleRequestValidator.hs` which on inspection was a misread (`*` interpreted as `+=`) and not a real bug. The scanner's coverage was 1 of 5 validators before the run was abandoned due to CPU inference cost on consumer hardware. The scanner's added signal to this audit was **zero**; the integration is preserved for documentation and re-runnability on GPU.
6. **Catalyst Fund 14 deliverable.** This document is part of the close-out for [Quex Oracles project 1400103](https://projectcatalyst.io/funds/14/cardano-open-developers/quex-oracles-fully-decentralized-tee-powered-oracles-on-cardano). The Catalyst milestone framing should be read alongside the [Quex Cardano oracles close-out report](../../Metawork/projects/quex-tech/general/cardano/) (path is local to the author's workspace).

### 9.1 Acknowledgements & remediation status

| Finding | Status | Notes |
|---|---|---|
| REQ-C | Open | Highest priority; recommend the one-shot refund-token fix. |
| P7B-1 | Open | Architectural; needs product-side decision on TEE-attestation strategy. |
| REQ-A | Open | One-line fix; recommend addressing alongside REQ-C in same diff. |
| RESP-2 | Open | One-line fix in `findOracle`. |
| REQ-D | Open | Specification clarification; product decision. |
| LIB-1 | Open | Operational; deploy a never-spendable library validator. |
| REQ-B | Open | Validator-level bound checks. |
| RESP-A | Open | Defensive purpose dispatch. |
| SOPV-1 | Open | Add upper bound on `responseValidityPeriod`. |
| REQ-MAGIC-1 | Open | Style. |
| TEST-1 | Open | Meta; adopt `plutus-simple-model`. |
| EUS-1 | Open | Defensive; use `fromBuiltinData`. |
| RESP-B | Open | Documentation. |
| REQ-ERR | Open | `traceError` everywhere. |
| P9-1 | Open | Remove unused field or add `mkPoolActionID` self-check. |
| DOC-1 | Open | Author `docs/ARCHITECTURE.md`. |
| STAKE-1 | Open | Product decision on stake-credential strategy. |
| BUILD-1 | Open | Generate `cabal.project.freeze`; pin devcontainer digest. |

---

*End of audit.*

