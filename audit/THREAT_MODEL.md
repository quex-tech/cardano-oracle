# Cardano Oracle — Threat Model

Scope: `on-chain/src/{OracleRequestValidator, OracleResponseValidator,
SingleOraclePoolValidator, Validator}.hs` of `quex-tech/cardano-oracle`.
Reference: `request-mechanics.md`, `tokens.md`, `off-chain/README.md`,
developer-docs (`tdx/`, `overview/security.md`, `provider/td_oracle_requirements.md`),
`quex-v1-signer` (plutus branch), Halborn EVM audit
(`quex-v1-2025-06-25`).

## Parties

**Trusted**

- **TEE / Oracle (Intel TDX enclave running `quex-v1-signer`)** — holds a
  secp256k1 signing key generated *inside* the enclave; key never leaves.
  The corresponding pubkey is bound to the enclave via TDX attestation.
  Signs `(actionID, dataItem, relayer)` messages. Trust is *verifiable*:
  TDX hardware + open-source signer source + measurement-attested
  deployment, not blind operator trust.

**Untrusted**

- **Relayer** — any Cardano pubkey. Picks up TEE-signed messages and
  submits fulfillment txs. May drop, delay, reorder, or refuse. Cannot
  forge: the signature is verified on-chain against the pool pubkey, and
  the relayer pkh is *inside* the signed payload (MEV protection per
  `td_oracle_requirements.md`).
- **Requester (`reqOwner`)** — funds and reclaims own request UTxO.
  Trusted only with own funds (`txSignedBy txInfo reqOwner` gates the
  expired-reclaim path).
- **Consumer dApp** — out of scope for these validators; its safety
  depends on its own checks (see assumption #6).

**Authority (trusted to follow procedure)**

- **Pool authority** — controls `PoolID` native asset and its movement.
  For a *private* pool, may add/remove oracles by spending the
  pool-token UTxO. For a *single-oracle* pool, the pool token is locked
  at `SingleOraclePoolValidator` with token name `sha256(pubkey ‖
  validityPeriod)` and cannot be revoked.

## Trust assumptions

1. **TDX is sound, `quex-v1-signer` has no backdoor, Intel is honest.**
   The only blind-trust root. TDX isolates enclave memory from the
   machine owner; the open-source signer (plutus branch) does not
   exfiltrate the key. Both are independently auditable. If either
   breaks, every signed response is forgeable.
2. **Pool authority verified attestation before placing the pubkey in
   the pool datum.** The on-chain validator does *not* check
   attestation — it only verifies the signature against whatever pubkey
   the pool datum contains. The linkage "datum pubkey = TEE-locked
   private key" lives off-chain at registration time (`verify.quex.tech`).
3. **Pool authority minted `PoolID` exactly once.** `findPoolID` accepts
   any single non-ADA asset of quantity 1 in the reference input — it
   does not check the *minting policy*. Uniqueness is operational, not
   on-chain enforced. A re-mint silently forks pool authorization.
4. **TEE clock is monotonic and chain-synced.** Validators compare
   TEE-signed timestamps against `txInfoValidRange`. Skew above
   `ResponseValidityPeriod` makes responses always-stale or
   perpetually-fresh.
5. **The audited signer correctly binds `actionId` to the action it
   executed.** Per `td_oracle_requirements.md` § "responsibility of TD
   provider". Enforced by signer source — verified once during the
   `quex-v1-signer` audit, not per-response on-chain.
6. **Consumer dApp enforces response payload schema.** The response
   validator only requires the datum to decode as `(POSIXTime, Integer,
   BuiltinData)`; the `BuiltinData` body is opaque on-chain. Consumers
   must validate the payload, handle duplicate response UTxOs (allowed
   per `tokens.md`), and check freshness themselves.
7. **`reqCoinPerUTxOByte` is pinned to live protocol parameters by
   `pending_requests.py`.** Requester-supplied datum field; stale values
   silently break fulfillment economics (DoS to requester, no fund loss).

## Properties the protocol provides (verify in Step 3)

- **Content-addressed `ActionID`** = `keccak256(serialized HTTPAction)`
  (`quex_backend/models.py:230`). Same request parameters yield the same
  `PoolActionID = sha256(PoolID ‖ ActionID)` and share one response
  slot. Cached-response reuse is intentional, not a vulnerability.
- **MEV protection** — relayer pkh is *inside* the TEE-signed payload;
  validator enforces `relayer ∈ txInfoSignatories`. A third party cannot
  re-broadcast a signed response and capture the reward.
- **Replay protection** — `responseExpiresAt = signedAt +
  ResponseValidityPeriod` checked against `txInfoValidRange`; replacing
  an existing response UTxO requires `newTimestamp > oldTimestamp`.
- **Untrusted-relayer recourse** — requester recovers funds via the
  expired-reclaim path (`reqBefore` lapsed + `txSignedBy reqOwner`) if
  no relayer fulfills.
