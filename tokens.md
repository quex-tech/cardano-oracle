# Quex Oracle on Cardano. Tokens

This document specifies the on-chain tokens used by Quex Oracle Service and how those tokens are minted, spent, and burned.

## Token set

### Response token

Oracle responses are stored as UTxOs at the [oracle response validator](./on-chain/src/OracleResponseValidator.hs) address, each carrying a response token.

- Currency symbol: `PolicyID` = the oracle contract hash
- Token name: `PoolActionID` (SHA-256 hash of `(PoolID, ActionID)`). `ActionID` identifies the request, `PoolID` is the asset class of a pool token (described below)
- Datum in the response UTxO: `(Timestamp, Error, Response)` where `Response` is arbitrary BuiltinData
- The response validator caps the serialised size of the TEE-signed response data item at 4096 bytes (audit M1): an oversized payload would make every later consolidation or consumer read exceed the ex-unit budget, permanently DoS-ing that `PoolActionID`

Intent: the asset class `<PolicyID>.<PoolActionID>` acts as the deterministic index for "the response for this pool and this request."

Response tokens cannot be burned.

### Pool token

The oracles are organized in Oracle Pools by the set of actions they can perform.

Inclusion of an oracle into a pool is represented by a pool token stored in an arbitrary UTxO on-chain.

- The UTxO contains a pool token whose asset class is interpreted as `PoolID`
- The datum of that UTxO stores `(TDPublicKey, ResponseValidityPeriod)`
- `ResponseValidityPeriod` exists to prevent flooding the response address with stale answers

#### Single-oracle pool token (special case)

In general, any token can be a pool token. But some pools can be defined to have exactly one oracle with fixed settings.

- Token name is the SHA-256 hash of `(TDPublicKey, ResponseValidityPeriod)`
- These tokens are stored at the pool contract address (enforced by the [single-oracle pool contract](./on-chain/src/SingleOraclePoolValidator.hs))
- Revocation is not possible for a single-oracle pool

## Token lifecycle

### Add an oracle to the pool

To authorize an oracle:

1. Get `TDPublicKey` and choose `ResponseValidityPeriod`
2. Create a UTxO anywhere that holds the pool token (its asset class is `PoolID`)
3. Store `(TDPublicKey, ResponseValidityPeriod)` in that UTxO’s datum

### Remove an oracle from the pool

To revoke an oracle, spend the authorization UTxO and either:

- burn the pool token, or
- move it to a UTxO whose datum does not contain `(TDPublicKey, ResponseValidityPeriod)`

For single-oracle pools, revocation is not possible.

### Publish a response

Publishing is performed using:

- a reference input UTxO containing the pool token + `(TDPublicKey, ResponseValidityPeriod)`
- a TD response payload
- the derived `PoolActionID`

The publisher must:

1. compute `PoolActionID`
2. find all response UTxOs at the oracle contract address that contain `<PolicyID>.<PoolActionID>`
3. if none exist: mint 1 `<PolicyID>.<PoolActionID>` token; otherwise spend all such UTxOs and (if `N > 1`) burn the extra `N−1` tokens
4. create exactly one output back to the oracle contract address carrying exactly one `<PolicyID>.<PoolActionID>` token

Multiple response tokens of the same kind can exist. The protocol explicitly anticipates that; publishers consolidate by spending all and burning extras, but consumers should be prepared to see more than one.

## Response token discovery when duplicates exist

To locate a response, consumers compute `<PolicyID>.<PoolActionID>` and search the oracle contract address for UTxOs containing that asset. If multiple matches exist, a consumer may pick the first or select the "freshest" by timestamp; the spec guarantees they are all valid within `ResponseValidityPeriod`.
