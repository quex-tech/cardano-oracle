# Oracle Request Mechanics

This document explains how request UTxOs are validated on-chain, how reward/change are enforced, and how to create a request with `./pending_requests.py`.

## 1. What a request UTxO contains

Oracle request's datum contains:

- `reqAction`: encoded oracle action + proof
- `reqPoolID`: oracle pool identifier bytes
- `reqPoolActionID`: token name derived from pool + action
- `reqAfter`: earliest valid response timestamp (POSIX seconds)
- `reqBefore`: latest valid response timestamp (POSIX seconds)
- `reqOwner`: owner public key hash (the requester)
- `reqReward`: relayer reward in lovelace
- `reqCoinPerUTxOByte`: a protocol parameter
- `reqMaxCost`: upper bound for request spending in lovelace

## 2. Spend paths in `OracleRequestValidator`

The request script allows spending in two cases.

1. Expired request reclaim:
- If `reqBefore` is already in the past (w.r.t. tx validity range), spending is allowed only when the transaction is signed by `reqOwner`.
- This is the reclaim path used by recycling.

2. Fulfillment before expiry:
- The transaction must produce a valid response output for `reqPoolActionID`.
- The response datum timestamp must be within `[reqAfter, reqBefore]`.
- The owner must receive enough ADA change according to the cost formula below.

If these checks fail, spending the request UTxO is rejected.

## 3. Reward and user change (on-chain economics)

When fulfilling a request, the validator computes:

- `responseBytes = size(serialized response datum)`
- `oldResponseCoin = ADA from inputs that contain the same response NFT` (if replacing an old response)
- `realCost = reqReward + txFee + reqCoinPerUTxOByte * (274 + responseBytes) - oldResponseCoin`
- `cappedCost = max(0, min(reqMaxCost, realCost))`
- `minChange = requestCoin - cappedCost`

The transaction is valid only if:

- `minChange <= 0`, or
- there is an output to `reqOwner` with ADA `>= minChange`.

Interpretation:

- `reqReward` guarantees the relayer incentive budget.
- The requester cannot be charged above `reqMaxCost`.
- If an existing response UTxO is reused, `oldResponseCoin` reduces cost.
- Remaining locked ADA goes back to the requester as user change.

## 4. How much ADA a user should include in a request

The user does not set the exact locked lovelace directly.  
`./pending_requests.py add` computes it from `--max-response` and protocol params, then builds the request output amount.

Off-chain request budget (`reqMaxCost`) is computed as:

- `CARDANO_FEE_BUFFER` (`1_000_000`)
- `+ reqReward` (currently `50_000`)
- `+ coins_per_utxo_byte * max_response_size`
- `+ coins_per_utxo_byte * 274` (base response size) when there is no previous response UTxO for the same `poolActionID`

So, larger `--max-response` means more ADA must be locked upfront.

Then the request UTxO lovelace is set to at least:

- `reqMaxCost + min_lovelace_change_utxo`, and
- enough to satisfy minimum lovelace for the request output itself.

Why this amount is needed:

- It guarantees there is enough budget to pay relayer reward, response storage cost, and tx fee.
- It caps user exposure via `reqMaxCost`.
- It leaves room for owner change to be returned after fulfillment.

## 5. Creating a request with `./pending_requests.py`

See the off-chain guide:

- [Create and manage pending requests](off-chain/README.md#create-and-manage-pending-requests)
