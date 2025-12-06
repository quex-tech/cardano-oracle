# QUEX Cardano Oracle off-chain scripts

## Setup

Initialize `python3` virtual environment and install dependencies
```sh
uv sync
```

Activate virtual environment
```sh
source .venv/bin/activate
```

You are ready to go.

To deactivate the virtual environment later, type
```sh
deactivate
```

## Environment Variables

+ `WALLET_MNEMONIC`: mnemonic phrase for a wallet. Can be generated with `./wallet generate --passphrase <passphrase>`.
+ `CARDANO_NETWORK`: Cardano blockchain to use. Can be `preview`, `preprod`, or `mainnet`. Default is `preview`.
+ `BLOCKFROST_PROJECT`: blockfrost.io project ID to communicate with Cardano. If none, a local Ogmios V6 instance is assumed to be running.
+ `ORACLE_URL`: base URL of a QUEX Signer API to be used by default.
+ `ORACLE_POOL_ID`: ID of the oracle pool in hex to be used by default.

The environment variables can be set inside `.env` file:
```sh
$ cat .env
WALLET_MNEMONIC="word word word word word ..."
CARDANO_NETWORK=preview
BLOCKFROST_PROJECT=previewAbCdEf...
ORACLE_URL="http://10.13.192.131:8080"
ORACLE_POOL_ID="5fe701cba1ca79c5cb02939af0ef06842352928872097cd2d14862f5bd9b9df648a61ec5846452fff12fc0666f27d4fe0b6a38628c316797708ce7db"
```

## Usage

### Generate a wallet

```sh
./wallet.py generate --passphrase <passprhase>
```

Prints `WALLET_MNEMONIC` value. Put it into the `.env` file or set the environment variable.

Passphrase is optional. If speficied, you have to remember it and provide to the other scripts with the `--passhprase` option.

Also shows the addresses. Top up the treasury address.

You can print these addresses again with:

```sh
./wallet.py show --passphrase <passprhase>
```

Example output:

```
Verification key:         fd24791e13c21917c93385d4298d9417d3cbfe89b0a4253de85f8b36
Treasury address:         addr_test1vzj0a4rlwvfpxd264n4p7f2ajc9nexyk0aq0p5vnqg6tlvg366vdz
Oracles address:          addr_test1vpj8dczy5483zxuusllu39lf6e3mnwpcjt2xx9knps25r2quxnvlj
Library address:          addr_test1vp4e4zdu4xnla60ry9exg4ux3uws53n0jh9epun8vyntr7gwn5cy0
Request treasury address: addr_test1vr9fhn3lrz2kqnzgckx45taecmj7ycekuzk5ne5vp8x8yzgh9e3xe
```

### Register an oracle

Oracles can be added to a private pool or to a single-oracle pool.

Private pools allow the owner to add and remove oracles arbitrarily.

A single-oracle pool is immutable and contains a fixed single oracle and fixed oracle settings.

To add an oracle to a private pool, run:

```sh
./oracles.py add <url> <response_validity_period_minutes> --submit [--passphrase <passprhase>]
```

To add it to a single-oracle pool, add the `--pool-type single-oracle` option.

With all these scripts you can preview transactions before submitting them to the blockchain by omitting the `--submit` flag and passing the `--view-tx` parameter.

Once the transaction gets confirmed, you can view registered oracles with:

```sh
./oracles.py list
```

Example output:

```
- UTxO:                  89fdb53cee5c6e1829cb25a1a9fa4e7098afbd1c2563ecfcded23794ff28a337#0
  Pool:
    ID:                  96dc3580d31151f2e8e50203f...7374526571756573744f7261636c65506f6f6c
    Type:                private
  Public key:            037762fe9dd43dded3a9a57d078e3c7fa8d3274c183b6117ec3dab524e5b79247b
  Resp. validity period: 0:15:00
```

You can unregister an oracle from a private pool with:

```sh
./oracles.py delete <UTxO> --submit
```

### Initiate an HTTPS request and post the response to the blockchain

Put oracle URL to the `ORACLE_URL` environment variable or to the `.env` file. That way you will not have to specify `--oracle-url` parameter to the `relay.py` script each time.

If you have registered oracles to multiple pools, put the pool ID into `ORACLE_POOL_ID` or add `--oracle-pool-id <pool id>` to the following script.

Run:

```sh
./relay.py "https://api.binance.com/api/v3/depth?symbol=ADAUSDT&limit=1" \
  --filter "[.lastUpdateId] + ([.bids] | map(map(map(tonumber*100000000|floor))))" \
  "(uint,(uint,uint)[])" \
  --submit
```

You can provide the HTTP method, headers, request body, etc. See:

```sh
./relay.py -h
```

Once the transaction gets confirmed, you can view all posted responses with:

```sh
./responses.py
```

Example output:

```
- UTxO:          506e03a517d6c5b3b6bee6a9ee28934ab1a56cb1b3c1f02be4f7fff3ca1ee3a4#0
  PoolAction ID: ef1c3e97e659a0e989b14bd48a7ae8c40cca79b736196d9b7760a419f69093ad
  Timestamp:     2025-04-02T10:41:38Z
  Error:         0
  Value:         (12174962650,[(68080000,457539999999)])
```

### Lock and unlock funds at a demo contract

There is a demo contract that makes use of an oracle response.

To compile it, you need Response currency symbol and PoolAction ID.

Choose an action and get its PoolAction ID.

Both `./responses.py` and `./relay.py` print PoolAction ID to the console.

Get Response currency symbol:

```sh
./protocol.py
```

Example output:

```
Responses address:        addr_test1wr957agk4gqha54mla35n9c5zfwl4u0sw72s0pk5mlhml7q4xsuun
Response currency symbol: efd558979b0e353faa8ec7098d5ffd65d3b1bb6e1ca2daa16287400b
```

Edit [GenExampleUserBlueprint.hs](../on-chain/app/GenExampleUserBlueprint.hs).

Paste Response currency symbol to `currencySymbol` and PoolAction ID to `poolActionID` constants.

Edit `OracleResponse` type in [ExampleUserValidator.hs](../on-chain/src/ExampleUserValidator.hs) to reflect the response type.

Edit `isResponseGood` function in the same file to represent the desired condition to unlock funds.

Compile the script via [compile-contracts.sh](../compile-contracts.sh) or `cabal run gen-example-user-blueprint ../off-chain/plutus.user.json` from inside the Docker container.

Lock funds at the contract address:

```sh
./demo.py lock <ada amount> --submit
```

The funds will be transferred from the treasury.

Once the transaction gets confirmed, you can view the locked funds along with other demo contract info:

```sh
./demo.py show
```

Example output:

```
Contract address:                  addr_test1wr8ucu6n8eu2wsj6yexz6xsj945n39sprexj8zr6vcqewpsa99lxy
Expected response currency symbol: efd558979b0e353faa8ec7098d5ffd65d3b1bb6e1ca2daa16287400b
Expected PoolAction ID:            48a82f43395f4ea4be50f4da6360058fa8cd12a113524cab63ae14dba205a29b
Locked Lovelace:                   1000000
```

Get the address where the oracle responses are stored:

```sh
./protocol.py
```

Get the funds back to the treasury:

```sh
./demo.py spend <response address> --submit
```

There must be a fresh response at the address (created less than about 20 minutes ago). If the response has expired, `./relay.py` a new one.

## License

This project is licensed under the [Apache License 2.0](LICENSE).

See the [NOTICE](NOTICE) file for additional copyright and license information.
