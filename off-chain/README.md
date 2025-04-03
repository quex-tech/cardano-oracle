# QUEX Cardano Oracle off-chain scripts

## Setup

Initialize `python3` virtual environment
```sh
python3 -m venv venv
```

Activate virtual environment
```sh
source ./venv/bin/activate
```

Install dependencies
```sh
pip install -r requirements.txt
```

To deactivate virual environment, type
```sh
deactivate
```

## Environment Variables

+ `WALLET_MNEMONIC`: mnemonic phrase for the oracle pool owner wallet. Can be generated with `./wallet generate --passphrase <passphrase>`.
+ `CARDANO_NETWORK`: Cardano blockchain to use. Can be `preview`, `preprod`, or `mainnet`. Default is `preview`.
+ `BLOCKFROST_PROJECT`: blockfrost.io project ID to communicate with Cardano. If none, a local Ogmius V6 instance is assumed to be running.
+ `ORACLE_URL`: base URL of a QUEX Signer API to be used by default.

The environment variables can be set inside `.env` file:
```sh
$ cat .env
WALLET_MNEMONIC="word word word word word ..."
CARDANO_NETWORK=preview
BLOCKFROST_PROJECT=previewAbCdEf...
ORACLE_URL="http://10.13.192.131:8080"
```

## Usage

### Generate a wallet

```sh
./wallet generate --passphrase <passprhase>
```

Prints `WALLET_MNEMONIC` value. Put it into the `.env` file or set the environment variable.

Passphrase is optional. If speficied, you have to remember it and provide to the other scripts with the `--passhprase` option.

Also shows oracle pool owner addresses. Top up the treasury address.

You can print these addresses again with:

```sh
./wallet show --passphrase <passprhase>
```

Example output:

```
Verification key: fd24791e13c21917c93385d4298d9417d3cbfe89b0a4253de85f8b36
Treasury address: addr_test1vzj0a4rlwvfpxd264n4p7f2ajc9nexyk0aq0p5vnqg6tlvg366vdz
Oracles address:  addr_test1vpj8dczy5483zxuusllu39lf6e3mnwpcjt2xx9knps25r2quxnvlj
```

### Register an oracle

```sh
./oracles add <url> <response_validity_period_minutes> --submit [--passphrase <passprhase>]
```

With all these scripts you can preview transactions before submitting them to the blockchain by omitting the `--submit` flag and passing the `--view-tx` parameter.

Once the transaction gets confirmed, you can view registered oracles with:

```sh
./oracles list
```

Example output:

```
- UTxO: 89fdb53cee5c6e1829cb25a1a9fa4e7098afbd1c2563ecfcded23794ff28a337#0
  Pool: TestRequestOraclePool
  Public key: 037762fe9dd43dded3a9a57d078e3c7fa8d3274c183b6117ec3dab524e5b79247b
  Response validity period: 15.0 minutes
```

You can unregister an oracle with:

```sh
./oracles delete <UTxO> --submit
```

### Initiate an HTTPS request and post the response to the blockchain

Put oracle URL to the `ORACLE_URL` environment variable or to the `.env` file. That way you will not have to specify `--oracle-url` parameter to the `relay.py` script each time.

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