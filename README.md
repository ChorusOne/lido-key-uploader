# lido-key-uploader
Key Uploader for Lido (Ethereum2)

## Requirements
1. Geth node (http, or websocket)
2. Deposit data JSON file from `https://github.com/lidofinance/eth2.0-deposit-cli`.
3. Operator private key, and operator ID

## Installation
1. Clone this repository
2. Run `pip3 install -r requirements.txt`
3. You are good to go!

## Usage

```
./add_keys.py /path/to/deposit_data-1621943728.json --eth1-uri http://geth.node.com:8545  --operator 1 --pkey-file /path/to/private_key.json
```

The above will generate a TX based upon the keys and signatures in the deposit data JSON file. 

Gas is, by default, set to 13500000 which is sufficient for 100 concurrent keys. It can be overridden by `--gas` flag.
Additionally, the nonce can be overridden using `--nonce`; by default it will use the next available nonce for your given account.
```

### Licensing
Licensed using GPLv3, as there is code re-use and inspriration from http://github.com/lidofinance/lido-oracle.

