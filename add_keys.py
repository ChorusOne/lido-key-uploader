#!/usr/bin/env python3

import os
import json
import logging
import sys
import time
import click
from web3 import Web3, WebsocketProvider, HTTPProvider
from web3.exceptions import SolidityError, CannotHandleRequest, TimeExhausted

logger = logging.getLogger().setLevel("INFO")

ARTIFACTS_DIR = './assets'
POOL_ADDRESS = "0xae7ab96520de3a18e5e111b5eaab095312d7fe84"
POOL_ARTIFACT_FILE = 'Lido.json'
REGISTRY_ARTIFACT_FILE = 'NodeOperatorsRegistry.json'
GAS_LIMIT=13500000


def init_provider(eth1_provider):
    '''
    Initialise the Web3 provider.
    '''
    if eth1_provider.startswith('http'):
        provider = HTTPProvider(eth1_provider)
    elif eth1_provider.startswith('ws'):
        provider = WebsocketProvider(eth1_provider)
    else:
        logging.error('Unsupported ETH provider!')
        sys.exit(1)

    return Web3(provider)


def init_contracts(w3: Web3, pool_address):
    '''
    Initialise contracts.
    '''

    if not Web3.isChecksumAddress(pool_address):
        pool_address = Web3.toChecksumAddress(pool_address)

    pool_abi_path = os.path.join(ARTIFACTS_DIR, POOL_ARTIFACT_FILE)
    registry_abi_path = os.path.join(ARTIFACTS_DIR, REGISTRY_ARTIFACT_FILE)

    # Get Pool contract
    with open(pool_abi_path, 'r') as file:
        abi = json.load(file)
        file.close()
    pool = w3.eth.contract(abi=abi['abi'], address=pool_address)  # contract object

    # Get Registry contract
    registry_address = pool.functions.getOperators().call()
    logging.info(f'{registry_address=}')

    with open(registry_abi_path, 'r') as file:
        abi = json.load(file)
        file.close()
    return w3.eth.contract(abi=abi['abi'], address=registry_address)


def init_account(w3: Web3, pkey_file):
    '''
    Initialise the signer.
    '''
    password = os.getenv('PRIV_KEY_PW')
    if password == None:
        raise Exception("--pkey-file flag requires a password set using PRIV_KEY_PW")
    with open(pkey_file) as keyfile:
        encrypted_key = keyfile.read()
        account = w3.eth.account.from_key(w3.eth.account.decrypt(encrypted_key, password))

        logging.info(f'Account: {account.address}')

    return account



@click.command()
@click.option("--nonce", default=-1, type=int, help="Nonce to use (default uses next nonce on chain)")
@click.option("--gas", default=GAS_LIMIT, type=int, help="Gas limit - defaults to {}, which is suitable for submitting 100 keys.".format(GAS_LIMIT))
@click.option("--operator", help="Operator ID.", type=int)
@click.option("--pkey-file", help="Ethereum Encrypted Private Key file. Use in conjuction with PRIV_KEY_PW env var")
@click.option("--eth1-uri", help="Ethereum node address", type=str)
@click.option("--pool-address", help="Lido pool contract address - defaults to mainnet contract address", type=str, default=POOL_ADDRESS)
@click.argument('filename')
def main(filename, nonce, operator, gas, eth1_uri, pool_address, pkey_file):
    '''
    Main entrypoint.
    '''
    try:
        if eth1_uri == None:
            eth1_uri = os.environ.get('WEB3_PROVIDER_URI', None)
            if eth1_uri == None:
                raise Exception("Must pass --eth1-uri flag or set WEB3_PROVIDER_URI environment variable")
        if pkey_file is None:
            raise Exception("No private key file provided")
        w3 = init_provider(eth1_uri)
        registry = init_contracts(w3, pool_address)
        account = init_account(w3, pkey_file)

        if operator is None:
            raise Exception("--operator flag is required")

        with open(filename, 'r') as f:
            keyfile = json.load(f)
            f.close()

        keys = [x.get('pubkey') for x in keyfile]
        signatures = [x.get('signature') for x in keyfile]
        logging.info("Found %d keys...", len(keys))

        tx = build_tx(registry, operator, keys, signatures, account, gas)
        send_tx(w3, tx, account, nonce)
    except Exception as e:
        print("Error: {}".format(e))
        sys.exit(1)


def build_tx(registry, operator_id, keys, signatures, account, gas):
    '''
    Build an addSigningKeysOperatorBH tx from the keys and signatures provided.
    '''

    # sanity_check
    if len(keys) != len(signatures):
        raise Exception("Imbalance in keys and signatures")

    return registry.functions.addSigningKeysOperatorBH(
        operator_id,
        len(keys),
        "".join(keys),
        "".join(signatures)
    ).buildTransaction({
        'from': account.address,
        'gas': gas
    })

def send_tx(w3, tx, account, nonce):
    '''
    Send the contract interaction.
    '''
    try:
        # execute tx locally to check validity
        w3.eth.call(tx)
        logging.info('Calling tx locally succeeded.')
        print(f'Tx data: {tx.__repr__()}')
        if prompt('Should we send this TX? [y/n]: ', ''):
            sign_and_send_tx(w3, tx, account, nonce)
    except SolidityError as sl:
        str_sl = str(sl)
        logging.error(f'Calling tx locally failed: {str_sl}')
    except ValueError as exc:
        (args, ) = exc.args
        if args["code"] == -32000:
            raise
        else:
            logging.exception(f'Unexpected exception. {type(exc)}')
    except TimeExhausted as exc:
        raise
    except Exception as exc:
        logging.exception(f'Unexpected exception. {type(exc)}')


def sign_and_send_tx(w3, tx, account, nonce):
    logging.info('Preparing TX... CTRL-C to abort')
    time.sleep(3)  # To be able to Ctrl + C

    if nonce < 0:
      tx['nonce'] = w3.eth.getTransactionCount(
          account.address
      )
      logging.info("Using nonce %d from chain", tx['nonce'])  # Get correct transaction nonce for sender from the node
    else:
      tx['nonce'] = nonce
      logging.info("Using nonce %d from command line", tx['nonce'])  # Get correct transaction nonce for sender from the node

    signed = w3.eth.account.sign_transaction(tx, account.key)
    logging.info(f'TX hash: {signed.hash.hex()} ... CTRL-C to abort')
    time.sleep(3)

    logging.info('Sending TX... CTRL-C to abort')
    time.sleep(3)

    tx_hash = w3.eth.sendRawTransaction(signed.rawTransaction)
    logging.info('TX has been sent. Waiting for receipt...')
    tx_receipt = w3.eth.waitForTransactionReceipt(tx_hash)
    if tx_receipt.status == 1:
        logging.info('TX successful')
    else:
        logging.warning('TX reverted')
        logging.warning(tx_receipt)


def prompt(prompt_message, prompt_end):
    '''
    Prompt for user input.
    '''
    print(prompt_message, end='')
    while True:
        choice = input().lower()
        if choice == 'y':
            return True
        elif choice == 'n':
            return False
        else:
            print('Please respond with [y or n]: ', end=prompt_end)
            continue


if __name__ == '__main__':
    main()
