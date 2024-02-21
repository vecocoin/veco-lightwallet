import requests
import json
from dotenv import load_dotenv
import os

# Path to your .env file
env_path = '.env'
if os.path.exists(env_path):
    # Adjust behavior for custom RPC settings via SSH Tunnel
    print("Using custom RPC settings")
    load_dotenv()  # This loads the variables from .env into the environment
    rpc_user = os.getenv("RPC_USER")
    rpc_password = os.getenv("RPC_PASSWORD")
    rpc_host = os.getenv("RPC_HOST")
    rpc_port = os.getenv("RPC_PORT")
    prefix = os.getenv("PREFIX")
else:
    # Default behavior
    print("Using default RPC settings")
    rpc_user = "DEFAULT_RPC_USER_PLACEHOLDER"
    rpc_password = "DEFAULT_RPC_PASSWORD_PLACEHOLDER"
    rpc_host = "DEFAULT_RPC_HOST_PLACEHOLDER"
    rpc_port = "DEFAULT_RPC_PORT_PLACEHOLDER"
    prefix = "DEFAULT_RPC_PREFIX_PLACEHOLDER"


def get_address_utxos(address):
    headers = {'content-type': 'application/json'}
    payload = {
        "method": "getaddressutxos",
        "params": [{"addresses": [address]}],
        "jsonrpc": "2.0",
        "id": 0,
    }
    response = requests.post(f"{prefix}://{rpc_user}:{rpc_password}@{rpc_host}:{rpc_port}", headers=headers,
                             data=json.dumps(payload))

    if response.status_code == 200:
        result = response.json()['result']
        # Extract the desired data
        data = [{"address": utxo["address"], "txid": utxo["txid"], "vout": utxo["outputIndex"],
                 "scriptPubKey": utxo["script"], "amount": utxo["satoshis"] / 1e8} for utxo in result]
        return data
    else:
        print(f"\nError: Connection Status {response.status_code}")
        return None


def calculate_total_balance(address):
    data = get_address_utxos(address)
    if data:
        total_balance = sum(utxo["amount"] for utxo in data)
        return total_balance
    else:
        # print("No UTXO information for this address available (so far?)")
        return 0


def select_utxos_for_amount(address, amount_needed):
    utxos = get_address_utxos(address)
    selected_utxos = []
    total_amount = -0.000001  # start a bit below zero, empirical value, which removed some rare errors during tx generation

    for utxo in sorted(utxos, key=lambda x: x['amount'], reverse=True):
        if total_amount >= amount_needed:
            break
        selected_utxos.append(utxo)
        if utxo['amount'] > 0.00001:  # Remove dust utxos
            total_amount += utxo['amount']

    if total_amount < amount_needed:
        print("\nAddress balance not sufficient!")
        return None, 0

    return selected_utxos, total_amount


def create_raw_transaction(target_address, selected_utxos, amount_needed, change_address=None, fee_per_byte=1e-8):
    # Estimate the transaction size and calculate the fee
    estimated_tx_size = 10 + len(selected_utxos) * 148 + 2 * 34  # Simple estimation based on Bitcoin
    fee = max(round(estimated_tx_size * fee_per_byte, 8), 0.000002)  # Ensure a minimum fee of 000002 (could probably be lower but robustness is more important here)

    total_input_amount = sum(utxo['amount'] for utxo in selected_utxos)
    change_amount = total_input_amount - amount_needed - fee

    # Avoidance of dust outputs by adjusting the exchange rate or fees
    if 0 < change_amount < 0.0001:  # Dust-Threshold
        # Add the change to the fee when you are in danger of being Dust.
        fee += change_amount
        change_amount = 0

    outputs = {target_address: amount_needed}
    if change_amount > 0:
        outputs[change_address or target_address] = round(change_amount, 8)

    # Define the inputs based on the selected UTXOs
    inputs = [{"txid": utxo['txid'], "vout": utxo['vout']} for utxo in selected_utxos]

    # Create the raw transaction
    payload = json.dumps({
        "method": "createrawtransaction",
        "params": [inputs, outputs],
        "jsonrpc": "2.0"
    })
    response = requests.post(f"{prefix}://{rpc_user}:{rpc_password}@{rpc_host}:{rpc_port}",
                             headers={'content-type': 'application/json'}, data=payload)
    raw_tx_response = response.json()
    if 'error' in raw_tx_response and raw_tx_response['error']:
        print("\nError during generation of raw transactions:", raw_tx_response['error'])
        return None
    print("\nRaw transaction successfully generated!", raw_tx_response['result'])
    return raw_tx_response['result']


def sign_raw_tx_with_utxos(raw_tx_hex, selected_utxos, cwif):
    prev_txs = [{"txid": utxo['txid'], "vout": utxo['vout'], "scriptPubKey": utxo['scriptPubKey'], "redeemScript": ""} for utxo in selected_utxos]
    # print(prev_txs)
    payload = json.dumps({
        "method": "signrawtransaction",
        "params": [raw_tx_hex, prev_txs, [cwif]],
        "jsonrpc": "2.0"
    })
    response = requests.post(f"{prefix}://{rpc_user}:{rpc_password}@{rpc_host}:{rpc_port}", headers={'content-type': 'application/json'}, data=payload)
    sign_tx_response = response.json()

    if 'error' in sign_tx_response and sign_tx_response['error']:
        print("\nError while signing the UTXO transactions:", sign_tx_response['error'])
        return None
    print("\nRaw transaction successfully signed!", sign_tx_response['result'])
    return sign_tx_response['result']


def send_raw_tx(signed_tx):
    # RPC request to generate raw tx
    headers = {'content-type': 'application/json'}
    payload = json.dumps({
        "method": "sendrawtransaction",
        "params": [signed_tx['hex']],
        "jsonrpc": "2.0"
    })
    response = requests.post(f"{prefix}://{rpc_user}:{rpc_password}@{rpc_host}:{rpc_port}", headers=headers, data=payload)
    tx_id = response.json()
    return tx_id


def get_current_block():

    # headers = {'content-type': 'application/json'}
    payload = json.dumps({
        "jsonrpc": "2.0",
        "id": "getblockcount",
        "method": "getblockcount",
        "params": []  # getblockcount does not require any parameters
    })

    try:
        response = requests.post(f"{prefix}://{rpc_user}:{rpc_password}@{rpc_host}:{rpc_port}", headers={'content-type': 'application/json'}, data=payload)
        if response.status_code == 200:
            block_count = response.json().get('result', 'Keine Antwort erhalten')
            return True, block_count  # RPC connection available + current blockcount
        else:
            return False, "Error when retrieving the current block height"  # no connection, no block height
    except requests.exceptions.RequestException as e:
        print(f"\nRPC connection error: {e}")
        return False, f"RPC connection error: {e}"


# For console
print(f"Current block height: {get_current_block()}")
