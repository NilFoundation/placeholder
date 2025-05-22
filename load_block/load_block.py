import requests
import json
from web3 import Web3
import time
import sys

# ALCHEMY_API_KEY = "I38oXHAOj0OUcvNfObEX8cS0I3PAHj0R"
# ALCHEMY_RPC_URL = f"https://eth-mainnet.g.alchemy.com/v2/{ALCHEMY_API_KEY}"
RPC_URL = "https://0xrpc.io/eth"
#BLOCK_NUMBER = "0x1393622"  # 20526626 in hex
#BLOCK_NUMBER = "0x1393624"  # 20526628 in hex
#BLOCK_NUMBER = "0x1393625"  # 20526629 in hex
#BLOCK_NUMBER = "0x1202900"  # 18884864 in hex
#BLOCK_NUMBER = "0x1202901"  # 18884865 in hex
#BLOCK_NUMBER = "0x1202902"  # 18884866 in hex
#BLOCK_NUMBER = "0x1202903"  # 18884867 in hex
#BLOCK_NUMBER = "0x1202904"  # 18884868 in hex
#BLOCK_NUMBER = "0x1202905"  # 18884869 in hex
#BLOCK_NUMBER = "0x1393623"  # 20526627 in hex
#BLOCK_NUMBER = "0x1393625"  # 20526629 in hex
#BLOCK_NUMBER = "0x1393626"  # 20526630 in hex
BLOCK_NUMBER = "0x1393E44"  # 20528708 in hex


w3 = Web3(Web3.HTTPProvider(RPC_URL))

def send_request_with_backoff(payload, is_hex=False):
    delay = 4
    while True:
        try:
            response = requests.post(RPC_URL, json=payload).json()
            return response.get("result", "0x" if is_hex else {})
        except Exception as e:
            print("[ERROR] Increasing backoff to {} seconds!".format(delay*2))
            time.sleep(delay)
            delay *= 2


def get_block_data():
    print("[INFO] Fetching block data...")
    payload = {
        "jsonrpc": "2.0",
        "method": "eth_getBlockByNumber",
        "params": [BLOCK_NUMBER, True],
        "id": 1
    }
    return send_request_with_backoff(payload)


def get_transaction_data(tx_hash):
    payload = {
        "jsonrpc": "2.0",
        "method": "eth_getTransactionByHash",
        "params": [tx_hash],
        "id": 1
    }
    return send_request_with_backoff(payload)

def calculate_opcodes(tx_trace):
    opcodes = 0
    for trace in tx_trace["ops"]:
        opcodes+=1
        if( trace["sub"]):
            opcodes+= calculate_opcodes(trace["sub"])
    return opcodes



def get_transaction_trace(tx_hash):
    print(f"[INFO] Fetching trace data for {tx_hash}...")
    result = {}
    payload = {
        "jsonrpc": "2.0",
        "method": "debug_traceTransaction",
        "params": [tx_hash, {"tracer": "prestateTracer"}],
        "id": 1
    }

    result["prestate_trace"] =  send_request_with_backoff(payload)
    payload = {
        "jsonrpc": "2.0",
        "method": "debug_traceTransaction",
        "params": [tx_hash, {"tracer": "callTracer"}],
        "id": 1
    }

    result["call_trace"] =  send_request_with_backoff(payload)

    payload = {
        "jsonrpc": "2.0",
        "method": "trace_replayTransaction",
        "params": [tx_hash, ["vmTrace", "stateDiff"]],
        "id": 1
    }

    tx_trace = send_request_with_backoff(payload)

    if( "vmTrace" in tx_trace):
        tx_trace["opcodes_amount"] = result["opcodes_amount"] = calculate_opcodes(tx_trace["vmTrace"])

    path = "./tx_" + tx_hash + ".json"
    with open(path, "w+") as f:
        json.dump(tx_trace, f, indent=4)

    return result


def get_contract_bytecode(contract_address):
    payload = {
        "jsonrpc": "2.0",
        "method": "eth_getCode",
        "params": [contract_address, "latest"],
        "id": 1
    }
    return send_request_with_backoff(payload, is_hex=True)


def get_storage_value(account_address, slot):
    payload = {
        "jsonrpc": "2.0",
        "method": "eth_getStorageAt",
        "params": [account_address, slot, "latest"],
        "id": 1
    }
    return send_request_with_backoff(payload, is_hex=True)

1
if __name__ == "__main__":
    # Block number may be passed as a command line argument
    if( len(sys.argv) > 1):
        BLOCK_NUMBER =  hex(int(sys.argv[1]))

    start_time = time.time()
    formatted_data = {
        "block": {},
        "transactions": []
    }

    # Fetch Block Data
    block_data = get_block_data()
    formatted_data["block"] = block_data

    if not block_data:
        print("[FATAL] Block data is missing! Exiting.")
        exit(1)

    print(f"[INFO] Fetched Block {block_data['number']} with {len(block_data['transactions'])} transactions.")

    tx_hashes = [tx["hash"] for tx in block_data["transactions"]]

    total_opcodes_amount = 0
    for tx_hash in tx_hashes:
        tx_data = get_transaction_data(tx_hash)
        if not tx_data:
            continue

        tx_entry = {
            "tx_hash": tx_hash,
            "details": tx_data,
            "execution_trace": {},
            "contracts": []
        }

        trace_data = get_transaction_trace(tx_hash)
        if( "opcodes_amount" in trace_data):
            total_opcodes_amount += trace_data["opcodes_amount"]
        if trace_data:
            tx_entry["execution_trace"] = trace_data

        contract_address = tx_data.get("to")
        if contract_address:
            bytecode = get_contract_bytecode(contract_address)
            contract_entry = {"address": contract_address, "bytecode": bytecode, "storage": {}}

            # Fetch storage values if access list exists
            for access in tx_data.get("accessList", []):
                address = access["address"]
                storage_data = {slot: get_storage_value(address, slot) for slot in access["storageKeys"]}
                if address == contract_address:
                    contract_entry["storage"] = storage_data

            tx_entry["contracts"].append(contract_entry)

        formatted_data["transactions"].append(tx_entry)

    formatted_data["total_opcodes_amount"] = total_opcodes_amount
    # Save everything
    formatted_file_path = "block.json"
    with open(formatted_file_path, "w+") as f:
        json.dump(formatted_data, f, indent=4)

    print(f"[SUCCESS] Data fetching complete! JSON saved as {formatted_file_path}")
    print(f"[INFO] Total execution time: {time.time() - start_time:.2f} seconds.")