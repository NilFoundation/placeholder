import requests
import json
from web3 import Web3
import time

ALCHEMY_API_KEY = "I38oXHAOj0OUcvNfObEX8cS0I3PAHj0R"
ALCHEMY_RPC_URL = f"https://eth-mainnet.g.alchemy.com/v2/{ALCHEMY_API_KEY}"
BLOCK_NUMBER = "0x1393625"  # 20526629 in hex

w3 = Web3(Web3.HTTPProvider(ALCHEMY_RPC_URL))


def get_block_data():
    print("[INFO] Fetching block data...")
    payload = {
        "jsonrpc": "2.0",
        "method": "eth_getBlockByNumber",
        "params": [BLOCK_NUMBER, True],
        "id": 1
    }
    response = requests.post(ALCHEMY_RPC_URL, json=payload).json()
    return response.get("result", {})


def get_transaction_data(tx_hash):
    payload = {
        "jsonrpc": "2.0",
        "method": "eth_getTransactionByHash",
        "params": [tx_hash],
        "id": 1
    }
    response = requests.post(ALCHEMY_RPC_URL, json=payload).json()
    return response.get("result", {})

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
    response = requests.post(ALCHEMY_RPC_URL, json=payload).json()

    result["prestate_trace"] =  response.get("result", {})
    payload = {
        "jsonrpc": "2.0",
        "method": "debug_traceTransaction",
        "params": [tx_hash, {"tracer": "callTracer"}],
        "id": 1
    }
    response = requests.post(ALCHEMY_RPC_URL, json=payload).json()
    result["call_trace"] =  response.get("result", {})

    payload = {
        "jsonrpc": "2.0",
        "method": "trace_replayTransaction",
        "params": [tx_hash, ["vmTrace", "stateDiff"]],
        "id": 1
    }
    response = requests.post(ALCHEMY_RPC_URL, json=payload).json()
    tx_trace = response.get("result", {})

    if( "vmTrace" in tx_trace):
        tx_trace["opcodes_amount"] = result["opcodes_amount"] = calculate_opcodes(tx_trace["vmTrace"])

    path = "tx_" + tx_hash + ".json"
    with open(path, "w") as f:
        json.dump(tx_trace, f, indent=4)

    return result


def get_contract_bytecode(contract_address):
    payload = {
        "jsonrpc": "2.0",
        "method": "eth_getCode",
        "params": [contract_address, "latest"],
        "id": 1
    }
    response = requests.post(ALCHEMY_RPC_URL, json=payload).json()
    return response.get("result", "0x")


def get_storage_value(account_address, slot):
    payload = {
        "jsonrpc": "2.0",
        "method": "eth_getStorageAt",
        "params": [account_address, slot, "latest"],
        "id": 1
    }
    response = requests.post(ALCHEMY_RPC_URL, json=payload).json()
    return response.get("result", "0x")


if __name__ == "__main__":
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

    total_opcodes_amount = 0;
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
    formatted_file_path = "final_20526629.json"
    with open(formatted_file_path, "w") as f:
        json.dump(formatted_data, f, indent=4)

    print(f"[SUCCESS] Data fetching complete! JSON saved as {formatted_file_path}")
    print(f"[INFO] Total execution time: {time.time() - start_time:.2f} seconds.")