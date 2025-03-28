from copy import deepcopy
import math
import time
import json
from eth_utils import (
    keccak,
)
import rlp
from rlp.sedes import (
    Binary,
    big_endian_int,
)
from trie import (
    HexaryTrie,
    constants
)
from web3._utils.encoding import (
    pad_bytes,
)
import requests

RPC_URL = "https://docs-demo.quiknode.pro/"
BLOCK_NUMBER = "0x151d747"  

def send_request_with_backoff(payload, is_hex=False):
    delay = 4
    while True:
        response = requests.post(RPC_URL, json=payload)
        if response.status_code != 200:
            print("[ERROR] Increasing backoff to {} seconds!".format(delay*2))
            time.sleep(delay)
            delay *= 2
            continue
        return response.json().get("result", "0x" if is_hex else {})

# Create a temperoray trie object base on the proof
def format_proof_nodes(proof):
    trie_proof = []
    for rlp_node in proof:
        decoded = [e.hex() for e in rlp.decode(bytes.fromhex(rlp_node[2:]))]
        trie_proof.append(decoded)

    return trie_proof

def parse_proof_data(_proof):
    formatted = deepcopy(_proof)
    formatted["accountProof"] = format_proof_nodes(formatted["accountProof"])
    for s in formatted["storageProof"]:
        s["proof"] = format_proof_nodes(s["proof"])
    return formatted

def verify_proof(proof, root):
    root = bytes.fromhex(root[2:])
    # Initialize the trie
    trie_root = Binary.fixed_length(32, allow_empty=True)
    hash32 = Binary.fixed_length(32)

    #Create account object
    class _Account(rlp.Serializable):
        fields = [
                    ('nonce', big_endian_int),
                    ('balance', big_endian_int),
                    ('storage', trie_root),
                    ('code_hash', hash32)
                ]

    # Create the key value pair from account object
    if proof["nonce"] == "0x0" and proof["balance"] == "0x0":
        # Account is empty
        rlp_account = constants.BLANK_NODE
    else:
        acc = _Account(
            int(proof["nonce"], 16), int(proof["balance"], 16), bytes.fromhex(proof["storageHash"][2:]), bytes.fromhex(proof["codeHash"][2:])
        )
        rlp_account = rlp.encode(acc)
    trie_key = keccak(bytes.fromhex(proof["address"][2:]))

    address = proof["address"]
    #Verifying account proof
    accoutProof = []
    for p in proof["accountProof"]:
        accoutProof.append([bytes.fromhex(e) for e in p])
    assert rlp_account == HexaryTrie.get_from_proof(
        root, trie_key, accoutProof
    ), f"Failed to verify account proof {address}"

    #Verifying storage proof
    for storage_proof in proof["storageProof"]:
        key = storage_proof["key"]
        trie_key = keccak(pad_bytes(b'\x00', 32, bytes.fromhex(key[2:])))
        root = bytes.fromhex(proof["storageHash"][2:])
        if storage_proof["value"] == "0x0":
            rlp_value = b''
        else:
            valueLen = math.ceil(len(storage_proof["value"][2:])/2)
            rlp_value = rlp.encode(int(storage_proof["value"], 16).to_bytes(valueLen, "big")) #node data is serialised wit rlp serialization

        formatted_storage_proof = []
        for p in storage_proof["proof"]:
            formatted_storage_proof.append([bytes.fromhex(e) for e in p])
        val = storage_proof["value"]
        # Check correctness of storage value
        assert rlp_value == HexaryTrie.get_from_proof(
            root, trie_key, formatted_storage_proof,
        ), f"Failed to verify storage proof {key} {rlp_value} {val}"

    return True

def get_eth_proof(address, slots, block_number):
    payload = {
        "jsonrpc": "2.0",
        "method": "eth_getProof",
        "params": [address, slots, block_number],
        "id": 1
    }
    proof_data = parse_proof_data(send_request_with_backoff(payload))
    return proof_data


def get_transaction_trace(tx_hash, post_state_root, pre_state_root):
    print(f"[INFO] Fetching trace and proof data for {tx_hash}...")
    result = {}
    payload = {
        "jsonrpc": "2.0",
        "method": "debug_traceTransaction",
        "params": [tx_hash, {"tracer": "prestateTracer"}],
        "id": 1
    }
    result = send_request_with_backoff(payload)
    for address in result:
        if "storage" in result[address]:
            keys = list(result[address]["storage"].keys())
        else:
            keys = []
        result[address]["postState"] = get_eth_proof(address, keys, BLOCK_NUMBER)
        verify_proof(result[address]["postState"], post_state_root)
        result[address]["preState"] = get_eth_proof(address, keys, hex(int(BLOCK_NUMBER, 16)-1))
        verify_proof(result[address]["preState"], pre_state_root)

    return result

def get_block_data():
    print("[INFO] Fetching block data...")
    payload = {
        "jsonrpc": "2.0",
        "method": "eth_getBlockByNumber",
        "params": [BLOCK_NUMBER, False],
        "id": 1
    }
    received_block = send_request_with_backoff(payload)

    payload = {
        "jsonrpc": "2.0",
        "method": "eth_getBlockByNumber",
        "params": [hex(int(BLOCK_NUMBER, 16) - 1), False],
        "id": 1
    }
    pre_state_root = send_request_with_backoff(payload)["stateRoot"]
    formatted_block = dict()
    formatted_block["stateRoot"] = received_block["stateRoot"]
    formatted_block["number"] = received_block["number"]
    formatted_block["transactions"] = dict()
    for trx in received_block["transactions"]:
        formatted_block["transactions"][trx] = get_transaction_trace(
            trx, 
            post_state_root=formatted_block["stateRoot"],
            pre_state_root=pre_state_root)
    return formatted_block

if __name__ == "__main__":

    start_time = time.time()
    # Save everything
    formatted_file_path = "block_with_proof_{}.json".format(int(BLOCK_NUMBER, 16))
    with open(formatted_file_path, "w+") as f:
        json.dump(get_block_data(), f, indent=4)

    print(f"[SUCCESS] Data fetching complete! JSON saved as {formatted_file_path}")
    print(f"[INFO] Total execution time: {time.time() - start_time:.2f} seconds.")