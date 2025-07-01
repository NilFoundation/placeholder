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
ACCOUNT_TRIE = "0000000000000000000000000000000000000000"

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
    formatted_block["preStateRoot"] = pre_state_root
    formatted_block["number"] = received_block["number"]
    formatted_block["transactions"] = dict()
    for trx in received_block["transactions"]:
        formatted_block["transactions"][trx] = get_transaction_trace(
            trx, 
            post_state_root=formatted_block["stateRoot"],
            pre_state_root=pre_state_root)
    return formatted_block

def add_subtree_to_tree(tree1, tree2):
    for row in tree2:
        if row not in tree1:
            tree1.append(row)

def prepare_subtree(subtree):
    result = []
    for s in subtree:
        result.append({
            "hash": keccak(rlp.encode([bytes.fromhex(r) for r in s])).hex(),
            "inners": s
        })
    return result

def get_root(subtree):
    return keccak(rlp.encode([bytes.fromhex(r) for r in subtree[0]])).hex()

def extract_mpt_traces(block):
    graphs = {
        "postState": {
            ACCOUNT_TRIE: {
                "root": block["stateRoot"][2:],
                "nodes": []
            }
        },
        "preState": {
            ACCOUNT_TRIE: {
                "root": block["preStateRoot"][2:],
                "nodes": []
            }
        }
    }
    leaf_nodes = {
        "postState": {
            ACCOUNT_TRIE: []
        },
        "preState": {
            ACCOUNT_TRIE: []
        }
    }

    for trx in block["transactions"]:
        for addr in block["transactions"][trx]:
            entry = block["transactions"][trx][addr]
            
            subtree = entry["preState"]["accountProof"]
            fields = [
                "nonce",
                "balance",
                "code",
                ]
            for (i, x) in enumerate(fields):
                if x in entry["preState"]:
                    if len(subtree[-1]) == 2 and subtree[-1][0][0] in ['2', '3']:
                        leaf_nodes["preState"][ACCOUNT_TRIE].append({
                            "original_key": addr[2:],
                            "node": subtree[-1],
                            "offset": 0,
                            "selector": i
                        })
            add_subtree_to_tree(graphs["preState"][ACCOUNT_TRIE]["nodes"], prepare_subtree(subtree))

            if len(entry["preState"]["storageProof"]) != 0:
                if addr not in graphs["preState"]:
                    graphs["preState"][addr[2:]] = {
                        "root": get_root(entry["preState"]["storageProof"][0]["proof"]),
                        "nodes": []
                        }
                if addr not in leaf_nodes["preState"]:
                    leaf_nodes["preState"][addr] = []
                
                if len(subtree[-1]) == 2 and subtree[-1][0][0] in ['2', '3']:
                    leaf_nodes["preState"][ACCOUNT_TRIE].append({
                        "original_key": addr[2:],
                        "node": subtree[-1],
                        "offset": 0,
                        "selector": 3
                    })
                for subtree in entry["preState"]["storageProof"]:
                    if len(subtree["proof"][-1]) == 2 and subtree["proof"][-1][0][0] in ['2', '3']:
                        leaf_nodes["preState"][addr].append({
                            "original_key": subtree["key"][2:],
                            "node": subtree["proof"][-1],
                            "offset": 0
                            })
                    add_subtree_to_tree(graphs["preState"][addr[2:]]["nodes"], prepare_subtree(subtree["proof"]))
            # post state   
            subtree = entry["postState"]["accountProof"]
            for (i, x) in enumerate(fields):
                if x in entry["postState"]:
                    if len(subtree[-1]) == 2 and subtree[-1][0][0] in ['2', '3']:
                        leaf_nodes["postState"][ACCOUNT_TRIE].append({
                            "original_key": addr[2:],
                            "node": subtree[-1],
                            "offset": 0,
                            "selector": i
                        })
            add_subtree_to_tree(graphs["postState"][ACCOUNT_TRIE]["nodes"], prepare_subtree(subtree))

            if len(entry["postState"]["storageProof"]) != 0:
                if addr not in graphs["postState"]:
                    graphs["postState"][addr[2:]] = {
                        "root": get_root(entry["postState"]["storageProof"][0]["proof"]),
                        "nodes": []
                        }
                if addr not in leaf_nodes["postState"]:
                    leaf_nodes["postState"][addr] = []

                if len(subtree[-1]) == 2 and subtree[-1][0][0] in ['2', '3']:
                    leaf_nodes["postState"][ACCOUNT_TRIE].append({
                        "original_key": addr[2:],
                        "node": subtree[-1],
                        "offset": 0,
                        "selector": 3
                    })

                for subtree in entry["postState"]["storageProof"]:
                    if len(subtree["proof"][-1]) == 2 and subtree["proof"][-1][0][0] in ['2', '3']:
                        leaf_nodes["postState"][addr].append({
                            "original_key": subtree["key"][2:],
                            "node": subtree["proof"][-1],
                            "offset": 0
                            })
                    add_subtree_to_tree(graphs["postState"][addr[2:]]["nodes"], prepare_subtree(subtree["proof"]))
    return graphs, leaf_nodes


if __name__ == "__main__":

    start_time = time.time()
    # Save everything
    # formatted_file_path = "block_with_proof_{}_3.json".format(int(BLOCK_NUMBER, 16))
    # with open(formatted_file_path, "w+") as f:
    #     json.dump(get_block_data(), f, indent=4)

    graphs, leaf_nodes = extract_mpt_traces(get_block_data())

    print(f"[INFO] Total data fetching time: {time.time() - start_time:.2f} seconds.")

    outputs = ["mpt_account_batch_{}.json".format(int(BLOCK_NUMBER, 16)),
               "mpt_leaf_account_{}.json".format(int(BLOCK_NUMBER, 16)),
               "mpt_account_batch_{}.json".format(int(BLOCK_NUMBER, 16) - 1),
               "mpt_leaf_account_{}.json".format(int(BLOCK_NUMBER, 16) - 1),
               "mpt_storage_multi_trie_{}.json".format(int(BLOCK_NUMBER, 16)),
               "mpt_storage_multi_trie_{}.json".format(int(BLOCK_NUMBER, 16) - 1),
               "mpt_leaf_storage_multi_trie_{}.json".format(int(BLOCK_NUMBER, 16) - 1),
               "mpt_leaf_storage_multi_trie_{}.json".format(int(BLOCK_NUMBER, 16)),
               "mpt_account_batch_no_leaf_{}.json".format(int(BLOCK_NUMBER, 16) - 1),
               "mpt_account_batch_no_leaf_{}.json".format(int(BLOCK_NUMBER, 16))]
        
    with open("mpt_account_batch_{}.json".format(int(BLOCK_NUMBER, 16)), "w+") as f:
        json.dump(graphs["postState"][ACCOUNT_TRIE], f, indent=4)
    with open("mpt_leaf_account_{}.json".format(int(BLOCK_NUMBER, 16)), "w+") as f:
            json.dump(leaf_nodes["postState"][ACCOUNT_TRIE], f, indent=4)
    with open("mpt_account_batch_{}.json".format(int(BLOCK_NUMBER, 16) - 1), "w+") as f:
            json.dump(graphs["preState"][ACCOUNT_TRIE], f, indent=4)
    with open("mpt_leaf_account_{}.json".format(int(BLOCK_NUMBER, 16) - 1), "w+") as f:
            json.dump(leaf_nodes["preState"][ACCOUNT_TRIE], f, indent=4)

    with open("mpt_storage_multi_trie_{}.json".format(int(BLOCK_NUMBER, 16)), "w+") as f:
            cp = deepcopy(graphs["postState"])
            del cp[ACCOUNT_TRIE]
            cp = list(dict(sorted(cp.items())).values())
            json.dump(cp, f, indent=4)

    with open("mpt_storage_multi_trie_{}.json".format(int(BLOCK_NUMBER, 16) - 1), "w+") as f:
            cp = deepcopy(graphs["preState"])
            del cp[ACCOUNT_TRIE]
            cp = list(dict(sorted(cp.items())).values())
            json.dump(cp, f, indent=4)

    with open("mpt_account_batch_no_leaf_{}.json".format(int(BLOCK_NUMBER, 16) - 1), "w+") as f:
            src = graphs["preState"][ACCOUNT_TRIE]
            cp = {
                "root": src["root"],
                "nodes": []
            }
            for s in src["nodes"]:
                if len(s["inners"]) == 2 and s["inners"][0][0] in ["2", "3"]:
                    continue
                cp["nodes"].append(s)
            json.dump(cp, f, indent=4)
    with open("mpt_account_batch_no_leaf_{}.json".format(int(BLOCK_NUMBER, 16)), "w+") as f:
            src = graphs["postState"][ACCOUNT_TRIE]
            cp = {
                "root": src["root"],
                "nodes": []
            }
            for s in src["nodes"]:
                if len(s["inners"]) == 2 and s["inners"][0][0] in ["2", "3"]:
                    continue
                cp["nodes"].append(s)
            json.dump(cp, f, indent=4)


    with open("mpt_leaf_storage_multi_trie_{}.json".format(int(BLOCK_NUMBER, 16) - 1), "w+") as f:
            cp = deepcopy(leaf_nodes["preState"])
            del cp[ACCOUNT_TRIE]
            cp = dict(sorted(cp.items()))
            json.dump(cp, f, indent=4)

    with open("mpt_leaf_storage_multi_trie_{}.json".format(int(BLOCK_NUMBER, 16)), "w+") as f:
            cp = deepcopy(leaf_nodes["postState"])
            del cp[ACCOUNT_TRIE]
            cp = dict(sorted(cp.items()))
            json.dump(cp, f, indent=4)
    print(f"[SUCCESS] Traces saved as {outputs}")
