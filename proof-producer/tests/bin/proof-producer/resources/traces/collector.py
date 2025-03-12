#!/usr/bin/env python3

import os
import argparse
import yaml
import tempfile
import shutil
import subprocess
import re
import time

def run_command(
    cmd,
    log_file=None,
    cwd=None,
    env=None,
    raise_on_error=True
):
    """
    Runs a command with subprocess, optionally logging stdout/stderr
    to a file. If raise_on_error is True, raises an exception if
    the command fails.
    """
    print(f"[INFO] Running command: {' '.join(cmd)}")
    with subprocess.Popen(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        cwd=cwd,
        env=env
    ) as proc:
        stdout, stderr = proc.communicate()

    if log_file is not None:
        with open(log_file, "a") as lf:
            lf.write(f"\n--- COMMAND: {' '.join(cmd)} ---\n")
            lf.write("STDOUT:\n")
            lf.write(stdout)
            lf.write("\nSTDERR:\n")
            lf.write(stderr)
            lf.write("\n--- END COMMAND OUTPUT ---\n")

    if proc.returncode != 0 and raise_on_error:
        raise RuntimeError(
            f"Command {' '.join(cmd)} failed with code {proc.returncode}\n"
            f"stderr:\n{stderr}"
        )

    return stdout, stderr, proc.returncode


def parse_block_hash_from_output(output):
    match = re.search(r"Hash of the block:\s*([0-9a-fA-Fx]+)", output)
    if match:
        return match.group(1)
    return None


def find_compiled_bin_artifact(temp_dir, contract_name):
    """
    Searches temp_dir (recursively) for a .bin file whose filename ends with
    either `<contract_name>.bin` or `:<contract_name>.bin`.

    Returns the full path without extension if found, or None if not found.
    """
    for root, _, files in os.walk(temp_dir):
        for filename in files:
            if filename.endswith(f"{contract_name}.bin") or filename.endswith(f":{contract_name}.bin"):
                path = os.path.join(root, filename)
                return os.path.splitext(path)[0] # remove the .bin extension
    return None


def parse_arguments():
    """
    Parses CLI arguments using argparse.
    --config is required for the YAML file path.
    --invocation is optional.
    """
    parser = argparse.ArgumentParser(description="Run EVM trace collection pipeline.")
    parser.add_argument(
        "--config",
        required=True,
        help="Path to the YAML config file."
    )

    parser.add_argument(
        "--invocation",
        required=False,
        help="Optional invocation filter (name key in YAML invocation description)"
    )
    return parser.parse_args()

def fetch_nil_binary_path(tool: str, config: dict):
    NIL_ROOT_PLACEHOLDER = "$NIL_ROOT"

    nil_root = None
    if "root" in config:
        nil_root = config["root"]

    tool_path = config.get(tool)
    return tool_path.replace(NIL_ROOT_PLACEHOLDER, nil_root) if tool_path else None


def main():

    # Parse CLI arguments
    args = parse_arguments()
    config_path = args.config
    desired_invocation = args.invocation

    # Load the YAML config
    with open(config_path, "r") as f:
        config = yaml.safe_load(f)

    # Extract global options

    nil_cfg_node = config.get("nil_config")
    nild_path = fetch_nil_binary_path("nild_path", nil_cfg_node)
    prover_path = fetch_nil_binary_path("prover_path", nil_cfg_node)
    nil_block_gen_path = fetch_nil_binary_path("nil_block_generator_path", nil_cfg_node)
    faucet_path = fetch_nil_binary_path("faucet_path", nil_cfg_node)

    need_json_traces = config.get("need_json_traces", False)
    solc_path = config.get("solc_path", "solc")
    log_file = config.get("log_file", None)
    keep_artifacts = config.get("keep_artifacts", False)

    # Contracts to compile via solc (global setup)
    contracts = config.get("contracts", [])

    # Create a temp directory for ephemeral artifacts (or final location if keep_artifacts=True)
    temp_dir = tempfile.mkdtemp(prefix="zkevm_trace_")
    print(f"[INFO] Using temp directory: {temp_dir}")

    # Compile the listed contracts with `solc`
    for contract_source_path in contracts:
        if not os.path.exists(contract_source_path):
            raise FileNotFoundError(f"[ERROR] Contract file '{contract_source_path}' not found.")

        # Example solc command, generating .bin and .abi:
        solc_cmd = [
            solc_path,
            "-o", temp_dir,
            "--bin",
            "--abi",
            contract_source_path,
            "--overwrite",
            "--metadata-hash", "none"
        ]
        run_command(solc_cmd, log_file=log_file)

    # Start the faucet in the background
    print("[INFO] Starting faucet in the background...")
    with open(log_file, "a") if log_file else open(os.devnull, "w") as lf_out:
        faucet_proc = subprocess.Popen(
            [faucet_path, "run"],
            stdout=lf_out,
            stderr=lf_out,
            text=True
        )

    nild_proc = None
    try:
        # Process each invocation
        invocations = config.get("invocations", [])
        if not invocations:
            print("[WARNING] No invocations found in the config file.")

        for idx, invocation in enumerate(invocations, start=1):
            name = invocation.get("name")
            if desired_invocation and name != desired_invocation:
                print(f"[INFO] Skipping invocation #{idx} '{name}' (not requested)")
                continue

            print(f"[INFO] Processing invocation #{idx}: {invocation.get("name")}")
            if "description" in invocation:
                print(f"[INFO] Description: {invocation.get("description")}")

            if "contract_name" not in invocation:
                raise KeyError(f"[ERROR] Missing 'contract_name' in invocation #{idx}")

            contract_name = invocation["contract_name"]

            # We'll locate the compiled .bin for this contract_name in temp_dir
            compiled_bin_path = find_compiled_bin_artifact(temp_dir, contract_name)
            if not compiled_bin_path:
                raise FileNotFoundError(
                    f"[ERROR] Could not find compiled .bin artifact for contract '{contract_name}' "
                    f"in temp_dir '{temp_dir}'. Make sure solc produced <contract_name>.bin or "
                    f"<filename>:<contract_name>.bin"
                )

            calls = invocation.get("calls", [])
            if not calls:
                raise ValueError(f"[ERROR] No calls specified for invocation #{idx}")

            # Validate that each call has the required keys: method, count
            for c_idx, call_info in enumerate(calls, start=1):
                if "method" not in call_info:
                    raise KeyError(f"[ERROR] Missing 'method' in invocation #{idx}, call #{c_idx}")
                if "count" not in call_info:
                    raise KeyError(f"[ERROR] Missing 'count' in invocation #{idx}, call #{c_idx}")

            # nil_block_generator init
            run_command([nil_block_gen_path, "init"], log_file=log_file, cwd=temp_dir)

            # nil_block_generator add-contract
            cmd_add_contract = [
                nil_block_gen_path, "add-contract",
                "--contract-name", contract_name,
                "--contract-path", compiled_bin_path,
                "--args", "" # constructor args are not supported yet
            ]
            run_command(cmd_add_contract, log_file=log_file, cwd=temp_dir)

            # nil_block_generator call-contract for each call
            for c_idx, call_info in enumerate(calls, start=1):
                method = call_info["method"]
                args = call_info.get("args", "")
                count = str(call_info["count"])

                cmd_call_contract = [
                    nil_block_gen_path, "call-contract",
                    "--contract-name", contract_name,
                    "--method", method,
                    "--args", args,
                    "--count", count
                ]
                run_command(cmd_call_contract, log_file=log_file, cwd=temp_dir)

            # nil_block_generator get-block (parse block hash)
            stdout, stderr, _ = run_command(
                [nil_block_gen_path, "get-block"],
                log_file=log_file,
                cwd=temp_dir
            )
            block_hash = parse_block_hash_from_output(stdout)
            if not block_hash:
                raise RuntimeError(
                    f"[ERROR] Could not parse block hash from get-block output in invocation #{idx}."
                )
            print(f"[INFO] Found block hash: {block_hash}")

            # Start nild in the background
            print("[INFO] Starting nild in the background...")
            with open(log_file, "a") if log_file else open(os.devnull, "w") as lf_out:
                nild_proc = subprocess.Popen(
                    [nild_path,
                    "run",
                    "--http-port", "8529",
                    ],
                    cwd=temp_dir,
                    stdout=lf_out,
                    stderr=lf_out,
                    text=True
                )

            time.sleep(5) # wait for nild to start

            print("[INFO] fetching block traces...")

            # Decide which marshal_mode to use based on `need_json_traces`
            marshal_mode_value = "bin"
            if need_json_traces:
                marshal_mode_value = "bin,json"

            traces_output_path = invocation.get("traces_output_path")

            trace_cmd = [
                prover_path,
                "trace",
                f"{traces_output_path}",
                "1", # shard id
                block_hash,
                f"--marshal-mode={marshal_mode_value}"
            ]
            run_command(trace_cmd, log_file=log_file)

            print("[INFO] Stopping nild...")
            nild_proc.terminate()
            try:
                nild_proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                print("[WARNING] nild did not stop on terminate(), sending kill...")
                nild_proc.kill()

            print(f"[INFO] Done with invocation #{idx}")

        # Stop faucet
        print("[INFO] Stopping faucet...")
        faucet_proc.terminate()
        try:
            faucet_proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            print("[WARNING] faucet did not stop on terminate(), sending kill...")
            faucet_proc.kill()

    except Exception as ex:
        print(f"[ERROR] Exception occurred: {ex}")

        if nild_proc:
            print("[INFO] Stopping nild...")
            nild_proc.terminate()
            try:
                nild_proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                print("[WARNING] nild did not stop on terminate(), sending kill...")
                nild_proc.kill()

        print("[INFO] Stopping faucet...")
        faucet_proc.terminate()
        try:
            faucet_proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            print("[WARNING] faucet did not stop on terminate(), sending kill...")
            faucet_proc.kill()

        raise ex

    # Cleanup temp dir if needed
    if not keep_artifacts:
        print(f"[INFO] Removing temp directory: {temp_dir}")
        shutil.rmtree(temp_dir, ignore_errors=True)
    else:
        print(f"[INFO] Preserving temp directory: {temp_dir}")


if __name__ == "__main__":
    main()
