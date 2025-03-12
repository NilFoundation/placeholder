#!/usr/bin/env -S bash -ex

# Check if NIL_BIN and TRACE_NAME are set
if [[ -z "$NIL_BIN" || -z "$TRACE_NAME" ]]; then
  echo "Error: NIL_BIN and TRACE_NAME must be set."
  exit 1
fi

# Compile sample contract
SCRIPT_DIR=`dirname "$0"`
solc -o $SCRIPT_DIR --bin --abi $SCRIPT_DIR/benchmark_data.sol --overwrite --metadata-hash none

# Generate block with hundred increment and hundred exp transactions
$NIL_BIN/nil_block_generator init
CONTRACT_NAME=simple_storage
$NIL_BIN/nil_block_generator add-contract --contract-name $CONTRACT_NAME --contract-path $SCRIPT_DIR/SimpleStorage
$NIL_BIN/nil_block_generator call-contract --contract-name $CONTRACT_NAME --args "" --method increment --count 100
$NIL_BIN/nil_block_generator call-contract --contract-name $CONTRACT_NAME --args "" --method exponentiate --count 100
BLOCK_HASH=`$NIL_BIN/nil_block_generator get-block | tail -1 | awk '{print $NF;}'`

# Start nild in the background
$NIL_BIN/nild run --http-port 8529 &
NILD_PID=$!

# Wait for service initialization
sleep 4

# Collect traces
$NIL_BIN/prover trace $TRACE_NAME 1 $BLOCK_HASH

# Stop the background nild process
kill $NILD_PID
