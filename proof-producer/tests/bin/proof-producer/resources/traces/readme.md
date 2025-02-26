# Collect traces for tests
Instruction how to update EVM traces for tests.

## Dependency
1. [solc](https://github.com/ethereum/solidity)
2. [nild](https://github.com/NilFoundation/nil)
3. [nil_block_generator](https://github.com/NilFoundation/nil)
4. [prover](https://github.com/NilFoundation/nil)

## Common pipeline
1. Compile contract
```bash
solc -o <OUTPUT PATH> --bin --abi <CONTRACT CODE> --overwrite --no-cbor-metadata --metadata-hash none
```
2. Generate block on nil node
```bash
# create smart account
nil_block_generator init
# deploy contract
nil_block_generator add-contract --contract-name <ANY NAME> --contract-path <COMPILED CONTRACT>
# add record to the config
nil_block_generator call-contract --contract-name <ANY NAME> --args <CALL ARGS> --method <CONTRACT METHOD> --count <MUN CALLs>
# execute all calls, all transaction should be in a single block
nil_block_generator get-block
```
3. Collect traces
```bash
prover trace <OUPUT PATH> 1 <BLOCK HASH>
```
To collect traces by prover you need to run `nild` in another terminal from the same working directory as `nil_block_generator`
```bash
/nild run --http-port 8529
```

## Update test data

### simple increment
```bash
solc -o . --bin --abi contracts/tracer_data.sol --overwrite --no-cbor-metadata --metadata-hash none
nil_block_generator init
nil_block_generator add-contract --contract-name increment --contract-path SimpleStorage
nil_block_generator call-contract --contract-name increment --args "" --method increment --count 1
nil_block_generator get-block
nild run --http-port 8529 # should be run in another terminal (or with &) and stopped after collecting the traces with prover
prover trace simple/increment_simple 1 $block_hash
```

### multi transactions
```bash
solc -o . --bin --abi contracts/tracer_data.sol --overwrite --no-cbor-metadata --metadata-hash none
nil_block_generator init
nil_block_generator add-contract --contract-name increment --contract-path SimpleStorage
nil_block_generator call-contract --contract-name increment --args "" --method increment --count 2
nil_block_generator get-block
nild run --http-port 8529 # should be run in another terminal (or with &) and stopped after collecting the traces with prover
prover trace multi_tx/increment_multi_tx 1 $block_hash
```

### exponential
```bash
solc -o . --bin --abi contracts/tracer_data.sol --overwrite --no-cbor-metadata --metadata-hash none
nil_block_generator init
nil_block_generator add-contract --contract-name exp --contract-path SimpleStorage
nil_block_generator call-contract --contract-name exp --args "" --method exponentiate --count 1
nil_block_generator get-block
nild run --http-port 8529 # should be run in another terminal (or with &) and stopped after collecting the traces with prover
prover trace exp/exp 1 $block_hash
```

### arithmetic corner cases

#### add overflow
```bash
solc -o . --bin --abi contracts/tracer_data.sol --overwrite --no-cbor-metadata --metadata-hash none
nil_block_generator init
nil_block_generator add-contract --contract-name Uint256CornerCaseTests --contract-path Uint256CornerCaseTests
nil_block_generator call-contract --contract-name Uint256CornerCaseTests --method addAsm --count 1 --args "0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF 0x2"

nil_block_generator get-block
nild run --http-port 8529 # should be run in another terminal (or with &) and stopped after collecting the traces with prover
prover trace corner_cases/addition_overflow/addition_overflow 1 $block_hash
```

#### mul overflow
```bash
solc -o . --bin --abi contracts/tracer_data.sol --overwrite --no-cbor-metadata --metadata-hash none
nil_block_generator init
nil_block_generator add-contract --contract-name Uint256CornerCaseTests --contract-path Uint256CornerCaseTests
nil_block_generator call-contract --contract-name Uint256CornerCaseTests --method mulAsm --count 1 --args "0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFE 0xFF"

nil_block_generator get-block
nild run --http-port 8529 # should be run in another terminal (or with &) and stopped after collecting the traces with prover
prover trace corner_cases/multiplication_overflow/mul_overflow 1 $block_hash
```

#### exp overflow
```bash
solc -o . --bin --abi contracts/tracer_data.sol --overwrite --no-cbor-metadata --metadata-hash none
nil_block_generator init
nil_block_generator add-contract --contract-name Uint256CornerCaseTests --contract-path Uint256CornerCaseTests
nil_block_generator call-contract --contract-name Uint256CornerCaseTests --method expAsm --count 1 --args "0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFE 0xFF"

nil_block_generator get-block
nild run --http-port 8529 # should be run in another terminal (or with &) and stopped after collecting the traces with prover
prover trace corner_cases/exponentiation_overflow/exp_overflow 1 $block_hash
```

#### sub underflow
```bash
solc -o . --bin --abi contracts/tracer_data.sol --overwrite --no-cbor-metadata --metadata-hash none
nil_block_generator init
nil_block_generator add-contract --contract-name exp --contract-path Uint256CornerCaseTests
nil_block_generator call-contract --contract-name Uint256CornerCaseTests --method subAsm --count 1 --args "0x1 0x2"
nil_block_generator get-block
nild run --http-port 8529 # should be run in another terminal (or with &) and stopped after collecting the traces with prover
prover trace corner_cases/substraction_underflow/substraction_underflow 1 $block_hash
```

#### div by zero
```bash
solc -o . --bin --abi contracts/tracer_data.sol --overwrite --no-cbor-metadata --metadata-hash none
nil_block_generator init
nil_block_generator add-contract --contract-name Uint256CornerCaseTests --contract-path Uint256CornerCaseTests
nil_block_generator call-contract --contract-name Uint256CornerCaseTests --method divAsm --count 1 --args "0x11 0x0"
nil_block_generator get-block
nild run --http-port 8529 # should be run in another terminal (or with &) and stopped after collecting the traces with prover
prover trace corner_cases/division_by_zero/div_by_zero 1 $block_hash
```

### broken index
```bash
solc -o . --bin --abi contracts/tracer_data.sol --overwrite --no-cbor-metadata --metadata-hash none
nil_block_generator init
nil_block_generator add-contract --contract-name increment --contract-path SimpleStorage
nil_block_generator call-contract --contract-name increment --args "" --method increment --count 1
nil_block_generator get-block
nild run --http-port 8529 # should be run in another terminal (or with &) and stopped after collecting the traces with prover
prover trace broken_index/increment_simple 1 $block_hash
prover increment_simple 1 $block_hash
# mix files
```
