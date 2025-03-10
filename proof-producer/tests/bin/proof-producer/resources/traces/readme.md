# Collect traces for tests
Instruction how to update EVM traces for tests.

## Dependencies
1. [solc](https://github.com/ethereum/solidity)
2. [nild, nil_block_generator, faucet, prover](https://github.com/NilFoundation/nil)

## Update traces

To recollect all regular test cases just run

```collector.py --config=collector_config.yaml```

### Trace validity test cases

#### Hash mismatch test case
After update of `traces.proto` file used in cluster just save any previously collected trace to `different_proto/increment_simple.pb....`

#### Broken index test case
- Run

  ```collector.py --config=collector_config.yaml --invocation=simple-increment```
- Copy traces from `simple` subdirectory to `broken_index` one
- Run collector again
- Copy any single file from `simple` subdirectory to `broken_index` (replace the existing one)


## How to add new test case
- Add Solidity code you want to test to `contracts/tracer_data.sol` (or define it in a separate file if needed)
- Configure `collector_config.yaml`:
  - Adjust paths for nil and solc binaries used in your system
  - Define all Solitidy files you want to compile
  - Prepare subdirectory for traces to be put (e.g. `my_test_case/trace_files`)
  - Add invocations you want to test (contract name, method call sequence, directory for traces to be stored)
- Run

  ```collector.py --config=collector_config.yaml --invocation=<your_test_case_name_defined_in_yaml>```
