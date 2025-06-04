# Circuits Traspiler Library for =nil; Foundation's zkLLVM circuit compiler

## Usage

This library uses Boost CMake build modules (https://github.com/NilFoundation/placeholder/tree/master/crypto3/cmake).
To actually include this library in a project it is required to:

1. Add [CMake Modules](https://github.com/NilFoundation/placeholder/tree/master/crypto3/cmake) to target project repository.
2. Add all the internal dependencies using [CMake Modules](https://github.com/NilFoundation/placeholder/tree/master/crypto3/cmake) to target project repository.
3. Initialize parent project with [CMake Modules](https://github.com/NilFoundation/placeholder/tree/master/crypto3/cmake) (Look at [crypto3](https://github.com/NilFoundation/placeholder/tree/master/crypto3) for the example).

## Run examples
This library is used in the [proof-producer](https://github.com/NilFoundation/placeholder/tree/master/proof-producer) binary.
It produces gate argument for EVM from `fill-assignment` stage, which generates `circuit.crct` and `assignment.tbl` file.
It can also create test proof to check gate argument by [evm-placeholder-verification](https://github.com/NilFoundation/evm-placeholder-verification).

1. Build proof-producer binary file
Follow build instruction for [proof-producer](https://github.com/NilFoundation/placeholder/tree/master/proof-producer)
```bash
nix build .#proof-producer -L
```
2. Generate circuit and assignemnt table
```bash
./result/bin/proof-producer \
    --stage "preset" \
    --circuit-name "zkevm" \
    --circuit="circuit.crct"
```

```bash
./result/bin/proof-producer \
    --stage "fill-assignment" \
    --circuit-name "zkevm" \
    --trace "trace.pb" \
    --assignment-table="assignment.tbl"
```

3. Let `output_folder` is a folder for transpiler output. Run to generate gate argument files:
```bash
./result/bin/proof-producer \
    --circuit="circuit.crct" \
    --assignment-table="assignment.tbl" \
    --evm-verifier "output_folder" \
    --proof="proof.bin" -q 10
```
4. Copy `output_folder` to `evm-placeholder-verification/contracts/zkllvm`.

5. Run hardhat to verify proof:
```bash
npx hardhat deploy
npx hardhat verify-circuit-proof --test output_folder
```
## Dependencies

### Internal

Crypto3 suite:

* [Algebra](https://github.com/NilFoundation/placeholder/tree/master/crypto3/libs/algebra).
* [Math](https://github.com/NilFoundation/placeholder/tree/master/crypto3/libs/math).
* [Multiprecision](https://github.com/NilFoundation/placeholder/tree/master/crypto3/libs/multiprecision).
* [Zk](https://github.com/NilFoundation/placeholder/tree/master/crypto3/libs/zk).
* [Blueprint](https://github.com/NilFoundation/placeholder/tree/master/crypto3/libs/blueprint).

### External
* [Boost](https://boost.org) (>= 1.76)
