# Parallel Cryptography Suite
Multi threaded implementation some modules from the cryptography suite.
 
## Contents
1. [Structure](#structure)
2. [Build & test](#build_&_test)
3. [Usage](#usage)

## Structure
parallel-crypto3
├── benchmarks
├── cmake
├── libs
└── test_tools

## Build & test

To run single test:

```bash
nix develop .#<derivation>
eval "$configurePhase" // automatically move to the build directory
ninja <test-name>
```

For example:
```bash
nix develop .#parallel-crypto3-debug-tests
eval "$configurePhase" // automatically move to the build directory
ninja actor_math_polynomial_test
```
