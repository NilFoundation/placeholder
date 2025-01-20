# Cryptography Suite
Crypto3 cryptography suite's purpose is:
1. To provide a secure, fast and architecturally clean C++ generic cryptography schemes implementation.
2. To provide a developer-friendly, modular suite, usable for novel schemes implementation and further
   extension.
3. To provide a Standard Template Library-alike C++ interface and concept-based architecture implementation.

Libraries are designed to be state of the art, highly performant and providing a one-stop solution for
all cryptographic operations. They are supported on Linux operating system and architectures (x86/ARM).

Developed by [=nil; Crypto3](https://crypto3.nil.foundation) and supported by [=nil; Foundation](https://nil.foundation).

Rationale, tutorials and references are available [here](https://crypto3.nil.foundation/projects/crypto3)
 
## Contents
1. [Structure](#structure)
2. [Build & test](#build_&_test)
3. [Usage](#usage)

## Structure
This folder contains the whole suite. Single-purposed libraries (e.g. [block
](https://github.com/NilFoundation/placeholder/tree/master/crypto3/libs/block) or [hash](https://github.com/NilFoundation/placeholder/tree/master/crypto3/libs/hash)) are not advised to be
used outside this suite or properly constructed CMake project and should be handled with great care.
```
crypto3
├── benchmarks
├── cmake: cmake sub-module with helper functions/macros to build crypto3 library umbrella-repository
├── docs: documentation, tutorials and guides
├── libs
│   ├── algebra: algebraic operations and structures being used for elliptic-curve cryptography
│   ├── benchmark_tools: utilities to run benchmarks
│   ├── blueprint: components and circuits for zk schemes
│   ├── containers: containers and generic commitment schemes for accumulating data, includes Merkle Tree
│   ├── hash: hashing algorithms
│   ├── marshalling: marshalling libraries for types in crypto3 library
│   ├── math: set of Fast Fourier Transforms evaluation algorithms and Polynomial Arithmetics
│   ├── multiprecision: integer, rational, floating-point, complex and interval number types. 
│   ├── random: randomisation primitives 
│   ├── transpiler
│   └── zk: zk cryptography schemes
```

## Build & test

To run single test:
```bash
nix develop .#<derivation>
eval "$configurePhase" // automatically move to the build directory
ninja <test-name>
```

For example:
```bash
nix develop .#crypto3-debug-tests
eval "$configurePhase" // automatically move to the build directory
ninja algebra_curves_test
```

## Usage

The suite is used as header-only libraries.
