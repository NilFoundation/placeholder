# zkEVM-framework

Framework for test verification of state of cluster based on EVM

## Content

* Block generator
* EVM assigner
* Proof producer

### Libraries

* `NilCore` - definitions of data structures used for fetching data from shards
* `zkEVMAssignerRunner` - provide interace for run EVM assigner and fill assignment tables
* `zkEVMRpc` - provide interface for send / process requests to RPC
* `zkEVMJsonHelpers` - provide interface for process json configuration files
* `zkEVMOutputArtifacts` - provide interface for manage difernt modes of printing assignment tables (binary, readable, paricular display)

## Dependencies

### Build dependencies

* [CMake](https://cmake.org/)
* [GCC 13+](https://gcc.gnu.org/) (required by SSZ++)
* [Ninja](https://ninja-build.org/) (recommended)

### SSZ++

* Hashtree [Repository](https://github.com/prysmaticlabs/hashtree)
* intx: GMP (intx dependency) [Homepage](https://gmplib.org/), intx [Repository](https://github.com/chfast/intx)
* SSZ++ [Repository](https://github.com/OffchainLabs/sszpp)

### EVM-assigner

* evmc [Repository](https://github.com/ethereum/evmc)
* =nil; crypto3 [Repository](https://github.com/NilFoundation/crypto3)
* =nil; zkllvm-blueprint [Repository](https://github.com/NilFoundation/zkllvm-blueprint)
* =nil; evm-assigner [Repository](https://github.com/NilFoundation/evm-assigner)
* Valijson [Repository](https://github.com/tristanpenman/valijson)

## Clone

Using SSH:

```plain
git clone git@github.com:NilFoundation/zkEVM-framework.git
```

Or if you are using GitHub PAT to authenticate using HTTPS:

```plain
git clone https://<GITGUB_TOKEN>@github.com/NilFoundation/zkEVM-framework.git
```

## Nix environment

Instead of installing all dependencies manually,
you can use [Nix](https://nixos.org/download#download-nix) environment with all installed deps.

For using experimantal features `flake`, `nix-command` add follow line
to your Nix configuration file (`/etc/nix/nix.conf`):

```plaintext
experimental-features = nix-command flakes
```

Because zkEVM-framework currently has EVM-assigner as a dependency which is private repository,
it is required to configure Nix with GitHub Personal Access Token (PAT).
In order to generate your PAT, go [here](https://github.com/settings/tokens). Your token
must have access to content of private repositories.

Then add this to your Nix configuration file (`/etc/nix/nix.conf`):

```plaintext
access-tokens = github.com=<YOUR PAT>
```

If for some reason you don't want to use PAT, you can fallback to using SSH authentication
using `--override-input` option. Add this to your Nix command:

```plaintext
--override-input nil-evm-assigner git+ssh://git@github.com/NilFoundation/evm-assigner.git
````

To activate development environment run:

```bash
nix develop
```

If you want Nix to use your local version of dependency instead of cloning it from GitHub,
you can use `--override-input`. E.g. if you want to use your local evm-assigner, use this:

```bash
nix develop --override-input nil-evm-assigner path:/path/to/evm-assigner
```

Same option applies to `nix build` and etc.

## Build

```plain
cmake --workflow --preset release-build
```

Or with Nix:

```bash
nix build
```

## Assigner

### Build && run

```bash
nix run .#assigner -- -b block -t assignments -e pallas
```

## Test

### Configure tests

Configure with tests enabled:

```bash
cmake -B ${BUILD_DIR:-build} -DENABLE_TESTS=TRUE ...
```

When configuring with enabled tests, you can specify, which tests to enable. By default all tests are enabled.

```bash
# Data types tests won't be enabled
cmake -B ${BUILD_DIR:-build} -DENABLE_TESTS=TRUE -DENABLE_DATA_TYPES_TESTS=FALSE ...
```

### Build tests

```bash
cmake --build ${BUILD_DIR:-build}
```

When using `Ninja` generator, you can build only tests using target `tests/all`:

```bash
cmake --build ${BUILD_DIR:-build} -t tests/all
```

### Run tests

```bash
ctest --test-dir ${BUILD_DIR:-build}/tests
```

When using Nix, you can configure, build and run tests with:

```bash
nix flake check
```

## Build API documentation

zkEVM-framework is using Doxygen to generate API documentaion.
To build it, firts enable building documentation at configuration:

```bash
cmake -B ${BUILD_DIR:-build} -DBUILD_DOCS=TRUE ...
```

Then build documentation:

```bash
cmake -B ${BUILD_DIR:-build} -t docs
```

To see HTML documentation, open `${BUILD_DIR}/html`.

## Usage

### Block call

Account storage contains one account with deployed contract.
Incoming block has one transaction which call deployed contract
Config file with initial state of account storage could be passed with `-s`

```bash
nix run .#assigner [-L] [--override-input nil-evm-assigner /path_to/evm-assigner] -- -b bin/assigner/example_data/call_block.ssz -t assignments -e pallas [-s bin/assigner/example_data/state.json] [--log-level debug]
```

### Block generation

Test block could be generated from config file in JSON format

WARNING: for use block_generator script need to clone and build `nil` [repository](https://github.com/NilFoundation/nil). Make sure if `nild` and `nil` in PATH.

```bash
nix run .#block_gen [-L] -- -i bin/assigner/example_data/call_block.json -o call_block.ssz
```

### Nil CLI block generation

Wrapper script for `nil` is available to deploy and call Solidity contracts.
It requires `nild` and `nil` binaries in `PATH` (already available inside Nix dev environment).

Usage:

For use not default wallet neet to create custom configuration file

```bash
# Generate custom coniguration file
./bin/block_generator/block_generator.py --mode make-config --cli-config-name <path to create new config file>
```

And use `--cli-config-name <path to create new config file>` in each follow commands

```bash
# Generate block, get ShardId, BlockHash. Write block data and state of the correspond contract to the files
./bin/block_generator/block_generator.py --mode generate-block --block-config-name bin/block_generator/example_data/block_config.json [-o block.jsdon] [-s state.json]
```

Config file format:

```json
{
    "contracts" : [
        {
            "id": 1,
            "path": "path/to/solidity/contract"
        },
        ...
    ],

    "transactions" : [
        {
            "contractId" : 1, // index of the deployed contract
            "methodName" : "methodToCall", // name of a method in the contract
            "callArguments": [  // Optional arguments for the method
                "0x123456"
            ]
        },
        ...
    ]
}
```

To deploy and call contracts manually use [nil_cli](https://github.com/NilFoundation/nil/README.md) directly.

### Human-readable assignments

While generating assignment table, you can partially dump it into text form.
This is enabled by `--output-text` option, which specifies output filename or stdout.

```bash
assigner --output-text out.txt
```

Using this option enables other options for tables, columns and rows selection:

```bash
assigner --output-text - \
    --tables 0 \
    --rows 0- \
    --columns witness0-1,3 \
    --columns public_input-1
```

This extracts all raws of w_0, w_1, w_3 and firts public input columns from table with index 0 and prints it to stdout.
The syntax for ranges specification is: `Range(,Range)*` where `Range = N|N-|-N|N-N` where `N` is a number.
