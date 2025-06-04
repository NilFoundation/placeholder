# =nil; Foundation
[![Discord](https://img.shields.io/discord/969303013749579846.svg?logo=discord&style=flat-square)](https://discord.gg/KmTAEjbmM3)
[![Telegram](https://img.shields.io/badge/Telegram-2CA5E0?style=flat-square&logo=telegram&logoColor=dark)](https://t.me/nilfoundation)
[![Twitter](https://img.shields.io/twitter/follow/nil_foundation)](https://twitter.com/nil_foundation)

This repository is a collection of various nil-projects related to zero-knowledge proof. Check out subfolders for more.
Supported by [=nil; Foundation](https://nil.foundation).

## Contents
1. [Structure](#structure)
2. [Dependencies](#dependencies)
3. [Build & test](#build_&_test)
4. [Contributing](#contributing)
5. [Community](#community)
6. [Licence](#Licence)

## Structure
root
├── crypto3
├── debug-tools
├── proof-producer

## Dependencies
- [clang](https://clang.llvm.org/) (>= 11.0)/GCC (>= 10.0)/MSVC (>= 14.20)
- [cmake](https://cmake.org) (>= 3.6)
- [boost](https://boost.org) (>= 1.76)

All dependencies managed by `nix`.

So first install nix using the following command:

```bash
curl --proto '=https' --tlsv1.2 -sSf -L https://install.determinate.systems/nix | sh -s -- install
```

then allow `nix-command` and `flakes` experimental features by adding line

```bash
experimental-features = nix-command flakes
```

in nix configuration file (`/etc/nix/nix.conf`).

## Build & test
To activate Nix development environment:

```bash
nix develop
```

To run all tests:

```bash
nix flake check
```

To build an individual derivation:
```bash
nix build -L .#<derivation>
```
For example:
```bash
nix build -L .#proof-producer
```

To list all available nix-targets, call
```bash
nix flake show
```
If the build fails with OOM, cores number to use could be set with `--cores` [option](https://nix.dev/manual/nix/2.25/command-ref/nix-build.html#opt-cores).

For incremental build:
```bash
nix develop .#<derivation>
eval "$configurePhase" // automatically move to the build directory
eval "$buildPhase" // build
eval "$checkPhase" // run tests
```

if you want to build a single target:
```bash
nix develop .#<derivation>
eval "$configurePhase" // automatically move to the build directory
ninja <target>
```

## Building on macOS

On macOS you should use one of the clang-based derivations, for example

```bash
nix develop '.#develop-clang'
```

Make sure to use a derivation with sanitizer disabled (like `develop-clang`), because it does not work correctly on macOS.

## Contributing
See [contributing](./docs/manual/contributing.md) for contribution guidelines.

## Community
You can contact us
 several ways:
 * E-Mail. Just drop a line to [nemo@nil.foundation](mailto:nemo@nil.foundation).
 * Telegram Group. Join our Telegram group [@nilfoundation](https://t.me/nilfoundation) and ask any question in there.
 * Discord [channel](https://discord.gg/KmTAEjbmM3) for discussions.
 * Issue. Issue which does not belong to any particular module (or you just don't know where to put it) can be
  created in this repository. The team will answer that.
 * Discussion Topic (proposal, tutorial request, suggestion, etc). Would be happy to discuss that in the repository's GitHub [Discussions](https://github.com/NilFoundation/crypto3/discussions)

## Licence
The software is provided under [MIT](LICENSE) Licence.
