# =nil; Foundation's Cryptography Suite
[![Discord](https://img.shields.io/discord/969303013749579846.svg?logo=discord&style=flat-square)](https://discord.gg/KmTAEjbmM3)
[![Telegram](https://img.shields.io/badge/Telegram-2CA5E0?style=flat-square&logo=telegram&logoColor=dark)](https://t.me/nilfoundation)
[![Twitter](https://img.shields.io/twitter/follow/nil_foundation)](https://twitter.com/nil_foundation)

Placeholder repository is a collection of various nil-projects. Check out subfolders for more.
Supported by [=nil; Foundation](https://nil.foundation)
 
## Contents
1. [Dependencies](#Dependencies)
2. [Build](#Build)
3. [Licence](#Licence)

### Dependencies

Install nix using the following command:

```
curl --proto '=https' --tlsv1.2 -sSf -L https://install.determinate.systems/nix | sh -s -- install
```

### Build

For most cases, you want to have an incremental build:
```
nix develop .#crypto3-debug-tests
eval "$configurePhase" // automatically move to the build directory
eval "$buildPhase"
eval "$checkPhase"
```

if you want to build a single test:
```
nix develop .#crypto3-debug-tests
eval "$configurePhase" // automatically move to the build directory
ninja TEST_NAME
```

To build and test an individual project (crypto3, for example):
```
nix build -L .?#checks.x86_64-linux.crypto3-gcc
```
To list all available nix-targets, call
```
nix flake show
```

### Licence

The software is provided under [MIT](LICENSE) Licence.

