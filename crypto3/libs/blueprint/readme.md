# Circuit Definition Library for =nil; Foundation's Cryptography Suite

=nil; Foundation's Circuit Definition library which provides interfaces for generating ZK circuits used in proof generation. It holds information about the circuit itself, its gates, constraints, and other fixed expressions, public and private assignments needed by the ZK-SNARK system.

## Usage

This library uses Boost CMake build modules (https://github.com/NilFoundation/placeholder/tree/master/crypto3/cmake).
To actually include this library in a project it is required to:

1. Add [CMake Modules](https://github.com/NilFoundation/placeholder/tree/master/crypto3/cmake) to target project repository.
2. Add all the internal dependencies using [CMake Modules](https://github.com/NilFoundation/placeholder/tree/master/crypto3/cmake) to target project repository.
3. Initialize parent project with [CMake Modules](https://github.com/NilFoundation/placeholder/tree/master/crypto3/cmake) (Look at [crypto3](https://github.com/NilFoundation/placeholder/tree/master/crypto3) for the example)

## Dependencies

### Internal

* [Algebra](https://github.com/NilFoundation/placeholder/tree/master/crypto3/libs/algebra).
* [Zk](https://github.com/NilFoundation/placeholder/tree/master/crypto3/libs/zk).
* [Random](https://github.com/NilFoundation/placeholder/tree/master/crypto3/libs/random).
* [Hash](https://github.com/NilFoundation/placeholder/tree/master/crypto3/libs/hash).

### External
* [Boost](https://boost.org) (>= 1.73)
