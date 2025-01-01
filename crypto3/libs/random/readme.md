# =nil; Foundation's Random Module

=nil; Foundation's Random module.

Contains: 
* Finite fields
* Curves
* Pairing
* Constexpr BLAS.

## Usage

This library uses Boost CMake build modules (https://github.com/NilFoundation/placeholder/tree/master/crypto3/cmake).
To actually include this library in a project it is required to:

1. Add [CMake Modules](https://github.com/NilFoundation/placeholder/tree/master/crypto3/cmake) to target project repository.
2. Add all the internal dependencies using [CMake Modules](https://github.com/NilFoundation/placeholder/tree/master/crypto3/cmake) to target project repository.
3. Initialize parent project with [CMake Modules](https://github.com/NilFoundation/placeholder/tree/master/crypto3/cmake) (Look at [crypto3](https://github.com/NilFoundation/placeholder/tree/master/crypto3) for the example)

## Dependencies

### Internal

* [Multiprecision](https://github.com/NilFoundation/placeholder/tree/master/crypto3/libs/multiprecision).

### External
* [Boost](https://boost.org) (>= 1.73)
