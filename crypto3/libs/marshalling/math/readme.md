# Marshalling utilities for =nil;Crypto3 math primitives - polynomials and terms
This module provides extension of [=nil;Marshalling](https://github.com/NilFoundation/placeholder/tree/master/crypto3/libs/marshalling) utilities for [=nil;Crypto3 Math](https://github.com/NilFoundation/placeholder/tree/master/crypto3/libs/math)

## Usage

This library uses Boost CMake build modules (https://github.com/NilFoundation/placeholder/tree/master/crypto3/cmake).
To actually include this library in a project it is required to:

1. Add [CMake Modules](https://github.com/NilFoundation/placeholder/tree/master/crypto3/cmake) to target project repository.
2. Add all the internal dependencies using [CMake Modules](https://github.com/NilFoundation/placeholder/tree/master/crypto3/cmake) to target project repository.
3. Initialize parent project with [CMake Modules](https://github.com/NilFoundation/placeholder/tree/master/crypto3/cmake) (Look at [crypto3](https://github.com/NilFoundation/placeholder/tree/master/crypto3) for the example)

## Dependencies
### External

* [Boost](https://boost.org) (>= 1.74)

