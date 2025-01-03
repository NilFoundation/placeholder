# =nil; Foundation Marshalling Library

This library is used throughout the project to transform data from one type to another.
To define representation rules for custom type we use template-defined pseudo-DSL.

## Usage

This library uses Boost CMake build modules (https://github.com/NilFoundation/placeholder/tree/master/crypto3/cmake).
To actually include this library in a project it is required to:

1. Add [CMake Modules](https://github.com/NilFoundation/placeholder/tree/master/crypto3/cmake) to target project repository.
2. Add all the internal dependencies using [CMake Modules](https://github.com/NilFoundation/placeholder/tree/master/crypto3/cmake) to target project repository.
3. Initialize parent project with [CMake Modules](https://github.com/NilFoundation/placeholder/tree/master/crypto3/cmake) (Look at [crypto3](https://github.com/NilFoundation/placeholder/tree/master/crypto3) for the example)

## Dependencies

### Internal

### External
* [Boost](https://boost.org) (>= 1.81)
