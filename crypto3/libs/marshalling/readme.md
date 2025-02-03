# Crypto3 Marshalling library

This library is used throughout the project to transform data from one type to
another. To define representation rules for custom type we use template-defined
pseudo-DSL.

With term *marshalling* we denote both serialization and deserialization of
objects.

Serialization is the process of transforming C++ object (elliptic curve point
for example) into the series of simple units (vector of bytes for example).

Deserialization is the opposing process.

The process is done using intermediate representation of C++ objects as
tree-like structure of tuples/bundles/arrays of elements. Then this structure
is transformed into series of bytes.

For serialization the corresponding functions are `make_XXX` and `pack_XXX`.
Deserialization is done using functions like `fill_XXX` and `unpack_XXX`.

The library consists of following modules:

```
marshalling
├── algebra
├── containers
├── core
├── math
├── multiprecision
├── zk
```

For convenience the umbrella `pack` function is provided, that can be used for
either process. See `algebra/examples` for example usage. `core/examples`
contains samples for creating custom `fill_S` and `make_S` functions.

## Algebra

Provides support for marshalling of algebraic elements: field elements and
elliptic curve points.

## Containers

Provides support for marshalling of Merkle tree structures.

## Core

Provides support for marshalling of basic types as well as template-defined
helper functions for arrays and vectors of other elements.

## Math

Provides support for marshalling of math objects: polynomials and arithmetic
expressions.

## Multiprecision

Provides support for marshalling of multiprecision itegrals.

## ZK

Provides support for marshalling of Zero-Knowledge structures: commitments of
different schemes, assignment table, constraint system and various structures
comprising Placeholder proof.

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
ninja marshalling_algebra_curve_element_test
```

## Usage

The suite is used as header-only libraries.
