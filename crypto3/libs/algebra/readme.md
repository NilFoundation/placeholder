# =nil; Foundation's Algebraic Constructions Module

=nil; Foundation's Algebraic Constructions module.

Contains:
* Finite fields
* Curves
* Pairing
* Constexpr BLAS

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

## What's included

### Elliptic curves

Module supports following family of elliptic curves:
* Pasta curves
* MNT-4 and MNT-6 298 bits versions
* BLS12 381 and 377 bits versions
* alt_bn128
* Families of secp_k1 and secp_r1 curves 160..521 bits versions
* ed25519
* jubjub and babyjubjub

### Finite fields

Module supports variety of modular fields with highly optimized implementation.
Base fields and scalar groups for each curve are supported.
There is also an implementation of [Goldilocks](https://2π.com/22/goldilocks/) field.

To support pairings on particular curves the module provides support for
extension fields, such as $F_{p^2}$, $F_{p^3}$, $F_{p^4}$, $F_{p^6}$ and $F_{p^{12}}$.

The $F_{p^{12}}$ is implemented as "tower extension": $F_{p^2}$ over $F_{p^3}$ over $F_{p^2}$.

The $F_{p^{6}}$ is implemented as $F_{p^2}$ over $F_{p^3}$ and as $F_{p^3}$ over $F_{p^2}$.

### Pairings

Elliptic curve pairings are implemented for MNT-4, MNT-6, BLS12-381, BLS12-377 and alt_bn128 curves.

Different curves implement different approaches.

For MNT families the implementation is aligned with
[arkworks-rs](https://github.com/arkworks-rs/algebra/tree/master/ec).

For BN254 (alt_bn128) and BLS12 curves the implementation follows these papers: 
[Optimal Ate Pairing](https://eprint.iacr.org/2016/130) and
[The Realm of the Pairings](https://eprint.iacr.org/2013/722.pdf)
The implementation closely resembles
[scipr-lab/libff](https://github.com/scipr-lab/libff/tree/develop/libff/algebra/curves/bls12_381) approach.

### Multiexp

Module contains implementation for multiple-scalar exponentiation using different
approaches, described in:
* "Faster batch forgery identification", [INDOCRYPT 2012](https://eprint.iacr.org/2012/549.pdf)
* Bos and Coster, "Addition chain heuristics", CRYPTO '89 with improvements suggested in
  Bernstein, Duif, Lange, Schwabe, and Yang, "High-speed high-security signatures", CHES '11

For testing purposes, naive implementation is also included.

### Basic Linear Algebra Subprograms (BLAS)

Module provides support for vector operations (element-wise multiplication,
multiplication by scalar, etc) as well as matrix operations.
The implementation is honed for performance and uses `constexpr` for all operations.

