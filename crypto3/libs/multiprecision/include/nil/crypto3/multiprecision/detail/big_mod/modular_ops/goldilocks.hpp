//---------------------------------------------------------------------------//
// Copyright (c) 2024 Andrey Nefedov <ioxid@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#pragma once

#include <climits>
#include <cstdint>
#include <limits>
#include <type_traits>

#include <boost/assert.hpp>

#include "nil/crypto3/multiprecision/detail/big_mod/modular_ops/common.hpp"
#include "nil/crypto3/multiprecision/detail/int128.hpp"
#include "nil/crypto3/multiprecision/detail/intel_intrinsics.hpp"

namespace nil::crypto3::multiprecision {
    inline constexpr std::uint64_t goldilocks_modulus = 0xffffffff00000001ULL;

    namespace detail {
        class goldilocks_modular_ops : public common_modular_ops<std::uint64_t> {
          public:
            using base_type = std::uint64_t;

          private:
            static constexpr std::uint64_t NEG_ORDER = ~goldilocks_modulus + 1;

          public:
            constexpr goldilocks_modular_ops()
                : common_modular_ops<std::uint64_t>(goldilocks_modulus) {}

            static constexpr void add(base_type &result, const base_type &y) {
                BOOST_ASSERT(result < goldilocks_modulus && y < goldilocks_modulus);
                uint128_t sum =
                    static_cast<uint128_t>(result) + static_cast<uint128_t>(y);
                if (sum >= goldilocks_modulus) {
                    sum -= goldilocks_modulus;
                }
                result = sum;
                BOOST_ASSERT(result < goldilocks_modulus);
            }

            static constexpr base_type reduce128(const uint128_t &input) {
                /*

let (x_lo, x_hi) = split(x); // This is a no-op
let x_hi_hi = x_hi >> 32;
let x_hi_lo = x_hi & Goldilocks::NEG_ORDER;

let (mut t0, borrow) = x_lo.overflowing_sub(x_hi_hi);
if borrow {
    branch_hint(); // A borrow is exceedingly rare. It is faster to branch.
    t0 -= Goldilocks::NEG_ORDER; // Cannot underflow.
}
let t1 = x_hi_lo * Goldilocks::NEG_ORDER;
let t2 = unsafe { add_no_canonicalize_trashing_input(t0, t1) };
Goldilocks::new(t2)

                */

                std::uint64_t x_lo = input;
                std::uint64_t x_hi = input >> 64;
                std::uint64_t x_hi_hi = x_hi >> 32;
                std::uint64_t x_hi_lo = x_hi & NEG_ORDER;

                std::uint64_t t0 = 0u;
                std::uint8_t borrow = subborrow_limb(0, x_lo, x_hi_hi, &t0);
                if (borrow) {
                    t0 -= NEG_ORDER;
                }
                std::uint64_t t1 = x_hi_lo * NEG_ORDER;
                std::uint64_t t2 = 0;
                std::uint8_t carry = addcarry_limb(0, t0, t1, &t2);
                std::uint64_t result = t2 + NEG_ORDER * carry;
                // TODO(ioxid): store noncanonical and remove this canonicalization
                if (result >= goldilocks_modulus) {
                    result -= goldilocks_modulus;
                }
                return result;
            }

            static constexpr void mul(base_type &result, const base_type &y) {
                BOOST_ASSERT(result < goldilocks_modulus && y < goldilocks_modulus);
                uint128_t prod =
                    static_cast<uint128_t>(result) * static_cast<uint128_t>(y);
                result = reduce128(prod);
                BOOST_ASSERT(result < goldilocks_modulus);
            }

            template<typename T,
                     std::enable_if_t<
                         is_integral_v<T> && !std::numeric_limits<T>::is_signed, int> = 0>
            static constexpr void adjust_modular(base_type &result, const T &input) {
                result = static_cast<std::uint64_t>(input % goldilocks_modulus);
            }
        };

        // Compile-time storage for goldilocks arithmetic operations. Differs from
        // modular_ops_storage_ct in that goldilocks has no modulus parameter
        class goldilocks_modular_ops_storage {
          public:
            using modular_ops_t = goldilocks_modular_ops;

            constexpr goldilocks_modular_ops_storage() {}

            static constexpr const modular_ops_t &ops() { return m_modular_ops; }

            static constexpr bool compare_eq(
                const goldilocks_modular_ops_storage & /*other*/) {
                return true;
            }

          private:
            static constexpr modular_ops_t m_modular_ops{};
        };
    }  // namespace detail

}  // namespace nil::crypto3::multiprecision
