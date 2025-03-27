//---------------------------------------------------------------------------//
// Copyright (c) 2024-2025 Andrey Nefedov <ioxid@nil.foundation>
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

#include "nil/crypto3/multiprecision/detail/addcarry_subborrow.hpp"
#include "nil/crypto3/multiprecision/detail/big_mod/modular_ops/common.hpp"
#include "nil/crypto3/multiprecision/detail/big_mod/modular_ops_storage.hpp"
#include "nil/crypto3/multiprecision/detail/int128.hpp"

#include "nil/crypto3/bench/scoped_profiler.hpp"

#if !defined(NIL_CO3_MP_HAS_INT128)
#include "nil/crypto3/multiprecision/detail/big_mod/modular_ops/montgomery.hpp"
#endif

namespace nil::crypto3::multiprecision {
    inline constexpr std::uint64_t goldilocks_modulus = 0xFFFFFFFF00000001ULL;

    namespace detail {
#if defined(NIL_CO3_MP_HAS_INT128)
        class goldilocks_modular_ops : public common_modular_ops<std::uint64_t> {
          public:
            using base_type = std::uint64_t;

          private:
            static constexpr std::uint64_t NEG_ORDER = ~goldilocks_modulus + 1;

          public:
            constexpr goldilocks_modular_ops()
                : common_modular_ops<std::uint64_t>(goldilocks_modulus) {}

            static constexpr void add(base_type &result, const base_type &y) {
                bench::register_add();
                BOOST_ASSERT(result < goldilocks_modulus && y < goldilocks_modulus);
                detail::uint128_t sum = static_cast<detail::uint128_t>(result) +
                                        static_cast<detail::uint128_t>(y);
                if (sum >= goldilocks_modulus) {
                    sum -= goldilocks_modulus;
                }
                result = sum;
                BOOST_ASSERT(result < goldilocks_modulus);
            }

          private:
            static constexpr base_type reduce128(const detail::uint128_t &input) {
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
                std::uint8_t borrow = subborrow(0, x_lo, x_hi_hi, &t0);
                if (borrow) {
                    t0 -= NEG_ORDER;
                }
                std::uint64_t t1 = x_hi_lo * NEG_ORDER;
                std::uint64_t t2 = 0;
                std::uint8_t carry = addcarry(0, t0, t1, &t2);
                std::uint64_t result = t2 + NEG_ORDER * carry;
                // TODO(ioxid): store noncanonical and remove this canonicalization
                if (result >= goldilocks_modulus) {
                    result -= goldilocks_modulus;
                }
                return result;
            }

          public:
            static constexpr void mul(base_type &result, const base_type &y) {
                bench::register_mul();
                BOOST_ASSERT(result < goldilocks_modulus && y < goldilocks_modulus);
                detail::uint128_t prod = static_cast<detail::uint128_t>(result) *
                                         static_cast<detail::uint128_t>(y);
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
#else
        class goldilocks_modular_ops : public detail::montgomery_modular_ops<64> {
          public:
            constexpr goldilocks_modular_ops()
                : detail::montgomery_modular_ops<64>(goldilocks_modulus) {}
        };
#endif

        using goldilocks_modular_ops_storage =
            modular_ops_storage_fixed_ct<goldilocks_modular_ops>;
    }  // namespace detail
}  // namespace nil::crypto3::multiprecision
