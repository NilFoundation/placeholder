//---------------------------------------------------------------------------//
// Copyright (c) 2024-2025 Andrey Nefedov <ioxid@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#pragma once

#include <cstddef>
#include <cstdint>
#include <limits>
#include <type_traits>

#include <boost/assert.hpp>

#include "nil/crypto3/multiprecision/detail/addcarry_subborrow.hpp"
#include "nil/crypto3/multiprecision/detail/big_mod/modular_ops/montgomery_utils.hpp"
#include "nil/crypto3/multiprecision/detail/big_mod/modular_ops/simple_31_bit.hpp"

#include "nil/crypto3/bench/scoped_profiler.hpp"

namespace nil::crypto3::multiprecision::detail {
    // Montgomery modular operations for 31-bit modulus.
    class montgomery_31_bit_modular_ops : public simple_31_bit_modular_ops {
      public:
        using base_type = std::uint32_t;

      private:
        static constexpr std::size_t MontgomeryBits = 32;
        static constexpr std::uint64_t MontgomeryMask =
            (static_cast<std::uint64_t>(1) << MontgomeryBits) - 1;

      public:
        constexpr montgomery_31_bit_modular_ops(const base_type &m)
            : simple_31_bit_modular_ops(m), m_montgomery_mu(montgomery_inverse(m)) {}

        constexpr base_type to_montgomery(const base_type &input) const {
            return (static_cast<std::uint64_t>(input) << MontgomeryBits) % mod();
        }

      private:
        constexpr base_type montgomery_reduce(const std::uint64_t &input) const {
            auto t =
                (static_cast<std::uint64_t>(input) * m_montgomery_mu) & MontgomeryMask;
            auto u = t * mod();

            std::uint64_t s = 0;
            auto borrow = subborrow(0, static_cast<std::uint64_t>(input), u, &s);
            auto r = (s >> MontgomeryBits) + (borrow ? mod() : 0);
            return r;
        }

      public:
        constexpr base_type one() const { return m_one; }

        constexpr void increment(base_type &a) const { this->add(a, m_one); }

        constexpr void decrement(base_type &a) const { this->sub(a, m_one); }

        constexpr void mul(base_type &result, const base_type &y) const {
            bench::register_mul();
            BOOST_ASSERT(result < mod() && y < mod());
            result = montgomery_reduce(static_cast<std::uint64_t>(result) * y);
            BOOST_ASSERT(result < mod());
        }

        template<typename T,
                 std::enable_if_t<is_integral_v<T> && !std::numeric_limits<T>::is_signed,
                                  int> = 0>
        constexpr void adjust_modular(base_type &result, const T &input) const {
            result = to_montgomery(static_cast<base_type>(input % mod()));
        }

        constexpr void adjust_regular(base_type &result, const base_type &input) const {
            BOOST_ASSERT(input < mod());
            result = montgomery_reduce(input);
        }

      private:
        base_type m_montgomery_mu;
        base_type m_one = to_montgomery(1u);
    };
}  // namespace nil::crypto3::multiprecision::detail
