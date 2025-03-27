//---------------------------------------------------------------------------//
// Copyright (c) 2020 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020 Ilias Khairullin <ilias@nil.foundation>
// Copyright (c) 2021 Aleksei Moskvin <alalmoskvin@nil.foundation>
// Copyright (c) 2024 Andrey Nefedov <ioxid@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#pragma once

#include <climits>
#include <cstddef>
#include <limits>
#include <type_traits>

#include <boost/assert.hpp>

#include "nil/crypto3/multiprecision/detail/integer_ops_base.hpp"
#include "nil/crypto3/multiprecision/type_traits.hpp"
#include "nil/crypto3/multiprecision/unsigned_utils.hpp"

#include "nil/crypto3/bench/scoped_profiler.hpp"

namespace nil::crypto3::multiprecision::detail {
    template<typename base_type_>
    class common_modular_ops {
      public:
        using base_type = base_type_;
        using pow_unsigned_intermediate_type = base_type;
        static constexpr std::size_t Bits = sizeof(base_type) * CHAR_BIT;

        static_assert(is_integral_v<base_type>);

        constexpr common_modular_ops(const base_type &m) : m_mod(m) {}

        constexpr bool compare_eq(const common_modular_ops &other) const {
            return mod() == other.mod();
        }

        constexpr void negate_inplace(base_type &raw_base) const {
            if (!is_zero(raw_base)) {
                auto initial_raw_base = raw_base;
                raw_base = mod();
                raw_base -= initial_raw_base;
            }
        }

        constexpr void sub(base_type &a, const base_type &b) const {
            bench::register_sub();
            if (a < b) {
                auto v = mod();
                v -= b;
                a += v;
            } else {
                a -= b;
            }
        }

        constexpr void increment(base_type &a) const {
            ++a;
            if (a == mod()) {
                a = 0u;
            }
        }

        constexpr void decrement(base_type &a) const {
            if (is_zero(a)) {
                a = m_mod;
            }
            --a;
        }

        static constexpr base_type one() { return 1u; }

        constexpr void adjust_regular(base_type &result, const base_type &input) const {
            BOOST_ASSERT(input < this->mod());
            result = input;
        }

        constexpr const auto &mod() const { return m_mod; }

      private:
        base_type m_mod{};
    };

    template<
        typename T, typename modular_ops_t,
        std::enable_if_t<is_integral_v<T> && !std::numeric_limits<T>::is_signed, int> = 0>
    constexpr void pow_unsigned(typename modular_ops_t::base_type &result,
                                const typename modular_ops_t::base_type &a, T exp,
                                const modular_ops_t &ops) {
        // input parameter should be less than modulus
        BOOST_ASSERT(a < ops.mod());

        if (is_zero(exp)) {
            result = ops.one();
            return;
        }
        if (ops.mod() == 1u) {
            result = 0u;
            return;
        }

        typename modular_ops_t::pow_unsigned_intermediate_type base = a, res = ops.one();

        while (true) {
            bool lsb = bit_test(exp, 0u);
            exp >>= 1u;
            if (lsb) {
                ops.mul(res, base);
                if (is_zero(exp)) {
                    break;
                }
            }
            ops.mul(base, base);
        }
        result = static_cast<typename modular_ops_t::base_type>(res);
    }

    // Helper methods for initialization using adjust_modular from appropriate modular_ops

    template<
        typename T, typename modular_ops_t,
        std::enable_if_t<is_integral_v<T> && !std::numeric_limits<T>::is_signed, int> = 0>
    constexpr void init_raw_base(typename modular_ops_t::base_type &raw_base, const T &b,
                                 const modular_ops_t &ops) {
        ops.adjust_modular(raw_base, b);
    }

    template<typename T, typename modular_ops_t,
             std::enable_if_t<std::is_integral_v<T> && std::is_signed_v<T>, int> = 0>
    constexpr void init_raw_base(typename modular_ops_t::base_type &raw_base, T b,
                                 const modular_ops_t &ops) {
        ops.adjust_modular(raw_base, unsigned_abs(b));
        if (b < 0) {
            ops.negate_inplace(raw_base);
        }
    }
}  // namespace nil::crypto3::multiprecision::detail
