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
#include <limits>
#include <type_traits>

#include <boost/assert.hpp>

#include "nil/crypto3/multiprecision/type_traits.hpp"
#include "nil/crypto3/multiprecision/unsigned_utils.hpp"

namespace nil::crypto3::multiprecision::detail {
    template<typename base_type>
    class common_modular_ops {
      public:
        constexpr common_modular_ops(const base_type &m) : m_mod(m) {}

        constexpr const auto &mod() const { return m_mod; }

        constexpr bool compare_eq(const common_modular_ops &other) const {
            return mod() == other.mod();
        }

        constexpr void negate_inplace(base_type &raw_base) const {
            if (!raw_base.is_zero()) {
                auto initial_raw_base = raw_base;
                raw_base = mod();
                raw_base -= initial_raw_base;
            }
        }

        constexpr void sub(base_type &a, const base_type &b) const {
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
            ++a;
            if (a == mod()) {
                a = 0u;
            }
        }

      protected:
        base_type m_mod;
    };

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
