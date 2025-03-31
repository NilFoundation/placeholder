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

#include "nil/crypto3/multiprecision/detail/big_mod/modular_ops/common.hpp"

#include "nil/crypto3/bench/scoped_profiler.hpp"

namespace nil::crypto3::multiprecision::detail {
    class simple_31_bit_modular_ops : public common_modular_ops<std::uint32_t> {
      public:
        using base_type = std::uint32_t;
        static constexpr std::size_t Bits = 31;

        constexpr void add(base_type &result, const base_type &y) const {
            bench::register_add();
            BOOST_ASSERT(result < mod() && y < mod());
            result += y;
            if (result >= mod()) {
                result -= mod();
            }
            BOOST_ASSERT(result < mod());
        }

        constexpr void mul(base_type &result, const base_type &y) const {
            bench::register_mul();
            BOOST_ASSERT(result < mod() && y < mod());
            result = (static_cast<std::uint64_t>(result) * y) % mod();
            BOOST_ASSERT(result < mod());
        }

        template<typename T,
                 std::enable_if_t<is_integral_v<T> && !std::numeric_limits<T>::is_signed,
                                  int> = 0>
        constexpr void adjust_modular(base_type &result, const T &input) const {
            result = static_cast<base_type>(input % mod());
        }
    };
}  // namespace nil::crypto3::multiprecision::detail
