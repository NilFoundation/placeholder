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

#include <boost/assert.hpp>

#include "nil/crypto3/multiprecision/detail/big_mod/modular_ops/simple_31_bit.hpp"
#include "nil/crypto3/multiprecision/detail/big_mod/modular_ops_storage.hpp"

#include "nil/crypto3/bench/scoped_profiler.hpp"

namespace nil::crypto3::multiprecision {
    inline constexpr std::uint32_t mersenne31_modulus = 0x7FFFFFFFU;

    namespace detail {
        // Optimized Mersenne31 ops. Custom multiplication implementation is used.
        class mersenne31_modular_ops : public simple_31_bit_modular_ops {
          public:
            using base_type = std::uint32_t;

            constexpr mersenne31_modular_ops()
                : simple_31_bit_modular_ops(mersenne31_modulus) {}

            constexpr void mul(base_type &result, const base_type &y) const {
                bench::register_mul();
                BOOST_ASSERT(result < mod() && y < mod());
                auto prod = static_cast<std::uint64_t>(result) * y;
                std::uint32_t prod_lo =
                    prod & ((static_cast<std::uint64_t>(1) << 31) - 1);
                std::uint32_t prod_hi = prod >> 31;
                result = prod_lo;
                this->add(result, prod_hi);
                BOOST_ASSERT(result < mod());
            }
        };

        using mersenne31_modular_ops_storage =
            modular_ops_storage_fixed_ct<mersenne31_modular_ops>;
    }  // namespace detail
}  // namespace nil::crypto3::multiprecision
