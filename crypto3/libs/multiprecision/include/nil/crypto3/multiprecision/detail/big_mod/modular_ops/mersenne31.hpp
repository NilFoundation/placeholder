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

#include "nil/crypto3/multiprecision/detail/big_mod/modular_ops/montgomery.hpp"
#include "nil/crypto3/multiprecision/detail/big_mod/modular_ops_storage.hpp"

namespace nil::crypto3::multiprecision {
    inline constexpr std::uint32_t mersenne31_modulus = 0x7FFFFFFFU;

    namespace detail {
        class mersenne31_modular_ops : public detail::montgomery_modular_ops<31> {
          public:
            constexpr mersenne31_modular_ops()
                : detail::montgomery_modular_ops<31>(mersenne31_modulus) {}
        };

        using mersenne31_modular_ops_storage =
            modular_ops_storage_fixed_ct<mersenne31_modular_ops>;
    }  // namespace detail
}  // namespace nil::crypto3::multiprecision
