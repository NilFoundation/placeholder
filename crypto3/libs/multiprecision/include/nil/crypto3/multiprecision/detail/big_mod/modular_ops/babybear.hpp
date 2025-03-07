//---------------------------------------------------------------------------//
// Copyright (c) 2024-2025 Andrey Nefedov <ioxid@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#pragma once

#include <cstdint>

#include "nil/crypto3/multiprecision/detail/big_mod/modular_ops/montgomery_31_bit.hpp"
#include "nil/crypto3/multiprecision/detail/big_mod/modular_ops_storage.hpp"

namespace nil::crypto3::multiprecision {
    inline constexpr std::uint32_t babybear_modulus = 0x78000001U;

    namespace detail {
        // Optimized BabyBear ops. Montomery form is used for fast multiplication.
        class babybear_modular_ops : public montgomery_31_bit_modular_ops {
          public:
            constexpr babybear_modular_ops()
                : montgomery_31_bit_modular_ops(babybear_modulus) {}
        };

        using babybear_modular_ops_storage =
            modular_ops_storage_fixed_ct<babybear_modular_ops>;
    }  // namespace detail
}  // namespace nil::crypto3::multiprecision
