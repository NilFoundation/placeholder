//---------------------------------------------------------------------------//
// Copyright (c) 2020 Mikhail Komarov <nemo@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#pragma once

// IWYU pragma: private; include "nil/crypto3/multiprecision/big_int/modular/big_mod.hpp"

#include "nil/crypto3/multiprecision/big_int/ops/inverse.hpp"

namespace nil::crypto3::multiprecision {
    template<typename big_mod_t>
    constexpr big_mod_t inverse_extended_euclidean_algorithm(const big_mod_t &modular) {
        return modular.with_replaced_base(
            inverse_extended_euclidean_algorithm(modular.base(), modular.mod()));
    }
}  // namespace nil::crypto3::multiprecision
