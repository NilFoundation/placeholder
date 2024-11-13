//---------------------------------------------------------------------------//
// Copyright (c) 2020 Mikhail Komarov <nemo@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#pragma once

// IWYU pragma: private; include "nil/crypto3/multiprecision/big_integer/modular/modular_big_integer.hpp"

#include "nil/crypto3/multiprecision/big_integer/ops/inverse.hpp"

namespace nil::crypto3::multiprecision {
    template<typename modular_big_integer_t>
    constexpr modular_big_integer_t inverse_extended_euclidean_algorithm(
        const modular_big_integer_t &modular) {
        return modular.with_replaced_base(
            inverse_extended_euclidean_algorithm(modular.base(), modular.mod()));
    }
}  // namespace nil::crypto3::multiprecision
