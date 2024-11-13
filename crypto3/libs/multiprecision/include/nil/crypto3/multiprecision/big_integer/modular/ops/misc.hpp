//---------------------------------------------------------------------------//
// Copyright (c) 2020 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2019-2021 Aleksei Moskvin <alalmoskvin@nil.foundation>
// Copyright (c) 2020 Ilias Khairullin <ilias@nil.foundation>
// Copyright (c) 2024 Andrey Nefedov <ioxid@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#pragma once

// IWYU pragma: private; include "nil/crypto3/multiprecision/big_integer/modular/modular_big_integer.hpp"

#include <cmath>
#include <cstddef>
#include <type_traits>

#include "nil/crypto3/multiprecision/big_integer/big_integer.hpp"
#include "nil/crypto3/multiprecision/big_integer/modular/modular_big_integer_impl.hpp"

namespace nil::crypto3::multiprecision {
    template<typename modular_big_integer_t, std::size_t Bits,
             std::enable_if_t<detail::is_modular_big_integer_v<modular_big_integer_t>, int> = 0>
    constexpr modular_big_integer_t powm(const modular_big_integer_t &b,
                                         const big_integer<Bits> &e) {
        auto result = b;
        result.ops().exp(result.base_data(), b.base_data(), e);
        return result;
    }
}  // namespace nil::crypto3::multiprecision
