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

// IWYU pragma: private; include "nil/crypto3/multiprecision/big_int/modular/big_mod.hpp"

#include <cstddef>
#include <type_traits>

#include "nil/crypto3/multiprecision/big_int/big_uint.hpp"
#include "nil/crypto3/multiprecision/big_int/modular/big_mod_impl.hpp"

namespace nil::crypto3::multiprecision {
    template<typename big_mod_t, std::size_t Bits,
             std::enable_if_t<detail::is_big_mod_v<big_mod_t>, int> = 0>
    constexpr big_mod_t powm(const big_mod_t &b, const big_uint<Bits> &e) {
        auto result = b;
        result.ops().exp(result.raw_base(), b.raw_base(), e);
        return result;
    }

    template<typename big_mod_t, typename T,
             std::enable_if_t<detail::is_big_mod_v<big_mod_t> && std::is_integral_v<T>, int> = 0>
    constexpr big_mod_t powm(const big_mod_t &b, T e) {
        return powm(b, static_cast<big_uint<detail::get_bits<T>()>>(e));
    }
}  // namespace nil::crypto3::multiprecision
