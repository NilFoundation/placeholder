//---------------------------------------------------------------------------//
// Copyright (c) 2020 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2021 Aleksei Moskvin <alalmoskvin@gmail.com>
// Copyright (c) 2024 Andrey Nefedov <ioxid@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#pragma once

#include <cstddef>
#include <stdexcept>
#include <type_traits>

#include <boost/assert.hpp>

#include "nil/crypto3/multiprecision/big_mod.hpp"
#include "nil/crypto3/multiprecision/big_uint.hpp"
#include "nil/crypto3/multiprecision/detail/big_int.hpp"
#include "nil/crypto3/multiprecision/detail/extended_euclidean_algorithm.hpp"

namespace nil::crypto3::multiprecision {
    template<std::size_t Bits>
    constexpr big_uint<Bits> inverse_mod(const big_uint<Bits>& a,
                                         const big_uint<Bits>& m) {
        big_int<Bits> aa = a, mm = m, x, y, g;
        g = detail::extended_euclidean_algorithm(aa, mm, x, y);
        if (g != 1u) {
            throw std::invalid_argument("no multiplicative inverse");
        }
        x %= m;
        if (x.negative()) {
            x += m;
        }
        BOOST_ASSERT(x < m && !x.negative());
        return x.abs();
    }

    template<typename big_mod_t, std::enable_if_t<is_big_mod_v<big_mod_t>, int> = 0>
    constexpr big_mod_t inverse(const big_mod_t& modular) {
        return big_mod_t(inverse_mod(modular.base(), modular.mod()),
                         modular.ops_storage());
    }
}  // namespace nil::crypto3::multiprecision
