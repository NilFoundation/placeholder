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

#include "nil/crypto3/multiprecision/big_uint.hpp"
#include "nil/crypto3/multiprecision/detail/big_int.hpp"
#include "nil/crypto3/multiprecision/detail/half_extended_euclidean_algorithm.hpp"
#include "nil/crypto3/multiprecision/type_traits.hpp"

namespace nil::crypto3::multiprecision {
    template<std::size_t Bits>
    constexpr big_uint<Bits> inverse_mod(const big_uint<Bits>& a,
                                         const big_uint<Bits>& m) {
        big_int<Bits> aa = a, mm = m, x, g;
        g = detail::half_extended_euclidean_algorithm(aa, mm, x);
        if (g != 1u) {
            throw std::invalid_argument("no multiplicative inverse");
        }
        x %= m;
        if (x.negative()) {
            x += m;
        }
        BOOST_ASSERT(!x.negative() && x.abs() < m);
        return x.abs();
    }

    template<typename big_mod_t, std::enable_if_t<is_big_mod_v<big_mod_t>, int> = 0>
    constexpr big_mod_t inverse(const big_mod_t& modular) {
        return big_mod_t(inverse_mod(detail::as_big_uint(modular.to_integral()),
                                     detail::as_big_uint(modular.mod())),
                         modular.ops_storage());
    }
}  // namespace nil::crypto3::multiprecision
