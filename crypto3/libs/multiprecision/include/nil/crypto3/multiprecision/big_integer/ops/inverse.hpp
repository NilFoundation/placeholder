//---------------------------------------------------------------------------//
// Copyright (c) 2020 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2021 Aleksei Moskvin <alalmoskvin@gmail.com>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#pragma once

// IWYU pragma: private; include "nil/crypto3/multiprecision/big_integer/big_integer.hpp"

#include <cstddef>

#include "nil/crypto3/multiprecision/big_integer/big_integer_impl.hpp"
#include "nil/crypto3/multiprecision/big_integer/detail/assert.hpp"
#include "nil/crypto3/multiprecision/big_integer/signed_big_integer.hpp"

namespace nil::crypto3::multiprecision {
    namespace detail {
        // a^(-1) mod p
        // http://www-math.ucdenver.edu/~wcherowi/courses/m5410/exeucalg.html
        template<std::size_t Bits>
        constexpr signed_big_integer<Bits> extended_euclidean_algorithm(
            const signed_big_integer<Bits>& num1, const signed_big_integer<Bits>& num2,
            signed_big_integer<Bits>& bezout_x, signed_big_integer<Bits>& bezout_y) {
            signed_big_integer<Bits> x, y, tmp_num1 = num1, tmp_num2 = num2;
            y = 1u;
            x = 0u;

            bezout_x = 1u;
            bezout_y = 0u;

            // Extended Euclidean Algorithm
            while (!is_zero(tmp_num2)) {
                signed_big_integer<Bits> quotient = tmp_num1;
                signed_big_integer<Bits> remainder = tmp_num1;
                signed_big_integer<Bits> placeholder;

                quotient /= tmp_num2;
                remainder %= tmp_num2;

                tmp_num1 = tmp_num2;
                tmp_num2 = remainder;

                signed_big_integer<Bits> temp_x = x, temp_y = y;
                placeholder = quotient * x;
                placeholder = bezout_x - placeholder;
                x = placeholder;
                bezout_x = temp_x;

                placeholder = quotient * y;
                placeholder = bezout_y - placeholder;
                y = placeholder;
                bezout_y = temp_y;
            }
            return tmp_num1;
        }
    }  // namespace detail

    template<std::size_t Bits>
    constexpr big_integer<Bits> inverse_extended_euclidean_algorithm(const big_integer<Bits>& a,
                                                                     const big_integer<Bits>& m) {
        signed_big_integer<Bits> aa = a, mm = m, x, y, g;
        g = detail::extended_euclidean_algorithm(aa, mm, x, y);
        if (g != 1u) {
            return 0u;
        }
        x %= m;
        if (x.negative()) {
            x += m;
        }
        NIL_CO3_MP_ASSERT(x < m && !x.negative());
        return x.abs();
    }
}  // namespace nil::crypto3::multiprecision