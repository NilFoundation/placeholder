//---------------------------------------------------------------------------//
// Copyright (c) 2020 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2021 Aleksei Moskvin <alalmoskvin@gmail.com>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#pragma once

// IWYU pragma: private; include "nil/crypto3/multiprecision/big_uint.hpp"

#include <cstddef>
#include <stdexcept>

#include "nil/crypto3/multiprecision/detail/assert.hpp"
#include "nil/crypto3/multiprecision/detail/big_int.hpp"
#include "nil/crypto3/multiprecision/detail/big_uint/big_uint_impl.hpp"

namespace nil::crypto3::multiprecision {
    namespace detail {
        // a^(-1) mod p
        // http://www-math.ucdenver.edu/~wcherowi/courses/m5410/exeucalg.html
        template<std::size_t Bits>
        constexpr big_int<Bits> extended_euclidean_algorithm(big_int<Bits> num1, big_int<Bits> num2,
                                                             big_int<Bits>& bezout_x,
                                                             big_int<Bits>& bezout_y) {
            big_int<Bits> x, y;
            y = 1u;
            x = 0u;

            bezout_x = 1u;
            bezout_y = 0u;

            // Extended Euclidean Algorithm
            while (!num2.is_zero()) {
                big_int<Bits> quotient;
                big_int<Bits> remainder;

                divide_qr(num1, num2, quotient, remainder);

                num1 = num2;
                num2 = remainder;

                big_int<Bits> temp_x = x, temp_y = y;
                x = bezout_x - quotient * x;
                bezout_x = temp_x;

                y = bezout_y - quotient * y;
                bezout_y = temp_y;
            }

            return num1;
        }
    }  // namespace detail

    template<std::size_t Bits>
    constexpr big_uint<Bits> gcd(const big_uint<Bits>& a, const big_uint<Bits>& b) {
        big_int<Bits> aa = a, bb = b, x, y, g;
        g = detail::extended_euclidean_algorithm(aa, bb, x, y);
        NIL_CO3_MP_ASSERT(!g.negative());
        return g.abs();
    }

    template<std::size_t Bits>
    constexpr big_uint<Bits> inverse_mod(const big_uint<Bits>& a, const big_uint<Bits>& m) {
        big_int<Bits> aa = a, mm = m, x, y, g;
        g = detail::extended_euclidean_algorithm(aa, mm, x, y);
        if (g != 1u) {
            throw std::invalid_argument("no multiplicative inverse");
        }
        x %= m;
        if (x.negative()) {
            x += m;
        }
        NIL_CO3_MP_ASSERT(x < m && !x.negative());
        return x.abs();
    }
}  // namespace nil::crypto3::multiprecision
