//---------------------------------------------------------------------------//
// Copyright (c) 2018-2020 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2021 Aleksei Moskvin <alalmoskvin@gmail.com>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#pragma once

// IWYU pragma: private; include "nil/crypto3/multiprecision/big_integer/big_integer.hpp"

#include <cstddef>
#include <stdexcept>

#include "nil/crypto3/multiprecision/big_integer/big_integer_impl.hpp"

namespace nil::crypto3::multiprecision {

    template<std::size_t Bits>
    constexpr int jacobi(const big_integer<Bits> &a, const big_integer<Bits> &n) {
        using big_integer_t = big_integer<Bits>;

        if (n % 2 == 0 || n <= 1) {
            throw std::invalid_argument("jacobi: second argument must be odd and > 1");
        }

        big_integer_t x = a, y = n;
        int J = 1;

        while (y > 1) {
            x %= y;

            big_integer_t yd2 = y;
            yd2 >>= 1;

            if (x > yd2) {
                big_integer_t tmp(y);
                tmp -= x;
                x = tmp;
                if (y % 4 == 3) {
                    J = -J;
                }
            }
            if (is_zero(x)) {
                return 0;
            }

            size_t shifts = lsb(x);
            x >>= shifts;
            if (shifts & 1) {
                std::size_t y_mod_8 = static_cast<std::size_t>(y % 8);
                if (y_mod_8 == 3 || y_mod_8 == 5) {
                    J = -J;
                }
            }

            if (x % 4 == 3 && y % 4 == 3) {
                J = -J;
            }

            std::swap(x, y);
        }
        return J;
    }
}  // namespace nil::crypto3::multiprecision