//---------------------------------------------------------------------------//
// Copyright (c) 2018-2020 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2021 Aleksei Moskvin <alalmoskvin@gmail.com>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#pragma once

#include <boost/assert.hpp>
#include <cstddef>

#include "nil/crypto3/multiprecision/big_integer/modular/modular_functions.hpp"

namespace nil::crypto3::multiprecision {
    template<unsigned Bits_>
    class big_integer;
    
    template<typename Backend>
    constexpr int eval_jacobi(const Backend &a, const Backend &n) {
        using boost::multiprecision::default_ops::eval_divide;
        using boost::multiprecision::default_ops::eval_get_sign;
        using boost::multiprecision::default_ops::eval_gt;
        using boost::multiprecision::default_ops::eval_integer_modulus;
        using boost::multiprecision::default_ops::eval_is_zero;
        using boost::multiprecision::default_ops::eval_lsb;
        using boost::multiprecision::default_ops::eval_lt;
        using boost::multiprecision::default_ops::eval_modulus;
        using boost::multiprecision::default_ops::eval_right_shift;

        // BOOST_THROW_EXCEPTION(std::invalid_argument("jacobi: second argument must be odd
        // and > 1"));
        BOOST_ASSERT(eval_integer_modulus(n, 2) && eval_gt(n, 1));

        Backend x = a, y = n;
        int J = 1;

        while (eval_gt(y, 1)) {
            eval_modulus(x, y);

            Backend yd2 = y;
            eval_right_shift(yd2, 1);

            if (eval_gt(x, yd2)) {
                Backend tmp(y);
                eval_subtract(tmp, x);
                x = tmp;
                if (eval_integer_modulus(y, 4) == 3) {
                    J = -J;
                }
            }
            if (eval_is_zero(x)) {
                return 0;
            }

            size_t shifts = eval_lsb(x);
            custom_right_shift(x, shifts);
            if (shifts & 1) {
                std::size_t y_mod_8 = eval_integer_modulus(y, 8);
                if (y_mod_8 == 3 || y_mod_8 == 5) {
                    J = -J;
                }
            }

            if (eval_integer_modulus(x, 4) == 3 && eval_integer_modulus(y, 4) == 3) {
                J = -J;
            }

            // std::swap(x, y);
            auto tmp = x;
            x = y;
            y = tmp;
        }
        return J;
    }
}  // namespace nil::crypto3::multiprecision
