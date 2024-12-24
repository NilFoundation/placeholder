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

#include <boost/assert.hpp>

#include "nil/crypto3/multiprecision/detail/big_int.hpp"

namespace nil::crypto3::multiprecision::detail {
    // Classical Extended Euclidean Algorithm
    // https://web.archive.org/web/20230511143526/http://www-math.ucdenver.edu/~wcherowi/courses/m5410/exeucalg.html
    template<std::size_t Bits>
    constexpr big_int<Bits> half_extended_euclidean_algorithm(big_int<Bits> num1,
                                                              big_int<Bits> num2,
                                                              big_int<Bits>& bezout_x) {
        big_int<Bits> x = 0u;

        bezout_x = 1u;

        big_int<Bits> quotient;
        big_int<Bits> remainder;
        big_int<Bits> temp_x;

        while (!num2.is_zero()) {
            divide_qr(num1, num2, quotient, remainder);

            num1 = num2;
            num2 = remainder;

            temp_x = x;
            x = bezout_x - quotient * x;
            bezout_x = temp_x;
        }

        return num1;
    }
}  // namespace nil::crypto3::multiprecision::detail
