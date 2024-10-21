///////////////////////////////////////////////////////////////
//  Copyright (c) 2023 Martun Karapetyan <martun@nil.foundation>
//
//  Distributed under the Boost Software License, Version 1.0.
//  (See accompanying file LICENSE_1_0.txt or copy at https://www.boost.org/LICENSE_1_0.txt
//
//  Contains multiply for big_integer, which does nothing but converts it to
//  cpp_int_backend and does the multiplication.
//

#pragma once

#include "nil/crypto3/multiprecision/big_integer/big_integer_impl.hpp"
#include "nil/crypto3/multiprecision/big_integer/storage.hpp"

// Functions in this file should be called only for creation of montgomery and Barett
// params, calculation of inverse element and montgomery_reduce. Since these functions
// are relatively slow and are not called very often, we will not optimize them. We do
// NOT care about the execution speed, and will just redirect calls to normal
// boost::cpp_int.

// Caller is responsible for the result to fit in Bits1 Bits, we will NOT throw!!!

namespace nil::crypto3::multiprecision::detail {
    template<unsigned Bits1>
    inline constexpr void multiply(big_integer<Bits1> &result, const limb_type &b) noexcept {
        auto result_cpp_int = result.to_cpp_int();
        result_cpp_int *= b;
        result.from_cpp_int(result_cpp_int);
    }

    template<unsigned Bits1, unsigned Bits2>
    inline constexpr void multiply(big_integer<Bits1> &result,
                                   const big_integer<Bits2> &a) noexcept {
        auto result_cpp_int = result.to_cpp_int();
        result_cpp_int *= a.to_cpp_int();
        result.from_cpp_int(result_cpp_int);
    }
}  // namespace nil::crypto3::multiprecision::detail
