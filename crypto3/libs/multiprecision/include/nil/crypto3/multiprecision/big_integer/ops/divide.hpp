///////////////////////////////////////////////////////////////
//  Copyright (c) 2023 Martun Karapetyan <martun@nil.foundation>
//
//  Distributed under the Boost Software License, Version 1.0.
//  (See accompanying file LICENSE_1_0.txt or copy at https://www.boost.org/LICENSE_1_0.txt
//
//  Contains eval_modulus for big_integer, which uses conversion to cpp_int_backend to
//  actually apply the operation.
//

#pragma once

#include "nil/crypto3/multiprecision/big_integer/big_integer_impl.hpp"

namespace nil::crypto3::multiprecision {

    // Functions in this file should be called only for creation of montgomery and Barett
    // params, no during "normal" execution, so we do NOT care about the execution speed,
    // and will just redirect calls to normal boost::cpp_int.

    template<unsigned Bits1, unsigned Bits2, unsigned Bits3>
    inline constexpr void eval_modulus(big_integer<Bits1> &result, const big_integer<Bits2> &a,
                                       const big_integer<Bits3> &b) noexcept {
        result = a;
        // Call the function below.
        eval_modulus(result, b);
    }

    // Just a call to the upper function, similar to operator*=.
    // Caller is responsible for the result to fit in Bits1 Bits, we will NOT throw!
    template<unsigned Bits1, unsigned Bits2>
    inline constexpr void eval_modulus(big_integer<Bits1> &result,
                                       const big_integer<Bits2> &a) noexcept {
        auto result_cpp_int = result.to_cpp_int();
        result_cpp_int %= a.to_cpp_int();
        result.from_cpp_int(result_cpp_int);
    }

    // This function should be called only for creation of montgomery and Barett params and
    // calculation of inverse, element, not during "normal" execution. We will use
    // conversion to normal boost::cpp_int here and then convert back.
    template<unsigned Bits1, unsigned Bits2, unsigned Bits3>
    inline constexpr void eval_divide(big_integer<Bits1> &result, const big_integer<Bits2> &a,
                                      const big_integer<Bits3> &b) noexcept {
        result = a;
        // Just make a call to the lower function.
        eval_divide(result, b);
    }

    // Caller is responsible for the result to fit in Bits1 Bits, we will NOT throw!
    // Covers the case where the second operand is not trivial.
    template<unsigned Bits1, unsigned Bits2>
    inline constexpr void eval_divide(big_integer<Bits1> &result,
                                      const big_integer<Bits2> &a) noexcept {
        auto result_cpp_int = result.to_cpp_int();
        result_cpp_int /= a.to_cpp_int();
        result.from_cpp_int(result_cpp_int);
    }
}  // namespace nil::crypto3::multiprecision
