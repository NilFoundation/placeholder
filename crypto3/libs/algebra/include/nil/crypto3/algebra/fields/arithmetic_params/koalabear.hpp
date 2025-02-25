//---------------------------------------------------------------------------//
// Copyright (c) 2025 Andrey Nefedov <ioxid@nil.foundation>
//
// MIT License
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_ALGEBRA_FIELDS_KOALABEAR_ARITHMETIC_PARAMS_HPP
#define CRYPTO3_ALGEBRA_FIELDS_KOALABEAR_ARITHMETIC_PARAMS_HPP

#include <cstddef>

#include <nil/crypto3/algebra/fields/params.hpp>

#include <nil/crypto3/algebra/fields/koalabear.hpp>

namespace nil::crypto3::algebra::fields {
    template<>
    struct arithmetic_params<koalabear> : public params<koalabear> {
        constexpr static std::size_t two_adicity = 24;
        constexpr static integral_type arithmetic_generator = 1u;
        constexpr static integral_type geometric_generator = 0x02;
        constexpr static integral_type multiplicative_generator = 3u;
        constexpr static integral_type root_of_unity = 0x6ac49f88u;
    };
}  // namespace nil::crypto3::algebra::fields

#endif  // CRYPTO3_ALGEBRA_FIELDS_KOALABEAR_ARITHMETIC_PARAMS_HPP
