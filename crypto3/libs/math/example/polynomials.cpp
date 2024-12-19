//---------------------------------------------------------------------------//
// Copyright (c) 2024 Vasiliy Olekhov <vasiliy.olekhov@nil.foundation>
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
// This example demonstrates operations on polynomials

#include <iostream>

#include <nil/crypto3/algebra/fields/arithmetic_params/bls12.hpp>
#include <nil/crypto3/math/polynomial/polynomial.hpp>
#include <nil/crypto3/math/polynomial/basic_operations.hpp>
#include <nil/crypto3/math/polynomial/xgcd.hpp>
#include <nil/crypto3/algebra/fields/bls12/scalar_field.hpp>

#include <nil/crypto3/math/polynomial/polynomial.hpp>

int main() {
    using field_type = typename nil::crypto3::algebra::fields::bls12_scalar_field<381>::value_type;
    using polynomial = nil::crypto3::math::polynomial<field_type>;

    /* 3x^2 + 2x + 1 */
    polynomial a({1,2,3});
    std::cout << "a = " << a << std::endl;
    
    /* 7x^5 */
    polynomial b({0,0,0,0,0,7});
    std::cout << "b = " << b << std::endl;

    polynomial c = a + b;
    std::cout << "a+b = " << c << std::endl;

    polynomial d = a * b;
    std::cout << "a*b = " << d << std::endl;

    field_type x = 2;
    std::cout << std::dec;
    std::cout << "a(" << x << ") = " << a.evaluate(x) << std::endl;
    std::cout << "b(" << x << ") = " << b.evaluate(x) << std::endl;
    return 0;
}
