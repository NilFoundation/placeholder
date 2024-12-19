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
// This example demonstrates polynomials in different forms

#include <iostream>

#include <nil/crypto3/algebra/fields/arithmetic_params/bls12.hpp>
#include <nil/crypto3/math/polynomial/polynomial.hpp>
#include <nil/crypto3/math/polynomial/basic_operations.hpp>
#include <nil/crypto3/math/polynomial/xgcd.hpp>
#include <nil/crypto3/algebra/fields/bls12/scalar_field.hpp>

#include <nil/crypto3/math/polynomial/polynomial.hpp>
#include <nil/crypto3/math/polynomial/polynomial_dfs.hpp>

int main() {
    using field_type = typename nil::crypto3::algebra::fields::bls12_scalar_field<381>::value_type;
    using polynomial = nil::crypto3::math::polynomial<field_type>;
    using polynomial_dfs = nil::crypto3::math::polynomial_dfs<field_type>;

    /* 3x^2 + 2x + 1 */
    polynomial a({1,2,3});
    std::cout << "a = " << a << std::endl;

    polynomial_dfs a_dfs;
    a_dfs.from_coefficients(a);
    std::cout << "a_dfs = " << a_dfs << std::endl;
    field_type x = 2;
    std::cout << std::dec;
    std::cout << "a(" << x << ") = " << a.evaluate(x) << std::endl;
    std::cout << "a_dfs(" << x << ") = " << a_dfs.evaluate(x) << std::endl;

    /* 7x^5 */
    polynomial b({0,0,0,0,0,7});
    std::cout << "b = " << b << std::endl;

    polynomial_dfs b_dfs;
    b_dfs.from_coefficients(b);
    std::cout << "b_dfs = " << b_dfs << std::endl;


    polynomial_dfs c_dfs = a_dfs + b_dfs;
    std::cout << "(a+b)_dfs = " << c_dfs << std::endl;

    polynomial c(c_dfs.coefficients());
    std::cout << "(a+b) = " << c << std::endl;
 
    return 0;
}
