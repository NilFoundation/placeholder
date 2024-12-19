//---------------------------------------------------------------------------//
// Copyright (c) 2024 Vasiliy Olekhov <vasiliy.olekhov@nil.foundation>
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
// This example shows basic operations on curve elements: addition, subtraction
// doubling, scalar multiplication and transformation to affine coordinates

#include <iostream>

#include <nil/crypto3/multiprecision/literals.hpp>

#include <nil/crypto3/algebra/curves/pallas.hpp>

using namespace nil::crypto3::algebra;

int main() {

    auto G = curves::pallas::g1_type<>::value_type::one();
    auto A = G+G;
    auto B = A;
    B.double_inplace();
    auto C = A + B;
    auto D = C - G;

    std::cout << "Generator: " << G << std::endl;
    std::cout << "A = 2*G : " << A << std::endl;
    std::cout << "B = 2*A : " << B << std::endl;
    std::cout << "C = A + B : " << C << std::endl;
    std::cout << "D = C - G : " << D << std::endl;
    std::cout << "5*G : " << G*5 << std::endl;
    std::cout << "5*G == D? : " << std::boolalpha << (D == G*5) << std::endl;

    std::cout << "D   (affine) : " << D.to_affine() << std::endl;
    std::cout << "5*G (affine) : " << (G*5).to_affine() << std::endl;
    return 0;
}
