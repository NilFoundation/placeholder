//---------------------------------------------------------------------------//
// Copyright (c) 2020-2021 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020-2021 Nikita Kaskov <nbering@nil.foundation>
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
// This example demonstrates generation of elements for different structures:
// * Field modulo p
// * Elliptic curve point
// * Extended Field - GT group for pairing-friendly curve

#include <iostream>

#include <nil/crypto3/multiprecision/literals.hpp>

#include <nil/crypto3/algebra/curves/alt_bn128.hpp>
#include <nil/crypto3/algebra/curves/bls12.hpp>

#include <nil/crypto3/algebra/random_element.hpp>

using namespace nil::crypto3::algebra;


template<typename Type>
void random_element_example() {
    typename Type::value_type v = random_element<Type>();

    std::cout << "Got random value:" << v << std::endl;
}

int main() {
    std::cout << "ALT_BN128-254 Fq random element choice:" << std::endl;
    random_element_example<typename fields::alt_bn128_fq<254>>();

    std::cout << "BLS12-381 G1 random element choice:" << std::endl;
    random_element_example<typename curves::bls12<381>::g1_type<>>();

    std::cout << "BLS12-381 Gt random element choice:" << std::endl;
    random_element_example<typename curves::bls12<381>::gt_type>();

    return 0;
}
