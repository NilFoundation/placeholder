//---------------------------------------------------------------------------//
// Copyright (c) 2020-2021 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020-2021 Nikita Kaskov <nbering@nil.foundation>
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
// This example demonstrates the multiexp function with different implementations:
// * Naive
// * Bernstein, Doumen, Lange, Oosterwijk (BDLO)
// * Bos-Coster

#include <iostream>
#include <vector>
#include <boost/assert.hpp>

#include <nil/crypto3/algebra/curves/bls12.hpp>
#include <nil/crypto3/algebra/curves/params/multiexp/bls12.hpp>
#include <nil/crypto3/algebra/curves/params/wnaf/bls12.hpp>
#include <nil/crypto3/algebra/multiexp/multiexp.hpp>
#include <nil/crypto3/algebra/multiexp/policies.hpp>
#include <nil/crypto3/algebra/random_element.hpp>

using namespace nil::crypto3::algebra;

template<typename curve_group_type>
bool example_multiexp()
{

    using point = typename curve_group_type::value_type;
    using scalar = typename curve_group_type::params_type::scalar_field_type;

    std::size_t N = 8;

    std::vector<point> points(N);
    std::vector<typename scalar::value_type> scalars(N);

    for(auto & p: points) {
        p = random_element<curve_group_type>();
    }

    for(auto & s: scalars) {
        s = random_element<scalar>();
    }

    point naive_result = policies::multiexp_method_naive_plain::process(
            points.begin(), points.end(),
            scalars.begin(), scalars.end());

    point bdlo12_result = policies::multiexp_method_BDLO12::process(
            points.begin(), points.end(),
            scalars.begin(), scalars.end());

    point bos_coster_result = policies::multiexp_method_bos_coster::process(
            points.begin(), points.end(),
            scalars.begin(), scalars.end());

    return (naive_result == bdlo12_result) && (naive_result == bos_coster_result);
}

int main() {
    using g1 = curves::bls12<381>::g1_type<>;
    using g2 = curves::bls12<381>::g2_type<>;
    using scalar_field_type = curves::bls12<381>::scalar_field_type;

    std::cout << "Checking for BLS12-381 G1: " << std::boolalpha << example_multiexp<g1>() << std::endl;
    std::cout << "Checking for BLS12-381 G2: " << std::boolalpha << example_multiexp<g2>() << std::endl;

    return 0;
}
