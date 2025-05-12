//---------------------------------------------------------------------------//
// Copyright (c) 2020-2021 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020-2021 Nikita Kaskov <nbering@nil.foundation>
// Copyright (c) 2020-2021 Ilias Khairullin <ilias@nil.foundation>
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

#define BOOST_TEST_MODULE algebra_fpn_test

#include <cstddef>

#include <boost/test/unit_test.hpp>

#include <nil/crypto3/algebra/fields/babybear.hpp>

#include <nil/crypto3/algebra/random_element.hpp>


using namespace nil::crypto3::algebra;


BOOST_AUTO_TEST_CASE(fpn_operations) {
    using Field = fields::babybear_fp4;
    using Value = typename Field::value_type;
    using SmallField  = typename Field::small_subfield;
    using SmallValue = typename SmallField::value_type;
    std::vector<SmallValue> f(5);
    for (std::size_t i = 0; i < f.size(); ++i) {
        f[i] = random_element<SmallField>();
    }
    const Value big_value = random_element<Field>();
    const SmallValue small_value = random_element<SmallField>();

    Value with_big;
    auto cur_big = Value::one();
    for (std::size_t i = 0; i < f.size(); ++i) {
        with_big += cur_big * f[i];
        cur_big *= big_value;
    }
    with_big *= small_value;

    std::array<SmallValue, Field::arity> small_dec;
    cur_big = Value::one();
    for (std::size_t i = 0; i < f.size(); ++i) {
        for (std::size_t j = 0; j < Field::arity; ++j) {
            small_dec[j] += cur_big.binomial_extension_coefficient(j) * f[i];
        }
        cur_big *= big_value;
    }
    for (std::size_t j = 0; j < Field::arity; ++j) {
        small_dec[j] *= small_value;
    }
    Value with_small = small_dec;

    BOOST_CHECK_EQUAL(with_big, with_small);
}
