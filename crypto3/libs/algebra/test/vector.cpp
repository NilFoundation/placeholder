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

#define BOOST_TEST_MODULE constexpr_vector_test

#include <boost/test/unit_test.hpp>
#include <boost/test/data/test_case.hpp>
#include <boost/test/data/monomorphic.hpp>

#include <nil/crypto3/algebra/vector/vector.hpp>
#include <nil/crypto3/algebra/vector/math.hpp>
#include <nil/crypto3/algebra/vector/operators.hpp>
#include <nil/crypto3/algebra/vector/utility.hpp>

#include <nil/crypto3/algebra/fields/goldilocks64/base_field.hpp>

using namespace nil::crypto3::algebra;

using field = fields::goldilocks64_base_field;
using value = field::value_type;

static_assert(make_vector(1, 2, 3) == vector {1, 2, 3}, "make_vector and uniform initialization deduction guide");

static_assert(make_vector(1, 2, 3) == vector {{1, 2, 3}}, "make_vector and aggregate initialization deduction guide");

static_assert(elementwise([](value x) { return x.inversed(); }, vector {1, 2, 4}) ==
        vector<value, 3> {1, 0x7fffffff80000001_big_uint64, 0xbfffffff40000001_big_uint64},
              "elementwise");

static_assert(vector {1, 2, 3} == vector {1, 2, 3}, "operator==");

static_assert(vector {1, 2, 3} != vector {3, 2, 1}, "operator!=");

static_assert(vector {1, 2, 3} + vector {1, 2, 3} == vector {2, 4, 6}, "operator+");

static_assert(sum(vector {1, 2, 3}) == 6, "sum");

static_assert(iota<5>(0) == vector {0, 1, 2, 3, 4}, "iota");

static_assert(iota<5, value>() == vector<value, 5> {0, 1, 2, 3, 4}, "iota");

static_assert(fill<4>(2) == vector {2, 2, 2, 2}, "fill");

static_assert(generate<4>([](auto i) { return value(i * i); }) == vector<value, 4> {0, 1, 4, 9}, "generate");

static_assert(vector {1, 2, 3} == slice<3>(vector {1, 2, 3, 4}), "slice-no offset");

static_assert(vector {2, 3, 4} == slice<3>(vector {1, 2, 3, 4}, 1), "slice with offset");
