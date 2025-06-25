//---------------------------------------------------------------------------//
// Copyright (c) 2024 Elena Tatuzova <e.tatuzova@nil.foundation>
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
#define BOOST_TEST_MODULE blueprint_plonk_benchmarking_test

#include <cstdlib>
#include <string_view>
#include <unordered_map>

#include <boost/algorithm/string.hpp>
#include <boost/assert.hpp>
#include <boost/test/data/monomorphic.hpp>
#include <boost/test/data/test_case.hpp>
#include <boost/test/unit_test.hpp>

#include <nil/crypto3/algebra/curves/alt_bn128.hpp>
#include <nil/crypto3/algebra/fields/babybear.hpp>
#include <nil/crypto3/algebra/curves/pallas.hpp>
#include <nil/crypto3/algebra/fields/goldilocks.hpp>

#include <nil/crypto3/algebra/fields/arithmetic_params/alt_bn128.hpp>
#include <nil/crypto3/algebra/fields/arithmetic_params/babybear.hpp>
#include <nil/crypto3/algebra/fields/arithmetic_params/pallas.hpp>
#include <nil/crypto3/algebra/fields/arithmetic_params/goldilocks.hpp>
#include <nil/crypto3/algebra/random_element.hpp>

#include <nil/crypto3/hash/algorithm/hash.hpp>
#include <nil/crypto3/hash/keccak.hpp>

#include "./debugtt_test_fixture.hpp"

// TODO(ioxid): these tests work in multithread mode.
// In single thread mode they can fail to compile.
// Also compiling in multithread mode takes too long time in CI with GCC.

BOOST_GLOBAL_FIXTURE(zkEVMGlobalFixture);

// Just for CI to pass
BOOST_AUTO_TEST_SUITE(fake_test_suite)
BOOST_AUTO_TEST_CASE(fake_test) {}
BOOST_AUTO_TEST_SUITE_END()


BOOST_FIXTURE_TEST_SUITE(benchmarking_fixed_sizes, zkEVMDebugTTTestFixture,
                         *boost::unit_test::disabled())

constexpr l1_size_restrictions gen_max_sizes(std::size_t max_bits) {
    std::size_t max_rows = (1 << max_bits) - 2;
    l1_size_restrictions max_sizes;
    max_sizes.max_exponentiations = max_rows;
    max_sizes.max_keccak_blocks = max_rows;
    max_sizes.max_bytecode = max_rows;
    max_sizes.max_mpt = max_rows;
    max_sizes.max_rw = max_rows;
    max_sizes.max_copy = max_rows;
    max_sizes.max_zkevm_rows = max_rows;
    max_sizes.max_exponentiations = max_rows;
    max_sizes.max_exp_rows = max_rows;
    max_sizes.max_state = max_rows;
    max_sizes.max_mpt = max_rows;
    return max_sizes;
}

BOOST_DATA_TEST_CASE(minimal_math_pallas_fixed_size, boost::unit_test::data::xrange(30)) {
    using FieldType = typename algebra::curves::pallas::scalar_field_type;
    complex_test<FieldType>("minimal_math.json", gen_max_sizes(sample));
}

BOOST_DATA_TEST_CASE(minimal_math_bn254_fixed_size, boost::unit_test::data::xrange(30)) {
    using FieldType = typename algebra::curves::alt_bn128_254::scalar_field_type;
    complex_test<FieldType>("minimal_math.json", gen_max_sizes(sample));
}

BOOST_DATA_TEST_CASE(minimal_math_goldilocks_fixed_size,
                     boost::unit_test::data::xrange(30)) {
    using FieldType = typename algebra::fields::goldilocks;
    complex_test<FieldType>("minimal_math.json", gen_max_sizes(sample));
}

BOOST_DATA_TEST_CASE(minimal_math_goldilocks_fp2_fixed_size,
                     boost::unit_test::data::xrange(30)) {
    using FieldType = typename algebra::fields::goldilocks_fp2;
    complex_test<FieldType>("minimal_math.json", gen_max_sizes(sample));
}

BOOST_DATA_TEST_CASE(minimal_math_babybear_fixed_size,
                     boost::unit_test::data::xrange(30)) {
    using FieldType = typename algebra::fields::babybear;
    complex_test<FieldType>("minimal_math.json", gen_max_sizes(sample));
}

BOOST_DATA_TEST_CASE(minimal_math_babybear_fp4_fixed_size,
                     boost::unit_test::data::xrange(30)) {
    using FieldType = typename algebra::fields::babybear_fp4;
    complex_test<FieldType>("minimal_math.json", gen_max_sizes(sample));
}

BOOST_DATA_TEST_CASE(minimal_math_babybear_fp5_fixed_size,
                     boost::unit_test::data::xrange(30)) {
    using FieldType = typename algebra::fields::babybear_fp5;
    complex_test<FieldType>("minimal_math.json", gen_max_sizes(sample));
}

BOOST_AUTO_TEST_SUITE_END()
