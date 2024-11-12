//---------------------------------------------------------------------------//
// Copyright (c) 2024 Martun Karapetyan <martun@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#define BOOST_TEST_MODULE big_integer_comparision_test

#include <boost/random/mersenne_twister.hpp>
#include <boost/random/random_device.hpp>
#include <boost/random/uniform_int_distribution.hpp>
#include <boost/test/unit_test.hpp>
#include <cstddef>

// We need cpp_int to compare to it.
#include <boost/multiprecision/cpp_int.hpp>

#include "nil/crypto3/multiprecision/big_integer/big_integer.hpp"
#include "nil/crypto3/multiprecision/big_integer/cpp_int_conversions.hpp"

using namespace boost::multiprecision;

using nil::crypto3::multiprecision::big_integer;
using nil::crypto3::multiprecision::to_cpp_int;
using nil::crypto3::multiprecision::unsigned_cpp_int_type;

// This test case uses normal boost::cpp_int for comparison to our big_integer
template<std::size_t Bits1, std::size_t Bits2>
void value_comparisons_tests(const big_integer<Bits1>& a, const big_integer<Bits2>& b) {
    typedef big_integer<Bits1> Backend1;
    typedef big_integer<Bits2> Backend2;
    typedef unsigned_cpp_int_type<Bits1> cpp_int_number1;
    typedef unsigned_cpp_int_type<Bits2> cpp_int_number2;

    // Convert from big_integer to cpp_int_backend numbers.
    cpp_int_number1 a_cppint = to_cpp_int(a);
    cpp_int_number2 b_cppint = to_cpp_int(b);

    BOOST_CHECK_EQUAL(a > b, a_cppint > b_cppint);
    BOOST_CHECK_EQUAL(a >= b, a_cppint >= b_cppint);
    BOOST_CHECK_EQUAL(a == b, a_cppint == b_cppint);
    BOOST_CHECK_EQUAL(a < b, a_cppint < b_cppint);
    BOOST_CHECK_EQUAL(a <= b, a_cppint <= b_cppint);
    BOOST_CHECK_EQUAL(a != b, a_cppint != b_cppint);
}

template<std::size_t Bits1, std::size_t Bits2>
void value_comparisons_tests(const std::size_t N) {
    using standard_number1 = big_integer<Bits1>;
    using standard_number2 = big_integer<Bits2>;

    int seed = 0;
    boost::random::mt19937 gen(seed);
    boost::random::uniform_int_distribution<standard_number1> d1;
    boost::random::uniform_int_distribution<standard_number2> d2;

    for (std::size_t i = 0; i < N; ++i) {
        standard_number1 a = d1(gen);
        standard_number2 b = d2(gen);
        value_comparisons_tests(a, b);
    }
}

BOOST_AUTO_TEST_SUITE(static_tests)

BOOST_AUTO_TEST_CASE(base_test_backend_12_17) { value_comparisons_tests<12, 17>(1000); }

BOOST_AUTO_TEST_CASE(base_test_backend_260_130) { value_comparisons_tests<260, 130>(1000); }

BOOST_AUTO_TEST_CASE(base_test_backend_128_256) { value_comparisons_tests<128, 256>(1000); }

BOOST_AUTO_TEST_SUITE_END()
