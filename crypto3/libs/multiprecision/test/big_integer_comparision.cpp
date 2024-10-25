//---------------------------------------------------------------------------//
// Copyright (c) 2024 Martun Karapetyan <martun@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#define BOOST_TEST_MODULE big_integer_comparision_test

// Suddenly, BOOST_MP_ASSERT is NOT constexpr, and it is used in constexpr functions throughout the
// boost, resulting to compilation errors on all compilers in debug mode. We need to switch
// assertions off inside cpp_int to make this code compile in debug mode. So we use this workaround
// to turn off file 'boost/multiprecision/detail/assert.hpp' which contains definition of
// BOOST_MP_ASSERT and BOOST_MP_ASSERT_MSG.
#ifndef BOOST_MP_DETAIL_ASSERT_HPP
#define BOOST_MP_DETAIL_ASSERT_HPP
#define BOOST_MP_ASSERT(expr) ((void)0)
#define BOOST_MP_ASSERT_MSG(expr, msg) ((void)0)
#endif

#include <boost/random/mersenne_twister.hpp>
#include <boost/random/random_device.hpp>
#include <boost/random/uniform_int_distribution.hpp>
#include <boost/test/unit_test.hpp>
#include <cstddef>

// We need cpp_int to compare to it.
#include <boost/multiprecision/cpp_int.hpp>
#include <nil/crypto3/multiprecision/big_integer/big_integer.hpp>

using namespace boost::multiprecision;

using nil::crypto3::multiprecision::big_integer;

// This test case uses normal boost::cpp_int for comparison to our big_integer
template<unsigned Bits1, unsigned Bits2>
void value_comparisons_tests(const big_integer<Bits1>& a, const big_integer<Bits2>& b) {
    typedef big_integer<Bits1> Backend1;
    typedef big_integer<Bits2> Backend2;
    typedef typename Backend1::cpp_int_type cpp_int_number1;
    typedef typename Backend2::cpp_int_type cpp_int_number2;

    // Convert from big_integer to cpp_int_backend numbers.
    cpp_int_number1 a_cppint = a.to_cpp_int();
    cpp_int_number2 b_cppint = b.to_cpp_int();

    BOOST_CHECK_EQUAL(a > b, a_cppint > b_cppint);
    BOOST_CHECK_EQUAL(a >= b, a_cppint >= b_cppint);
    BOOST_CHECK_EQUAL(a == b, a_cppint == b_cppint);
    BOOST_CHECK_EQUAL(a < b, a_cppint < b_cppint);
    BOOST_CHECK_EQUAL(a <= b, a_cppint <= b_cppint);
    BOOST_CHECK_EQUAL(a != b, a_cppint != b_cppint);
}

template<unsigned Bits1, unsigned Bits2>
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
