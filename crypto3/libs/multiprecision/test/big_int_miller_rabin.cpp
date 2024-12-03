///////////////////////////////////////////////////////////////
//  Copyright (c) 2020 Mikhail Komarov.
//  Copyright (c) 2021 Aleksei Moskvin <alalmoskvin@gmail.com>
//  Distributed under the Boost Software License, Version 1.0. (See accompanying file
//  LICENSE_1_0.txt or copy at https://www.boost.org/LICENSE_1_0.txt

#define BOOST_TEST_MODULE big_int_miller_rabin_test

#include <boost/test/data/monomorphic.hpp>
#include <boost/test/data/test_case.hpp>
#include <boost/test/unit_test.hpp>

#include "nil/crypto3/multiprecision/big_int/literals.hpp"
#include "nil/crypto3/multiprecision/big_int/miller_rabin.hpp"

using namespace nil::crypto3::multiprecision;
using namespace nil::crypto3::multiprecision::literals;

BOOST_AUTO_TEST_SUITE(miller_rabin_tests)

BOOST_AUTO_TEST_CASE(miller_rabin_builtin_test) {
    BOOST_CHECK(miller_rabin_test(2u, 1000));
    BOOST_CHECK(miller_rabin_test(3u, 1000));
    BOOST_CHECK(!miller_rabin_test(4u, 1000));
    BOOST_CHECK(miller_rabin_test(17u, 1000));
    BOOST_CHECK(!miller_rabin_test(27u, 1000));
    BOOST_CHECK(miller_rabin_test(101u, 1000));
    BOOST_CHECK(!miller_rabin_test(207u, 1000));
}

BOOST_AUTO_TEST_CASE(miller_rabin_big_uint_test) {
    BOOST_CHECK(miller_rabin_test(2_bigui128, 1000));
    BOOST_CHECK(miller_rabin_test(3_bigui128, 1000));
    BOOST_CHECK(!miller_rabin_test(4_bigui128, 1000));
    BOOST_CHECK(miller_rabin_test(17_bigui128, 1000));
    BOOST_CHECK(!miller_rabin_test(27_bigui128, 1000));
    BOOST_CHECK(miller_rabin_test(101_bigui128, 1000));
    BOOST_CHECK(!miller_rabin_test(207_bigui128, 1000));
}

BOOST_AUTO_TEST_SUITE_END()
