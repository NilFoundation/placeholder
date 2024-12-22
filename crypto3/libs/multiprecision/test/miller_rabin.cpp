//---------------------------------------------------------------------------//
// Copyright (c) 2020 Mikhail Komarov
// Copyright (c) 2021 Aleksei Moskvin <alalmoskvin@gmail.com>
// Copyright (c) 2024 Andrey Nefedov <ioxid@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#define BOOST_TEST_MODULE miller_rabin_test

#include <boost/test/data/monomorphic.hpp>
#include <boost/test/data/test_case.hpp>
#include <boost/test/unit_test.hpp>

#include "nil/crypto3/multiprecision/literals.hpp"
#include "nil/crypto3/multiprecision/miller_rabin.hpp"

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
    BOOST_CHECK(!miller_rabin_test(100'000u, 1000));
    BOOST_CHECK(!miller_rabin_test(100'005u, 1000));
    BOOST_CHECK(miller_rabin_test(1'000'000'007u, 1000));
    BOOST_CHECK(miller_rabin_test(1'000'000'009u, 1000));
}

BOOST_AUTO_TEST_CASE(miller_rabin_big_uint_test) {
    BOOST_CHECK(miller_rabin_test(2_big_uint128, 1000));
    BOOST_CHECK(miller_rabin_test(3_big_uint128, 1000));
    BOOST_CHECK(!miller_rabin_test(4_big_uint128, 1000));
    BOOST_CHECK(miller_rabin_test(17_big_uint128, 1000));
    BOOST_CHECK(!miller_rabin_test(27_big_uint128, 1000));
    BOOST_CHECK(miller_rabin_test(101_big_uint128, 1000));
    BOOST_CHECK(!miller_rabin_test(207_big_uint128, 1000));
    BOOST_CHECK(!miller_rabin_test(100000_big_uint128, 1000));
    BOOST_CHECK(!miller_rabin_test(100005_big_uint128, 1000));
    BOOST_CHECK(miller_rabin_test(1000000007_big_uint128, 1000));
    BOOST_CHECK(miller_rabin_test(1000000009_big_uint128, 1000));
}

BOOST_AUTO_TEST_SUITE_END()
