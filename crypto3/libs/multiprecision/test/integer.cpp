//---------------------------------------------------------------------------//
// Copyright (c) 2024 Andrey Nefedov <ioxid@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#define BOOST_TEST_MODULE integer_test

#include <stdexcept>

#include <boost/test/unit_test.hpp>

#include "nil/crypto3/multiprecision/integer.hpp"

using namespace nil::crypto3::multiprecision;

BOOST_AUTO_TEST_SUITE(bit_operations)

BOOST_AUTO_TEST_CASE(lsb_test) {
    BOOST_CHECK_THROW(lsb(0u), std::invalid_argument);
    BOOST_CHECK_EQUAL(lsb(0b001u), 0);
    BOOST_CHECK_EQUAL(lsb(0b010u), 1);
    BOOST_CHECK_EQUAL(lsb(0b011u), 0);
    BOOST_CHECK_EQUAL(lsb(0b100u), 2);
    BOOST_CHECK_EQUAL(lsb(0b101u), 0);
    BOOST_CHECK_EQUAL(lsb(0b110u), 1);
    BOOST_CHECK_EQUAL(lsb(0b111u), 0);
}

BOOST_AUTO_TEST_CASE(msb_test) {
    BOOST_CHECK_THROW(msb(0u), std::invalid_argument);
    BOOST_CHECK_EQUAL(msb(0b001u), 0);
    BOOST_CHECK_EQUAL(msb(0b010u), 1);
    BOOST_CHECK_EQUAL(msb(0b011u), 1);
    BOOST_CHECK_EQUAL(msb(0b100u), 2);
    BOOST_CHECK_EQUAL(msb(0b101u), 2);
    BOOST_CHECK_EQUAL(msb(0b110u), 2);
    BOOST_CHECK_EQUAL(msb(0b111u), 2);
}

BOOST_AUTO_TEST_CASE(bit_test_test) {
    BOOST_CHECK_EQUAL(bit_test(0b001u, 0), true);
    BOOST_CHECK_EQUAL(bit_test(0b001u, 1), false);
    BOOST_CHECK_EQUAL(bit_test(0b001u, 2), false);
    BOOST_CHECK_EQUAL(bit_test(0u, 2), false);
    BOOST_CHECK_EQUAL(bit_test(0b1111u, 10000), false);
}

BOOST_AUTO_TEST_CASE(bit_set_test) {
    unsigned a = 0;
    BOOST_CHECK_EQUAL(bit_test(a, 0), false);
    BOOST_CHECK_EQUAL(bit_test(bit_set(a, 0), 0), true);
    BOOST_CHECK_EQUAL(bit_test(bit_set(a, 0), 0), true);
    BOOST_CHECK_EQUAL(bit_test(a, 1), false);
    BOOST_CHECK_EQUAL(bit_test(bit_set(a, 1), 1), true);
    BOOST_CHECK_EQUAL(bit_test(bit_set(a, 1), 1), true);
    BOOST_CHECK_THROW(bit_set(a, 10000), std::invalid_argument);
}

BOOST_AUTO_TEST_CASE(bit_unset_test) {
    unsigned a = 0b11;
    BOOST_CHECK_EQUAL(bit_test(a, 0), true);
    BOOST_CHECK_EQUAL(bit_test(bit_unset(a, 0), 0), false);
    BOOST_CHECK_EQUAL(bit_test(bit_unset(a, 0), 0), false);
    BOOST_CHECK_EQUAL(bit_test(a, 1), true);
    BOOST_CHECK_EQUAL(bit_test(bit_unset(a, 1), 1), false);
    BOOST_CHECK_EQUAL(bit_test(bit_unset(a, 1), 1), false);
    BOOST_CHECK_THROW(bit_unset(a, 10000), std::invalid_argument);
}

BOOST_AUTO_TEST_CASE(bit_flip_test) {
    unsigned a = 0b11;
    BOOST_CHECK_EQUAL(bit_test(a, 0), true);
    BOOST_CHECK_EQUAL(bit_test(bit_flip(a, 0), 0), false);
    BOOST_CHECK_EQUAL(bit_test(bit_flip(a, 0), 0), true);
    BOOST_CHECK_EQUAL(bit_test(a, 1), true);
    BOOST_CHECK_EQUAL(bit_test(bit_flip(a, 1), 1), false);
    BOOST_CHECK_EQUAL(bit_test(bit_flip(a, 1), 1), true);
    BOOST_CHECK_THROW(bit_flip(a, 10000), std::invalid_argument);
}

BOOST_AUTO_TEST_SUITE_END()

BOOST_AUTO_TEST_CASE(is_zero_test) {
    BOOST_CHECK(is_zero(0u));
    BOOST_CHECK(is_zero(0));
    BOOST_CHECK(!is_zero(1));
    BOOST_CHECK(!is_zero(1u));
    BOOST_CHECK(!is_zero(-1));
    BOOST_CHECK(!is_zero(600));
    BOOST_CHECK(!is_zero(600u));
    BOOST_CHECK(!is_zero(-600));
}
