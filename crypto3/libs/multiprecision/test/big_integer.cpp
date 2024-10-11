
#define BOOST_TEST_MODULE big_integer_test

#include <boost/test/unit_test.hpp>

#include <utility>

#include <boost/random/uniform_int_distribution.hpp>

#include "nil/crypto3/multiprecision/big_integer/big_integer.hpp"
#include "nil/crypto3/multiprecision/big_integer/literals.hpp"

using namespace nil::crypto3::multiprecision::literals;

BOOST_AUTO_TEST_SUITE(big_integer_smoke_tests)

BOOST_AUTO_TEST_CASE(construct) {
    nil::crypto3::multiprecision::big_integer<315> a = 0x123_big_integer315;
}

BOOST_AUTO_TEST_CASE(to_string_trivial) { BOOST_CHECK((0x1_big_integer315).str() == "1"); }

BOOST_AUTO_TEST_SUITE_END()

BOOST_AUTO_TEST_SUITE(big_integer_operations_tests)

BOOST_AUTO_TEST_CASE(ops) {
    nil::crypto3::multiprecision::big_integer<315> a = 2u;

    auto b = a + a;
    b += a;
    ++b;
    b++;

    --b;
    b--;
    b -= a;
    b = b - a;

    b = std::move(a);

    b = a * b;
    b *= a;
    b = a / b;
    b /= a;
    b = a % b;
    b %= a;

    b = a & b;
    b &= a;
    b = a | b;
    b |= a;
    b = a ^ b;
    b ^= a;

    b = ~a;

    // b = -b;
    b = +b;
}

BOOST_AUTO_TEST_SUITE_END()
