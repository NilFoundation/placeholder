#define BOOST_TEST_MODULE big_integer_test

#include <boost/test/unit_test.hpp>

#include <utility>

#include <boost/random/uniform_int_distribution.hpp>

#include "nil/crypto3/multiprecision/big_integer/literals.hpp"
#include "nil/crypto3/multiprecision/big_integer/modular/modular_big_integer.hpp"

using namespace nil::crypto3::multiprecision;
using namespace nil::crypto3::multiprecision::literals;

BOOST_AUTO_TEST_SUITE(big_integer_smoke_tests)

constexpr auto mod = 0x123_big_integer315;

BOOST_AUTO_TEST_CASE(operations) {
    modular_big_integer_ct<mod> a = 2;

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

    b = -b;
    b = +b;
}

BOOST_AUTO_TEST_SUITE_END()
