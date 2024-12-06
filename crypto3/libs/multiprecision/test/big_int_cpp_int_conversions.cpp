#define BOOST_TEST_MODULE big_int_cpp_int_conversions_test

#include <boost/test/unit_test.hpp>

#include "nil/crypto3/multiprecision/cpp_int_conversions.hpp"
#include "nil/crypto3/multiprecision/literals.hpp"

NIL_CO3_MP_DEFINE_BIG_UINT_LITERAL(60)
BOOST_MP_DEFINE_SIZED_CPP_INT_LITERAL(60)

using namespace nil::crypto3::multiprecision::literals;
using namespace boost::multiprecision::literals;

BOOST_AUTO_TEST_SUITE(cpp_int_conversion)

BOOST_AUTO_TEST_CASE(to_cpp_int) {
    BOOST_CHECK_EQUAL(nil::crypto3::multiprecision::to_cpp_int(0xFFFFFFFFFFF_bigui60).str(),
                      "17592186044415");
}

BOOST_AUTO_TEST_CASE(from_cpp_int) {
    auto result = nil::crypto3::multiprecision::to_big_uint(0xFFFFFFFFFFF_cppui60);
    BOOST_CHECK_EQUAL(result, 0xFFFFFFFFFFF_bigui60);
}

BOOST_AUTO_TEST_SUITE_END()
