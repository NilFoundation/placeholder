
#define BOOST_TEST_MODULE big_integer_test

#include "nil/crypto3/multiprecision/big_integer/big_integer.hpp"

#include <boost/multiprecision/number.hpp>
#include <boost/test/unit_test.hpp>
#include <cstdint>
#include <utility>

#include "nil/crypto3/multiprecision/big_integer/cpp_int_conversions.hpp"
#include "nil/crypto3/multiprecision/big_integer/literals.hpp"

NIL_CO3_MP_DEFINE_BIG_INTEGER_LITERAL(32)
NIL_CO3_MP_DEFINE_BIG_INTEGER_LITERAL(33)
NIL_CO3_MP_DEFINE_BIG_INTEGER_LITERAL(36)
NIL_CO3_MP_DEFINE_BIG_INTEGER_LITERAL(37)
NIL_CO3_MP_DEFINE_BIG_INTEGER_LITERAL(60)
NIL_CO3_MP_DEFINE_BIG_INTEGER_LITERAL(83)
NIL_CO3_MP_DEFINE_BIG_INTEGER_LITERAL(85)
NIL_CO3_MP_DEFINE_BIG_INTEGER_LITERAL(133)

BOOST_MP_DEFINE_SIZED_CPP_INT_LITERAL(60)

using namespace nil::crypto3::multiprecision::literals;
using namespace boost::multiprecision::literals;

BOOST_AUTO_TEST_SUITE(smoke)

BOOST_AUTO_TEST_CASE(construct_constexpr) {
    constexpr nil::crypto3::multiprecision::big_integer<60> a = 0x123_big_integer60;
}

BOOST_AUTO_TEST_CASE(to_string_trivial) { BOOST_CHECK_EQUAL((0x1_big_integer60).str(), "0x1"); }

BOOST_AUTO_TEST_CASE(to_string_small) { BOOST_CHECK_EQUAL((0x20_big_integer60).str(), "0x20"); }

BOOST_AUTO_TEST_CASE(to_string_medium) {
    constexpr auto a = 0x123456789ABCDEF1234321_big_integer85;
    BOOST_CHECK_EQUAL(a.str(), "0x123456789ABCDEF1234321");
}

BOOST_AUTO_TEST_CASE(to_string_big) {
    constexpr auto a = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF000000000000000000000001_big_integer224;
    BOOST_CHECK_EQUAL(a.str(), "0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF000000000000000000000001");
}

BOOST_AUTO_TEST_CASE(ops) {
    nil::crypto3::multiprecision::big_integer<60> a = 2u, b;

    auto c1{a};
    auto c2{std::move(a)};
    auto c3{2};
    auto c4{2u};
    b = a;
    b = std::move(a);
    b = 2;
    b = 2u;

#define TEST_BINARY_OP(op) \
    do {                   \
        b = 32u;           \
        a = 4;             \
        b = a op a;        \
        /* b = 2 op a; */  \
        /* b = a op 2; */  \
        /* b = 2u op a; */ \
        /* b = a op 2u; */ \
        b = 32u;           \
        b op## = a;        \
        /* b op## = 2; */  \
        /*b op## = 2u; */  \
    } while (false)

    TEST_BINARY_OP(+);
    ++b;
    b++;
    b = +b;

    TEST_BINARY_OP(-);
    --b;
    b--;
    // b = -b;

    TEST_BINARY_OP(%);
    TEST_BINARY_OP(/);
    TEST_BINARY_OP(*);

    TEST_BINARY_OP(&);
    TEST_BINARY_OP(|);
    TEST_BINARY_OP(^);

    b = ~a;
}

BOOST_AUTO_TEST_SUITE_END()

BOOST_AUTO_TEST_SUITE(cpp_int_conversion)

BOOST_AUTO_TEST_CASE(to_cpp_int) {
    BOOST_CHECK_EQUAL(nil::crypto3::multiprecision::to_cpp_int(0xFFFFFFFFFFF_big_integer60).str(),
                      "17592186044415");
}

BOOST_AUTO_TEST_CASE(from_cpp_int) {
    auto result = nil::crypto3::multiprecision::to_big_integer(0xFFFFFFFFFFF_cppui60);
    BOOST_CHECK_EQUAL(result, 0xFFFFFFFFFFF_big_integer60);
}

BOOST_AUTO_TEST_SUITE_END()

BOOST_AUTO_TEST_SUITE(addition)

BOOST_AUTO_TEST_CASE(simple) {
    BOOST_CHECK_EQUAL(0x2_big_integer60 + 0x3_big_integer60, 0x5_big_integer60);
}

BOOST_AUTO_TEST_CASE(does_not_wrap) {
    BOOST_CHECK_EQUAL(0xFFFFFFFF_big_integer32 + 0x2_big_integer32, 0x100000001_big_integer33);
}

BOOST_AUTO_TEST_CASE(does_not_wrap_rev) {
    BOOST_CHECK_EQUAL(0x2_big_integer32 + 0xFFFFFFFF_big_integer32, 0x100000001_big_integer33);
}

BOOST_AUTO_TEST_CASE(multilimb) {
    BOOST_CHECK_EQUAL(0xAFFFFFFFF_big_integer36 + 0x2_big_integer36, 0xB00000001_big_integer36);
}

BOOST_AUTO_TEST_CASE(multilimb_rev) {
    BOOST_CHECK_EQUAL(0x2_big_integer36 + 0xAFFFFFFFF_big_integer36, 0xB00000001_big_integer36);
}

BOOST_AUTO_TEST_SUITE_END()

BOOST_AUTO_TEST_SUITE(multiplication)

BOOST_AUTO_TEST_CASE(simple) {
    BOOST_CHECK_EQUAL(0x2_big_integer60 * 0x3_big_integer60, 0x6_big_integer60);
}

BOOST_AUTO_TEST_CASE(wraps) {
    BOOST_CHECK_EQUAL(0xFFFFFFFF_big_integer32 * 0x2_big_integer32, 0x1FFFFFFFE_big_integer33);
}

BOOST_AUTO_TEST_CASE(multilimb) {
    BOOST_CHECK_EQUAL(0xAFFFFFFFF_big_integer36 * 0x2_big_integer36, 0x15FFFFFFFE_big_integer37);
}

BOOST_AUTO_TEST_SUITE_END()

BOOST_AUTO_TEST_SUITE(division)

BOOST_AUTO_TEST_CASE(simple) {
    BOOST_CHECK_EQUAL(0x7_big_integer60 / 0x2_big_integer60, 0x3_big_integer60);
}

BOOST_AUTO_TEST_CASE(multilimb) {
    BOOST_CHECK_EQUAL(0xFFFFFFFF_big_integer36 / 0x2_big_integer36, 0x7FFFFFFF_big_integer36);
}

BOOST_AUTO_TEST_CASE(failing_small) {
    BOOST_CHECK_EQUAL(0x442a8c9973ac96aec_big_integer / 0x1874dfece1887_big_integer,
                      0x2c988_big_integer);
}

BOOST_AUTO_TEST_CASE(big) {
    BOOST_CHECK_EQUAL(
        0x1BDC9C98EE1BE3D7952E78252011D4D4D5_big_integer133 / 0x7DDD38BA708356E41324F_big_integer83,
        0x38AB4C1B9E373_big_integer133);
}

BOOST_AUTO_TEST_SUITE_END()

BOOST_AUTO_TEST_SUITE(modulus)

BOOST_AUTO_TEST_CASE(simple) {
    BOOST_CHECK_EQUAL(0x7_big_integer60 % 0x4_big_integer60, 0x3_big_integer60);
}

BOOST_AUTO_TEST_CASE(multilimb) {
    BOOST_CHECK_EQUAL(0xFFFFFFFF_big_integer36 % 0x7_big_integer36, 0x3_big_integer36);
}

BOOST_AUTO_TEST_CASE(failing) {
    BOOST_CHECK_EQUAL(
        0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001_big_integer256 % 2, 1u);
}

BOOST_AUTO_TEST_CASE(failing2) {
    BOOST_CHECK_EQUAL(
        0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001_big_integer256 %
            0x200000000_big_integer,
        0x100000001_big_integer);
}

BOOST_AUTO_TEST_CASE(failing3) {
    BOOST_CHECK_EQUAL(0xFFFFFFFFFFFFFFFFFFFFFFFF_big_integer % 0x100000000FFFFFFFF_big_integer,
                      0x1fffffffe_big_integer);
}

BOOST_AUTO_TEST_CASE(big) {
    BOOST_CHECK_EQUAL(
        0x1BDC9C98EE1BE3D7952E78252011D4D4D5_big_integer133 % 0x7DDD38BA708356E41324F_big_integer83,
        0xE60EDD894AC4D0D82E58_big_integer133);
}

BOOST_AUTO_TEST_SUITE_END()

BOOST_AUTO_TEST_SUITE(convert)

BOOST_AUTO_TEST_CASE(to_uint64_t) {
    std::uint64_t a = static_cast<std::uint64_t>(0x123456789ABCDEF_big_integer64);
    BOOST_CHECK_EQUAL(a, 0x123456789ABCDEF);
}

BOOST_AUTO_TEST_CASE(from_uint64_t) {
    nil::crypto3::multiprecision::big_integer<64> a =
        static_cast<std::uint64_t>(0x123456789ABCDEFull);
    BOOST_CHECK_EQUAL(a, 0x123456789ABCDEF_big_integer64);
}

BOOST_AUTO_TEST_CASE(from_int64_t) {
    nil::crypto3::multiprecision::big_integer<64> a =
        static_cast<std::int64_t>(0x123456789ABCDEFull);
    BOOST_CHECK_EQUAL(a, 0x123456789ABCDEF_big_integer64);
}

BOOST_AUTO_TEST_SUITE_END()