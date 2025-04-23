//---------------------------------------------------------------------------//
// Copyright (c) 2024 Andrey Nefedov <ioxid@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#define BOOST_TEST_MODULE big_uint_basic_test

#include <boost/test/unit_test.hpp>

#include <array>
#include <cstdint>
#include <ios>
#include <iterator>
#include <stdexcept>
#include <tuple>
#include <utility>
#include <vector>

#include "nil/crypto3/multiprecision/big_uint.hpp"
#include "nil/crypto3/multiprecision/literals.hpp"
#include "nil/crypto3/multiprecision/pow.hpp"

NIL_CO3_MP_DEFINE_BIG_UINT_LITERAL(9)
NIL_CO3_MP_DEFINE_BIG_UINT_LITERAL(32)
NIL_CO3_MP_DEFINE_BIG_UINT_LITERAL(33)
NIL_CO3_MP_DEFINE_BIG_UINT_LITERAL(36)
NIL_CO3_MP_DEFINE_BIG_UINT_LITERAL(37)
NIL_CO3_MP_DEFINE_BIG_UINT_LITERAL(60)
NIL_CO3_MP_DEFINE_BIG_UINT_LITERAL(83)
NIL_CO3_MP_DEFINE_BIG_UINT_LITERAL(85)
NIL_CO3_MP_DEFINE_BIG_UINT_LITERAL(133)

using namespace nil::crypto3::multiprecision;

BOOST_AUTO_TEST_SUITE(smoke)

BOOST_AUTO_TEST_CASE(construct_constexpr) { constexpr big_uint<60> a = 0x123_big_uint60; }

BOOST_AUTO_TEST_CASE(to_string_zero) { BOOST_CHECK_EQUAL((0x0_big_uint60).str(), "0x0"); }

BOOST_AUTO_TEST_CASE(to_string_trivial) {
    BOOST_CHECK_EQUAL((0x1_big_uint60).str(), "0x1");
}

BOOST_AUTO_TEST_CASE(to_string_small) {
    BOOST_CHECK_EQUAL((0x20_big_uint60).str(), "0x20");
}

BOOST_AUTO_TEST_CASE(to_string_medium) {
    constexpr auto a = 0x123456789ABCDEF1234321_big_uint85;
    BOOST_CHECK_EQUAL(a.str(), "0x123456789ABCDEF1234321");
}

BOOST_AUTO_TEST_CASE(to_string_big) {
    constexpr auto a =
        0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF000000000000000000000001_big_uint224;
    BOOST_CHECK_EQUAL(a.str(),
                      "0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF000000000000000000000001");
}

BOOST_AUTO_TEST_CASE(to_string_decimal_zero) {
    BOOST_CHECK_EQUAL((0x0_big_uint60).str(std::ios_base::dec), "0");
}

BOOST_AUTO_TEST_CASE(to_string_decimal_trivial) {
    BOOST_CHECK_EQUAL((0x1_big_uint60).str(std::ios_base::dec), "1");
}

BOOST_AUTO_TEST_CASE(to_string_decimal_small) {
    BOOST_CHECK_EQUAL((0x20_big_uint60).str(std::ios_base::dec), "32");
}

BOOST_AUTO_TEST_CASE(to_string_decimal_medium) {
    constexpr auto a = 0x123456789ABCDEF1234321_big_uint85;
    BOOST_CHECK_EQUAL(a.str(std::ios_base::dec), "22007822920628982396437281");
}

BOOST_AUTO_TEST_CASE(to_string_decimal_big) {
    constexpr auto a =
        0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF000000000000000000000001_big_uint224;
    BOOST_CHECK_EQUAL(
        a.str(std::ios_base::dec),
        "26959946667150639794667015087019630673557916260026308143510066298881");
}

BOOST_AUTO_TEST_CASE(to_string_format_flags) {
    BOOST_CHECK_EQUAL(1002_big_uint64 .str(), "0x3EA");
    BOOST_CHECK_EQUAL(1002_big_uint64 .str(std::ios_base::hex), "3ea");
    BOOST_CHECK_EQUAL(1002_big_uint64 .str(std::ios_base::hex | std::ios_base::showbase),
                      "0x3ea");
    BOOST_CHECK_EQUAL(1002_big_uint64 .str(std::ios_base::hex | std::ios_base::uppercase),
                      "3EA");
    BOOST_CHECK_EQUAL(1002_big_uint64 .str(std::ios_base::hex | std::ios_base::showbase |
                                           std::ios_base::uppercase),
                      "0x3EA");
    BOOST_CHECK_EQUAL(1002_big_uint64 .str(std::ios_base::dec), "1002");
    BOOST_CHECK_EQUAL(1002_big_uint64 .str(std::ios_base::dec | std::ios_base::showbase),
                      "1002");
}

BOOST_AUTO_TEST_CASE(ops) {
    big_uint<60> a = 2u, b;

    auto c1{a};
    auto c2{std::move(a)};  // NOLINT
    auto c3{2};
    auto c4{2u};
    b = a;
    b = std::move(a);  // NOLINT
    b = 2;
    b = 2u;

#define TEST_BINARY_OP(op) \
    do {                   \
        b = 32u;           \
        a = 30;            \
        b = a op a;        \
        b = 200 op a;      \
        b = a op 20;       \
        b = 200u op a;     \
        b = a op 20u;      \
        b = 36u;           \
        b op## = a;        \
        b op## = 2;        \
        b op## = 2u;       \
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
#undef TEST_BINARY_OP

    b = ~a;
}

BOOST_AUTO_TEST_SUITE_END()

BOOST_AUTO_TEST_SUITE(addition)

BOOST_AUTO_TEST_CASE(simple) {
    BOOST_CHECK_EQUAL(0x2_big_uint60 + 0x3_big_uint60, 0x5_big_uint60);
}

BOOST_AUTO_TEST_CASE(overflow_throws) {
    BOOST_CHECK_THROW(0xFFFFFFFF_big_uint32 + 0x2_big_uint32, std::overflow_error);
}

BOOST_AUTO_TEST_CASE(overflow_throws_rev) {
    BOOST_CHECK_THROW(0x2_big_uint32 + 0xFFFFFFFF_big_uint32, std::overflow_error);
}

BOOST_AUTO_TEST_CASE(multilimb) {
    BOOST_CHECK_EQUAL(0xAFFFFFFFF_big_uint36 + 0x2_big_uint36, 0xB00000001_big_uint36);
}

BOOST_AUTO_TEST_CASE(multilimb_rev) {
    BOOST_CHECK_EQUAL(0x2_big_uint36 + 0xAFFFFFFFF_big_uint36, 0xB00000001_big_uint36);
}

BOOST_AUTO_TEST_SUITE_END()

BOOST_AUTO_TEST_SUITE(multiplication)

BOOST_AUTO_TEST_CASE(simple) {
    BOOST_CHECK_EQUAL(0x2_big_uint60 * 0x3_big_uint60, 0x6_big_uint60);
}

BOOST_AUTO_TEST_CASE(multilimb) {
    BOOST_CHECK_EQUAL(0xAFFFFFFFF_big_uint37 * 0x2_big_uint37, 0x15FFFFFFFE_big_uint37);
}

BOOST_AUTO_TEST_CASE(overflow_throws) {
    BOOST_CHECK_THROW(0xFFFFFFFF_big_uint32 * 0x2_big_uint32, std::overflow_error);
}

BOOST_AUTO_TEST_CASE(multilimb_overflow_throws) {
    BOOST_CHECK_THROW(0xAFFFFFFFF_big_uint36 * 0x2_big_uint36, std::overflow_error);
}

BOOST_AUTO_TEST_SUITE_END()

BOOST_AUTO_TEST_SUITE(division)

BOOST_AUTO_TEST_CASE(simple) {
    BOOST_CHECK_EQUAL(0x7_big_uint60 / 0x2_big_uint60, 0x3_big_uint60);
}

BOOST_AUTO_TEST_CASE(multilimb) {
    BOOST_CHECK_EQUAL(0xFFFFFFFF_big_uint36 / 0x2_big_uint36, 0x7FFFFFFF_big_uint36);
}

BOOST_AUTO_TEST_CASE(failing_small) {
    BOOST_CHECK_EQUAL(0x442a8c9973ac96aec_big_uint / 0x1874dfece1887_big_uint,
                      0x2c988_big_uint);
}

BOOST_AUTO_TEST_CASE(big) {
    BOOST_CHECK_EQUAL(0x1BDC9C98EE1BE3D7952E78252011D4D4D5_big_uint133 /
                          0x7DDD38BA708356E41324F_big_uint83,
                      0x38AB4C1B9E373_big_uint133);
}

BOOST_AUTO_TEST_SUITE_END()

BOOST_AUTO_TEST_SUITE(modulus)

BOOST_AUTO_TEST_CASE(simple) {
    BOOST_CHECK_EQUAL(0x7_big_uint60 % 0x4_big_uint60, 0x3_big_uint60);
}

BOOST_AUTO_TEST_CASE(multilimb) {
    BOOST_CHECK_EQUAL(0xFFFFFFFF_big_uint36 % 0x7_big_uint36, 0x3_big_uint36);
}

BOOST_AUTO_TEST_CASE(failing) {
    BOOST_CHECK_EQUAL(
        0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001_big_uint256 %
            2u,
        1u);
}

BOOST_AUTO_TEST_CASE(failing2) {
    BOOST_CHECK_EQUAL(
        0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001_big_uint256 %
            0x200000000_big_uint,
        0x100000001_big_uint);
}

BOOST_AUTO_TEST_CASE(failing3) {
    BOOST_CHECK_EQUAL(0xFFFFFFFFFFFFFFFFFFFFFFFF_big_uint % 0x100000000FFFFFFFF_big_uint,
                      0x1fffffffe_big_uint);
}

BOOST_AUTO_TEST_CASE(big) {
    BOOST_CHECK_EQUAL(0x1BDC9C98EE1BE3D7952E78252011D4D4D5_big_uint133 %
                          0x7DDD38BA708356E41324F_big_uint83,
                      0xE60EDD894AC4D0D82E58_big_uint133);
}

BOOST_AUTO_TEST_SUITE_END()

BOOST_AUTO_TEST_SUITE(convert)

BOOST_AUTO_TEST_CASE(to_uint64_t) {
    std::uint64_t a = static_cast<std::uint64_t>(0x123456789ABCDEF_big_uint64);
    BOOST_CHECK_EQUAL(a, 0x123456789ABCDEF);
}

BOOST_AUTO_TEST_CASE(from_uint64_t) {
    big_uint<64> a = static_cast<std::uint64_t>(0x123456789ABCDEFull);
    BOOST_CHECK_EQUAL(a, 0x123456789ABCDEF_big_uint64);
}

BOOST_AUTO_TEST_CASE(from_int64_t) {
    big_uint<64> a = static_cast<std::int64_t>(0x123456789ABCDEFull);
    BOOST_CHECK_EQUAL(a, 0x123456789ABCDEF_big_uint64);
}

BOOST_AUTO_TEST_SUITE_END()

BOOST_AUTO_TEST_SUITE(truncation)

BOOST_AUTO_TEST_CASE(conversion_to_shorter_number) {
    using standart_number = big_uint<256>;
    using short_number = big_uint<128>;
    constexpr standart_number x =
        0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f_big_uint256;
    short_number s = x.truncate<128>();
    // 2nd half of the number must stay.
    BOOST_CHECK_EQUAL(s, 0xfffffffffffffffffffffffefffffc2f_big_uint128);
}

BOOST_AUTO_TEST_SUITE_END()

using big_uint_types =
    std::tuple<big_uint<7>, big_uint<16>, big_uint<32>, big_uint<64>, big_uint<256>>;

using int_types = std::tuple<std::int8_t, std::int16_t, std::int32_t, std::int64_t,  //
                             std::uint8_t, std::uint16_t, std::uint32_t, uint64_t,   //
                             big_uint<7>>;

using unsigned_builtin_types =
    std::tuple<std::uint8_t, std::uint16_t, std::uint32_t, std::uint64_t>;

using signed_types = std::tuple<std::int8_t, std::int16_t, std::int32_t, std::int64_t>;

BOOST_AUTO_TEST_SUITE(assignment)

BOOST_AUTO_TEST_CASE_TEMPLATE(assignment_signed, T, signed_types) {
    BOOST_CHECK_EQUAL(big_uint<7>(static_cast<T>(2)), 2_big_uint7);
    BOOST_CHECK_THROW(big_uint<7>(static_cast<T>(-1)), std::range_error);
    BOOST_CHECK_THROW(big_uint<7>(static_cast<T>(128)), std::range_error);
    BOOST_CHECK_THROW(big_uint<7>(static_cast<T>(129)), std::range_error);
    big_uint<7> n;
    BOOST_CHECK_EQUAL(n = static_cast<T>(2), 2_big_uint7);
    BOOST_CHECK_THROW(n = static_cast<T>(-1), std::range_error);
    BOOST_CHECK_THROW(n = static_cast<T>(128), std::range_error);
}

BOOST_AUTO_TEST_CASE_TEMPLATE(assignment_unsigned, T, unsigned_builtin_types) {
    BOOST_CHECK_EQUAL(big_uint<7>(static_cast<T>(2)), 2_big_uint7);
    BOOST_CHECK_THROW(big_uint<7>(static_cast<T>(128)), std::range_error);
    BOOST_CHECK_THROW(big_uint<7>(static_cast<T>(129)), std::range_error);
    big_uint<7> n;
    BOOST_CHECK_EQUAL(n = static_cast<T>(2), 2_big_uint7);
    BOOST_CHECK_THROW(n = static_cast<T>(128), std::range_error);
}

BOOST_AUTO_TEST_SUITE_END()

BOOST_AUTO_TEST_SUITE(checked_operations)

BOOST_AUTO_TEST_CASE_TEMPLATE(addition_positive, T, int_types) {
    BOOST_CHECK_EQUAL(20_big_uint7 + static_cast<T>(10), 30_big_uint7);
    BOOST_CHECK_EQUAL(static_cast<T>(10) + 20_big_uint7, 30_big_uint7);
    BOOST_CHECK_THROW(120_big_uint7 + static_cast<T>(10), std::overflow_error);
    BOOST_CHECK_THROW(static_cast<T>(10) + 120_big_uint7, std::overflow_error);
}

BOOST_AUTO_TEST_CASE_TEMPLATE(addition_negative, T, signed_types) {
    BOOST_CHECK_EQUAL(20_big_uint7 + static_cast<T>(-5), 15_big_uint7);
    BOOST_CHECK_EQUAL(static_cast<T>(-5) + 20_big_uint7, 15_big_uint7);
    BOOST_CHECK_THROW(5_big_uint7 + static_cast<T>(-20), std::overflow_error);
    BOOST_CHECK_THROW(static_cast<T>(-20) + 5_big_uint7, std::overflow_error);
}

BOOST_AUTO_TEST_CASE(addition_small_big_uint_overflow) {
    BOOST_CHECK_THROW(2_big_uint7 + 127ull, std::overflow_error);
    BOOST_CHECK_THROW(127ull + 2_big_uint7, std::overflow_error);
    BOOST_CHECK_THROW(2_big_uint7 + 0x40000000000000ull, std::overflow_error);
    BOOST_CHECK_THROW(0x40000000000000ull + 2_big_uint7, std::overflow_error);
    big_uint<7> a = 2;
    BOOST_CHECK_THROW(a += 127_big_uint7, std::overflow_error);
}

BOOST_AUTO_TEST_CASE(unary_plus) {
    BOOST_CHECK_EQUAL(+20_big_uint7, 20_big_uint7);
    BOOST_CHECK_EQUAL(+0_big_uint7, 0_big_uint7);
}

BOOST_AUTO_TEST_CASE_TEMPLATE(subtraction_positive, T, int_types) {
    BOOST_CHECK_THROW(0_big_uint7 - static_cast<T>(1), std::overflow_error);
    BOOST_CHECK_THROW(static_cast<T>(0) - 1_big_uint7, std::overflow_error);
    BOOST_CHECK_EQUAL(20_big_uint7 - static_cast<T>(5), 15_big_uint7);
    BOOST_CHECK_EQUAL(static_cast<T>(20) - 5_big_uint7, 15_big_uint7);
    BOOST_CHECK_THROW(5_big_uint7 - static_cast<T>(20), std::overflow_error);
    BOOST_CHECK_THROW(static_cast<T>(5) - 20_big_uint7, std::overflow_error);
}

BOOST_AUTO_TEST_CASE_TEMPLATE(subtraction_negative, T, signed_types) {
    BOOST_CHECK_EQUAL(0_big_uint7 - static_cast<T>(-1), 1_big_uint7);
    BOOST_CHECK_THROW(static_cast<T>(-1) - 0_big_uint7, std::range_error);
    BOOST_CHECK_EQUAL(20_big_uint7 - static_cast<T>(-10), 30_big_uint7);
    BOOST_CHECK_THROW(120_big_uint7 - static_cast<T>(-10), std::overflow_error);
    BOOST_CHECK_THROW(static_cast<T>(-10) - 5_big_uint7, std::range_error);
}

BOOST_AUTO_TEST_CASE_TEMPLATE(multiplication_positive, T, int_types) {
    BOOST_CHECK_EQUAL(20_big_uint7 * static_cast<T>(2), 40_big_uint7);
    BOOST_CHECK_EQUAL(static_cast<T>(2) * 20_big_uint7, 40_big_uint7);
    BOOST_CHECK_THROW(70_big_uint7 * static_cast<T>(2), std::overflow_error);
    BOOST_CHECK_THROW(static_cast<T>(2) * 70_big_uint7, std::overflow_error);
}

BOOST_AUTO_TEST_CASE_TEMPLATE(multiplication_negative, T, signed_types) {
    BOOST_CHECK_THROW(20_big_uint7 * static_cast<T>(-2), std::range_error);
    BOOST_CHECK_THROW(static_cast<T>(-2) * 20_big_uint7, std::range_error);
    BOOST_CHECK_THROW(70_big_uint7 * static_cast<T>(-2), std::range_error);
    BOOST_CHECK_THROW(static_cast<T>(-2) * 70_big_uint7, std::range_error);
}

BOOST_AUTO_TEST_CASE_TEMPLATE(division_positive, T, int_types) {
    BOOST_CHECK_EQUAL(21_big_uint7 / static_cast<T>(5), 4_big_uint7);
    BOOST_CHECK_EQUAL(static_cast<T>(21) / 5_big_uint7, 4_big_uint7);
}

BOOST_AUTO_TEST_CASE_TEMPLATE(division_negative, T, signed_types) {
    BOOST_CHECK_THROW(21_big_uint7 / static_cast<T>(-5), std::range_error);
    BOOST_CHECK_THROW(static_cast<T>(-21) / 5_big_uint7, std::range_error);
}

BOOST_AUTO_TEST_CASE_TEMPLATE(division_zero, T, int_types) {
    BOOST_CHECK_EQUAL(0_big_uint7 / static_cast<T>(5), 0_big_uint7);
    BOOST_CHECK_EQUAL(static_cast<T>(0) / 5_big_uint7, 0_big_uint7);
    BOOST_CHECK_THROW(21_big_uint7 / static_cast<T>(0), std::overflow_error);
    BOOST_CHECK_THROW(static_cast<T>(21) / 0_big_uint7, std::overflow_error);
}

BOOST_AUTO_TEST_CASE_TEMPLATE(modulus_positive, T, int_types) {
    BOOST_CHECK_EQUAL(21_big_uint7 % static_cast<T>(5), 1_big_uint7);
    BOOST_CHECK_EQUAL(static_cast<T>(21) % 5_big_uint7, 1_big_uint7);
}

BOOST_AUTO_TEST_CASE_TEMPLATE(modulus_negative, T, signed_types) {
    BOOST_CHECK_THROW(21_big_uint7 % static_cast<T>(-5), std::range_error);
    BOOST_CHECK_THROW(static_cast<T>(-21) % 5_big_uint7, std::range_error);
}

BOOST_AUTO_TEST_CASE_TEMPLATE(modulus_zero, T, int_types) {
    BOOST_CHECK_THROW(21_big_uint7 % static_cast<T>(0), std::overflow_error);
    BOOST_CHECK_THROW(static_cast<T>(21) % 0_big_uint7, std::overflow_error);
}

BOOST_AUTO_TEST_SUITE_END()

BOOST_AUTO_TEST_SUITE(wrapping_operations)

BOOST_AUTO_TEST_CASE_TEMPLATE(addition_positive, T, int_types) {
    BOOST_CHECK_EQUAL(wrapping_add(20_big_uint7, static_cast<T>(10)), 30_big_uint7);
    BOOST_CHECK_EQUAL(wrapping_add(static_cast<T>(10), 20_big_uint7), 30_big_uint7);
    BOOST_CHECK_EQUAL(wrapping_add(120_big_uint7, static_cast<T>(10)), 2_big_uint7);
    BOOST_CHECK_EQUAL(wrapping_add(static_cast<T>(10), 120_big_uint7), 2_big_uint7);
}

BOOST_AUTO_TEST_CASE_TEMPLATE(addition_negative, T, signed_types) {
    BOOST_CHECK_EQUAL(wrapping_add(20_big_uint7, static_cast<T>(-5)), 15_big_uint7);
    BOOST_CHECK_EQUAL(wrapping_add(static_cast<T>(-5), 20_big_uint7), 15_big_uint7);
    BOOST_CHECK_EQUAL(wrapping_add(5_big_uint7, static_cast<T>(-20)), 113_big_uint7);
    BOOST_CHECK_EQUAL(wrapping_add(static_cast<T>(-20), 5_big_uint7), 113_big_uint7);
}

BOOST_AUTO_TEST_CASE(wrapping_neg) {
    BOOST_CHECK_EQUAL(20_big_uint7 .wrapping_neg(), 108_big_uint7);
    BOOST_CHECK_EQUAL(0_big_uint7 .wrapping_neg(), 0_big_uint7);
}

BOOST_AUTO_TEST_CASE_TEMPLATE(subtraction_positive, T, int_types) {
    BOOST_CHECK_EQUAL(wrapping_sub(0_big_uint7, 1), 127_big_uint7);
    BOOST_CHECK_EQUAL(wrapping_sub(0, 1_big_uint7), 127_big_uint7);
    BOOST_CHECK_EQUAL(wrapping_sub(20_big_uint7, static_cast<T>(5)), 15_big_uint7);
    BOOST_CHECK_EQUAL(wrapping_sub(static_cast<T>(20), 5_big_uint7), 15_big_uint7);
    BOOST_CHECK_EQUAL(wrapping_sub(5_big_uint7, static_cast<T>(20)), 113_big_uint7);
    BOOST_CHECK_EQUAL(wrapping_sub(static_cast<T>(5), 20_big_uint7), 113_big_uint7);
}

BOOST_AUTO_TEST_CASE_TEMPLATE(subtraction_negative, T, signed_types) {
    BOOST_CHECK_EQUAL(wrapping_sub(0_big_uint7, -1), 1_big_uint7);
    BOOST_CHECK_EQUAL(wrapping_sub(-1, 0_big_uint7), 127_big_uint7);
    BOOST_CHECK_EQUAL(wrapping_sub(20_big_uint7, static_cast<T>(-10)), 30_big_uint7);
    BOOST_CHECK_EQUAL(wrapping_sub(static_cast<T>(-10), 20_big_uint7), 98_big_uint7);
    BOOST_CHECK_EQUAL(wrapping_sub(120_big_uint7, static_cast<T>(-10)), 2_big_uint7);
    BOOST_CHECK_EQUAL(wrapping_sub(static_cast<T>(-10), 120_big_uint7), 126_big_uint7);
}

BOOST_AUTO_TEST_CASE_TEMPLATE(multiplication_positive, T, int_types) {
    BOOST_CHECK_EQUAL(wrapping_mul(20_big_uint7, static_cast<T>(2)), 40_big_uint7);
    BOOST_CHECK_EQUAL(wrapping_mul(static_cast<T>(2), 20_big_uint7), 40_big_uint7);
    BOOST_CHECK_EQUAL(wrapping_mul(70_big_uint7, static_cast<T>(2)), 12_big_uint7);
    BOOST_CHECK_EQUAL(wrapping_mul(static_cast<T>(2), 70_big_uint7), 12_big_uint7);
}

BOOST_AUTO_TEST_CASE_TEMPLATE(multiplication_negative, T, signed_types) {
    BOOST_CHECK_EQUAL(wrapping_mul(20_big_uint7, static_cast<T>(-2)), 88_big_uint7);
    BOOST_CHECK_EQUAL(wrapping_mul(static_cast<T>(-2), 20_big_uint7), 88_big_uint7);
    BOOST_CHECK_EQUAL(wrapping_mul(70_big_uint7, static_cast<T>(-2)), 116_big_uint7);
    BOOST_CHECK_EQUAL(wrapping_mul(static_cast<T>(-2), 70_big_uint7), 116_big_uint7);
}

BOOST_AUTO_TEST_SUITE_END()

BOOST_AUTO_TEST_CASE(overflowing_add_assign_test) {
    auto n = 122_big_uint7;
    BOOST_CHECK_EQUAL(overflowing_add_assign(n, 4_big_uint7), false);
    BOOST_CHECK_EQUAL(overflowing_add_assign(n, 4_big_uint7), true);
    BOOST_CHECK_THROW((void)overflowing_add_assign(n, 0x100_big_uint9),
                      std::overflow_error);
}

BOOST_AUTO_TEST_SUITE(bit_operations)

BOOST_AUTO_TEST_CASE_TEMPLATE(and_positive, T, int_types) {
    BOOST_CHECK_EQUAL(21_big_uint7 & static_cast<T>(7), 5_big_uint7);
    BOOST_CHECK_EQUAL(static_cast<T>(7) & 21_big_uint7, 5_big_uint7);
}

BOOST_AUTO_TEST_CASE_TEMPLATE(and_negative, T, signed_types) {
    BOOST_CHECK_THROW(21_big_uint7 & static_cast<T>(-7), std::range_error);
    BOOST_CHECK_THROW(static_cast<T>(-7) & 21_big_uint7, std::range_error);
}

BOOST_AUTO_TEST_CASE_TEMPLATE(or_positive, T, int_types) {
    BOOST_CHECK_EQUAL(21_big_uint7 | static_cast<T>(7), 23_big_uint7);
    BOOST_CHECK_EQUAL(static_cast<T>(7) | 21_big_uint7, 23_big_uint7);
}

BOOST_AUTO_TEST_CASE_TEMPLATE(or_negative, T, signed_types) {
    BOOST_CHECK_THROW(21_big_uint7 | static_cast<T>(-7), std::range_error);
    BOOST_CHECK_THROW(static_cast<T>(-7) | 21_big_uint7, std::range_error);
}

BOOST_AUTO_TEST_CASE_TEMPLATE(xor_positive, T, int_types) {
    BOOST_CHECK_EQUAL(21_big_uint7 ^ static_cast<T>(7), 18_big_uint7);
    BOOST_CHECK_EQUAL(static_cast<T>(7) ^ 21_big_uint7, 18_big_uint7);
}

BOOST_AUTO_TEST_CASE_TEMPLATE(xor_negative, T, signed_types) {
    BOOST_CHECK_THROW(21_big_uint7 ^ static_cast<T>(-7), std::range_error);
    BOOST_CHECK_THROW(static_cast<T>(-7) ^ 21_big_uint7, std::range_error);
}

BOOST_AUTO_TEST_CASE(complement) {
    BOOST_CHECK_EQUAL(~21_big_uint7, 106_big_uint7);
    BOOST_CHECK_EQUAL(~0_big_uint7, 127_big_uint7);
}

BOOST_AUTO_TEST_CASE(shift_left) {
    BOOST_CHECK_EQUAL(21_big_uint7 << 1, 42_big_uint7);
    BOOST_CHECK_EQUAL(21_big_uint7 << 3, 40_big_uint7);
    BOOST_CHECK_EQUAL(21_big_uint7 << 5, 32_big_uint7);
    BOOST_CHECK_EQUAL(21_big_uint7 << 7, 0_big_uint7);
    BOOST_CHECK_EQUAL(21_big_uint7 << 0, 21_big_uint7);
    BOOST_CHECK_THROW(21_big_uint7 << -1, std::range_error);
}

BOOST_AUTO_TEST_CASE(shift_right) {
    BOOST_CHECK_EQUAL(21_big_uint7 >> 1, 10_big_uint7);
    BOOST_CHECK_EQUAL(21_big_uint7 >> 3, 2_big_uint7);
    BOOST_CHECK_EQUAL(21_big_uint7 >> 5, 0_big_uint7);
    BOOST_CHECK_EQUAL(21_big_uint7 >> 7, 0_big_uint7);
    BOOST_CHECK_EQUAL(21_big_uint7 >> 0, 21_big_uint7);
    BOOST_CHECK_THROW(21_big_uint7 >> -1, std::range_error);
}

BOOST_AUTO_TEST_CASE(bit_set) {
    auto n = 21_big_uint7;
    n.bit_set(6);
    BOOST_CHECK_EQUAL(n, 85_big_uint7);
    n.bit_set(6);
    BOOST_CHECK_EQUAL(n, 85_big_uint7);
}

BOOST_AUTO_TEST_CASE(bit_flip) {
    auto n = 21_big_uint7;
    n.bit_flip(6);
    BOOST_CHECK_EQUAL(n, 85_big_uint7);
    n.bit_flip(6);
    BOOST_CHECK_EQUAL(n, 21_big_uint7);
}

BOOST_AUTO_TEST_CASE(bit_unset) {
    auto n = 21_big_uint7;
    n.bit_unset(0);
    BOOST_CHECK_EQUAL(n, 20_big_uint7);
    n.bit_unset(0);
    BOOST_CHECK_EQUAL(n, 20_big_uint7);
}

BOOST_AUTO_TEST_CASE(bit_test) {
    BOOST_CHECK_EQUAL(21_big_uint7 .bit_test(0), true);
    BOOST_CHECK_EQUAL(21_big_uint7 .bit_test(1), false);
    BOOST_CHECK_EQUAL(21_big_uint7 .bit_test(2), true);
    BOOST_CHECK_EQUAL(21_big_uint7 .bit_test(3), false);
    BOOST_CHECK_EQUAL(21_big_uint7 .bit_test(4), true);
    BOOST_CHECK_EQUAL(21_big_uint7 .bit_test(5), false);
}

BOOST_AUTO_TEST_CASE(msb) {
    BOOST_CHECK_EQUAL(21_big_uint7 .msb(), 4);
    BOOST_CHECK_THROW(0_big_uint7 .msb(), std::invalid_argument);
    BOOST_CHECK_EQUAL(32_big_uint7 .msb(), 5);
    BOOST_CHECK_EQUAL(1_big_uint7 .msb(), 0);
    BOOST_CHECK_EQUAL(2_big_uint7 .msb(), 1);
}

BOOST_AUTO_TEST_CASE(lsb) {
    BOOST_CHECK_EQUAL(21_big_uint7 .lsb(), 0);
    BOOST_CHECK_THROW(0_big_uint7 .lsb(), std::invalid_argument);
    BOOST_CHECK_EQUAL(32_big_uint7 .lsb(), 5);
    BOOST_CHECK_EQUAL(1_big_uint7 .lsb(), 0);
    BOOST_CHECK_EQUAL(2_big_uint7 .lsb(), 1);
}

BOOST_AUTO_TEST_SUITE_END()

BOOST_AUTO_TEST_SUITE(comparison)

BOOST_AUTO_TEST_CASE(with_signed) {
    BOOST_CHECK(!(7_big_uint7 == -10));
    BOOST_CHECK(!(7_big_uint7 < -10));
    BOOST_CHECK(7_big_uint7 > -10);
    BOOST_CHECK(!(7_big_uint7 <= -10));
    BOOST_CHECK(7_big_uint7 >= -10);

    BOOST_CHECK(7_big_uint7 == 7);
    BOOST_CHECK(!(7_big_uint7 == 5));

    BOOST_CHECK(7_big_uint7 < 10);
    BOOST_CHECK(!(7_big_uint7 < 5));
    BOOST_CHECK(!(7_big_uint7 < 7));

    BOOST_CHECK(!(7_big_uint7 > 10));
    BOOST_CHECK(7_big_uint7 > 5);
    BOOST_CHECK(!(7_big_uint7 > 7));

    BOOST_CHECK(7_big_uint7 <= 10);
    BOOST_CHECK(!(7_big_uint7 <= 5));
    BOOST_CHECK(7_big_uint7 <= 7);

    BOOST_CHECK(!(7_big_uint7 >= 10));
    BOOST_CHECK(7_big_uint7 >= 5);
    BOOST_CHECK(7_big_uint7 >= 7);
}

BOOST_AUTO_TEST_CASE(with_unsigned) {
    BOOST_CHECK(7_big_uint7 == 7u);
    BOOST_CHECK(!(7_big_uint7 == 5u));

    BOOST_CHECK(7_big_uint7 < 10u);
    BOOST_CHECK(!(7_big_uint7 < 5u));
    BOOST_CHECK(!(7_big_uint7 < 7u));

    BOOST_CHECK(!(7_big_uint7 > 10u));
    BOOST_CHECK(7_big_uint7 > 5u);
    BOOST_CHECK(!(7_big_uint7 > 7u));

    BOOST_CHECK(7_big_uint7 <= 10u);
    BOOST_CHECK(!(7_big_uint7 <= 5u));
    BOOST_CHECK(7_big_uint7 <= 7u);

    BOOST_CHECK(!(7_big_uint7 >= 10u));
    BOOST_CHECK(7_big_uint7 >= 5u);
    BOOST_CHECK(7_big_uint7 >= 7u);
}

BOOST_AUTO_TEST_CASE(with_bool) {
    BOOST_CHECK(0_big_uint7 == false);
    BOOST_CHECK(0_big_uint7 != true);
    BOOST_CHECK(1_big_uint7 == true);
    BOOST_CHECK(1_big_uint7 != false);
    BOOST_CHECK(2_big_uint7 != false);
    BOOST_CHECK(2_big_uint7 != true);
}

BOOST_AUTO_TEST_SUITE_END()

BOOST_AUTO_TEST_CASE(powm_test) {
    BOOST_CHECK_EQUAL(powm(2_big_uint7, 4_big_uint7, 5_big_uint7), 1_big_uint7);
    BOOST_CHECK_EQUAL(powm(2_big_uint7, 4_big_uint7, 5), 1);
    BOOST_CHECK_EQUAL(powm(2_big_uint7, 4, 5_big_uint7), 1_big_uint7);
    BOOST_CHECK_EQUAL(powm(2, 4, 5), 1);
}

BOOST_AUTO_TEST_CASE(import_test) {
    big_uint<64> val;
    std::array<std::uint8_t, 8> arr1{0x12, 0x34, 0x56, 0x78, 0x90, 0xab, 0xcd, 0xef};
    val.import_bits(arr1.begin(), arr1.end(), 8, true);
    BOOST_CHECK_EQUAL(val, 0x1234567890abcdef_big_uint64);

    std::array<std::uint8_t, 8> arr2{0x12, 0x34, 0x56, 0x78, 0x90, 0xab, 0xcd, 0xef};
    val.import_bits(arr2.begin(), arr2.end(), 8, false);
    BOOST_CHECK_EQUAL(val, 0xefcdab9078563412_big_uint64);

    std::array<std::uint8_t, 1> arr3{0x01};
    val.import_bits(arr3.begin(), arr3.end(), 8, true);
    BOOST_CHECK_EQUAL(val, 0x1_big_uint64);

    std::array<std::uint8_t, 1> arr4{0x01};
    val.import_bits(arr4.begin(), arr4.end(), 8, false);
    BOOST_CHECK_EQUAL(val, 0x1_big_uint64);

    std::array<std::uint8_t, 1> arr5{0x00};
    val.import_bits(arr5.begin(), arr5.end(), 8, true);
    BOOST_CHECK_EQUAL(val, 0x0_big_uint64);

    std::array<std::uint8_t, 2> arr6{0x00, 0x00};
    val.import_bits(arr6.begin(), arr6.end(), 8, true);
    BOOST_CHECK_EQUAL(val, 0x0_big_uint64);

    std::array<std::uint8_t, 2> arr7{0x01, 0x00};
    val.import_bits(arr7.begin(), arr7.end(), 8, true);
    BOOST_CHECK_EQUAL(val, 0x100_big_uint64);

    std::array<std::uint8_t, 2> arr8{0x01, 0x00};
    val.import_bits(arr8.begin(), arr8.end(), 8, false);
    BOOST_CHECK_EQUAL(val, 0x1_big_uint64);

    std::array<std::uint8_t, 16> arr9{};
    val.import_bits(arr9.begin(), arr9.end(), 8, true);
    BOOST_CHECK_EQUAL(val, 0x0_big_uint64);
    val.import_bits(arr9.begin(), arr9.end(), 8, false);
    BOOST_CHECK_EQUAL(val, 0x0_big_uint64);
}

BOOST_AUTO_TEST_CASE(import_overflow) {
    big_uint<14> val;
    std::array<std::uint8_t, 8> arr1{0x12, 0x34, 0x56, 0x78, 0x90, 0xab, 0xcd, 0xef};
    BOOST_CHECK_THROW((val.import_bits(arr1.begin(), arr1.end(), 8, true)),
                      std::overflow_error);
    BOOST_CHECK_THROW((val.import_bits(arr1.begin(), arr1.end(), 8, false)),
                      std::overflow_error);

    std::array<std::uint8_t, 2> arr3{0xff, 0xff};
    BOOST_CHECK_THROW((val.import_bits(arr3.begin(), arr3.end(), 8, true)),
                      std::overflow_error);
    BOOST_CHECK_THROW((val.import_bits(arr3.begin(), arr3.end(), 8, false)),
                      std::overflow_error);

    big_uint<64> val2;

    std::array<std::uint64_t, 2> arr4{0xff, 0xff};
    BOOST_CHECK_THROW((val2.import_bits(arr4.begin(), arr4.end(), 64, true)),
                      std::overflow_error);
    BOOST_CHECK_THROW((val2.import_bits(arr4.begin(), arr4.end(), 64, false)),
                      std::overflow_error);
}

BOOST_AUTO_TEST_CASE(export_test) {
    big_uint<64> val = 0x1234567890abcdef_big_uint64;
    std::vector<std::uint8_t> result;

    val.export_bits(std::back_inserter(result), 8, true);
    BOOST_TEST(result == (std::vector<std::uint8_t>{0x12, 0x34, 0x56, 0x78, 0x90, 0xab,
                                                    0xcd, 0xef}),
               boost::test_tools::per_element());
    result.clear();

    val.export_bits(std::back_inserter(result), 8, false);
    BOOST_TEST(result == (std::vector<std::uint8_t>{0xef, 0xcd, 0xab, 0x90, 0x78, 0x56,
                                                    0x34, 0x12}),
               boost::test_tools::per_element());
    result.clear();

    val.export_bits(std::back_inserter(result), 4, true);
    BOOST_TEST(result == (std::vector<std::uint8_t>{0x01, 0x02, 0x03, 0x04, 0x05, 0x06,
                                                    0x07, 0x08, 0x09, 0x00, 0x0a, 0x0b,
                                                    0x0c, 0x0d, 0x0e, 0x0f}),
               boost::test_tools::per_element());
    result.clear();

    val = 0x2_big_uint64;

    val.export_bits(std::back_inserter(result), 1, true);
    BOOST_TEST(result == (std::vector<std::uint8_t>{0x01, 0x00}),
               boost::test_tools::per_element());
    result.clear();

    val.export_bits(std::back_inserter(result), 1, false);
    BOOST_TEST(result == (std::vector<std::uint8_t>{0x00, 0x01}),
               boost::test_tools::per_element());
    result.clear();
}
