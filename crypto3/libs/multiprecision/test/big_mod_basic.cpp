//---------------------------------------------------------------------------//
// Copyright (c) 2024 Andrey Nefedov <ioxid@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#define BOOST_TEST_MODULE big_mod_basic_test

#include <cstdint>
#include <utility>

#include <boost/test/unit_test.hpp>

#include "nil/crypto3/multiprecision/big_mod.hpp"
#include "nil/crypto3/multiprecision/big_uint.hpp"
#include "nil/crypto3/multiprecision/literals.hpp"

using namespace nil::crypto3::multiprecision;
using namespace nil::crypto3::multiprecision::literals;

NIL_CO3_MP_DEFINE_BIG_UINT_LITERAL(2)
NIL_CO3_MP_DEFINE_BIG_UINT_LITERAL(32)
NIL_CO3_MP_DEFINE_BIG_UINT_LITERAL(36)
NIL_CO3_MP_DEFINE_BIG_UINT_LITERAL(57)
NIL_CO3_MP_DEFINE_BIG_UINT_LITERAL(60)

using namespace nil::crypto3::multiprecision::literals;

constexpr auto mod = 0x123456789ABCDEF_big_uint57;
using montgomery_big_mod_t = montgomery_big_mod<mod>;
using big_mod_t = big_mod<mod>;

BOOST_AUTO_TEST_SUITE(smoke)

BOOST_AUTO_TEST_CASE(construct_constexpr) {
    constexpr montgomery_big_mod_t a =
        static_cast<montgomery_big_mod_t>(0x123_big_uint64);
}

BOOST_AUTO_TEST_CASE(construct_modular_ct_trivial_montgomery) {
    static constexpr auto mod = 0x3_big_uint2;
    auto_big_mod<mod> a = auto_big_mod<mod>(0x5_big_uint);
    BOOST_CHECK_EQUAL(a.str(), "0x2");
}

BOOST_AUTO_TEST_CASE(construct_modular_rt_trivial_montgomery) {
    big_mod_rt<2> a(0x5_big_uint, 0x3_big_uint2);
    BOOST_CHECK_EQUAL(a.str(), "0x2");
}

BOOST_AUTO_TEST_CASE(construct_modular_ct_small_montgomery) {
    static constexpr auto mod = 0x79_big_uint7;
    auto_big_mod<mod> a = auto_big_mod<mod>(0x1234_big_uint);
    BOOST_CHECK_EQUAL(a.str(), "0x3E");
}

BOOST_AUTO_TEST_CASE(construct_modular_rt_small_montgomery) {
    big_mod_rt<7> a(0x1234_big_uint, 0x79_big_uint7);
    BOOST_CHECK_EQUAL(a.str(), "0x3E");
}

BOOST_AUTO_TEST_CASE(construct_modular_ct_small) {
    static constexpr auto mod = 0x78_big_uint7;
    auto_big_mod<mod> a = auto_big_mod<mod>(0x1234_big_uint);
    BOOST_CHECK_EQUAL(a.str(), "0x64");
}

BOOST_AUTO_TEST_CASE(construct_modular_rt_small) {
    big_mod_rt<7> a(0x1234_big_uint, 0x78_big_uint7);
    BOOST_CHECK_EQUAL(a.str(), "0x64");
}

BOOST_AUTO_TEST_CASE(to_string_trivial) {
    BOOST_CHECK_EQUAL((static_cast<montgomery_big_mod_t>(0x1_big_uint)).str(), "0x1");
}

BOOST_AUTO_TEST_CASE(to_string_small) {
    BOOST_CHECK_EQUAL((static_cast<montgomery_big_mod_t>(0x20_big_uint)).str(), "0x20");
}

BOOST_AUTO_TEST_CASE(ops) {
    montgomery_big_mod_t a = 2u, b;

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
        b = a op a;        \
        b = 2 op a;        \
        b = a op 2;        \
        b = 2u op a;       \
        b = a op 2u;       \
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
    b = -b;

#undef TEST_BINARY_OP
}

BOOST_AUTO_TEST_CASE(montgomery_increment) {
    auto a = static_cast<montgomery_big_mod_t>(0x2_big_uint64);
    ++a;
    BOOST_CHECK_EQUAL(a, static_cast<montgomery_big_mod_t>(0x3_big_uint64));
}

BOOST_AUTO_TEST_CASE(montgomery_decrement) {
    auto a = static_cast<montgomery_big_mod_t>(0x2_big_uint64);
    --a;
    BOOST_CHECK_EQUAL(a, static_cast<montgomery_big_mod_t>(0x1_big_uint64));
}

BOOST_AUTO_TEST_CASE(montgomery_increment_rvalue) {
    BOOST_CHECK_EQUAL(++static_cast<montgomery_big_mod_t>(0x2_big_uint64),
                      static_cast<montgomery_big_mod_t>(0x3_big_uint64));
}

BOOST_AUTO_TEST_CASE(montgomery_decrement_rvalue) {
    BOOST_CHECK_EQUAL(--static_cast<montgomery_big_mod_t>(0x2_big_uint64),
                      static_cast<montgomery_big_mod_t>(0x1_big_uint64));
}

BOOST_AUTO_TEST_CASE(increment) {
    auto a = static_cast<big_mod_t>(0x2_big_uint64);
    ++a;
    BOOST_CHECK_EQUAL(a, static_cast<big_mod_t>(0x3_big_uint64));
}

BOOST_AUTO_TEST_CASE(decrement) {
    auto a = static_cast<big_mod_t>(0x2_big_uint64);
    --a;
    BOOST_CHECK_EQUAL(a, static_cast<big_mod_t>(0x1_big_uint64));
}

BOOST_AUTO_TEST_CASE(increment_rvalue) {
    BOOST_CHECK_EQUAL(++static_cast<big_mod_t>(0x2_big_uint64),
                      static_cast<big_mod_t>(0x3_big_uint64));
}

BOOST_AUTO_TEST_CASE(decrement_rvalue) {
    BOOST_CHECK_EQUAL(--static_cast<big_mod_t>(0x2_big_uint64),
                      static_cast<big_mod_t>(0x1_big_uint64));
}

BOOST_AUTO_TEST_SUITE_END()

BOOST_AUTO_TEST_SUITE(addition)

BOOST_AUTO_TEST_CASE(simple) {
    BOOST_CHECK_EQUAL(static_cast<montgomery_big_mod_t>(0x2_big_uint64) +
                          static_cast<montgomery_big_mod_t>(0x3_big_uint64),
                      static_cast<montgomery_big_mod_t>(0x5_big_uint64));
}

BOOST_AUTO_TEST_CASE(multilimb) {
    BOOST_CHECK_EQUAL(static_cast<montgomery_big_mod_t>(0xAFFFFFFFF_big_uint64) +
                          static_cast<montgomery_big_mod_t>(0x2_big_uint36),
                      static_cast<montgomery_big_mod_t>(0xB00000001_big_uint64));
}

BOOST_AUTO_TEST_SUITE_END()

BOOST_AUTO_TEST_SUITE(multiplication)

BOOST_AUTO_TEST_CASE(simple) {
    BOOST_CHECK_EQUAL(static_cast<montgomery_big_mod_t>(0x2_big_uint64) *
                          static_cast<montgomery_big_mod_t>(0x3_big_uint64),
                      static_cast<montgomery_big_mod_t>(0x6_big_uint64));
}

BOOST_AUTO_TEST_CASE(multilimb) {
    BOOST_CHECK_EQUAL(static_cast<montgomery_big_mod_t>(0xAFFFFFFFF_big_uint64) *
                          static_cast<montgomery_big_mod_t>(0x2_big_uint36),
                      static_cast<montgomery_big_mod_t>(0x15FFFFFFFE_big_uint64));
}

BOOST_AUTO_TEST_CASE(big) {
    static constexpr auto mod =
        0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF000000000000000000000001_big_uint224;
    big_mod<mod> a = 0xC5067EE5D80302E0561545A8467C6D5C98BC4D37672EB301C38CE9A9_big_uint224;

    big_mod<mod> b = 0xE632329C42040E595D127EB6889D22215DBE56F540425C705D6BF83_big_uint224;

    BOOST_CHECK_EQUAL((a * b).base(),
                      0x107BC09A9F3443A6F6458495ADD98CBA1FCD15F17D0EAB66302FEFA6_big_uint224);
}

BOOST_AUTO_TEST_CASE(big_assign) {
    static constexpr auto mod =
        0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF000000000000000000000001_big_uint224;
    big_mod<mod> a = 0xC5067EE5D80302E0561545A8467C6D5C98BC4D37672EB301C38CE9A9_big_uint224;

    big_mod<mod> b = 0xE632329C42040E595D127EB6889D22215DBE56F540425C705D6BF83_big_uint224;

    a *= b;

    BOOST_CHECK_EQUAL(a.base(),
                      0x107BC09A9F3443A6F6458495ADD98CBA1FCD15F17D0EAB66302FEFA6_big_uint224);
}

BOOST_AUTO_TEST_SUITE_END()

BOOST_AUTO_TEST_SUITE(convert)

BOOST_AUTO_TEST_CASE(from_uint64_t) {
    montgomery_big_mod_t a = static_cast<std::uint64_t>(0x123456789ABCDEFull);
    BOOST_CHECK_EQUAL(a, static_cast<montgomery_big_mod_t>(0x123456789ABCDEF_big_uint64));
}

BOOST_AUTO_TEST_CASE(from_int64_t) {
    montgomery_big_mod_t a = static_cast<std::int64_t>(0x123456789ABCDEFull);
    BOOST_CHECK_EQUAL(a, static_cast<montgomery_big_mod_t>(0x123456789ABCDEF_big_uint64));
}

BOOST_AUTO_TEST_CASE(init_from_big_uint512_is_modulo) {
    montgomery_big_mod_t a =
        0xAA9E37FDB4756C822359B5D50B63A666C1E8D71142E315D224BF596CD169F7B60F01A02DEB2B562B8D51AFD478E1C21155F0E950C265CB32656FC073CDF19DA2_big_uint512;
    BOOST_CHECK_EQUAL(a.base(), 0xD7C1CF32317E71_big_uint);
}

BOOST_AUTO_TEST_CASE(init_from_signed_is_modulo) {
    montgomery_big_mod_t a = -1;
    BOOST_CHECK_EQUAL(a.base(), 0x123456789ABCDEE_big_uint64);
}

BOOST_AUTO_TEST_SUITE_END()

BOOST_AUTO_TEST_SUITE(bugs)

BOOST_AUTO_TEST_CASE(secp256k1_incorrect_multiplication) {
    using standart_number = nil::crypto3::multiprecision::big_uint<256>;
    using modular_number = nil::crypto3::multiprecision::montgomery_big_mod_rt<256>;

    constexpr standart_number modulus =
        0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f_big_uint256;
    constexpr standart_number x_standard =
        0xb5d724ce6f44c3c587867bbcb417e9eb6fa05e7e2ef029166568f14eb3161387_big_uint256;
    constexpr standart_number res_standard =
        0xad6e1fcc680392abfb075838eafa513811112f14c593e0efacb6e9d0d7770b4_big_uint256;
    constexpr modular_number x(x_standard, modulus);
    constexpr modular_number res(res_standard, modulus);
    BOOST_CHECK_EQUAL(x * x, res);
}

BOOST_AUTO_TEST_CASE(bad_negation) {
    using standart_number = nil::crypto3::multiprecision::big_uint<256>;
    using modular_number = nil::crypto3::multiprecision::montgomery_big_mod_rt<256>;

    constexpr standart_number modulus =
        0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f_big_uint256;
    constexpr modular_number x(0u, modulus);
    constexpr modular_number res = -x;

    BOOST_CHECK(res == 0u);
    BOOST_CHECK(res == x);
    BOOST_CHECK(-res == x);
}

BOOST_AUTO_TEST_CASE(goldilocks_multiplication_noncanonical) {
    goldilocks_mod a = 0xEB17187D25277580ULL;
    goldilocks_mod b = 0xBF79143CE60CA966ULL;
    BOOST_CHECK_EQUAL((a * b).base(), 0x8);
}

BOOST_AUTO_TEST_SUITE_END()
