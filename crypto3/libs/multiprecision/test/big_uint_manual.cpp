//---------------------------------------------------------------------------//
// Copyright (c) 2012 John Maddock
// Copyright (c) 2024 Andrey Nefedov <ioxid@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#define BOOST_TEST_MODULE big_uint_manual_test

#include <algorithm>
#include <climits>
#include <cmath>
#include <compare>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <ios>
#include <iostream>
#include <limits>
#include <sstream>
#include <stdexcept>
#include <string>
#include <string_view>
#include <type_traits>

#include <boost/test/unit_test.hpp>

#include <boost/functional/hash.hpp>
#include <boost/type_index/stl_type_index.hpp>

#include "nil/crypto3/multiprecision/big_uint.hpp"
#include "nil/crypto3/multiprecision/gcd.hpp"  // IWYU pragma: keep
#include "nil/crypto3/multiprecision/pow.hpp"  // IWYU pragma: keep

template<class T>
struct is_twos_complement_integer : public std::integral_constant<bool, false> {};

template<class T>
struct is_checked_cpp_int : public std::integral_constant<bool, true> {};

template<class big_uint_t, class val_t>
void test_comparisons(val_t, val_t, const std::integral_constant<bool, false>&) {}

constexpr int ordering_as_int(std::strong_ordering cmp) noexcept {
    return (cmp < 0) ? -1 : (cmp == 0 ? 0 : 1);
}

template<class big_uint_t, class val_t>
void test_comparisons(val_t a, val_t b, const std::integral_constant<bool, true>&) {
    big_uint_t r1(a);
    big_uint_t r2(b);
    big_uint_t z(1);

    int cr = a < b ? -1 : a > b ? 1 : 0;

    BOOST_CHECK_EQUAL(r1 == r2, a == b);
    BOOST_CHECK_EQUAL(r1 != r2, a != b);
    BOOST_CHECK_EQUAL(r1 <= r2, a <= b);
    BOOST_CHECK_EQUAL(r1 < r2, a < b);
    BOOST_CHECK_EQUAL(r1 >= r2, a >= b);
    BOOST_CHECK_EQUAL(r1 > r2, a > b);

    BOOST_CHECK_EQUAL(r1 == b, a == b);
    BOOST_CHECK_EQUAL(r1 != b, a != b);
    BOOST_CHECK_EQUAL(r1 <= b, a <= b);
    BOOST_CHECK_EQUAL(r1 < b, a < b);
    BOOST_CHECK_EQUAL(r1 >= b, a >= b);
    BOOST_CHECK_EQUAL(r1 > b, a > b);

    BOOST_CHECK_EQUAL(a == r2, a == b);
    BOOST_CHECK_EQUAL(a != r2, a != b);
    BOOST_CHECK_EQUAL(a <= r2, a <= b);
    BOOST_CHECK_EQUAL(a < r2, a < b);
    BOOST_CHECK_EQUAL(a >= r2, a >= b);
    BOOST_CHECK_EQUAL(a > r2, a > b);

    BOOST_CHECK_EQUAL(r1 * z == r2, a == b);
    BOOST_CHECK_EQUAL(r1 * z != r2, a != b);
    BOOST_CHECK_EQUAL(r1 * z <= r2, a <= b);
    BOOST_CHECK_EQUAL(r1 * z < r2, a < b);
    BOOST_CHECK_EQUAL(r1 * z >= r2, a >= b);
    BOOST_CHECK_EQUAL(r1 * z > r2, a > b);

    BOOST_CHECK_EQUAL(r1 == r2 * z, a == b);
    BOOST_CHECK_EQUAL(r1 != r2 * z, a != b);
    BOOST_CHECK_EQUAL(r1 <= r2 * z, a <= b);
    BOOST_CHECK_EQUAL(r1 < r2 * z, a < b);
    BOOST_CHECK_EQUAL(r1 >= r2 * z, a >= b);
    BOOST_CHECK_EQUAL(r1 > r2 * z, a > b);

    BOOST_CHECK_EQUAL(r1 * z == r2 * z, a == b);
    BOOST_CHECK_EQUAL(r1 * z != r2 * z, a != b);
    BOOST_CHECK_EQUAL(r1 * z <= r2 * z, a <= b);
    BOOST_CHECK_EQUAL(r1 * z < r2 * z, a < b);
    BOOST_CHECK_EQUAL(r1 * z >= r2 * z, a >= b);
    BOOST_CHECK_EQUAL(r1 * z > r2 * z, a > b);

    BOOST_CHECK_EQUAL(r1 * z == b, a == b);
    BOOST_CHECK_EQUAL(r1 * z != b, a != b);
    BOOST_CHECK_EQUAL(r1 * z <= b, a <= b);
    BOOST_CHECK_EQUAL(r1 * z < b, a < b);
    BOOST_CHECK_EQUAL(r1 * z >= b, a >= b);
    BOOST_CHECK_EQUAL(r1 * z > b, a > b);

    BOOST_CHECK_EQUAL(a == r2 * z, a == b);
    BOOST_CHECK_EQUAL(a != r2 * z, a != b);
    BOOST_CHECK_EQUAL(a <= r2 * z, a <= b);
    BOOST_CHECK_EQUAL(a < r2 * z, a < b);
    BOOST_CHECK_EQUAL(a >= r2 * z, a >= b);
    BOOST_CHECK_EQUAL(a > r2 * z, a > b);

    BOOST_CHECK_EQUAL(ordering_as_int(r1 <=> r2), cr);
    BOOST_CHECK_EQUAL(ordering_as_int(r2 <=> r1), -cr);
    BOOST_CHECK_EQUAL(ordering_as_int(r1 <=> b), cr);
    BOOST_CHECK_EQUAL(ordering_as_int(r2 <=> a), -cr);
}

template<class big_uint_t, class Exp>
void test_conditional(big_uint_t v, Exp e) {
    //
    // Verify that Exp is usable in Boolean contexts, and has the same value as v:
    //
    if (e) {
        BOOST_CHECK(v);
    } else {
        BOOST_CHECK(!v);
    }
    if (!e) {
        BOOST_CHECK(!v);
    } else {
        BOOST_CHECK(v);
    }
}

template<class big_uint_t>
void test_complement(big_uint_t a, big_uint_t b, big_uint_t c,
                     const std::integral_constant<bool, true>&) {
    int i = 1020304;
    int j = 56789123;
    int sign_mask = ~0;
    if (std::numeric_limits<big_uint_t>::is_signed) {
        BOOST_CHECK_EQUAL(~a, (~i & sign_mask));
        c = a & ~b;
        BOOST_CHECK_EQUAL(c, (i & (~j & sign_mask)));
        c = ~(a | b);
        BOOST_CHECK_EQUAL(c, (~(i | j) & sign_mask));
    } else {
        BOOST_CHECK_EQUAL((~a & a), 0);
    }
}

template<class big_uint_t>
void test_complement(big_uint_t, big_uint_t, big_uint_t,
                     const std::integral_constant<bool, false>&) {}

template<class big_uint_t>
void test_signed_integer_ops(const std::integral_constant<bool, true>&) {
    big_uint_t a(20);
    big_uint_t b(7);
    big_uint_t c(5);
    BOOST_CHECK_EQUAL(-a % c, 0);
    BOOST_CHECK_EQUAL(-a % b, -20 % 7);
    BOOST_CHECK_EQUAL(-a % -b, -20 % -7);
    BOOST_CHECK_EQUAL(a % -b, 20 % -7);
    BOOST_CHECK_EQUAL(-a % 7, -20 % 7);
    BOOST_CHECK_EQUAL(-a % -7, -20 % -7);
    BOOST_CHECK_EQUAL(a % -7, 20 % -7);
    BOOST_CHECK_EQUAL(-a % 7u, -20 % 7);
    BOOST_CHECK_EQUAL(-a % a, 0);
    BOOST_CHECK_EQUAL(-a % 5, 0);
    BOOST_CHECK_EQUAL(-a % -5, 0);
    BOOST_CHECK_EQUAL(a % -5, 0);

    b = -b;
    BOOST_CHECK_EQUAL(a % b, 20 % -7);
    a = -a;
    BOOST_CHECK_EQUAL(a % b, -20 % -7);
    BOOST_CHECK_EQUAL(a % -7, -20 % -7);
    b = 7;
    BOOST_CHECK_EQUAL(a % b, -20 % 7);
    BOOST_CHECK_EQUAL(a % 7, -20 % 7);
    BOOST_CHECK_EQUAL(a % 7u, -20 % 7);

    a = 20;
    a %= b;
    BOOST_CHECK_EQUAL(a, 20 % 7);
    a = -20;
    a %= b;
    BOOST_CHECK_EQUAL(a, -20 % 7);
    a = 20;
    a %= -b;
    BOOST_CHECK_EQUAL(a, 20 % -7);
    a = -20;
    a %= -b;
    BOOST_CHECK_EQUAL(a, -20 % -7);
    a = 5;
    a %= b - a;
    BOOST_CHECK_EQUAL(a, 5 % (7 - 5));
    a = -20;
    a %= 7;
    BOOST_CHECK_EQUAL(a, -20 % 7);
    a = 20;
    a %= -7;
    BOOST_CHECK_EQUAL(a, 20 % -7);
    a = -20;
    a %= -7;
    BOOST_CHECK_EQUAL(a, -20 % -7);
#ifndef BOOST_NO_LONG_LONG
    a = -20;
    a %= 7uLL;
    BOOST_CHECK_EQUAL(a, -20 % 7);
    a = 20;
    a %= -7LL;
    BOOST_CHECK_EQUAL(a, 20 % -7);
    a = -20;
    a %= -7LL;
    BOOST_CHECK_EQUAL(a, -20 % -7);
#endif
    a = 400;
    b = 45;
    BOOST_CHECK_EQUAL(gcd(a, -45), 45);
    BOOST_CHECK_EQUAL(gcd(-400, b), 45);
    a = -20;
    BOOST_CHECK_EQUAL(abs(a), 20);
    BOOST_CHECK_EQUAL(abs(-a), 20);
    BOOST_CHECK_EQUAL(abs(+a), 20);
    a = 20;
    BOOST_CHECK_EQUAL(abs(a), 20);
    BOOST_CHECK_EQUAL(abs(-a), 20);
    BOOST_CHECK_EQUAL(abs(+a), 20);
    a = -400;
    b = 45;
    BOOST_CHECK_EQUAL(gcd(a, b), 5);
    BOOST_CHECK_EQUAL(gcd(a, 45), 5);
    BOOST_CHECK_EQUAL(gcd(-400, b), 5);
    big_uint_t r;
    divide_qr(a, b, c, r);
    BOOST_CHECK_EQUAL(c, a / b);
    BOOST_CHECK_EQUAL(r, a % b);
    BOOST_CHECK_EQUAL(integer_modulus(a, 57), abs(a % 57));
    b = -57;
    divide_qr(a, b, c, r);
    BOOST_CHECK_EQUAL(c, a / b);
    BOOST_CHECK_EQUAL(r, a % b);
    BOOST_CHECK_EQUAL(integer_modulus(a, -57), abs(a % -57));
    a = 458;
    divide_qr(a, b, c, r);
    BOOST_CHECK_EQUAL(c, a / b);
    BOOST_CHECK_EQUAL(r, a % b);
    BOOST_CHECK_EQUAL(integer_modulus(a, -57), abs(a % -57));
#ifndef TEST_CHECKED_INT
    if (is_checked_cpp_int<big_uint_t>::value) {
        a = -1;
#ifndef BOOST_NO_EXCEPTIONS
        BOOST_CHECK_THROW(a << 2, std::range_error);
        BOOST_CHECK_THROW(a >> 2, std::range_error);
        BOOST_CHECK_THROW(a <<= 2, std::range_error);
        BOOST_CHECK_THROW(a >>= 2, std::range_error);
#endif
    } else {
        a = -1;
        BOOST_CHECK_EQUAL(a << 10, -1024);
        a = -23;
        BOOST_CHECK_EQUAL(a << 10, -23552);
        a = -23456;
        BOOST_CHECK_EQUAL(a >> 10, -23);
        a = -3;
        BOOST_CHECK_EQUAL(a >> 10, -1);
    }
#endif
}
template<class big_uint_t>
void test_signed_integer_ops(const std::integral_constant<bool, false>&) {}

template<class big_uint_t>
inline big_uint_t negate_if_signed(big_uint_t r,
                                   const std::integral_constant<bool, true>&) {
    return -r;
}
template<class big_uint_t>
inline big_uint_t negate_if_signed(big_uint_t r,
                                   const std::integral_constant<bool, false>&) {
    return r;
}

template<class big_uint_t, class Int>
void test_integer_overflow() {
    if (std::numeric_limits<big_uint_t>::digits > std::numeric_limits<Int>::digits) {
        big_uint_t m((std::numeric_limits<Int>::max)());
        Int r;
        ++m;
        if (is_checked_cpp_int<big_uint_t>::value) {
            BOOST_CHECK_THROW((void)static_cast<Int>(m), std::overflow_error);
        } else if (std::is_signed<Int>::value) {
            r = static_cast<Int>(m);
            BOOST_CHECK_EQUAL(r, (std::numeric_limits<Int>::max)());
        } else {
            r = static_cast<Int>(m);
            BOOST_CHECK_EQUAL(r, 0);
        }
        // Again with much larger value:
        m = 1u;
        m <<= (std::min)(std::numeric_limits<big_uint_t>::digits - 1, 1000);
        if (is_checked_cpp_int<big_uint_t>::value) {
            BOOST_CHECK_THROW((void)static_cast<Int>(m), std::overflow_error);
        } else if (std::is_signed<Int>::value && std::is_integral<Int>::value) {
            r = static_cast<Int>(m);
            BOOST_CHECK_EQUAL(r, (std::numeric_limits<Int>::max)());
        } else {
            r = static_cast<Int>(m);
            BOOST_CHECK_EQUAL(r, 0);
        }

        if (std::numeric_limits<big_uint_t>::is_signed && (std::is_signed<Int>::value)) {
            m = (std::numeric_limits<Int>::min)();
            --m;
            if (is_checked_cpp_int<big_uint_t>::value) {
                BOOST_CHECK_THROW((void)static_cast<Int>(m), std::overflow_error);
            } else {
                r = static_cast<Int>(m);
                BOOST_CHECK_EQUAL(r, (std::numeric_limits<Int>::min)());
            }
            // Again with much larger value:
            m = 2u;
            m = pow(m, (std::min)(std::numeric_limits<big_uint_t>::digits - 1, 1000));
            ++m;
            m = negate_if_signed(
                m, std::integral_constant<bool,
                                          std::numeric_limits<big_uint_t>::is_signed>());
            if (is_checked_cpp_int<big_uint_t>::value) {
                BOOST_CHECK_THROW((void)static_cast<Int>(m), std::overflow_error);
            } else {
                r = static_cast<Int>(m);
                BOOST_CHECK_EQUAL(r, (std::numeric_limits<Int>::min)());
            }
        } else if (std::numeric_limits<big_uint_t>::is_signed &&
                   !std::is_signed<Int>::value) {
            // signed to unsigned converison with overflow, it's really not clear what
            // should happen here!
            m = (std::numeric_limits<Int>::max)();
            ++m;
            m = negate_if_signed(
                m, std::integral_constant<bool,
                                          std::numeric_limits<big_uint_t>::is_signed>());
            BOOST_CHECK_THROW((void)static_cast<Int>(m), std::range_error);
            // Again with much larger value:
            m = 2u;
            m = pow(m, (std::min)(std::numeric_limits<big_uint_t>::digits - 1, 1000));
            m = negate_if_signed(
                m, std::integral_constant<bool,
                                          std::numeric_limits<big_uint_t>::is_signed>());
            BOOST_CHECK_THROW((void)static_cast<Int>(m), std::range_error);
        }
    }
}

template<class big_uint_t, class Int>
void test_integer_round_trip() {
    if (std::numeric_limits<big_uint_t>::digits >= std::numeric_limits<Int>::digits) {
        big_uint_t m((std::numeric_limits<Int>::max)());
        Int r = static_cast<Int>(m);
        BOOST_CHECK_EQUAL(m, r);
        if (std::numeric_limits<big_uint_t>::is_signed &&
            (std::numeric_limits<big_uint_t>::digits >
             std::numeric_limits<Int>::digits)) {
            m = (std::numeric_limits<Int>::min)();
            r = static_cast<Int>(m);
            BOOST_CHECK_EQUAL(m, r);
        }
    }
    test_integer_overflow<big_uint_t, Int>();
}

template<class big_uint_t>
void test_integer_ops() {  // NOLINT
    test_signed_integer_ops<big_uint_t>(
        std::integral_constant<bool, std::numeric_limits<big_uint_t>::is_signed>());

    big_uint_t a(20);
    big_uint_t b(7);
    big_uint_t c(5);
    BOOST_CHECK_EQUAL(a % b, 20 % 7);
    BOOST_CHECK_EQUAL(a % 7, 20 % 7);
    BOOST_CHECK_EQUAL(a % 7u, 20 % 7);
    BOOST_CHECK_EQUAL(a % a, 0);
    BOOST_CHECK_EQUAL(a % c, 0);
    BOOST_CHECK_EQUAL(a % 5, 0);
    a = a % (b + 0);
    BOOST_CHECK_EQUAL(a, 20 % 7);
    a = 20;
    c = (a + 2) % (a - 1);
    BOOST_CHECK_EQUAL(c, 22 % 19);
    c = 5;
    a = b % (a - 15);
    BOOST_CHECK_EQUAL(a, 7 % 5);
    a = 20;

    a = 20;
    a %= 7;
    BOOST_CHECK_EQUAL(a, 20 % 7);
#ifndef BOOST_NO_LONG_LONG
    a = 20;
    a %= 7uLL;
    BOOST_CHECK_EQUAL(a, 20 % 7);
#endif
    a = 20;
    ++a;
    BOOST_CHECK_EQUAL(a, 21);
    --a;
    BOOST_CHECK_EQUAL(a, 20);
    BOOST_CHECK_EQUAL(a++, 20);
    BOOST_CHECK_EQUAL(a, 21);
    BOOST_CHECK_EQUAL(a--, 21);
    BOOST_CHECK_EQUAL(a, 20);
    a = 2000;
    a <<= 20;
    BOOST_CHECK_EQUAL(a, 2000L << 20);
    a >>= 20;
    BOOST_CHECK_EQUAL(a, 2000);
    a <<= 20u;
    BOOST_CHECK_EQUAL(a, 2000L << 20);
    a >>= 20u;
    BOOST_CHECK_EQUAL(a, 2000);
#ifndef BOOST_NO_EXCEPTIONS
    BOOST_CHECK_THROW(a <<= -20, std::range_error);
    BOOST_CHECK_THROW((void)(a >>= -20), std::range_error);
    BOOST_CHECK_THROW((void)big_uint_t(a << -20), std::range_error);
    BOOST_CHECK_THROW((void)big_uint_t(a >> -20), std::range_error);
#endif
#ifndef BOOST_NO_LONG_LONG
    if (sizeof(long long) > sizeof(std::size_t)) {
        // extreme values should trigger an exception:
#ifndef BOOST_NO_EXCEPTIONS
        BOOST_CHECK_THROW(a >>= (1uLL << (sizeof(long long) * CHAR_BIT - 2)),
                          std::range_error);
        BOOST_CHECK_THROW(a <<= (1uLL << (sizeof(long long) * CHAR_BIT - 2)),
                          std::range_error);
        BOOST_CHECK_THROW(a >>= -(1LL << (sizeof(long long) * CHAR_BIT - 2)),
                          std::range_error);
        BOOST_CHECK_THROW(a <<= -(1LL << (sizeof(long long) * CHAR_BIT - 2)),
                          std::range_error);
        BOOST_CHECK_THROW(a >>= (1LL << (sizeof(long long) * CHAR_BIT - 2)),
                          std::range_error);
        BOOST_CHECK_THROW(a <<= (1LL << (sizeof(long long) * CHAR_BIT - 2)),
                          std::range_error);
#endif
        // Unless they fit within range:
        a = 2000L;
        a <<= 20uLL;
        BOOST_CHECK_EQUAL(a, (2000L << 20));
        a = 2000;
        a <<= 20LL;
        BOOST_CHECK_EQUAL(a, (2000L << 20));

#ifndef BOOST_NO_EXCEPTIONS
        BOOST_CHECK_THROW(big_uint_t(a >> (1uLL << (sizeof(long long) * CHAR_BIT - 2))),
                          std::range_error);
        BOOST_CHECK_THROW(big_uint_t(a <<= (1uLL << (sizeof(long long) * CHAR_BIT - 2))),
                          std::range_error);
        BOOST_CHECK_THROW(big_uint_t(a >>= -(1LL << (sizeof(long long) * CHAR_BIT - 2))),
                          std::range_error);
        BOOST_CHECK_THROW(big_uint_t(a <<= -(1LL << (sizeof(long long) * CHAR_BIT - 2))),
                          std::range_error);
        BOOST_CHECK_THROW(big_uint_t(a >>= (1LL << (sizeof(long long) * CHAR_BIT - 2))),
                          std::range_error);
        BOOST_CHECK_THROW(big_uint_t(a <<= (1LL << (sizeof(long long) * CHAR_BIT - 2))),
                          std::range_error);
#endif
        // Unless they fit within range:
        a = 2000L;
        BOOST_CHECK_EQUAL(big_uint_t(a << 20uLL), (2000L << 20));
        a = 2000;
        BOOST_CHECK_EQUAL(big_uint_t(a << 20LL), (2000L << 20));
    }
#endif
    a = 20;
    b = a << 20;
    BOOST_CHECK_EQUAL(b, (20 << 20));
    b = a >> 2;
    BOOST_CHECK_EQUAL(b, (20 >> 2));
    b = (a + 2) << 10;
    BOOST_CHECK_EQUAL(b, (22 << 10));
    b = (a + 3) >> 3;
    BOOST_CHECK_EQUAL(b, (23 >> 3));
    //
    // Bit fiddling:
    //
    int i = 1020304;
    int j = 56789123;
    int k = 4523187;
    a = i;
    b = j;
    c = a;
    c &= b;
    BOOST_CHECK_EQUAL(c, (i & j));
    c = a;
    c &= j;
    BOOST_CHECK_EQUAL(c, (i & j));
    c = a;
    c &= a + b;
    BOOST_CHECK_EQUAL(c, (i & (i + j)));
    BOOST_CHECK_EQUAL((a & b), (i & j));
    c = k;
    a = a & (b + k);
    BOOST_CHECK_EQUAL(a, (i & (j + k)));
    a = i;
    a = (b + k) & a;
    BOOST_CHECK_EQUAL(a, (i & (j + k)));
    a = i;
    c = a & b & k;
    BOOST_CHECK_EQUAL(c, (i & j & k));
    c = a;
    c &= (c + b);
    BOOST_CHECK_EQUAL(c, (i & (i + j)));
    c = a & (b | 1);
    BOOST_CHECK_EQUAL(c, (i & (j | 1)));

    test_complement<big_uint_t>(a, b, c,
                                typename is_twos_complement_integer<big_uint_t>::type());

    a = i;
    b = j;
    c = a;
    c |= b;
    BOOST_CHECK_EQUAL(c, (i | j));
    c = a;
    c |= j;
    BOOST_CHECK_EQUAL(c, (i | j));
    c = a;
    c |= a + b;
    BOOST_CHECK_EQUAL(c, (i | (i + j)));
    BOOST_CHECK_EQUAL((a | b), (i | j));
    c = k;
    a = a | (b + k);
    BOOST_CHECK_EQUAL(a, (i | (j + k)));
    a = i;
    a = (b + k) | a;
    BOOST_CHECK_EQUAL(a, (i | (j + k)));
    a = i;
    c = a | b | k;
    BOOST_CHECK_EQUAL(c, (i | j | k));
    c = a;
    c |= (c + b);
    BOOST_CHECK_EQUAL(c, (i | (i + j)));
    c = a | (b | 1);
    BOOST_CHECK_EQUAL(c, (i | (j | 1)));

    a = i;
    b = j;
    c = a;
    c ^= b;
    BOOST_CHECK_EQUAL(c, (i ^ j));
    c = a;
    c ^= j;
    BOOST_CHECK_EQUAL(c, (i ^ j));
    c = a;
    c ^= a + b;
    BOOST_CHECK_EQUAL(c, (i ^ (i + j)));
    BOOST_CHECK_EQUAL((a ^ b), (i ^ j));
    c = k;
    a = a ^ (b + k);
    BOOST_CHECK_EQUAL(a, (i ^ (j + k)));
    a = i;
    a = (b + k) ^ a;
    BOOST_CHECK_EQUAL(a, (i ^ (j + k)));
    a = i;
    c = a ^ b ^ k;
    BOOST_CHECK_EQUAL(c, (i ^ j ^ k));
    c = a;
    c ^= (c + b);
    BOOST_CHECK_EQUAL(c, (i ^ (i + j)));
    c = a ^ (b | 1);
    BOOST_CHECK_EQUAL(c, (i ^ (j | 1)));

    a = i;
    b = j;
    c = k;
    //
    // Non-member functions:
    //
    a = 400;
    b = 45;
    BOOST_CHECK_EQUAL(gcd(a, b), 5);
    // BOOST_CHECK_EQUAL(gcd(a, 45), 5);
    // BOOST_CHECK_EQUAL(gcd(a, 45u), 5);
    // BOOST_CHECK_EQUAL(gcd(400, b), 5);
    // BOOST_CHECK_EQUAL(gcd(400u, b), 5);

    if (std::numeric_limits<big_uint_t>::is_bounded) {
        // Fixed precision integer:
        a = (std::numeric_limits<big_uint_t>::max)() - 1;
        b = (std::numeric_limits<big_uint_t>::max)() / 35;
        big_uint_t div = gcd(a, b);
        BOOST_CHECK_EQUAL(a % div, 0);
        BOOST_CHECK_EQUAL(b % div, 0);
    }

    //
    // Conditionals involving 2 arg functions:
    //
    test_conditional(big_uint_t(gcd(a, b)), gcd(a, b));

    big_uint_t r;
    divide_qr(a, b, c, r);
    BOOST_CHECK_EQUAL(c, a / b);
    BOOST_CHECK_EQUAL(r, a % b);
    divide_qr(a + 0, b, c, r);
    BOOST_CHECK_EQUAL(c, a / b);
    BOOST_CHECK_EQUAL(r, a % b);
    divide_qr(a, b + 0, c, r);
    BOOST_CHECK_EQUAL(c, a / b);
    BOOST_CHECK_EQUAL(r, a % b);
    divide_qr(a + 0, b + 0, c, r);
    BOOST_CHECK_EQUAL(c, a / b);
    BOOST_CHECK_EQUAL(r, a % b);
    // BOOST_CHECK_EQUAL(integer_modulus(a, 57), a % 57);
    for (i = 0; i < 20; ++i) {
        if (std::numeric_limits<big_uint_t>::is_specialized &&
            (!std::numeric_limits<big_uint_t>::is_bounded ||
             (i * 17 < std::numeric_limits<big_uint_t>::digits))) {
            BOOST_CHECK_EQUAL(lsb(big_uint_t(1) << (i * 17)),
                              static_cast<unsigned>(i * 17));
            BOOST_CHECK_EQUAL(msb(big_uint_t(1) << (i * 17)),
                              static_cast<unsigned>(i * 17));
            BOOST_CHECK(bit_test(big_uint_t(1) << (i * 17), i * 17));
            BOOST_CHECK(!bit_test(big_uint_t(1) << (i * 17), i * 17 + 1));
            if (i) {
                BOOST_CHECK(!bit_test(big_uint_t(1) << (i * 17), i * 17 - 1));
            }
            big_uint_t zero(0);
            BOOST_CHECK(bit_test(bit_set(zero, i * 17), i * 17));
            zero = 0;
            BOOST_CHECK_EQUAL(bit_flip(zero, i * 17), big_uint_t(1) << i * 17);
            zero = big_uint_t(1) << i * 17;
            BOOST_CHECK_EQUAL(bit_flip(zero, i * 17), 0);
            zero = big_uint_t(1) << i * 17;
            BOOST_CHECK_EQUAL(bit_unset(zero, i * 17), 0);
        }
    }
    //
    // pow, powm:
    //
    BOOST_CHECK_EQUAL(pow(big_uint_t(3), 4u), 81);
    BOOST_CHECK_EQUAL(pow(big_uint_t(3) + big_uint_t(0), 4u), 81);
    BOOST_CHECK_EQUAL(powm(big_uint_t(3), big_uint_t(4), big_uint_t(13)), 81 % 13);
    BOOST_CHECK_EQUAL(powm(big_uint_t(3), big_uint_t(4), 13), 81 % 13);
    BOOST_CHECK_EQUAL(powm(big_uint_t(3), big_uint_t(4), big_uint_t(13) + 0), 81 % 13);
    BOOST_CHECK_EQUAL(powm(big_uint_t(3), big_uint_t(4) + 0, big_uint_t(13)), 81 % 13);
    BOOST_CHECK_EQUAL(powm(big_uint_t(3), big_uint_t(4) + 0, 13), 81 % 13);
    BOOST_CHECK_EQUAL(powm(big_uint_t(3), big_uint_t(4) + 0, big_uint_t(13) + 0),
                      81 % 13);
    BOOST_CHECK_EQUAL(powm(big_uint_t(3), 4 + 0, big_uint_t(13)), 81 % 13);
    BOOST_CHECK_EQUAL(powm(big_uint_t(3), 4 + 0, 13), 81 % 13);
    BOOST_CHECK_EQUAL(powm(big_uint_t(3), 4 + 0, big_uint_t(13) + 0), 81 % 13);
    BOOST_CHECK_EQUAL(powm(big_uint_t(3) + 0, big_uint_t(4), big_uint_t(13)), 81 % 13);
    BOOST_CHECK_EQUAL(powm(big_uint_t(3) + 0, big_uint_t(4), 13), 81 % 13);
    BOOST_CHECK_EQUAL(powm(big_uint_t(3) + 0, big_uint_t(4), big_uint_t(13) + 0),
                      81 % 13);
    BOOST_CHECK_EQUAL(powm(big_uint_t(3) + 0, big_uint_t(4) + 0, big_uint_t(13)),
                      81 % 13);
    BOOST_CHECK_EQUAL(powm(big_uint_t(3) + 0, big_uint_t(4) + 0, 13), 81 % 13);
    BOOST_CHECK_EQUAL(powm(big_uint_t(3) + 0, big_uint_t(4) + 0, big_uint_t(13) + 0),
                      81 % 13);
    BOOST_CHECK_EQUAL(powm(big_uint_t(3) + 0, 4 + 0, big_uint_t(13)), 81 % 13);
    BOOST_CHECK_EQUAL(powm(big_uint_t(3) + 0, 4 + 0, 13), 81 % 13);
    BOOST_CHECK_EQUAL(powm(big_uint_t(3) + 0, 4 + 0, big_uint_t(13) + 0), 81 % 13);
    //
    // Conditionals involving 3 arg functions:
    //
    test_conditional(big_uint_t(powm(big_uint_t(3), big_uint_t(4), big_uint_t(13))),
                     powm(big_uint_t(3), big_uint_t(4), big_uint_t(13)));

#ifndef BOOST_NO_EXCEPTIONS
    //
    // Things that are expected errors:
    //
    BOOST_CHECK_THROW(big_uint_t("3.14"), std::invalid_argument);
    BOOST_CHECK_THROW(big_uint_t("3L"), std::invalid_argument);
    BOOST_CHECK_THROW((void)big_uint_t(big_uint_t(20) / 0u), std::overflow_error);
#endif
    //
    // Extra tests added for full coverage:
    //
    a = 20;
    b = 7;
    c = 20 % b;
    BOOST_CHECK_EQUAL(c, (20 % 7));
    c = 20 % (b + 0);
    BOOST_CHECK_EQUAL(c, (20 % 7));
    c = a & 10;
    BOOST_CHECK_EQUAL(c, (20 & 10));
    c = 10 & a;
    BOOST_CHECK_EQUAL(c, (20 & 10));
    c = (a + 0) & (b + 0);
    BOOST_CHECK_EQUAL(c, (20 & 7));
    c = 10 & (a + 0);
    BOOST_CHECK_EQUAL(c, (20 & 10));
    c = 10 | a;
    BOOST_CHECK_EQUAL(c, (20 | 10));
    c = (a + 0) | (b + 0);
    BOOST_CHECK(c == (20 | 7));
    c = 20 | (b + 0);
    BOOST_CHECK_EQUAL(c, (20 | 7));
    c = a ^ 7;
    BOOST_CHECK_EQUAL(c, (20 ^ 7));
    c = 20 ^ b;
    BOOST_CHECK_EQUAL(c, (20 ^ 7));
    c = (a + 0) ^ (b + 0);
    BOOST_CHECK_EQUAL(c, (20 ^ 7));
    c = 20 ^ (b + 0);
    BOOST_CHECK_EQUAL(c, (20 ^ 7));
    //
    // Rval_tue ref tests:
    //
    c = big_uint_t(20) % b;
    BOOST_CHECK_EQUAL(c, (20 % 7));
    c = a % big_uint_t(7);
    BOOST_CHECK_EQUAL(c, (20 % 7));
    c = big_uint_t(20) % big_uint_t(7);
    BOOST_CHECK_EQUAL(c, (20 % 7));
    c = big_uint_t(20) % 7;
    BOOST_CHECK_EQUAL(c, (20 % 7));
    c = 20 % big_uint_t(7);
    BOOST_CHECK_EQUAL(c, (20 % 7));
    c = big_uint_t(20) % (b * 1);
    BOOST_CHECK_EQUAL(c, (20 % 7));
    c = (a * 1 + 0) % big_uint_t(7);
    BOOST_CHECK_EQUAL(c, (20 % 7));
    c = big_uint_t(20) >> 2;
    BOOST_CHECK_EQUAL(c, (20 >> 2));
    c = big_uint_t(20) & b;
    BOOST_CHECK_EQUAL(c, (20 & 7));
    c = a & big_uint_t(7);
    BOOST_CHECK_EQUAL(c, (20 & 7));
    c = big_uint_t(20) & big_uint_t(7);
    BOOST_CHECK_EQUAL(c, (20 & 7));
    c = big_uint_t(20) & 7;
    BOOST_CHECK_EQUAL(c, (20 & 7));
    c = 20 & big_uint_t(7);
    BOOST_CHECK_EQUAL(c, (20 & 7));
    c = big_uint_t(20) & (b * 1 + 0);
    BOOST_CHECK_EQUAL(c, (20 & 7));
    c = (a * 1 + 0) & big_uint_t(7);
    BOOST_CHECK_EQUAL(c, (20 & 7));
    c = big_uint_t(20) | b;
    BOOST_CHECK_EQUAL(c, (20 | 7));
    c = a | big_uint_t(7);
    BOOST_CHECK_EQUAL(c, (20 | 7));
    c = big_uint_t(20) | big_uint_t(7);
    BOOST_CHECK_EQUAL(c, (20 | 7));
    c = big_uint_t(20) | 7;
    BOOST_CHECK_EQUAL(c, (20 | 7));
    c = 20 | big_uint_t(7);
    BOOST_CHECK_EQUAL(c, (20 | 7));
    c = big_uint_t(20) | (b * 1 + 0);
    BOOST_CHECK_EQUAL(c, (20 | 7));
    c = (a * 1 + 0) | big_uint_t(7);
    BOOST_CHECK_EQUAL(c, (20 | 7));
    c = big_uint_t(20) ^ b;
    BOOST_CHECK_EQUAL(c, (20 ^ 7));
    c = a ^ big_uint_t(7);
    BOOST_CHECK_EQUAL(c, (20 ^ 7));
    c = big_uint_t(20) ^ big_uint_t(7);
    BOOST_CHECK_EQUAL(c, (20 ^ 7));
    c = big_uint_t(20) ^ 7;
    BOOST_CHECK_EQUAL(c, (20 ^ 7));
    c = 20 ^ big_uint_t(7);
    BOOST_CHECK_EQUAL(c, (20 ^ 7));
    c = big_uint_t(20) ^ (b * 1 + 0);
    BOOST_CHECK_EQUAL(c, (20 ^ 7));
    c = (a * 1 + 0) ^ big_uint_t(7);
    BOOST_CHECK_EQUAL(c, (20 ^ 7));

    //
    // Round tripping of built in integers:
    //
    test_integer_round_trip<big_uint_t, short>();
    test_integer_round_trip<big_uint_t, unsigned short>();
    test_integer_round_trip<big_uint_t, int>();
    test_integer_round_trip<big_uint_t, unsigned int>();
    test_integer_round_trip<big_uint_t, long>();
    test_integer_round_trip<big_uint_t, unsigned long>();
#ifndef BOOST_NO_LONG_LONG
    test_integer_round_trip<big_uint_t, long long>();
    test_integer_round_trip<big_uint_t, unsigned long long>();
#endif
}

template<class T>
struct lexical_cast_target_type {
    typedef typename std::conditional<
        std::is_signed<T>::value && std::is_integral<T>::value, std::intmax_t,
        typename std::conditional<std::is_unsigned<T>::value, std::uintmax_t,
                                  T>::type>::type type;
};

template<class big_uint_t, class num_t>
void test_negative_mixed_minmax(std::integral_constant<bool, true> const&) {
    if (!std::numeric_limits<big_uint_t>::is_bounded ||
        (std::numeric_limits<big_uint_t>::digits >= std::numeric_limits<num_t>::digits)) {
        big_uint_t mx1((std::numeric_limits<num_t>::max)() - 1);
        ++mx1;
        big_uint_t mx2((std::numeric_limits<num_t>::max)());
        BOOST_CHECK_EQUAL(mx1, mx2);
        mx1 = (std::numeric_limits<num_t>::max)() - 1;
        ++mx1;
        mx2 = (std::numeric_limits<num_t>::max)();
        BOOST_CHECK_EQUAL(mx1, mx2);

        if (!std::numeric_limits<big_uint_t>::is_bounded ||
            (std::numeric_limits<big_uint_t>::digits >
             std::numeric_limits<num_t>::digits)) {
            big_uint_t mx3((std::numeric_limits<num_t>::min)() + 1);
            --mx3;
            big_uint_t mx4((std::numeric_limits<num_t>::min)());
            BOOST_CHECK_EQUAL(mx3, mx4);
            mx3 = (std::numeric_limits<num_t>::min)() + 1;
            --mx3;
            mx4 = (std::numeric_limits<num_t>::min)();
            BOOST_CHECK_EQUAL(mx3, mx4);
        }
    }
}
template<class big_uint_t, class num_t>
void test_negative_mixed_minmax(std::integral_constant<bool, false> const&) {}

template<class big_uint_t, class num_t>
void test_negative_mixed_numeric_limits(std::integral_constant<bool, true> const&) {
    typedef typename lexical_cast_target_type<num_t>::type target_type;
#if defined(TEST_MPFR)
    num_t tol = 10 * std::numeric_limits<num_t>::epsilon();
#else
    num_t tol = 0;
#endif
    static const int left_shift = std::numeric_limits<num_t>::digits - 1;
    num_t n1 = -static_cast<num_t>(
        1uLL << ((left_shift < 63) && (left_shift > 0) ? left_shift : 10));
    num_t n2 = -1;
    num_t n3 = 0;
    num_t n4 = -20;
    std::ios_base::fmtflags f = std::is_floating_point<num_t>::value
                                    ? std::ios_base::scientific
                                    : std::ios_base::fmtflags(0);
    int digits_to_print =
        std::is_floating_point<num_t>::value && std::numeric_limits<num_t>::is_specialized
            ? std::numeric_limits<num_t>::digits10 + 5
            : 0;
    if (std::numeric_limits<target_type>::digits <=
        std::numeric_limits<big_uint_t>::digits) {
        BOOST_CHECK_CLOSE(
            n1, checked_lexical_cast<target_type>(big_uint_t(n1).str(digits_to_print, f)),
            tol);
    }
    BOOST_CHECK_CLOSE(
        n2, checked_lexical_cast<target_type>(big_uint_t(n2).str(digits_to_print, f)), 0);
    BOOST_CHECK_CLOSE(
        n3, checked_lexical_cast<target_type>(big_uint_t(n3).str(digits_to_print, f)), 0);
    BOOST_CHECK_CLOSE(
        n4, checked_lexical_cast<target_type>(big_uint_t(n4).str(digits_to_print, f)), 0);
}

template<class big_uint_t, class num_t>
void test_negative_mixed_numeric_limits(std::integral_constant<bool, false> const&) {}

template<class big_uint_t, class num_t>
void test_negative_mixed(std::integral_constant<bool, true> const&) {
    typedef typename std::conditional<
        std::is_convertible<num_t, big_uint_t>::value,
        typename std::conditional<std::is_integral<num_t>::value &&
                                      (sizeof(num_t) < sizeof(int)),
                                  int, num_t>::type,
        big_uint_t>::type cast_type;
    typedef typename std::conditional<std::is_convertible<num_t, big_uint_t>::value,
                                      num_t, big_uint_t>::type simple_cast_type;
    std::cout << "Testing mixed arithmetic with type: " << typeid(big_uint_t).name()
              << " and " << typeid(num_t).name() << std::endl;
    static const int left_shift = std::numeric_limits<num_t>::digits - 1;
    num_t n1 = -static_cast<num_t>(
        1uLL << ((left_shift < 63) && (left_shift > 0) ? left_shift : 10));
    num_t n2 = -1;
    num_t n3 = 0;
    num_t n4 = -20;
    num_t n5 = -8;

    test_comparisons<big_uint_t>(n1, n2, std::is_convertible<num_t, big_uint_t>());
    test_comparisons<big_uint_t>(n1, n3, std::is_convertible<num_t, big_uint_t>());
    test_comparisons<big_uint_t>(n3, n1, std::is_convertible<num_t, big_uint_t>());
    test_comparisons<big_uint_t>(n2, n1, std::is_convertible<num_t, big_uint_t>());
    test_comparisons<big_uint_t>(n1, n1, std::is_convertible<num_t, big_uint_t>());
    test_comparisons<big_uint_t>(n3, n3, std::is_convertible<num_t, big_uint_t>());

    // Default construct:
    BOOST_CHECK_EQUAL(big_uint_t(n1), static_cast<cast_type>(n1));
    BOOST_CHECK_EQUAL(big_uint_t(n2), static_cast<cast_type>(n2));
    BOOST_CHECK_EQUAL(big_uint_t(n3), static_cast<cast_type>(n3));
    BOOST_CHECK_EQUAL(big_uint_t(n4), static_cast<cast_type>(n4));
    BOOST_CHECK_EQUAL(static_cast<cast_type>(n1), big_uint_t(n1));
    BOOST_CHECK_EQUAL(static_cast<cast_type>(n2), big_uint_t(n2));
    BOOST_CHECK_EQUAL(static_cast<cast_type>(n3), big_uint_t(n3));
    BOOST_CHECK_EQUAL(static_cast<cast_type>(n4), big_uint_t(n4));
    BOOST_CHECK_EQUAL(static_cast<num_t>(big_uint_t(n1)), n1);
    BOOST_CHECK_EQUAL(static_cast<num_t>(big_uint_t(n2)), n2);
    BOOST_CHECK_EQUAL(static_cast<num_t>(big_uint_t(n3)), n3);
    BOOST_CHECK_EQUAL(static_cast<num_t>(big_uint_t(n4)), n4);
    // Conversions when source is an expression template:
    BOOST_CHECK_EQUAL(static_cast<num_t>((big_uint_t(n1) + 0)), n1);
    BOOST_CHECK_EQUAL(static_cast<num_t>((big_uint_t(n2) + 0)), n2);
    BOOST_CHECK_EQUAL(static_cast<num_t>((big_uint_t(n3) + 0)), n3);
    BOOST_CHECK_EQUAL(static_cast<num_t>((big_uint_t(n4) + 0)), n4);
    test_negative_mixed_numeric_limits<big_uint_t, num_t>(
        std::integral_constant<bool, std::numeric_limits<big_uint_t>::is_specialized>());
    // Assignment:
    big_uint_t r(0);
    BOOST_CHECK(r != static_cast<cast_type>(n1));
    r = static_cast<simple_cast_type>(n1);
    BOOST_CHECK_EQUAL(r, static_cast<cast_type>(n1));
    r = static_cast<simple_cast_type>(n2);
    BOOST_CHECK_EQUAL(r, static_cast<cast_type>(n2));
    r = static_cast<simple_cast_type>(n3);
    BOOST_CHECK_EQUAL(r, static_cast<cast_type>(n3));
    r = static_cast<simple_cast_type>(n4);
    BOOST_CHECK_EQUAL(r, static_cast<cast_type>(n4));
    // Addition:
    r = static_cast<simple_cast_type>(n2);
    BOOST_CHECK_EQUAL(r + static_cast<simple_cast_type>(n4),
                      static_cast<cast_type>(n2 + n4));
    BOOST_CHECK_EQUAL(big_uint_t(r + static_cast<simple_cast_type>(n4)),
                      static_cast<cast_type>(n2 + n4));
    r += static_cast<simple_cast_type>(n4);
    BOOST_CHECK_EQUAL(r, static_cast<cast_type>(n2 + n4));
    // subtraction:
    r = static_cast<simple_cast_type>(n4);
    BOOST_CHECK_EQUAL(r - static_cast<simple_cast_type>(n5),
                      static_cast<cast_type>(n4 - n5));
    BOOST_CHECK_EQUAL(big_uint_t(r - static_cast<simple_cast_type>(n5)),
                      static_cast<cast_type>(n4 - n5));
    r -= static_cast<simple_cast_type>(n5);
    BOOST_CHECK_EQUAL(r, static_cast<cast_type>(n4 - n5));
    // Multiplication:
    r = static_cast<simple_cast_type>(n2);
    BOOST_CHECK_EQUAL(r * static_cast<simple_cast_type>(n4),
                      static_cast<cast_type>(n2 * n4));
    BOOST_CHECK_EQUAL(big_uint_t(r * static_cast<simple_cast_type>(n4)),
                      static_cast<cast_type>(n2 * n4));
    r *= static_cast<simple_cast_type>(n4);
    BOOST_CHECK_EQUAL(r, static_cast<cast_type>(n2 * n4));
    // Division:
    r = static_cast<simple_cast_type>(n1);
    BOOST_CHECK_EQUAL(r / static_cast<simple_cast_type>(n5),
                      static_cast<cast_type>(n1 / n5));
    BOOST_CHECK_EQUAL(big_uint_t(r / static_cast<simple_cast_type>(n5)),
                      static_cast<cast_type>(n1 / n5));
    r /= static_cast<simple_cast_type>(n5);
    BOOST_CHECK_EQUAL(r, static_cast<cast_type>(n1 / n5));
    //
    // Extra cases for full coverage:
    //
    r = big_uint_t(n4) + static_cast<simple_cast_type>(n5);
    BOOST_CHECK_EQUAL(r, static_cast<cast_type>(n4 + n5));
    r = static_cast<simple_cast_type>(n4) + big_uint_t(n5);
    BOOST_CHECK_EQUAL(r, static_cast<cast_type>(n4 + n5));
    r = big_uint_t(n4) - static_cast<simple_cast_type>(n5);
    BOOST_CHECK_EQUAL(r, static_cast<cast_type>(n4 - n5));
    r = static_cast<simple_cast_type>(n4) - big_uint_t(n5);
    BOOST_CHECK_EQUAL(r, static_cast<cast_type>(n4 - n5));
    r = static_cast<simple_cast_type>(n4) * big_uint_t(n5);
    BOOST_CHECK_EQUAL(r, static_cast<cast_type>(n4 * n5));
    r = static_cast<cast_type>(num_t(4) * n4) / big_uint_t(4);
    BOOST_CHECK_EQUAL(r, static_cast<cast_type>(n4));

    big_uint_t a, b, c;
    a = 20;
    b = 30;
    c = -a + b;
    BOOST_CHECK_EQUAL(c, 10);
    c = b + -a;
    BOOST_CHECK_EQUAL(c, 10);
    n4 = 30;
    c = -a + static_cast<cast_type>(n4);
    BOOST_CHECK_EQUAL(c, 10);
    c = static_cast<cast_type>(n4) + -a;
    BOOST_CHECK_EQUAL(c, 10);
    c = -a + -b;
    BOOST_CHECK_EQUAL(c, -50);
    n4 = 4;
    c = -(a + b) + static_cast<cast_type>(n4);
    BOOST_CHECK_EQUAL(c, -50 + 4);
    n4 = 50;
    c = (a + b) - static_cast<cast_type>(n4);
    BOOST_CHECK_EQUAL(c, 0);
    c = (a + b) - static_cast<cast_type>(n4);
    BOOST_CHECK_EQUAL(c, 0);
    c = a - -(b + static_cast<cast_type>(n4));
    BOOST_CHECK_EQUAL(c, 20 - -(30 + 50));
    c = -(b + static_cast<cast_type>(n4)) - a;
    BOOST_CHECK_EQUAL(c, -(30 + 50) - 20);
    c = a - -b;
    BOOST_CHECK_EQUAL(c, 50);
    c = -a - b;
    BOOST_CHECK_EQUAL(c, -50);
    c = -a - static_cast<cast_type>(n4);
    BOOST_CHECK_EQUAL(c, -20 - 50);
    c = static_cast<cast_type>(n4) - -a;
    BOOST_CHECK_EQUAL(c, 50 + 20);
    c = -(a + b) - big_uint_t(n4);
    BOOST_CHECK_EQUAL(c, -(20 + 30) - 50);
    c = static_cast<cast_type>(n4) - (a + b);
    BOOST_CHECK_EQUAL(c, 0);
    c = (a + b) * static_cast<cast_type>(n4);
    BOOST_CHECK_EQUAL(c, 50 * 50);
    c = static_cast<cast_type>(n4) * (a + b);
    BOOST_CHECK_EQUAL(c, 50 * 50);
    c = a * -(b + static_cast<cast_type>(n4));
    BOOST_CHECK_EQUAL(c, 20 * -(30 + 50));
    c = -(b + static_cast<cast_type>(n4)) * a;
    BOOST_CHECK_EQUAL(c, 20 * -(30 + 50));
    c = a * -b;
    BOOST_CHECK_EQUAL(c, 20 * -30);
    c = -a * b;
    BOOST_CHECK_EQUAL(c, 20 * -30);
    c = -a * static_cast<cast_type>(n4);
    BOOST_CHECK_EQUAL(c, -20 * 50);
    c = static_cast<cast_type>(n4) * -a;
    BOOST_CHECK_EQUAL(c, -20 * 50);
    c = -(a + b) + a;
    BOOST_CHECK(-50 + 20);
    c = static_cast<cast_type>(n4) - (a + b);
    BOOST_CHECK_EQUAL(c, 0);
    big_uint_t d = 10;
    c = (a + b) / d;
    BOOST_CHECK_EQUAL(c, 5);
    c = (a + b) / (d + 0);
    BOOST_CHECK_EQUAL(c, 5);
    c = (a + b) / static_cast<cast_type>(n4);
    BOOST_CHECK_EQUAL(c, 1);
    c = static_cast<cast_type>(n4) / (a + b);
    BOOST_CHECK_EQUAL(c, 1);
    d = 50;
    c = d / -(a + b);
    BOOST_CHECK_EQUAL(c, -1);
    c = -(a + b) / d;
    BOOST_CHECK_EQUAL(c, -1);
    d = 2;
    c = a / -d;
    BOOST_CHECK_EQUAL(c, 20 / -2);
    c = -a / d;
    BOOST_CHECK_EQUAL(c, 20 / -2);
    d = 50;
    c = -d / static_cast<cast_type>(n4);
    BOOST_CHECK_EQUAL(c, -1);
    c = static_cast<cast_type>(n4) / -d;
    BOOST_CHECK_EQUAL(c, -1);
    c = static_cast<cast_type>(n4) + a;
    BOOST_CHECK_EQUAL(c, 70);
    c = static_cast<cast_type>(n4) - a;
    BOOST_CHECK_EQUAL(c, 30);
    c = static_cast<cast_type>(n4) * a;
    BOOST_CHECK_EQUAL(c, 50 * 20);

    n1 = -2;
    n2 = -3;
    n3 = -4;
    a = static_cast<cast_type>(n1);
    b = static_cast<cast_type>(n2);
    c = static_cast<cast_type>(n3);
    d = a + b * c;
    BOOST_CHECK_EQUAL(d, -2 + -3 * -4);
    d = static_cast<cast_type>(n1) + b * c;
    BOOST_CHECK_EQUAL(d, -2 + -3 * -4);
    d = a + static_cast<cast_type>(n2) * c;
    BOOST_CHECK_EQUAL(d, -2 + -3 * -4);
    d = a + b * static_cast<cast_type>(n3);
    BOOST_CHECK_EQUAL(d, -2 + -3 * -4);
    d = static_cast<cast_type>(n1) + static_cast<cast_type>(n2) * c;
    BOOST_CHECK_EQUAL(d, -2 + -3 * -4);
    d = static_cast<cast_type>(n1) + b * static_cast<cast_type>(n3);
    BOOST_CHECK_EQUAL(d, -2 + -3 * -4);
    a += static_cast<cast_type>(n2) * c;
    BOOST_CHECK_EQUAL(a, -2 + -3 * -4);
    a = static_cast<cast_type>(n1);
    a += b * static_cast<cast_type>(n3);
    BOOST_CHECK_EQUAL(a, -2 + -3 * -4);
    a = static_cast<cast_type>(n1);

    d = b * c + a;
    BOOST_CHECK_EQUAL(d, -2 + -3 * -4);
    d = b * c + static_cast<cast_type>(n1);
    BOOST_CHECK_EQUAL(d, -2 + -3 * -4);
    d = static_cast<cast_type>(n2) * c + a;
    BOOST_CHECK_EQUAL(d, -2 + -3 * -4);
    d = b * static_cast<cast_type>(n3) + a;
    BOOST_CHECK_EQUAL(d, -2 + -3 * -4);
    d = static_cast<cast_type>(n2) * c + static_cast<cast_type>(n1);
    BOOST_CHECK_EQUAL(d, -2 + -3 * -4);
    d = b * static_cast<cast_type>(n3) + static_cast<cast_type>(n1);
    BOOST_CHECK_EQUAL(d, -2 + -3 * -4);

    a = -20;
    d = a - b * c;
    BOOST_CHECK_EQUAL(d, -20 - -3 * -4);
    n1 = -20;
    d = static_cast<cast_type>(n1) - b * c;
    BOOST_CHECK_EQUAL(d, -20 - -3 * -4);
    d = a - static_cast<cast_type>(n2) * c;
    BOOST_CHECK_EQUAL(d, -20 - -3 * -4);
    d = a - b * static_cast<cast_type>(n3);
    BOOST_CHECK_EQUAL(d, -20 - -3 * -4);
    d = static_cast<cast_type>(n1) - static_cast<cast_type>(n2) * c;
    BOOST_CHECK_EQUAL(d, -20 - -3 * -4);
    d = static_cast<cast_type>(n1) - b * static_cast<cast_type>(n3);
    BOOST_CHECK_EQUAL(d, -20 - -3 * -4);
    a -= static_cast<cast_type>(n2) * c;
    BOOST_CHECK_EQUAL(a, -20 - -3 * -4);
    a = static_cast<cast_type>(n1);
    a -= b * static_cast<cast_type>(n3);
    BOOST_CHECK_EQUAL(a, -20 - -3 * -4);

    a = -2;
    d = b * c - a;
    BOOST_CHECK_EQUAL(d, -3 * -4 - -2);
    n1 = -2;
    d = b * c - static_cast<cast_type>(n1);
    BOOST_CHECK_EQUAL(d, -3 * -4 - -2);
    d = static_cast<cast_type>(n2) * c - a;
    BOOST_CHECK_EQUAL(d, -3 * -4 - -2);
    d = b * static_cast<cast_type>(n3) - a;
    BOOST_CHECK_EQUAL(d, -3 * -4 - -2);
    d = static_cast<cast_type>(n2) * c - static_cast<cast_type>(n1);
    BOOST_CHECK_EQUAL(d, -3 * -4 - -2);
    d = b * static_cast<cast_type>(n3) - static_cast<cast_type>(n1);
    BOOST_CHECK_EQUAL(d, -3 * -4 - -2);
    //
    // Conversion from min and max values:
    //
    test_negative_mixed_minmax<big_uint_t, num_t>(
        std::integral_constant < bool, std::numeric_limits<big_uint_t>::is_integer&&
                                               std::numeric_limits<num_t>::is_integer >
                                           ());
    //
    // Rval_tue ref overloads:
    //
    a = 2;
    n1 = 3;
    d = -a + static_cast<cast_type>(n1);
    BOOST_CHECK_EQUAL(d, 1);
    d = static_cast<cast_type>(n1) + -a;
    BOOST_CHECK_EQUAL(d, 1);
    d = -a - static_cast<cast_type>(n1);
    BOOST_CHECK_EQUAL(d, -5);
    d = static_cast<cast_type>(n1) - -a;
    BOOST_CHECK_EQUAL(d, 5);
    d = -a * static_cast<cast_type>(n1);
    BOOST_CHECK_EQUAL(d, -6);
    d = static_cast<cast_type>(n1) * -a;
    BOOST_CHECK_EQUAL(d, -6);
    n1 = 4;
    d = -static_cast<cast_type>(n1) / a;
    BOOST_CHECK_EQUAL(d, -2);
    d = static_cast<cast_type>(n1) / -a;
    BOOST_CHECK_EQUAL(d, -2);
}

template<class big_uint_t, class num_t>
void test_negative_mixed(std::integral_constant<bool, false> const&) {}

template<class big_uint_t, class num_t>
void test_mixed(const std::integral_constant<bool, false>&) {}

template<class big_uint_t>
inline big_uint_t negate_value(const big_uint_t& val,
                               const std::integral_constant<bool, true>&) {
    return -val;
}
template<class big_uint_t>
inline big_uint_t negate_value(const big_uint_t& val,
                               const std::integral_constant<bool, false>&) {
    return val;
}

template<class big_uint_t, class num_t>
void test_mixed_numeric_limits(const std::integral_constant<bool, true>&) {
    typedef typename lexical_cast_target_type<num_t>::type target_type;
#if defined(TEST_MPFR)
    num_t tol = 10 * std::numeric_limits<num_t>::epsilon();
#else
    num_t tol = 0;
#endif

    big_uint_t d;

    static const int left_shift = std::numeric_limits<num_t>::digits - 1;
    num_t n1 = static_cast<num_t>(
        1uLL << ((left_shift < 63) && (left_shift > 0) ? left_shift : 10));
    num_t n2 = 1;
    num_t n3 = 0;
    num_t n4 = 20;

    std::ios_base::fmtflags f = std::is_floating_point<num_t>::value
                                    ? std::ios_base::scientific
                                    : std::ios_base::fmtflags(0);
    int digits_to_print =
        std::is_floating_point<num_t>::value && std::numeric_limits<num_t>::is_specialized
            ? std::numeric_limits<num_t>::digits10 + 5
            : 0;
    // if (std::numeric_limits<target_type>::digits <=
    // std::numeric_limits<big_uint_t>::digits) {
    //     BOOST_CHECK_CLOSE(n1,
    //     checked_lexical_cast<target_type>(big_uint_t(n1).str(digits_to_print, f)),
    //                       tol);
    // }
    // BOOST_CHECK_CLOSE(n2,
    // checked_lexical_cast<target_type>(big_uint_t(n2).str(digits_to_print, f)), 0);
    // BOOST_CHECK_CLOSE(n3,
    // checked_lexical_cast<target_type>(big_uint_t(n3).str(digits_to_print, f)), 0);
    // BOOST_CHECK_CLOSE(n4,
    // checked_lexical_cast<target_type>(big_uint_t(n4).str(digits_to_print, f)), 0);
}
template<class big_uint_t, class num_t>
void test_mixed_numeric_limits(const std::integral_constant<bool, false>&) {}

template<class big_uint_t, class num_t>
void test_mixed(const std::integral_constant<bool, true>&) {
    typedef typename std::conditional<
        std::is_convertible<num_t, big_uint_t>::value,
        typename std::conditional<std::is_integral<num_t>::value &&
                                      (sizeof(num_t) < sizeof(int)),
                                  int, num_t>::type,
        big_uint_t>::type cast_type;
    typedef typename std::conditional<std::is_convertible<num_t, big_uint_t>::value,
                                      num_t, big_uint_t>::type simple_cast_type;

    if (std::numeric_limits<big_uint_t>::is_specialized &&
        std::numeric_limits<big_uint_t>::is_bounded &&
        std::numeric_limits<big_uint_t>::digits < std::numeric_limits<num_t>::digits) {
        return;
    }

    std::cout << "Testing mixed arithmetic with type: " << typeid(big_uint_t).name()
              << " and " << typeid(num_t).name() << std::endl;
    static const int left_shift = std::numeric_limits<num_t>::digits - 1;
    num_t n1 = static_cast<num_t>(
        1uLL << ((left_shift < 63) && (left_shift > 0) ? left_shift : 10));
    num_t n2 = 1;
    num_t n3 = 0;
    num_t n4 = 20;
    num_t n5 = 8;

    test_comparisons<big_uint_t>(n1, n2, std::is_convertible<num_t, big_uint_t>());
    test_comparisons<big_uint_t>(n1, n3, std::is_convertible<num_t, big_uint_t>());
    test_comparisons<big_uint_t>(n1, n1, std::is_convertible<num_t, big_uint_t>());
    test_comparisons<big_uint_t>(n3, n1, std::is_convertible<num_t, big_uint_t>());
    test_comparisons<big_uint_t>(n2, n1, std::is_convertible<num_t, big_uint_t>());
    test_comparisons<big_uint_t>(n3, n3, std::is_convertible<num_t, big_uint_t>());

    // Default construct:
    BOOST_CHECK_EQUAL(big_uint_t(n1), static_cast<cast_type>(n1));
    BOOST_CHECK_EQUAL(big_uint_t(n2), static_cast<cast_type>(n2));
    BOOST_CHECK_EQUAL(big_uint_t(n3), static_cast<cast_type>(n3));
    BOOST_CHECK_EQUAL(big_uint_t(n4), static_cast<cast_type>(n4));
    BOOST_CHECK_EQUAL(static_cast<num_t>(big_uint_t(n1)), n1);
    BOOST_CHECK_EQUAL(static_cast<num_t>(big_uint_t(n2)), n2);
    BOOST_CHECK_EQUAL(static_cast<num_t>(big_uint_t(n3)), n3);
    BOOST_CHECK_EQUAL(static_cast<num_t>(big_uint_t(n4)), n4);
    // Again with expression templates:
    BOOST_CHECK_EQUAL(static_cast<num_t>(big_uint_t(n1) + 0), n1);
    BOOST_CHECK_EQUAL(static_cast<num_t>(big_uint_t(n2) + 0), n2);
    BOOST_CHECK_EQUAL(static_cast<num_t>(big_uint_t(n3) + 0), n3);
    BOOST_CHECK_EQUAL(static_cast<num_t>(big_uint_t(n4) + 0), n4);
    BOOST_CHECK_EQUAL(static_cast<cast_type>(n1), big_uint_t(n1));
    BOOST_CHECK_EQUAL(static_cast<cast_type>(n2), big_uint_t(n2));
    BOOST_CHECK_EQUAL(static_cast<cast_type>(n3), big_uint_t(n3));
    BOOST_CHECK_EQUAL(static_cast<cast_type>(n4), big_uint_t(n4));
    // Assignment:
    big_uint_t r(0);
    BOOST_CHECK(r != static_cast<cast_type>(n1));
    r = static_cast<simple_cast_type>(n1);
    BOOST_CHECK_EQUAL(r, static_cast<cast_type>(n1));
    r = static_cast<simple_cast_type>(n2);
    BOOST_CHECK_EQUAL(r, static_cast<cast_type>(n2));
    r = static_cast<simple_cast_type>(n3);
    BOOST_CHECK_EQUAL(r, static_cast<cast_type>(n3));
    r = static_cast<simple_cast_type>(n4);
    BOOST_CHECK_EQUAL(r, static_cast<cast_type>(n4));
    // Addition:
    r = static_cast<simple_cast_type>(n2);
    BOOST_CHECK_EQUAL(r + static_cast<simple_cast_type>(n4),
                      static_cast<cast_type>(n2 + n4));
    BOOST_CHECK_EQUAL(big_uint_t(r + static_cast<simple_cast_type>(n4)),
                      static_cast<cast_type>(n2 + n4));
    r += static_cast<simple_cast_type>(n4);
    BOOST_CHECK_EQUAL(r, static_cast<cast_type>(n2 + n4));
    // subtraction:
    r = static_cast<simple_cast_type>(n4);
    BOOST_CHECK_EQUAL(r - static_cast<simple_cast_type>(n5),
                      static_cast<cast_type>(n4 - n5));
    BOOST_CHECK_EQUAL(big_uint_t(r - static_cast<simple_cast_type>(n5)),
                      static_cast<cast_type>(n4 - n5));
    r -= static_cast<simple_cast_type>(n5);
    BOOST_CHECK_EQUAL(r, static_cast<cast_type>(n4 - n5));
    // Multiplication:
    r = static_cast<simple_cast_type>(n2);
    BOOST_CHECK_EQUAL(r * static_cast<simple_cast_type>(n4),
                      static_cast<cast_type>(n2 * n4));
    BOOST_CHECK_EQUAL(big_uint_t(r * static_cast<simple_cast_type>(n4)),
                      static_cast<cast_type>(n2 * n4));
    r *= static_cast<simple_cast_type>(n4);
    BOOST_CHECK_EQUAL(r, static_cast<cast_type>(n2 * n4));
    // Division:
    r = static_cast<simple_cast_type>(n1);
    BOOST_CHECK_EQUAL(r / static_cast<simple_cast_type>(n5),
                      static_cast<cast_type>(n1 / n5));
    BOOST_CHECK_EQUAL(big_uint_t(r / static_cast<simple_cast_type>(n5)),
                      static_cast<cast_type>(n1 / n5));
    r /= static_cast<simple_cast_type>(n5);
    BOOST_CHECK_EQUAL(r, static_cast<cast_type>(n1 / n5));
    //
    // special cases for full coverage:
    //
    r = static_cast<simple_cast_type>(n5) + big_uint_t(n4);
    BOOST_CHECK_EQUAL(r, static_cast<cast_type>(n4 + n5));
    r = static_cast<simple_cast_type>(n4) - big_uint_t(n5);
    BOOST_CHECK_EQUAL(r, static_cast<cast_type>(n4 - n5));
    r = static_cast<simple_cast_type>(n4) * big_uint_t(n5);
    BOOST_CHECK_EQUAL(r, static_cast<cast_type>(n4 * n5));
    r = static_cast<cast_type>(num_t(4) * n4) / big_uint_t(4);
    BOOST_CHECK_EQUAL(r, static_cast<cast_type>(n4));

    typedef std::integral_constant<
        bool, (!std::numeric_limits<num_t>::is_specialized ||
               std::numeric_limits<num_t>::is_signed) &&
                  (!std::numeric_limits<big_uint_t>::is_specialized ||
                   std::numeric_limits<big_uint_t>::is_signed)>
        signed_tag;

    test_negative_mixed<big_uint_t, num_t>(signed_tag());

    n1 = 2;
    n2 = 3;
    n3 = 4;
    big_uint_t a(n1), b(n2), c(n3), d;
    d = a + b * c;
    BOOST_CHECK_EQUAL(d, 2 + 3 * 4);
    d = static_cast<cast_type>(n1) + b * c;
    BOOST_CHECK_EQUAL(d, 2 + 3 * 4);
    d = a + static_cast<cast_type>(n2) * c;
    BOOST_CHECK_EQUAL(d, 2 + 3 * 4);
    d = a + b * static_cast<cast_type>(n3);
    BOOST_CHECK_EQUAL(d, 2 + 3 * 4);
    d = static_cast<cast_type>(n1) + static_cast<cast_type>(n2) * c;
    BOOST_CHECK_EQUAL(d, 2 + 3 * 4);
    d = static_cast<cast_type>(n1) + b * static_cast<cast_type>(n3);
    BOOST_CHECK_EQUAL(d, 2 + 3 * 4);
    a += static_cast<cast_type>(n2) * c;
    BOOST_CHECK_EQUAL(a, 2 + 3 * 4);
    a = static_cast<cast_type>(n1);
    a += b * static_cast<cast_type>(n3);
    BOOST_CHECK_EQUAL(a, 2 + 3 * 4);
    a = static_cast<cast_type>(n1);

    d = b * c + a;
    BOOST_CHECK_EQUAL(d, 2 + 3 * 4);
    d = b * c + static_cast<cast_type>(n1);
    BOOST_CHECK_EQUAL(d, 2 + 3 * 4);
    d = static_cast<cast_type>(n2) * c + a;
    BOOST_CHECK_EQUAL(d, 2 + 3 * 4);
    d = b * static_cast<cast_type>(n3) + a;
    BOOST_CHECK_EQUAL(d, 2 + 3 * 4);
    d = static_cast<cast_type>(n2) * c + static_cast<cast_type>(n1);
    BOOST_CHECK_EQUAL(d, 2 + 3 * 4);
    d = b * static_cast<cast_type>(n3) + static_cast<cast_type>(n1);
    BOOST_CHECK_EQUAL(d, 2 + 3 * 4);

    a = 20;
    d = a - b * c;
    BOOST_CHECK_EQUAL(d, 20 - 3 * 4);
    n1 = 20;
    d = static_cast<cast_type>(n1) - b * c;
    BOOST_CHECK_EQUAL(d, 20 - 3 * 4);
    d = a - static_cast<cast_type>(n2) * c;
    BOOST_CHECK_EQUAL(d, 20 - 3 * 4);
    d = a - b * static_cast<cast_type>(n3);
    BOOST_CHECK_EQUAL(d, 20 - 3 * 4);
    d = static_cast<cast_type>(n1) - static_cast<cast_type>(n2) * c;
    BOOST_CHECK_EQUAL(d, 20 - 3 * 4);
    d = static_cast<cast_type>(n1) - b * static_cast<cast_type>(n3);
    BOOST_CHECK_EQUAL(d, 20 - 3 * 4);
    a -= static_cast<cast_type>(n2) * c;
    BOOST_CHECK_EQUAL(a, 20 - 3 * 4);
    a = static_cast<cast_type>(n1);
    a -= b * static_cast<cast_type>(n3);
    BOOST_CHECK_EQUAL(a, 20 - 3 * 4);

    a = 2;
    d = b * c - a;
    BOOST_CHECK_EQUAL(d, 3 * 4 - 2);
    n1 = 2;
    d = b * c - static_cast<cast_type>(n1);
    BOOST_CHECK_EQUAL(d, 3 * 4 - 2);
    d = static_cast<cast_type>(n2) * c - a;
    BOOST_CHECK_EQUAL(d, 3 * 4 - 2);
    d = b * static_cast<cast_type>(n3) - a;
    BOOST_CHECK_EQUAL(d, 3 * 4 - a);
    d = static_cast<cast_type>(n2) * c - static_cast<cast_type>(n1);
    BOOST_CHECK_EQUAL(d, 3 * 4 - 2);
    d = b * static_cast<cast_type>(n3) - static_cast<cast_type>(n1);
    BOOST_CHECK_EQUAL(d, 3 * 4 - 2);

    test_mixed_numeric_limits<big_uint_t, num_t>(
        std::integral_constant<bool, std::numeric_limits<big_uint_t>::is_specialized>());
}

template<class big_uint_t>
void test_members(big_uint_t) {
    //
    // Test sign and zero functions:
    //
    big_uint_t a = 20;
    big_uint_t b = 30;
    // BOOST_CHECK(a.sign() > 0);
    BOOST_CHECK(!a.is_zero());
    // if (std::numeric_limits<big_uint_t>::is_signed) {
    //     a = -20;
    //     BOOST_CHECK(a.sign() < 0);
    //     BOOST_CHECK(!a.is_zero());
    // }
    a = 0;
    // BOOST_CHECK_EQUAL(a.sign(), 0);
    BOOST_CHECK(a.is_zero());

    // a = 20;
    // b = 30;
    // a.swap(b);
    // BOOST_CHECK_EQUAL(a, 30);
    // BOOST_CHECK_EQUAL(b, 20);
}

template<class big_uint_t>
void test_signed_ops(const std::integral_constant<bool, true>&) {
    big_uint_t a(8);
    big_uint_t b(64);
    big_uint_t c(500);
    big_uint_t d(1024);
    big_uint_t ac;
    BOOST_CHECK_EQUAL(-a, -8);
    ac = a;
    ac = ac - b;
    BOOST_CHECK_EQUAL(ac, 8 - 64);
    ac = a;
    ac -= a + b;
    BOOST_CHECK_EQUAL(ac, -64);
    ac = a;
    ac -= b - a;
    BOOST_CHECK_EQUAL(ac, 16 - 64);
    ac = -a;
    BOOST_CHECK_EQUAL(ac, -8);
    ac = a;
    ac -= -a;
    BOOST_CHECK_EQUAL(ac, 16);
    ac = a;
    ac += -a;
    BOOST_CHECK_EQUAL(ac, 0);
    ac = b;
    ac /= -a;
    BOOST_CHECK_EQUAL(ac, -8);
    ac = a;
    ac *= -a;
    BOOST_CHECK_EQUAL(ac, -64);
    ac = a + -b;
    BOOST_CHECK_EQUAL(ac, 8 - 64);
    ac = -a + b;
    BOOST_CHECK_EQUAL(ac, -8 + 64);
    ac = -a + -b;
    BOOST_CHECK_EQUAL(ac, -72);
    ac = a + -+-b;  // lots of unary operators!!
    BOOST_CHECK_EQUAL(ac, 72);
    test_conditional(big_uint_t(-a), -a);

    //
    // Rval_tue ref tests:
    //
    a = 3;
    b = 4;
    c = big_uint_t(20) + -(a + b);
    BOOST_CHECK_EQUAL(c, 13);
    c = big_uint_t(20) + -a;
    BOOST_CHECK_EQUAL(c, 17);
    c = -a + big_uint_t(20);
    BOOST_CHECK_EQUAL(c, 17);
    c = -a + b;
    BOOST_CHECK_EQUAL(c, 1);
    c = b + -a;
    BOOST_CHECK_EQUAL(c, 1);
    a = 2;
    b = 3;
    c = big_uint_t(10) - a;
    BOOST_CHECK_EQUAL(c, 8);
    c = a - big_uint_t(2);
    BOOST_CHECK_EQUAL(c, 0);
    c = big_uint_t(3) - big_uint_t(2);
    BOOST_CHECK_EQUAL(c, 1);
    a = 20;
    c = a - (a + b);
    BOOST_CHECK_EQUAL(c, -3);
    a = 2;
    c = (a * b) - (a + b);
    BOOST_CHECK_EQUAL(c, 1);
    c = big_uint_t(20) - -(a + b);
    BOOST_CHECK_EQUAL(c, 25);
    c = big_uint_t(20) - (-a);
    BOOST_CHECK_EQUAL(c, 22);
    c = (-b) - big_uint_t(-5);
    BOOST_CHECK_EQUAL(c, 2);
    c = (-b) - a;
    BOOST_CHECK_EQUAL(c, -5);
    c = b - (-a);
    BOOST_CHECK_EQUAL(c, 5);
    c = big_uint_t(3) * -(a + b);
    BOOST_CHECK_EQUAL(c, -15);
    c = -(a + b) * big_uint_t(3);
    BOOST_CHECK_EQUAL(c, -15);
    c = big_uint_t(2) * -a;
    BOOST_CHECK_EQUAL(c, -4);
    c = -a * big_uint_t(2);
    BOOST_CHECK_EQUAL(c, -4);
    c = -a * b;
    BOOST_CHECK_EQUAL(c, -6);
    a = 2;
    b = 4;
    c = big_uint_t(4) / -a;
    BOOST_CHECK_EQUAL(c, -2);
    c = -b / big_uint_t(2);
    BOOST_CHECK_EQUAL(c, -2);
    c = big_uint_t(4) / -(2 * a);
    BOOST_CHECK_EQUAL(c, -1);
    c = b / -(2 * a);
    BOOST_CHECK_EQUAL(c, -1);
    c = -(2 * a) / big_uint_t(2);
    BOOST_CHECK_EQUAL(c, -2);
}
template<class big_uint_t>
void test_signed_ops(const std::integral_constant<bool, false>&) {}

template<class big_uint_t>
void test_basic_conditionals(big_uint_t a, big_uint_t b) {
    if (a) {
        BOOST_ERROR("Unexpected non-zero result");
    }
    if (!a) {
    } else {
        BOOST_ERROR("Unexpected zero result");
    }
    b = 2;
    if (!b) {
        BOOST_ERROR("Unexpected zero result");
    }
    if (b) {
    } else {
        BOOST_ERROR("Unexpected non-zero result");
    }
    if (a && b) {
        BOOST_ERROR("Unexpected zero result");
    }
    if (!(a || b)) {
        BOOST_ERROR("Unexpected zero result");
    }
    if (a + b) {
    } else {
        BOOST_ERROR("Unexpected zero result");
    }
    if (b - 2) {
        BOOST_ERROR("Unexpected non-zero result");
    }
}

template<class T>
void test_relationals(T a, T b) {
    BOOST_CHECK_EQUAL((a == b), false);
    BOOST_CHECK_EQUAL((a != b), true);
    BOOST_CHECK_EQUAL((a <= b), true);
    BOOST_CHECK_EQUAL((a < b), true);
    BOOST_CHECK_EQUAL((a >= b), false);
    BOOST_CHECK_EQUAL((a > b), false);

    BOOST_CHECK_EQUAL((a + b == b), false);
    BOOST_CHECK_EQUAL((a + b != b), true);
    BOOST_CHECK_EQUAL((a + b >= b), true);
    BOOST_CHECK_EQUAL((a + b > b), true);
    BOOST_CHECK_EQUAL((a + b <= b), false);
    BOOST_CHECK_EQUAL((a + b < b), false);

    BOOST_CHECK_EQUAL((a == b + a), false);
    BOOST_CHECK_EQUAL((a != b + a), true);
    BOOST_CHECK_EQUAL((a <= b + a), true);
    BOOST_CHECK_EQUAL((a < b + a), true);
    BOOST_CHECK_EQUAL((a >= b + a), false);
    BOOST_CHECK_EQUAL((a > b + a), false);

    BOOST_CHECK_EQUAL((a + b == b + a), true);
    BOOST_CHECK_EQUAL((a + b != b + a), false);
    BOOST_CHECK_EQUAL((a + b <= b + a), true);
    BOOST_CHECK_EQUAL((a + b < b + a), false);
    BOOST_CHECK_EQUAL((a + b >= b + a), true);
    BOOST_CHECK_EQUAL((a + b > b + a), false);

    BOOST_CHECK_EQUAL((8 == b + a), false);
    BOOST_CHECK_EQUAL((8 != b + a), true);
    BOOST_CHECK_EQUAL((8 <= b + a), true);
    BOOST_CHECK_EQUAL((8 < b + a), true);
    BOOST_CHECK_EQUAL((8 >= b + a), false);
    BOOST_CHECK_EQUAL((8 > b + a), false);
    BOOST_CHECK_EQUAL((800 == b + a), false);
    BOOST_CHECK_EQUAL((800 != b + a), true);
    BOOST_CHECK_EQUAL((800 >= b + a), true);
    BOOST_CHECK_EQUAL((800 > b + a), true);
    BOOST_CHECK_EQUAL((800 <= b + a), false);
    BOOST_CHECK_EQUAL((800 < b + a), false);
    BOOST_CHECK_EQUAL((72 == b + a), true);
    BOOST_CHECK_EQUAL((72 != b + a), false);
    BOOST_CHECK_EQUAL((72 <= b + a), true);
    BOOST_CHECK_EQUAL((72 < b + a), false);
    BOOST_CHECK_EQUAL((72 >= b + a), true);
    BOOST_CHECK_EQUAL((72 > b + a), false);

    BOOST_CHECK_EQUAL((b + a == 8), false);
    BOOST_CHECK_EQUAL((b + a != 8), true);
    BOOST_CHECK_EQUAL((b + a >= 8), true);
    BOOST_CHECK_EQUAL((b + a > 8), true);
    BOOST_CHECK_EQUAL((b + a <= 8), false);
    BOOST_CHECK_EQUAL((b + a < 8), false);
    BOOST_CHECK_EQUAL((b + a == 800), false);
    BOOST_CHECK_EQUAL((b + a != 800), true);
    BOOST_CHECK_EQUAL((b + a <= 800), true);
    BOOST_CHECK_EQUAL((b + a < 800), true);
    BOOST_CHECK_EQUAL((b + a >= 800), false);
    BOOST_CHECK_EQUAL((b + a > 800), false);
    BOOST_CHECK_EQUAL((b + a == 72), true);
    BOOST_CHECK_EQUAL((b + a != 72), false);
    BOOST_CHECK_EQUAL((b + a >= 72), true);
    BOOST_CHECK_EQUAL((b + a > 72), false);
    BOOST_CHECK_EQUAL((b + a <= 72), true);
    BOOST_CHECK_EQUAL((b + a < 72), false);

    T c;
    //
    // min and max overloads:
    //
#if !defined(min) && !defined(max)
    //   using std::max;
    //   using std::min;
    // This works, but still causes complaints from inspect.exe, so use brackets to
    // prevent macrosubstitution, and to explicitly specify type T seems necessary, for
    // reasons unclear.
    a = 2;
    b = 5;
    c = 6;
    BOOST_CHECK_EQUAL((std::min<T>)(a, b), a);
    BOOST_CHECK_EQUAL((std::min<T>)(b, a), a);
    BOOST_CHECK_EQUAL((std::max<T>)(a, b), b);
    BOOST_CHECK_EQUAL((std::max<T>)(b, a), b);
    BOOST_CHECK_EQUAL((std::min<T>)(a, b + c), a);
    BOOST_CHECK_EQUAL((std::min<T>)(b + c, a), a);
    BOOST_CHECK_EQUAL((std::min<T>)(a, c - b), 1);
    BOOST_CHECK_EQUAL((std::min<T>)(c - b, a), 1);
    BOOST_CHECK_EQUAL((std::max<T>)(a, b + c), 11);
    BOOST_CHECK_EQUAL((std::max<T>)(b + c, a), 11);
    BOOST_CHECK_EQUAL((std::max<T>)(a, c - b), a);
    BOOST_CHECK_EQUAL((std::max<T>)(c - b, a), a);
    BOOST_CHECK_EQUAL((std::min<T>)(a + b, b + c), 7);
    BOOST_CHECK_EQUAL((std::min<T>)(b + c, a + b), 7);
    BOOST_CHECK_EQUAL((std::max<T>)(a + b, b + c), 11);
    BOOST_CHECK_EQUAL((std::max<T>)(b + c, a + b), 11);
    BOOST_CHECK_EQUAL((std::min<T>)(a + b, c - a), 4);
    BOOST_CHECK_EQUAL((std::min<T>)(c - a, a + b), 4);
    BOOST_CHECK_EQUAL((std::max<T>)(a + b, c - a), 7);
    BOOST_CHECK_EQUAL((std::max<T>)(c - a, a + b), 7);

    long l1(2), l2(3);
    long l3 = (std::min)(l1, l2) + (std::max)(l1, l2) + (std::max<long>)(l1, l2) +
              (std::min<long>)(l1, l2);
    BOOST_CHECK_EQUAL(l3, 10);

#endif
}

template<class T>
const T& self(const T& a) {
    return a;  // NOLINT
}

template<class big_uint_t>
void test() {
#if !defined(NO_MIXED_OPS) && !defined(SLOW_COMPILER)
    std::integral_constant<bool, true> tag;
    test_mixed<big_uint_t, unsigned char>(tag);
    test_mixed<big_uint_t, signed char>(tag);
    test_mixed<big_uint_t, char>(tag);
    test_mixed<big_uint_t, short>(tag);
    test_mixed<big_uint_t, unsigned short>(tag);
    test_mixed<big_uint_t, int>(tag);
    test_mixed<big_uint_t, unsigned int>(tag);
    test_mixed<big_uint_t, long>(tag);
    test_mixed<big_uint_t, unsigned long>(tag);
#ifdef BOOST_HAS_LONG_LONG
    test_mixed<big_uint_t, long long>(tag);
    test_mixed<big_uint_t, unsigned long long>(tag);
#endif

#endif
#ifndef MIXED_OPS_ONLY
    //
    // Integer only functions:
    //
    test_integer_ops<big_uint_t>();
    //
    // Test basic arithmetic:
    //
    big_uint_t a(8);
    big_uint_t b(64);
    big_uint_t c(500);
    big_uint_t d(1024);
    BOOST_CHECK_EQUAL(a + b, 72);
    a += b;
    BOOST_CHECK_EQUAL(a, 72);
    BOOST_CHECK_EQUAL(a - b, 8);
    a -= b;
    BOOST_CHECK_EQUAL(a, 8);
    BOOST_CHECK_EQUAL(a * b, 8 * 64L);
    a *= b;
    BOOST_CHECK_EQUAL(a, 8 * 64L);
    BOOST_CHECK_EQUAL(a / b, 8);
    a /= b;
    BOOST_CHECK_EQUAL(a, 8);
    big_uint_t ac(a);
    BOOST_CHECK_EQUAL(ac, a);
    ac = a * c;
    BOOST_CHECK_EQUAL(ac, 8 * 500L);
    ac = 8 * 500L;
    ac = ac + b + c;
    BOOST_CHECK_EQUAL(ac, 8 * 500L + 64 + 500);
    ac = a;
    ac = b + c + ac;
    BOOST_CHECK_EQUAL(ac, 8 + 64 + 500);
    ac = ac - b + c;
    BOOST_CHECK_EQUAL(ac, 8 + 64 + 500 - 64 + 500);
    ac = a;
    ac = b + c - ac;
    BOOST_CHECK_EQUAL(ac, -8 + 64 + 500);
    ac = a;
    ac = ac * b;
    BOOST_CHECK_EQUAL(ac, 8 * 64);
    ac = a;
    ac *= b * ac;
    BOOST_CHECK_EQUAL(ac, 8 * 8 * 64);
    ac = b;
    ac = ac / a;
    BOOST_CHECK_EQUAL(ac, 64 / 8);
    ac = b;
    ac /= ac / a;
    BOOST_CHECK_EQUAL(ac, 64 / (64 / 8));
    ac = a;
    ac = b + ac * a;
    BOOST_CHECK_EQUAL(ac, 64 * 2);
    ac = a;
    ac = b - ac * a;
    BOOST_CHECK_EQUAL(ac, 0);
    ac = a;
    ac = b * (ac + a);
    BOOST_CHECK_EQUAL(ac, 64 * (16));
    ac = a;
    ac = b / (ac * 1);
    BOOST_CHECK_EQUAL(ac, 64 / 8);
    ac = a;
    ac = ac + b;
    BOOST_CHECK_EQUAL(ac, 8 + 64);
    ac = a;
    ac = a + ac;
    BOOST_CHECK_EQUAL(ac, 16);
    ac = a;
    ac = a - ac;
    BOOST_CHECK_EQUAL(ac, 0);
    ac = a;
    ac += a + b;
    BOOST_CHECK_EQUAL(ac, 80);
    ac = a;
    ac += b + a;
    BOOST_CHECK_EQUAL(ac, 80);
    ac = +a;
    BOOST_CHECK_EQUAL(ac, 8);
    ac = 8;
    ac = a * ac;
    BOOST_CHECK_EQUAL(ac, 8 * 8);
    ac = a;
    ac = a;
    ac += +a;
    BOOST_CHECK_EQUAL(ac, 16);
    ac = a;
    ac += b - a;
    BOOST_CHECK_EQUAL(ac, 8 + 64 - 8);
    ac = a;
    ac += b * c;
    BOOST_CHECK_EQUAL(ac, 8 + 64 * 500);
    ac = a;
    ac = a;
    ac -= +a;
    BOOST_CHECK_EQUAL(ac, 0);
    ac = a;
    if (std::numeric_limits<big_uint_t>::is_signed ||
        is_twos_complement_integer<big_uint_t>::value) {
        ac = a;
        ac -= c - b;
        BOOST_CHECK_EQUAL(ac, 8 - (500 - 64));
        ac = a;
        ac -= b * c;
        BOOST_CHECK_EQUAL(ac, 8 - 500 * 64);
    }
    ac = a;
    ac += ac * b;
    BOOST_CHECK_EQUAL(ac, 8 + 8 * 64);
    if (std::numeric_limits<big_uint_t>::is_signed ||
        is_twos_complement_integer<big_uint_t>::value) {
        ac = a;
        ac -= ac * b;
        BOOST_CHECK_EQUAL(ac, 8 - 8 * 64);
    }
    ac = a * 8;
    ac *= +a;
    BOOST_CHECK_EQUAL(ac, 64 * 8);
    ac = a;
    ac *= b * c;
    BOOST_CHECK_EQUAL(ac, 8 * 64 * 500);
    ac = a;
    ac *= b / a;
    BOOST_CHECK_EQUAL(ac, 8 * 64 / 8);
    ac = a;
    ac *= b + c;
    BOOST_CHECK_EQUAL(ac, 8 * (64 + 500));
    ac = b;
    ac /= +a;
    BOOST_CHECK_EQUAL(ac, 8);
    ac = b;
    ac /= b / a;
    BOOST_CHECK_EQUAL(ac, 64 / (64 / 8));
    ac = b;
    ac /= a + big_uint_t(0);
    BOOST_CHECK_EQUAL(ac, 8);
    //
    // simple tests with immediate values, these calls can be optimised in many backends:
    //
    ac = a + b;
    BOOST_CHECK_EQUAL(ac, 72);
    ac = a + +b;
    BOOST_CHECK_EQUAL(ac, 72);
    ac = +a + b;
    BOOST_CHECK_EQUAL(ac, 72);
    ac = +a + +b;
    BOOST_CHECK_EQUAL(ac, 72);
    ac = a;
    ac = b / ac;
    BOOST_CHECK_EQUAL(ac, b / a);
    //
    // Comparisons:
    //
    test_relationals(a, b);
    test_members(a);
    //
    // Use in Boolean context:
    //
    a = 0;
    b = 2;
    test_basic_conditionals(a, b);
    //
    // Test iostreams:
    //
    std::stringstream ss;
    a = 20;
    b = 2;
    ss << a;
    ss >> c;
    BOOST_CHECK_EQUAL(a, c);
    ss.clear();
    ss << a + b;
    ss >> c;
    BOOST_CHECK_EQUAL(c, 22);
    BOOST_CHECK_EQUAL(c, a + b);
    //
    // More cases for complete code coverage:
    //
    a = 20;
    b = 30;
    using std::swap;
    swap(a, b);
    BOOST_CHECK_EQUAL(a, 30);
    BOOST_CHECK_EQUAL(b, 20);
    a = 20;
    b = 30;
    std::swap(a, b);
    BOOST_CHECK_EQUAL(a, 30);
    BOOST_CHECK_EQUAL(b, 20);
    a = 20;
    b = 30;
    a = a + b * 2;
    BOOST_CHECK_EQUAL(a, 20 + 30 * 2);
    a = 100;
    a = a - b * 2;
    BOOST_CHECK_EQUAL(a, 100 - 30 * 2);
    a = 20;
    a = a * (b + 2);
    BOOST_CHECK_EQUAL(a, 20 * (32));
    a = 20;
    a = (b + 2) * a;
    BOOST_CHECK_EQUAL(a, 20 * (32));
    a = 90;
    b = 2;
    a = a / (b + 0);
    BOOST_CHECK_EQUAL(a, 45);
    a = 20;
    b = 30;
    c = (a * b) + 22;
    BOOST_CHECK_EQUAL(c, 20 * 30 + 22);
    c = 22 + (a * b);
    BOOST_CHECK_EQUAL(c, 20 * 30 + 22);
    c = 10;
    ac = a + b * c;
    BOOST_CHECK_EQUAL(ac, 20 + 30 * 10);
    ac = b * c + a;
    BOOST_CHECK_EQUAL(ac, 20 + 30 * 10);
    a = a + b * c;
    BOOST_CHECK_EQUAL(a, 20 + 30 * 10);
    a = 20;
    b = a + b * c;
    BOOST_CHECK_EQUAL(b, 20 + 30 * 10);
    b = 30;
    c = a + b * c;
    BOOST_CHECK_EQUAL(c, 20 + 30 * 10);
    c = 10;
    c = a + b / c;
    BOOST_CHECK_EQUAL(c, 20 + 30 / 10);
    //
    // Additional tests for rvalue ref overloads:
    //
    a = 3;
    b = 4;
    c = big_uint_t(2) + a;
    BOOST_CHECK_EQUAL(c, 5);
    c = a + big_uint_t(2);
    BOOST_CHECK_EQUAL(c, 5);
    c = big_uint_t(3) + big_uint_t(2);
    BOOST_CHECK_EQUAL(c, 5);
    c = big_uint_t(2) + (a + b);
    BOOST_CHECK_EQUAL(c, 9);
    c = (a + b) + big_uint_t(2);
    BOOST_CHECK_EQUAL(c, 9);
    c = (a + b) + (a + b);
    BOOST_CHECK_EQUAL(c, 14);
    c = a * big_uint_t(4);
    BOOST_CHECK_EQUAL(c, 12);
    c = big_uint_t(3) * big_uint_t(4);
    BOOST_CHECK_EQUAL(c, 12);
    c = (a + b) * (a + b);
    BOOST_CHECK_EQUAL(c, 49);
    a = 2;
    c = b / big_uint_t(2);
    BOOST_CHECK_EQUAL(c, 2);
    c = big_uint_t(4) / a;
    BOOST_CHECK_EQUAL(c, 2);
    c = big_uint_t(4) / big_uint_t(2);
    BOOST_CHECK_EQUAL(c, 2);
    //
    // Test conditionals:
    //
    a = 20;
    test_conditional(a, +a);
    test_conditional(a, (a + 0));

    test_signed_ops<big_uint_t>(
        std::integral_constant<bool, std::numeric_limits<big_uint_t>::is_signed>());
    //
    // Test hashing:
    //
    boost::hash<big_uint_t> hasher;
    std::size_t s = hasher(a);
    BOOST_CHECK_NE(s, 0);
    std::hash<big_uint_t> hasher2;
    s = hasher2(a);
    BOOST_CHECK_NE(s, 0);

    //
    // Test move:
    //
    big_uint_t m(static_cast<big_uint_t&&>(a));
    BOOST_CHECK_EQUAL(m, 20);
    // Move from already moved from object:
    big_uint_t m2(static_cast<big_uint_t&&>(a));
    // assign from moved from object
    // (may result in "a" being left in valid state as implementation artifact):
    c = static_cast<big_uint_t&&>(a);
    // assignment to moved-from objects:
    c = static_cast<big_uint_t&&>(m);
    BOOST_CHECK_EQUAL(c, 20);
    m2 = c;
    BOOST_CHECK_EQUAL(c, 20);
    // Destructor of "a" checks destruction of moved-from-object...
    big_uint_t m3(static_cast<big_uint_t&&>(a));
#ifndef BOOST_MP_NOT_TESTING_NUMBER
    //
    // string and string_view:
    //
    {
        std::string s1("2");
        big_uint_t x(s1);
        BOOST_CHECK_EQUAL(x, 2);
        s1 = "3";
        // x.assign(s1);
        x = s1;
        BOOST_CHECK_EQUAL(x, 3);
#ifndef BOOST_NO_CXX17_HDR_STRING_VIEW
        s1 = "20";
        std::string_view v(s1.c_str(), 1);
        big_uint_t y(v);
        BOOST_CHECK_EQUAL(y, 2);
        std::string_view v2(s1.c_str(), 2);
        // y.assign(v2);
        y = v2;
        BOOST_CHECK_EQUAL(y, 20);
#endif
    }
#endif
    //
    // Bug cases, self assignment first:
    //
    a = 20;
    a = self(a);
    BOOST_CHECK_EQUAL(a, 20);

    a = 2;
    a = a * a * a;
    BOOST_CHECK_EQUAL(a, 8);
    a = 2;
    a = a + a + a;
    BOOST_CHECK_EQUAL(a, 6);
    a = 2;
    a = a - a + a;  // NOLINT
    BOOST_CHECK_EQUAL(a, 2);
    a = 2;
    a = a + a - a;
    BOOST_CHECK_EQUAL(a, 2);
    a = 2;
    a = a * a - a;
    BOOST_CHECK_EQUAL(a, 2);
    a = 2;
    a = a + a * a;
    BOOST_CHECK_EQUAL(a, 6);
    a = 2;
    a = (a + a) * a;
    BOOST_CHECK_EQUAL(a, 8);
#endif
}

BOOST_AUTO_TEST_CASE(boost_arithmetic_big_uint_test) {
    test<nil::crypto3::multiprecision::big_uint<31>>();
    test<nil::crypto3::multiprecision::big_uint<110>>();
    test<nil::crypto3::multiprecision::big_uint<254>>();
    test<nil::crypto3::multiprecision::big_uint<255>>();
    test<nil::crypto3::multiprecision::big_uint<256>>();
    test<nil::crypto3::multiprecision::big_uint<504>>();
    test<nil::crypto3::multiprecision::big_uint<512>>();
}
