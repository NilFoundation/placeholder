//---------------------------------------------------------------------------//
// Copyright (c) 2024 Andrey Nefedov <ioxid@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#pragma once

#include <climits>
#include <cmath>
#include <cstring>
#include <functional>
#include <ios>
#include <ostream>
#include <string>
#include <type_traits>

#include <boost/assert.hpp>
#include <boost/functional/hash.hpp>

#include "nil/crypto3/multiprecision/big_uint.hpp"
#include "nil/crypto3/multiprecision/detail/config.hpp"

namespace nil::crypto3::multiprecision {
    /**
     * @brief Big signed integer type
     *
     * @tparam Bits Number of bits, not including the sign bit
     *
     * @details
     * The sign bit is stored separately from the rest of the integer.
     *
     * @note
     * Unlike big_uint does not implement all arithmetic operations with all basic types.
     * It is only used internally for extended euclidean algorithm. It should be pretty
     * optimized for the use case, e.g. no unnecessary copying.
     */
    template<std::size_t Bits_>
    class big_int {
      public:
        static constexpr std::size_t Bits = Bits_;

        using unsigned_type = big_uint<Bits>;

        // Constructor

        constexpr big_int() noexcept {}

        template<std::size_t Bits2>
        constexpr big_int(const big_uint<Bits2>& b) : m_abs(b) {}

        template<class T, std::enable_if_t<std::is_integral_v<T> && std::is_signed_v<T>, int> = 0>
        constexpr big_int(T val) : m_abs(unsigned_abs(val)) {
            if (val < 0) {
                negate();
            }
        }

        template<class T, std::enable_if_t<std::is_integral_v<T> && std::is_unsigned_v<T>, int> = 0>
        constexpr big_int(T val) : m_abs(val) {}

        template<std::size_t Bits2>
        constexpr big_int(const big_int<Bits2>& other)
            : m_negative(other.negative()), m_abs(other.abs()) {}

        // Assignment

        template<std::size_t Bits2>
        constexpr big_int& operator=(const big_uint<Bits2>& b) {
            m_negative = false;
            m_abs = b;
        }

        template<std::size_t Bits2>
        constexpr big_int& operator=(const big_int<Bits2>& other) {
            m_negative = other.negative();
            m_abs = other.abs();
            return *this;
        }

        template<typename T,
                 std::enable_if_t<std::is_integral_v<T> && std::is_signed_v<T>, int> = 0>
        constexpr big_int& operator=(T val) {
            m_negative = false;
            m_abs = unsigned_abs(val);
            if (val < 0) {
                negate();
            }
            return *this;
        }

        template<typename T,
                 std::enable_if_t<std::is_integral_v<T> && std::is_unsigned_v<T>, int> = 0>
        constexpr big_int& operator=(T val) {
            m_negative = false;
            m_abs = val;
            return *this;
        }

        constexpr std::string str(std::ios_base::fmtflags flags = std::ios_base::dec) const {
            return (negative() ? std::string("-") : std::string("")) + m_abs.str(flags);
        }

        template<std::size_t Bits2, std::enable_if_t<(Bits2 < Bits), int> = 0>
        constexpr big_int<Bits2> truncate() const noexcept {
            return {m_negative, m_abs.template truncate<Bits2>()};
        }

        // Cast to integral types

        template<typename T, std::enable_if_t<std::is_integral_v<T>, int> = 0>
        explicit constexpr operator T() const {
            return multiplied_by_sign(static_cast<T>(abs()));
        }

        template<std::size_t Bits2>
        explicit constexpr operator big_uint<Bits2>() const {
            BOOST_ASSERT(!this->negative());
            return m_abs;
        }

        // Utilities

        constexpr bool negative() const { return m_negative; }

        constexpr int sign() const noexcept { return negative() ? -1 : (m_abs.is_zero() ? 0 : 1); }

        constexpr const unsigned_type& abs() const { return m_abs; }

        constexpr void negate() {
            if (m_abs.is_zero()) {
                return;
            }
            m_negative = !m_negative;
        }

        // Comparison

        template<std::size_t Bits2>
        constexpr int compare(const big_int<Bits2>& other) const noexcept {
            if (negative() && !other.negative()) {
                return -1;
            }
            if (!negative() && other.negative()) {
                return 1;
            }
            if (negative() && other.negative()) {
                return other.m_abs.compare(this->m_abs);
            }
            return this->m_abs.compare(other.m_abs);
        }

#define NIL_CO3_MP_BIG_INT_IMPL_OPERATOR(op)                                         \
    friend constexpr bool operator op(const big_int& a, const big_int& b) noexcept { \
        return a.compare(b) op 0;                                                    \
    }

        NIL_CO3_MP_BIG_INT_IMPL_OPERATOR(<)
        NIL_CO3_MP_BIG_INT_IMPL_OPERATOR(<=)
        NIL_CO3_MP_BIG_INT_IMPL_OPERATOR(>)
        NIL_CO3_MP_BIG_INT_IMPL_OPERATOR(>=)
        NIL_CO3_MP_BIG_INT_IMPL_OPERATOR(==)
        NIL_CO3_MP_BIG_INT_IMPL_OPERATOR(!=)

#undef NIL_CO3_MP_BIG_INT_IMPL_OPERATOR

        NIL_CO3_MP_FORCEINLINE constexpr bool is_zero() const noexcept { return abs().is_zero(); }

        // Arithmetic operations

        friend constexpr big_int operator+(big_int a, const big_int& b) noexcept {
            a += b;
            return a;
        }

        friend constexpr auto& operator+=(big_int& a, const big_int& b) noexcept {
            if (a.negative() == b.negative()) {
                a.m_abs += b.m_abs;
                return a;
            }
            if (a.m_abs >= b.m_abs) {
                a.m_abs -= b.m_abs;
            } else {
                auto a_m_abs = a.m_abs;
                a.m_abs = b.m_abs;
                a.m_abs -= a_m_abs;
                a.negate();
            }
            return a;
        }

        constexpr auto& operator++() {
            if (negative()) {
                --m_abs;
                normalize();
                return *this;
            }
            ++m_abs;
            return *this;
        }

        friend constexpr auto operator++(big_int& a, int) {
            auto copy = a;
            ++a;
            return copy;
        }

        friend constexpr auto operator+(const big_int& a) noexcept { return a; }

        friend constexpr auto operator-(const big_int& a, const big_int& b) { return a + (-b); }

        friend constexpr auto& operator-=(big_int& a, const big_int& b) {
            a = a - b;
            return a;
        }

        constexpr auto& operator--() {
            if (negative()) {
                ++m_abs;
                return *this;
            }
            if (is_zero(m_abs)) {
                m_negative = true;
                ++m_abs;
                return *this;
            }
            --m_abs;
            return *this;
        }

        friend constexpr auto operator--(big_int& a, int) {
            auto copy = a;
            --a;
            return copy;
        }

        friend constexpr auto operator-(big_int a) noexcept {
            a.negate();
            return a;
        }

        friend constexpr auto operator*(const big_int& a, const big_int& b) {
            big_int result = a.m_abs * b.m_abs;
            if (a.sign() * b.sign() < 0) {
                result = -result;
            }
            return result;
        }

        friend constexpr auto& operator*=(big_int& a, const big_int& b) {
            a = a * b;
            return a;
        }

        friend constexpr auto operator/(const big_int& a, const big_int& b) {
            big_int result = a.m_abs / b.m_abs;
            if (a.negative() != b.negative()) {
                result.negate();
            }
            return result;
        }

        friend constexpr auto& operator/=(big_int& a, const big_int& b) {
            a = a / b;
            return a;
        }

        friend constexpr auto operator%(const big_int& a, const big_int& b) {
            big_int result = a.m_abs % b.m_abs;
            if (a.negative() != b.negative()) {
                result.negate();
            }
            return result;
        }

        friend constexpr auto& operator%=(big_int& a, const big_int& b) {
            a = a % b;
            return a;
        }

        // Hash

        friend constexpr std::size_t hash_value(const big_int& val) noexcept {
            std::size_t result = 0;
            boost::hash_combine(result, val.abs());
            boost::hash_combine(result, val.negative());
            return result;
        }

        // IO

        friend std::ostream& operator<<(std::ostream& os, const big_int& value) {
            os << value.str(os.flags());
            return os;
        }

      private:
        constexpr void normalize() noexcept {
            if (m_abs.is_zero()) {
                m_negative = false;
            }
        }

        template<typename T>
        constexpr void multiply_by_sign(T& a) const {
            if (negative()) {
                a = -a;
            }
        }
        template<typename T>
        constexpr T multiplied_by_sign(const T& a) const {
            if (negative()) {
                return -a;
            }
            return a;
        }

        bool m_negative = false;
        big_uint<Bits> m_abs;

        // Friends

        template<std::size_t Bits1, std::size_t Bits2>
        friend constexpr void divide_qr(const big_int<Bits1>& a, const big_int<Bits2>& b,
                                        big_int<Bits1>& q, big_int<Bits1>& r);
    };

    // For generic code

    template<std::size_t Bits>
    constexpr bool is_zero(const big_int<Bits>& a) {
        return a.is_zero();
    }

    // To efficiently compute quotient and remainder at the same time

    template<std::size_t Bits1, std::size_t Bits2>
    constexpr void divide_qr(const big_int<Bits1>& a, const big_int<Bits2>& b, big_int<Bits1>& q,
                             big_int<Bits1>& r) {
        detail::divide(&q.m_abs, a.m_abs, b.m_abs, r.m_abs);
        q.m_negative = false;
        r.m_negative = false;
        if (a.negative() != b.negative()) {
            q.negate();
            r.negate();
        }
    }
}  // namespace nil::crypto3::multiprecision

template<std::size_t Bits>
struct std::hash<nil::crypto3::multiprecision::big_int<Bits>> {
    std::size_t operator()(const nil::crypto3::multiprecision::big_int<Bits>& a) const noexcept {
        return boost::hash<nil::crypto3::multiprecision::big_int<Bits>>{}(a);
    }
};
