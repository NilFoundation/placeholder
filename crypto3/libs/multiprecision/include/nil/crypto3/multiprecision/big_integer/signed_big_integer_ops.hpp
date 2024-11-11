#pragma once

#include <algorithm>
#include <climits>
#include <cstring>
#include <ostream>
#include <type_traits>

#include "nil/crypto3/multiprecision/big_integer/big_integer.hpp"
#include "nil/crypto3/multiprecision/big_integer/signed_big_integer.hpp"

namespace nil::crypto3::multiprecision {
    namespace detail {
        template<typename T>
        constexpr bool is_signed_big_integer_v = false;

        template<unsigned Bits>
        constexpr bool is_signed_big_integer_v<signed_big_integer<Bits>> = true;

        template<typename T>
        constexpr bool is_signed_integral_v = is_integral_v<T> || is_signed_big_integer_v<T>;

        template<typename T, std::enable_if_t<is_signed_big_integer_v<T>, int> = 0>
        constexpr std::size_t get_bits() {
            return T::Bits;
        }
    }  // namespace detail

#define CRYPTO3_MP_SIGNED_BIG_INTEGER_INTEGRAL_TEMPLATE                                            \
    template<typename T1, typename T2,                                                             \
             std::enable_if_t<                                                                     \
                 detail::is_signed_integral_v<T1> && detail::is_signed_integral_v<T2> &&           \
                     (detail::is_signed_big_integer_v<T1> || detail::is_signed_big_integer_v<T2>), \
                 int> = 0,                                                                         \
             typename largest_t =                                                                  \
                 signed_big_integer<std::max(detail::get_bits<T1>(), detail::get_bits<T2>())>>

    // TODO(ioxid): somehow error on overflow
#define CRYPTO3_MP_SIGNED_BIG_INTEGER_INTEGRAL_ASSIGNMENT_TEMPLATE                     \
    template<typename signed_big_integer_t, typename T,                                \
             std::enable_if_t<detail::is_signed_big_integer_v<signed_big_integer_t> && \
                                  detail::is_signed_integral_v<T>,                     \
                              int> = 0>

#define CRYPTO3_MP_SIGNED_BIG_INTEGER_UNARY_TEMPLATE \
    template<typename signed_big_integer_t,          \
             std::enable_if_t<detail::is_signed_big_integer_v<signed_big_integer_t>, int> = 0>

    // Comparison

#define CRYPTO3_MP_SIGNED_BIG_INTEGER_IMPL_OPERATOR(op)                    \
    CRYPTO3_MP_SIGNED_BIG_INTEGER_INTEGRAL_TEMPLATE                        \
    inline constexpr bool operator op(const T1& a, const T2& b) noexcept { \
        largest_t ap = a;                                                  \
        largest_t bp = b;                                                  \
        return ap.compare(bp) op 0;                                        \
    }

    CRYPTO3_MP_SIGNED_BIG_INTEGER_IMPL_OPERATOR(<)
    CRYPTO3_MP_SIGNED_BIG_INTEGER_IMPL_OPERATOR(<=)
    CRYPTO3_MP_SIGNED_BIG_INTEGER_IMPL_OPERATOR(>)
    CRYPTO3_MP_SIGNED_BIG_INTEGER_IMPL_OPERATOR(>=)
    CRYPTO3_MP_SIGNED_BIG_INTEGER_IMPL_OPERATOR(==)
    CRYPTO3_MP_SIGNED_BIG_INTEGER_IMPL_OPERATOR(!=)

    // TODO(ioxid): implement comparison with signed types, needed for boost::random
#undef CRYPTO3_MP_SIGNED_BIG_INTEGER_IMPL_OPERATOR

    // Arithmetic operations

    CRYPTO3_MP_SIGNED_BIG_INTEGER_INTEGRAL_TEMPLATE
    inline constexpr auto operator+(const T1& a, const T2& b) noexcept {
        signed_big_integer<largest_t::Bits + 1> result;
        result = decltype(result)::add(a, b);
        return result;
    }
    CRYPTO3_MP_SIGNED_BIG_INTEGER_INTEGRAL_ASSIGNMENT_TEMPLATE
    inline constexpr auto& operator+=(signed_big_integer_t& a, const T& b) noexcept {
        a = a + b;
        return a;
    }
    CRYPTO3_MP_SIGNED_BIG_INTEGER_UNARY_TEMPLATE
    inline constexpr auto& operator++(signed_big_integer_t& a) noexcept {
        a.increment();
        return a;
    }
    CRYPTO3_MP_SIGNED_BIG_INTEGER_UNARY_TEMPLATE
    inline constexpr auto operator++(signed_big_integer_t& a, int) noexcept {
        auto copy = a;
        ++a;
        return copy;
    }
    CRYPTO3_MP_SIGNED_BIG_INTEGER_UNARY_TEMPLATE
    inline constexpr auto operator+(const signed_big_integer_t& a) noexcept { return a; }

    CRYPTO3_MP_SIGNED_BIG_INTEGER_INTEGRAL_TEMPLATE
    inline constexpr auto operator-(const T1& a, const T2& b) noexcept {
        return T1::subtract(a, b);
    }
    CRYPTO3_MP_SIGNED_BIG_INTEGER_INTEGRAL_ASSIGNMENT_TEMPLATE
    inline constexpr auto& operator-=(signed_big_integer_t& a, const T& b) {
        a = a - b;
        return a;
    }
    CRYPTO3_MP_SIGNED_BIG_INTEGER_UNARY_TEMPLATE
    inline constexpr auto& operator--(signed_big_integer_t& a) noexcept {
        a.decrement();
        return a;
    }
    CRYPTO3_MP_SIGNED_BIG_INTEGER_UNARY_TEMPLATE
    inline constexpr auto operator--(signed_big_integer_t& a, int) noexcept {
        auto copy = a;
        --a;
        return copy;
    }

    CRYPTO3_MP_SIGNED_BIG_INTEGER_UNARY_TEMPLATE
    inline constexpr signed_big_integer_t operator-(signed_big_integer_t a) noexcept {
        a.negate();
        return a;
    }

    CRYPTO3_MP_SIGNED_BIG_INTEGER_INTEGRAL_TEMPLATE
    inline constexpr auto operator*(const T1& a, const T2& b) noexcept {
        return std::decay_t<decltype(a)>::multiply(a, b);
    }
    CRYPTO3_MP_SIGNED_BIG_INTEGER_INTEGRAL_ASSIGNMENT_TEMPLATE
    inline constexpr auto& operator*=(signed_big_integer_t& a, const T& b) noexcept {
        a = a * b;
        return a;
    }

    CRYPTO3_MP_SIGNED_BIG_INTEGER_INTEGRAL_TEMPLATE
    inline constexpr auto operator/(const T1& a, const T2& b) noexcept {
        return largest_t::divide(static_cast<largest_t>(a), static_cast<largest_t>(b));
    }
    CRYPTO3_MP_SIGNED_BIG_INTEGER_INTEGRAL_ASSIGNMENT_TEMPLATE
    inline constexpr auto& operator/=(signed_big_integer_t& a, const T& b) noexcept {
        a = a / b;
        return a;
    }

    CRYPTO3_MP_SIGNED_BIG_INTEGER_INTEGRAL_TEMPLATE
    inline constexpr auto operator%(const T1& a, const T2& b) noexcept {
        return largest_t::modulus(static_cast<largest_t>(a), static_cast<largest_t>(b));
    }
    CRYPTO3_MP_SIGNED_BIG_INTEGER_INTEGRAL_ASSIGNMENT_TEMPLATE
    inline constexpr auto& operator%=(signed_big_integer_t& a, const T& b) {
        a = a % b;
        return a;
    }

    // // Binary operations

    // CRYPTO3_MP_SIGNED_BIG_INTEGER_INTEGRAL_TEMPLATE
    // inline constexpr auto operator&(const T1& a, const T2& b) noexcept {
    //     largest_t result = a;
    //     T1::bitwise_and(result, b);
    //     return result;
    // }
    // CRYPTO3_MP_SIGNED_BIG_INTEGER_INTEGRAL_ASSIGNMENT_TEMPLATE
    // inline constexpr auto& operator&=(signed_big_integer_t& a, const T& b) {
    //     signed_big_integer_t::bitwise_and(a, b);
    //     return a;
    // }

    // CRYPTO3_MP_SIGNED_BIG_INTEGER_INTEGRAL_TEMPLATE
    // inline constexpr auto operator|(const T1& a, const T2& b) noexcept {
    //     largest_t result = a;
    //     T1::bitwise_or(result, b);
    //     return result;
    // }
    // CRYPTO3_MP_SIGNED_BIG_INTEGER_INTEGRAL_ASSIGNMENT_TEMPLATE
    // inline constexpr auto& operator|=(signed_big_integer_t& a, const T& b) {
    //     signed_big_integer_t::bitwise_or(a, b);
    //     return a;
    // }

    // CRYPTO3_MP_SIGNED_BIG_INTEGER_INTEGRAL_TEMPLATE
    // inline constexpr auto operator^(const T1& a, const T2& b) noexcept {
    //     largest_t result = a;
    //     T1::bitwise_xor(result, b);
    //     return result;
    // }
    // CRYPTO3_MP_SIGNED_BIG_INTEGER_INTEGRAL_ASSIGNMENT_TEMPLATE
    // inline constexpr auto& operator^=(signed_big_integer_t& a, const T& b) {
    //     signed_big_integer_t::bitwise_or(a, b);
    //     return a;
    // }

    // CRYPTO3_MP_SIGNED_BIG_INTEGER_UNARY_TEMPLATE
    // inline constexpr auto operator~(const signed_big_integer_t& a) noexcept {
    //     signed_big_integer_t result;
    //     signed_big_integer_t::complement(result, a);
    //     return result;
    // }

    // CRYPTO3_MP_SIGNED_BIG_INTEGER_UNARY_TEMPLATE
    // inline constexpr auto operator<<(const signed_big_integer_t& a, unsigned shift) noexcept {
    //     signed_big_integer_t result = a;
    //     signed_big_integer_t::left_shift(result, shift);
    //     return result;
    // }
    // CRYPTO3_MP_SIGNED_BIG_INTEGER_UNARY_TEMPLATE
    // inline constexpr auto& operator<<=(signed_big_integer_t& a, unsigned shift) noexcept {
    //     // TODO(ioxid): check
    //     signed_big_integer_t::left_shift(a, shift);
    //     return a;
    // }

    // CRYPTO3_MP_SIGNED_BIG_INTEGER_UNARY_TEMPLATE
    // inline constexpr auto operator>>(const signed_big_integer_t& a, unsigned shift) noexcept {
    //     signed_big_integer_t result = a;
    //     signed_big_integer_t::right_shift(result, shift);
    //     return result;
    // }
    // CRYPTO3_MP_SIGNED_BIG_INTEGER_UNARY_TEMPLATE
    // inline constexpr auto& operator>>=(signed_big_integer_t& a, unsigned shift) noexcept {
    //     // TODO(ioxid): check
    //     signed_big_integer_t::right_shift(a, shift);
    //     return a;
    // }

    // IO

    CRYPTO3_MP_SIGNED_BIG_INTEGER_UNARY_TEMPLATE
    std::ostream& operator<<(std::ostream& os, const signed_big_integer_t& value) {
        os << value.str();
        return os;
    }

#undef CRYPTO3_MP_SIGNED_BIG_INTEGER_UNARY_TEMPLATE
#undef CRYPTO3_MP_SIGNED_BIG_INTEGER_INTEGRAL_ASSIGNMENT_TEMPLATE
#undef CRYPTO3_MP_SIGNED_BIG_INTEGER_INTEGRAL_TEMPLATE
}  // namespace nil::crypto3::multiprecision
