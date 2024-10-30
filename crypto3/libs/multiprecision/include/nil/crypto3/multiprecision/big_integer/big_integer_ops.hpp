#pragma once

#include <algorithm>
#include <climits>
#include <cstring>
#include <ostream>
#include <type_traits>

#include "nil/crypto3/multiprecision/big_integer/big_integer_impl.hpp"

#include "nil/crypto3/multiprecision/big_integer/ops/import_export.hpp"  // IWYU pragma: export
#include "nil/crypto3/multiprecision/big_integer/ops/misc.hpp"           // IWYU pragma: export

namespace nil::crypto3::multiprecision {
    namespace detail {
        template<typename T>
        static constexpr bool always_false = false;

        template<typename T>
        constexpr bool is_big_integer_v = false;

        template<unsigned Bits>
        constexpr bool is_big_integer_v<big_integer<Bits>> = true;

        template<typename T>
        constexpr bool is_integral_v = std::is_integral_v<T> || is_big_integer_v<T>;

        template<typename T, std::enable_if_t<std::is_integral_v<T>, int> = 0>
        constexpr std::size_t get_bits() {
            return sizeof(T) * CHAR_BIT;
        }

        template<typename T, std::enable_if_t<is_big_integer_v<T>, int> = 0>
        constexpr std::size_t get_bits() {
            return T::Bits;
        }
    }  // namespace detail

#define CRYPTO3_MP_BIG_INTEGER_INTEGRAL_TEMPLATE                                                  \
    template<typename T1, typename T2,                                                            \
             std::enable_if_t<detail::is_integral_v<T1> && detail::is_integral_v<T2> &&           \
                                  (detail::is_big_integer_v<T1> || detail::is_big_integer_v<T2>), \
                              int> = 0,                                                           \
             typename largest_t =                                                                 \
                 big_integer<std::max(detail::get_bits<T1>(), detail::get_bits<T2>())>>

    // TODO(ioxid): somehow error on overflow
#define CRYPTO3_MP_BIG_INTEGER_INTEGRAL_ASSIGNMENT_TEMPLATE                                        \
    template<typename big_integer_t, typename T,                                                   \
             std::enable_if_t<detail::is_big_integer_v<big_integer_t> && detail::is_integral_v<T>, \
                              int> = 0>

#define CRYPTO3_MP_BIG_INTEGER_UNARY_TEMPLATE \
    template<typename big_integer_t,          \
             std::enable_if_t<detail::is_big_integer_v<big_integer_t>, int> = 0>

    // Comparison

#define CRYPTO3_MP_BIG_INTEGER_IMPL_OPERATOR(op)                           \
    CRYPTO3_MP_BIG_INTEGER_INTEGRAL_TEMPLATE                               \
    inline constexpr bool operator op(const T1& a, const T2& b) noexcept { \
        largest_t ap = a;                                                  \
        largest_t bp = b;                                                  \
        return ap.compare(bp) op 0;                                        \
    }

    CRYPTO3_MP_BIG_INTEGER_IMPL_OPERATOR(<)
    CRYPTO3_MP_BIG_INTEGER_IMPL_OPERATOR(<=)
    CRYPTO3_MP_BIG_INTEGER_IMPL_OPERATOR(>)
    CRYPTO3_MP_BIG_INTEGER_IMPL_OPERATOR(>=)
    CRYPTO3_MP_BIG_INTEGER_IMPL_OPERATOR(==)
    CRYPTO3_MP_BIG_INTEGER_IMPL_OPERATOR(!=)

    // TODO(ioxid): implement comparison with signed types, needed for boost::random
#undef CRYPTO3_MP_BIG_INTEGER_IMPL_OPERATOR

    // Arithmetic operations

    CRYPTO3_MP_BIG_INTEGER_INTEGRAL_TEMPLATE
    inline constexpr auto operator+(const T1& a, const T2& b) noexcept {
        big_integer<largest_t::Bits + 1> result = a;
        decltype(result)::add(result, result, b);
        return result;
    }
    CRYPTO3_MP_BIG_INTEGER_INTEGRAL_ASSIGNMENT_TEMPLATE
    inline constexpr auto& operator+=(big_integer_t& a, const T& b) noexcept {
        big_integer_t::add(a, a, b);
        return a;
    }
    CRYPTO3_MP_BIG_INTEGER_UNARY_TEMPLATE
    inline constexpr auto& operator++(big_integer_t& a) noexcept {
        a.increment();
        return a;
    }
    CRYPTO3_MP_BIG_INTEGER_UNARY_TEMPLATE
    inline constexpr auto operator++(big_integer_t& a, int) noexcept {
        auto copy = a;
        ++a;
        return copy;
    }
    CRYPTO3_MP_BIG_INTEGER_UNARY_TEMPLATE
    inline constexpr auto operator+(const big_integer_t& a) noexcept { return a; }

    CRYPTO3_MP_BIG_INTEGER_INTEGRAL_TEMPLATE
    inline constexpr auto operator-(const T1& a, const T2& b) noexcept {
        T1 result;
        T1::subtract(result, a, b);
        return result;
    }
    CRYPTO3_MP_BIG_INTEGER_INTEGRAL_ASSIGNMENT_TEMPLATE
    inline constexpr auto& operator-=(big_integer_t& a, const T& b) {
        big_integer_t::subtract(a, a, b);
        return a;
    }
    CRYPTO3_MP_BIG_INTEGER_UNARY_TEMPLATE
    inline constexpr auto& operator--(big_integer_t& a) noexcept {
        a.decrement();
        return a;
    }
    CRYPTO3_MP_BIG_INTEGER_UNARY_TEMPLATE
    inline constexpr auto operator--(big_integer_t& a, int) noexcept {
        auto copy = a;
        --a;
        return copy;
    }

    CRYPTO3_MP_BIG_INTEGER_UNARY_TEMPLATE
    inline constexpr big_integer_t operator-(const big_integer_t& /* unused */) noexcept {
        // TODO(ioxid): implement?
        static_assert(detail::always_false<big_integer_t>, "can't negate unsigned type");
    }

    CRYPTO3_MP_BIG_INTEGER_INTEGRAL_TEMPLATE
    inline constexpr auto operator*(const T1& a, const T2& b) noexcept {
        big_integer<detail::get_bits<T1>() + detail::get_bits<T2>()> result;
        decltype(result)::multiply(result, a, b);
        return result;
    }
    CRYPTO3_MP_BIG_INTEGER_INTEGRAL_ASSIGNMENT_TEMPLATE
    inline constexpr auto& operator*=(big_integer_t& a, const T& b) noexcept {
        big_integer<detail::get_bits<big_integer_t>() + detail::get_bits<T>()> result;
        decltype(result)::multiply(result, a, static_cast<big_integer_t>(b));
        a = result;
        return a;
    }

    CRYPTO3_MP_BIG_INTEGER_INTEGRAL_TEMPLATE
    inline constexpr auto operator/(const T1& a, const T2& b) noexcept {
        largest_t result;
        largest_t modulus;
        largest_t::divide(&result, a, b, modulus);
        return result;
    }
    CRYPTO3_MP_BIG_INTEGER_INTEGRAL_ASSIGNMENT_TEMPLATE
    inline constexpr auto& operator/=(big_integer_t& a, const T& b) noexcept {
        big_integer_t result;
        big_integer_t modulus;
        big_integer_t::divide(&result, a, b, modulus);
        a = result;
        return a;
    }

    CRYPTO3_MP_BIG_INTEGER_INTEGRAL_TEMPLATE
    inline constexpr auto operator%(const T1& a, const T2& b) noexcept {
        largest_t modulus;
        largest_t::divide(nullptr, a, b, modulus);
        return modulus;
    }
    CRYPTO3_MP_BIG_INTEGER_INTEGRAL_ASSIGNMENT_TEMPLATE
    inline constexpr auto& operator%=(big_integer_t& a, const T& b) {
        big_integer_t modulus;
        big_integer_t::divide(nullptr, a, b, modulus);
        a = modulus;
        return a;
    }

    CRYPTO3_MP_BIG_INTEGER_INTEGRAL_TEMPLATE
    inline constexpr auto operator&(const T1& a, const T2& b) noexcept {
        largest_t result = a;
        T1::bitwise_and(result, b);
        return result;
    }
    CRYPTO3_MP_BIG_INTEGER_INTEGRAL_ASSIGNMENT_TEMPLATE
    inline constexpr auto& operator&=(big_integer_t& a, const T& b) {
        big_integer_t::bitwise_and(a, b);
        return a;
    }

    CRYPTO3_MP_BIG_INTEGER_INTEGRAL_TEMPLATE
    inline constexpr auto operator|(const T1& a, const T2& b) noexcept {
        largest_t result = a;
        T1::bitwise_or(result, b);
        return result;
    }
    CRYPTO3_MP_BIG_INTEGER_INTEGRAL_ASSIGNMENT_TEMPLATE
    inline constexpr auto& operator|=(big_integer_t& a, const T& b) {
        big_integer_t::bitwise_or(a, b);
        return a;
    }

    CRYPTO3_MP_BIG_INTEGER_INTEGRAL_TEMPLATE
    inline constexpr auto operator^(const T1& a, const T2& b) noexcept {
        largest_t result = a;
        T1::bitwise_xor(result, b);
        return result;
    }
    CRYPTO3_MP_BIG_INTEGER_INTEGRAL_ASSIGNMENT_TEMPLATE
    inline constexpr auto& operator^=(big_integer_t& a, const T& b) {
        big_integer_t::bitwise_or(a, b);
        return a;
    }

    CRYPTO3_MP_BIG_INTEGER_UNARY_TEMPLATE
    inline constexpr auto operator~(const big_integer_t& a) noexcept {
        big_integer_t result;
        big_integer_t::complement(result, a);
        return result;
    }

    CRYPTO3_MP_BIG_INTEGER_UNARY_TEMPLATE
    inline constexpr auto operator<<(const big_integer_t& a, unsigned shift) noexcept {
        big_integer_t result = a;
        big_integer_t::left_shift(result, shift);
        return result;
    }
    CRYPTO3_MP_BIG_INTEGER_UNARY_TEMPLATE
    inline constexpr auto& operator<<=(big_integer_t& a, unsigned shift) noexcept {
        // TODO(ioxid): check
        big_integer_t::left_shift(a, shift);
        return a;
    }

    CRYPTO3_MP_BIG_INTEGER_UNARY_TEMPLATE
    inline constexpr auto operator>>(const big_integer_t& a, unsigned shift) noexcept {
        big_integer_t result = a;
        big_integer_t::right_shift(result, shift);
        return result;
    }
    CRYPTO3_MP_BIG_INTEGER_UNARY_TEMPLATE
    inline constexpr auto& operator>>=(big_integer_t& a, unsigned shift) noexcept {
        // TODO(ioxid): check
        big_integer_t::right_shift(a, shift);
        return a;
    }

    // IO

    CRYPTO3_MP_BIG_INTEGER_UNARY_TEMPLATE
    std::ostream& operator<<(std::ostream& os, const big_integer_t& value) {
        os << value.str() << std::endl;
        return os;
    }

#undef CRYPTO3_MP_BIG_INTEGER_UNARY_TEMPLATE
#undef CRYPTO3_MP_BIG_INTEGER_INTEGRAL_ASSIGNMENT_TEMPLATE
#undef CRYPTO3_MP_BIG_INTEGER_INTEGRAL_TEMPLATE
}  // namespace nil::crypto3::multiprecision
