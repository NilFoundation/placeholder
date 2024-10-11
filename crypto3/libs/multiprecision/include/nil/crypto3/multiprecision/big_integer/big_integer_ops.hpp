#pragma once

#include <algorithm>
#include <climits>
#include <cstring>
#include <ostream>
#include <type_traits>

#include "nil/crypto3/multiprecision/big_integer/big_integer_impl.hpp"

#include "nil/crypto3/multiprecision/big_integer/ops/add.hpp"
#include "nil/crypto3/multiprecision/big_integer/ops/bitwise.hpp"
#include "nil/crypto3/multiprecision/big_integer/ops/divide.hpp"
#include "nil/crypto3/multiprecision/big_integer/ops/import_export.hpp"  // IWYU pragma: export
#include "nil/crypto3/multiprecision/big_integer/ops/misc.hpp"           // IWYU pragma: export
#include "nil/crypto3/multiprecision/big_integer/ops/multiply.hpp"

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

        template<typename T, std::enable_if_t<std::is_integral_v<T>, bool> = true>
        constexpr std::size_t get_bits() {
            return sizeof(T) * CHAR_BIT;
        }

        template<typename T, std::enable_if_t<is_big_integer_v<T>, bool> = true>
        constexpr std::size_t get_bits() {
            return T::Bits;
        }
    }  // namespace detail

#define CRYPTO3_MP_BIG_INTEGER_INTEGRAL_TEMPLATE                                                  \
    template<typename T1, typename T2,                                                            \
             std::enable_if_t<detail::is_integral_v<T1> && detail::is_integral_v<T2> &&           \
                                  (detail::is_big_integer_v<T1> || detail::is_big_integer_v<T2>), \
                              bool> = true,                                                       \
             typename result_t =                                                                  \
                 big_integer<std::max(detail::get_bits<T1>(), detail::get_bits<T2>())>>

#define CRYPTO3_MP_BIG_INTEGER_INTEGRAL_ASSIGNMENT_TEMPLATE                                     \
    template<                                                                                   \
        typename big_integer_t, typename T,                                                     \
        std::enable_if_t<detail::is_big_integer_v<big_integer_t> && detail::is_integral_v<T> && \
                             detail::get_bits<T>() <= big_integer_t::Bits,                      \
                         bool> = true>

#define CRYPTO3_MP_BIG_INTEGER_UNARY_TEMPLATE \
    template<typename big_integer_t,          \
             std::enable_if_t<detail::is_big_integer_v<big_integer_t>, bool> = true>

    // Comparison

#define CRYPTO3_MP_BIG_INTEGER_IMPL_OPERATOR(op)                                             \
    CRYPTO3_MP_BIG_INTEGER_INTEGRAL_TEMPLATE                                                 \
    inline constexpr bool operator op(const T1& a, const T2& b) noexcept {                   \
        return compare<std::max(detail::get_bits<T1>(), detail::get_bits<T2>())>(a, b) op 0; \
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
        result_t tmp{a};
        eval_add(tmp, b);
        return tmp;
    }
    CRYPTO3_MP_BIG_INTEGER_INTEGRAL_ASSIGNMENT_TEMPLATE
    inline constexpr auto& operator+=(big_integer_t& a, const T& b) noexcept {
        eval_add<big_integer_t::Bits>(a, b);
        return a;
    }
    CRYPTO3_MP_BIG_INTEGER_UNARY_TEMPLATE
    inline constexpr auto& operator++(big_integer_t& a) noexcept {
        eval_increment(a);
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
        result_t tmp;
        eval_subtract(tmp, a, b);
        return tmp;
    }
    CRYPTO3_MP_BIG_INTEGER_INTEGRAL_ASSIGNMENT_TEMPLATE
    inline constexpr auto& operator-=(big_integer_t& a, const T& b) {
        eval_subtract(a, b);
        return a;
    }
    CRYPTO3_MP_BIG_INTEGER_UNARY_TEMPLATE
    inline constexpr auto& operator--(big_integer_t& a) noexcept {
        eval_decrement(a);
        return a;
    }
    CRYPTO3_MP_BIG_INTEGER_UNARY_TEMPLATE
    inline constexpr auto operator--(big_integer_t& a, int) noexcept {
        auto copy = a;
        --a;
        return copy;
    }

    CRYPTO3_MP_BIG_INTEGER_UNARY_TEMPLATE
    inline constexpr big_integer_t operator-(const big_integer_t& a) noexcept {
        // TODO(ioxid): implement?
        static_assert(detail::always_false<big_integer_t>, "can't negate unsigned type");
    }

    CRYPTO3_MP_BIG_INTEGER_INTEGRAL_TEMPLATE
    inline constexpr auto operator*(const T1& a, const T2& b) noexcept {
        result_t result{a};
        eval_multiply(result, b);
        return result;
    }
    CRYPTO3_MP_BIG_INTEGER_INTEGRAL_ASSIGNMENT_TEMPLATE
    inline constexpr auto& operator*=(big_integer_t& a, const T& b) noexcept {
        eval_multiply(a, b);
        return a;
    }

    CRYPTO3_MP_BIG_INTEGER_INTEGRAL_TEMPLATE
    inline constexpr auto operator/(const T1& a, const T2& b) noexcept {
        result_t result;
        eval_divide(result, a, b);
        return result;
    }
    CRYPTO3_MP_BIG_INTEGER_INTEGRAL_ASSIGNMENT_TEMPLATE
    inline constexpr auto& operator/=(big_integer_t& a, const T& b) noexcept {
        eval_divide(a, b);
        return a;
    }

    CRYPTO3_MP_BIG_INTEGER_INTEGRAL_TEMPLATE
    inline constexpr auto operator%(const T1& a, const T2& b) noexcept {
        result_t result;
        eval_modulus(result, a, b);
        return result;
    }
    CRYPTO3_MP_BIG_INTEGER_INTEGRAL_ASSIGNMENT_TEMPLATE
    inline constexpr auto& operator%=(big_integer_t& a, const T& b) {
        eval_modulus(a, b);
        return a;
    }

    CRYPTO3_MP_BIG_INTEGER_INTEGRAL_TEMPLATE
    inline constexpr auto operator&(const T1& a, const T2& b) noexcept {
        result_t result{a};
        eval_bitwise_and(result, b);
        return result;
    }
    CRYPTO3_MP_BIG_INTEGER_INTEGRAL_ASSIGNMENT_TEMPLATE
    inline constexpr auto& operator&=(big_integer_t& a, const T& b) {
        eval_bitwise_and(a, b);
        return a;
    }

    CRYPTO3_MP_BIG_INTEGER_INTEGRAL_TEMPLATE
    inline constexpr auto operator|(const T1& a, const T2& b) noexcept {
        result_t result{a};
        eval_bitwise_or(result, b);
        return result;
    }
    CRYPTO3_MP_BIG_INTEGER_INTEGRAL_ASSIGNMENT_TEMPLATE
    inline constexpr auto& operator|=(big_integer_t& a, const T& b) {
        eval_bitwise_or(a, b);
        return a;
    }

    CRYPTO3_MP_BIG_INTEGER_INTEGRAL_TEMPLATE
    inline constexpr auto operator^(const T1& a, const T2& b) noexcept {
        result_t result{a};
        eval_bitwise_xor(result, b);
        return result;
    }
    CRYPTO3_MP_BIG_INTEGER_INTEGRAL_ASSIGNMENT_TEMPLATE
    inline constexpr auto& operator^=(big_integer_t& a, const T& b) {
        eval_bitwise_or(a, b);
        return a;
    }

    CRYPTO3_MP_BIG_INTEGER_UNARY_TEMPLATE
    inline constexpr auto operator~(const big_integer_t& a) noexcept {
        big_integer_t result;
        eval_complement(result, a);
        return result;
    }

    CRYPTO3_MP_BIG_INTEGER_UNARY_TEMPLATE
    inline constexpr auto operator<<(const big_integer_t& a, unsigned shift) noexcept {
        big_integer_t result{a};
        eval_left_shift(result, shift);
        return result;
    }
    CRYPTO3_MP_BIG_INTEGER_UNARY_TEMPLATE
    inline constexpr auto& operator<<=(big_integer_t& a, unsigned shift) noexcept {
        // TODO(ioxid): check
        eval_left_shift(a, shift);
        return a;
    }

    CRYPTO3_MP_BIG_INTEGER_UNARY_TEMPLATE
    inline constexpr auto operator>>(const big_integer_t& a, unsigned shift) noexcept {
        big_integer_t result{a};
        eval_right_shift(result, shift);
        return result;
    }
    CRYPTO3_MP_BIG_INTEGER_UNARY_TEMPLATE
    inline constexpr auto& operator>>=(big_integer_t& a, unsigned shift) noexcept {
        // TODO(ioxid): check
        eval_right_shift(a, shift);
        return a;
    }

    // IO

    CRYPTO3_MP_BIG_INTEGER_UNARY_TEMPLATE
    std::ostream& operator<<(std::ostream& os, const big_integer_t& value) {
        // TODO(ioxid): rewrite without cpp_int
        os << value.to_cpp_int() << std::endl;
        return os;
    }

#undef CRYPTO3_MP_BIG_INTEGER_UNARY_TEMPLATE
#undef CRYPTO3_MP_BIG_INTEGER_INTEGRAL_ASSIGNMENT_TEMPLATE
#undef CRYPTO3_MP_BIG_INTEGER_INTEGRAL_TEMPLATE
}  // namespace nil::crypto3::multiprecision
