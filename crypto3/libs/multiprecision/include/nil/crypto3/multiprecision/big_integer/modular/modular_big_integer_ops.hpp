//---------------------------------------------------------------------------//
// Copyright (c) 2024 Andrey Nefedov <ioxid@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#pragma once

#include <cstddef>
#include <ostream>
#include <type_traits>

#include "nil/crypto3/multiprecision/big_integer/big_integer.hpp"
#include "nil/crypto3/multiprecision/big_integer/modular/modular_big_integer_impl.hpp"
#include "nil/crypto3/multiprecision/big_integer/modular/modular_ops.hpp"

namespace nil::crypto3::multiprecision {

    // Comparison

// TODO(ioxid): comparison with big_integer and basic types (including signed)
#define CRYPTO3_MP_MODULAR_BIG_INTEGER_COMPARISON_IMPL(op)                        \
    template<typename big_integer_t, typename modular_params_t>                   \
    inline constexpr bool operator op(                                            \
        const modular_big_integer<big_integer_t, modular_params_t>& a,            \
        const modular_big_integer<big_integer_t, modular_params_t>& b) noexcept { \
        return a.compare_eq(b) op true;                                           \
    }

    CRYPTO3_MP_MODULAR_BIG_INTEGER_COMPARISON_IMPL(==)
    CRYPTO3_MP_MODULAR_BIG_INTEGER_COMPARISON_IMPL(!=)
#undef CRYPTO3_MP_MODULAR_BIG_INTEGER_COMPARISON_IMPL

    namespace modular_detail {
        template<typename T>
        static constexpr bool always_false = false;

        template<typename T>
        constexpr bool is_modular_big_integer_v = false;

        template<typename big_integer_t, typename modular_params_t>
        constexpr bool
            is_modular_big_integer_v<modular_big_integer<big_integer_t, modular_params_t>> = true;

        template<typename T>
        constexpr bool is_integral_v =
            std::is_integral_v<T> || detail::is_big_integer_v<T> || is_modular_big_integer_v<T>;
    }  // namespace modular_detail

    namespace detail {
        template<typename T,
                 std::enable_if_t<modular_detail::is_modular_big_integer_v<T>, bool> = true>
        constexpr std::size_t get_bits() {
            return T::Bits;
        }
    }  // namespace detail

    // TODO(ioxid): choose result type
#define CRYPTO3_MP_MODULAR_BIG_INTEGER_INTEGRAL_TEMPLATE                                           \
    template<                                                                                      \
        typename T1, typename T2,                                                                  \
        std::enable_if_t<modular_detail::is_integral_v<T1> && modular_detail::is_integral_v<T2> && \
                             (modular_detail::is_modular_big_integer_v<T1> ||                      \
                              modular_detail::is_modular_big_integer_v<T2>),                       \
                         bool> = true,                                                             \
        typename result_t = T1>

#define CRYPTO3_MP_MODULAR_BIG_INTEGER_INTEGRAL_ASSIGNMENT_TEMPLATE                              \
    template<typename modular_big_integer_t, typename T,                                         \
             std::enable_if_t<modular_detail::is_modular_big_integer_v<modular_big_integer_t> && \
                                  modular_detail::is_integral_v<T> &&                            \
                                  detail::get_bits<T>() <= modular_big_integer_t::Bits,          \
                              bool> = true>

#define CRYPTO3_MP_MODULAR_BIG_INTEGER_UNARY_TEMPLATE                                          \
    template<typename modular_big_integer_t,                                                   \
             std::enable_if_t<modular_detail::is_modular_big_integer_v<modular_big_integer_t>, \
                              bool> = true>

    // Arithmetic operations

    CRYPTO3_MP_MODULAR_BIG_INTEGER_INTEGRAL_TEMPLATE
    inline constexpr auto operator+(const T1& a, const T2& b) noexcept {
        result_t tmp{a};
        // eval_add(tmp, b);
        return tmp;
    }
    CRYPTO3_MP_MODULAR_BIG_INTEGER_INTEGRAL_ASSIGNMENT_TEMPLATE
    inline constexpr auto& operator+=(modular_big_integer_t& a, const T& b) noexcept {
        // eval_add<modular_big_integer_t::Bits>(a, b);
        return a;
    }
    CRYPTO3_MP_MODULAR_BIG_INTEGER_UNARY_TEMPLATE
    inline constexpr auto& operator++(modular_big_integer_t& a) noexcept {
        // eval_increment(a);
        return a;
    }
    CRYPTO3_MP_MODULAR_BIG_INTEGER_UNARY_TEMPLATE
    inline constexpr auto operator++(modular_big_integer_t& a, int) noexcept {
        auto copy = a;
        // eval_increment(a);
        return copy;
    }
    CRYPTO3_MP_MODULAR_BIG_INTEGER_UNARY_TEMPLATE
    inline constexpr auto operator+(const modular_big_integer_t& a) noexcept { return a; }

    CRYPTO3_MP_MODULAR_BIG_INTEGER_INTEGRAL_TEMPLATE
    inline constexpr auto operator-(const T1& a, const T2& b) noexcept {
        result_t tmp;
        // eval_subtract(tmp, a, b);
        return tmp;
    }
    CRYPTO3_MP_MODULAR_BIG_INTEGER_INTEGRAL_ASSIGNMENT_TEMPLATE
    inline constexpr auto& operator-=(modular_big_integer_t& a, const T& b) {
        // eval_subtract(a, b);
        return a;
    }
    CRYPTO3_MP_MODULAR_BIG_INTEGER_UNARY_TEMPLATE
    inline constexpr auto& operator--(modular_big_integer_t& a) noexcept {
        // eval_decrement(a);
        return a;
    }
    CRYPTO3_MP_MODULAR_BIG_INTEGER_UNARY_TEMPLATE
    inline constexpr auto operator--(modular_big_integer_t& a, int) noexcept {
        auto copy = a;
        // eval_decrement(a);
        return copy;
    }

    CRYPTO3_MP_MODULAR_BIG_INTEGER_UNARY_TEMPLATE
    inline constexpr modular_big_integer_t operator-(const modular_big_integer_t& a) noexcept {
        modular_big_integer_t tmp{a};
        tmp.negate();
        return tmp;
    }

    CRYPTO3_MP_MODULAR_BIG_INTEGER_INTEGRAL_TEMPLATE
    inline constexpr auto operator*(const T1& a, const T2& b) noexcept {
        result_t result{a};
        eval_multiply(result, b);
        return result;
    }
    CRYPTO3_MP_MODULAR_BIG_INTEGER_INTEGRAL_ASSIGNMENT_TEMPLATE
    inline constexpr auto& operator*=(modular_big_integer_t& a, const T& b) noexcept {
        // eval_multiply(a, b);
        return a;
    }

    CRYPTO3_MP_MODULAR_BIG_INTEGER_INTEGRAL_TEMPLATE
    inline constexpr auto operator/(const T1& a, const T2& b) noexcept {
        result_t result;
        // eval_divide(result, a, b);
        return result;
    }
    CRYPTO3_MP_MODULAR_BIG_INTEGER_INTEGRAL_ASSIGNMENT_TEMPLATE
    inline constexpr auto& operator/=(modular_big_integer_t& a, const T& b) noexcept {
        // eval_divide(a, b);
        return a;
    }

    // IO

    template<unsigned Bits, typename modular_params_t>
    std::ostream& operator<<(
        std::ostream& os, const modular_big_integer<big_integer<Bits>, modular_params_t>& value) {
        os << value.base_data();
        return os;
    }

#undef CRYPTO3_MP_MODULAR_BIG_INTEGER_INTEGRAL_TEMPLATE
#undef CRYPTO3_MP_MODULAR_BIG_INTEGER_INTEGRAL_ASSIGNMENT_TEMPLATE
#undef CRYPTO3_MP_MODULAR_BIG_INTEGER_UNARY_TEMPLATE
}  // namespace nil::crypto3::multiprecision

// TODO(ioxid): should use this optimization?
// // We need to specialize this function, because default boost implementation is "return
// a.compare(b)
// // == 0;", which is waay slower.
// template<unsigned Bits, typename modular_params_t, expression_template_option
// ExpressionTemplates> inline constexpr bool operator==(
//     const number<big_integer_ts::modular_big_integer<big_integer<Bits>, modular_params_t>,
//                  ExpressionTemplates> &a,
//     const number<big_integer_ts::modular_big_integer<big_integer<Bits>, modular_params_t>,
//                  ExpressionTemplates> &b) {
//     return a.big_integer_t().compare_eq(b.big_integer_t());
// }
//
// // We need to specialize this function, because default boost implementation is "return
// a.compare(b)
// // == 0;", which is waay slower.
// template<unsigned Bits, typename modular_params_t, expression_template_option
// ExpressionTemplates> inline constexpr bool operator!=(
//     const number<big_integer_ts::modular_big_integer<big_integer<Bits>, modular_params_t>,
//                  ExpressionTemplates> &a,
//     const number<big_integer_ts::modular_big_integer<big_integer<Bits>, modular_params_t>,
//                  ExpressionTemplates> &b) {
//     return !a.big_integer_t().compare_eq(b.big_integer_t());
// }
// }
