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
#include "nil/crypto3/multiprecision/big_integer/modular/modular_big_integer_ops_impl.hpp"

namespace nil::crypto3::multiprecision {

    // Comparison

// TODO(ioxid): comparison with big_integer and basic types (including signed)
#define CRYPTO3_MP_MODULAR_BIG_INTEGER_COMPARISON_IMPL(op)                                  \
    template<typename big_integer_t, typename modular_ops_t>                                \
    inline constexpr bool operator op(                                                      \
        const detail::modular_big_integer_impl<big_integer_t, modular_ops_t>& a,            \
        const detail::modular_big_integer_impl<big_integer_t, modular_ops_t>& b) noexcept { \
        return a.compare_eq(b) op true;                                                     \
    }

    CRYPTO3_MP_MODULAR_BIG_INTEGER_COMPARISON_IMPL(==)
    CRYPTO3_MP_MODULAR_BIG_INTEGER_COMPARISON_IMPL(!=)
#undef CRYPTO3_MP_MODULAR_BIG_INTEGER_COMPARISON_IMPL

    namespace modular_detail {
        template<typename T>
        static constexpr bool always_false = false;

        template<typename T>
        constexpr bool is_modular_big_integer_v = false;

        template<unsigned Bits>
        constexpr bool is_modular_big_integer_v<modular_big_integer_rt<Bits>> = true;

        template<const auto& modulus>
        constexpr bool is_modular_big_integer_v<modular_big_integer_ct<modulus>> = true;

        template<typename T>
        constexpr bool is_integral_v =
            std::is_integral_v<T> || detail::is_big_integer_v<T> || is_modular_big_integer_v<T>;
    }  // namespace modular_detail

    namespace detail {
        template<typename T, std::enable_if_t<modular_detail::is_modular_big_integer_v<T>, int> = 0>
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
                         int> = 0,                                                                 \
        typename result_t = T1>

#define CRYPTO3_MP_MODULAR_BIG_INTEGER_INTEGRAL_ASSIGNMENT_TEMPLATE                              \
    template<typename modular_big_integer_t, typename T,                                         \
             std::enable_if_t<modular_detail::is_modular_big_integer_v<modular_big_integer_t> && \
                                  modular_detail::is_integral_v<T> &&                            \
                                  detail::get_bits<T>() <= modular_big_integer_t::Bits,          \
                              int> = 0>

#define CRYPTO3_MP_MODULAR_BIG_INTEGER_UNARY_TEMPLATE                                          \
    template<typename modular_big_integer_t,                                                   \
             std::enable_if_t<modular_detail::is_modular_big_integer_v<modular_big_integer_t>, \
                              int> = 0>

    // Arithmetic operations

    CRYPTO3_MP_MODULAR_BIG_INTEGER_INTEGRAL_TEMPLATE
    inline constexpr auto operator+(const T1& a, const T2& b) noexcept {
        BOOST_ASSERT(a.ops().compare_eq(b.ops()));
        result_t result{a};
        a.ops().add(result.base_data(), b.base_data());
        return result;
    }
    CRYPTO3_MP_MODULAR_BIG_INTEGER_INTEGRAL_ASSIGNMENT_TEMPLATE
    inline constexpr auto& operator+=(modular_big_integer_t& a, const T& b) noexcept {
        BOOST_ASSERT(a.ops().compare_eq(b.ops()));
        a.ops().add(a.base_data(), b.base_data());
        return a;
    }
    CRYPTO3_MP_MODULAR_BIG_INTEGER_UNARY_TEMPLATE
    inline constexpr auto& operator++(modular_big_integer_t& a) noexcept {
        // TODO(ioxid): implement faster
        a += static_cast<modular_big_integer_t>(1u);
        return a;
    }
    CRYPTO3_MP_MODULAR_BIG_INTEGER_UNARY_TEMPLATE
    inline constexpr auto operator++(modular_big_integer_t& a, int) noexcept {
        auto copy = a;
        // TODO(ioxid): implement faster
        a += static_cast<modular_big_integer_t>(1u);
        return copy;
    }
    CRYPTO3_MP_MODULAR_BIG_INTEGER_UNARY_TEMPLATE
    inline constexpr auto operator+(const modular_big_integer_t& a) noexcept { return a; }

    CRYPTO3_MP_MODULAR_BIG_INTEGER_INTEGRAL_TEMPLATE
    inline constexpr auto operator-(const T1& a, const T2& b) noexcept {
        result_t tmp{a};
        detail::subtract(tmp, b);
        return tmp;
    }
    CRYPTO3_MP_MODULAR_BIG_INTEGER_INTEGRAL_ASSIGNMENT_TEMPLATE
    inline constexpr auto& operator-=(modular_big_integer_t& a, const T& b) {
        detail::subtract(a, b);
        return a;
    }
    CRYPTO3_MP_MODULAR_BIG_INTEGER_UNARY_TEMPLATE
    inline constexpr auto& operator--(modular_big_integer_t& a) noexcept {
        // TODO(ioxid): implement faster
        a -= static_cast<modular_big_integer_t>(1u);
        return a;
    }
    CRYPTO3_MP_MODULAR_BIG_INTEGER_UNARY_TEMPLATE
    inline constexpr auto operator--(modular_big_integer_t& a, int) noexcept {
        auto copy = a;
        // TODO(ioxid): implement faster
        a -= static_cast<modular_big_integer_t>(1u);
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
        BOOST_ASSERT(a.ops().compare_eq(b.ops()));
        result_t result{a};
        a.ops().mul(result.base_data(), b.base_data());
        return result;
    }
    CRYPTO3_MP_MODULAR_BIG_INTEGER_INTEGRAL_ASSIGNMENT_TEMPLATE
    inline constexpr auto& operator*=(modular_big_integer_t& a, const T& b) noexcept {
        BOOST_ASSERT(a.ops().compare_eq(b.ops()));
        a.ops().add(a.base_data(), b.base_data());
        return a;
    }

    CRYPTO3_MP_MODULAR_BIG_INTEGER_INTEGRAL_TEMPLATE
    inline constexpr auto operator/(const T1& a, const T2& b) noexcept {
        result_t result;
        eval_divide(result, a, b);
        return result;
    }
    CRYPTO3_MP_MODULAR_BIG_INTEGER_INTEGRAL_ASSIGNMENT_TEMPLATE
    inline constexpr auto& operator/=(modular_big_integer_t& a, const T& b) noexcept {
        eval_divide(a, b);
        return a;
    }

    template<class big_integer_t, typename modular_ops_t>
    constexpr bool is_zero(
        const detail::modular_big_integer_impl<big_integer_t, modular_ops_t>& val) noexcept {
        return is_zero(val.base_data());
    }

    // Hash

    template<typename big_integer_t, typename modular_ops_t>
    inline constexpr std::size_t hash_value(
        const detail::modular_big_integer_impl<big_integer_t, modular_ops_t>& val) noexcept {
        return hash_value(val.base_data());
    }

    // IO

    template<unsigned Bits, typename modular_ops_t>
    std::ostream& operator<<(
        std::ostream& os,
        const detail::modular_big_integer_impl<big_integer<Bits>, modular_ops_t>& value) {
        os << value.str();
        return os;
    }

#undef CRYPTO3_MP_MODULAR_BIG_INTEGER_INTEGRAL_TEMPLATE
#undef CRYPTO3_MP_MODULAR_BIG_INTEGER_INTEGRAL_ASSIGNMENT_TEMPLATE
#undef CRYPTO3_MP_MODULAR_BIG_INTEGER_UNARY_TEMPLATE
}  // namespace nil::crypto3::multiprecision