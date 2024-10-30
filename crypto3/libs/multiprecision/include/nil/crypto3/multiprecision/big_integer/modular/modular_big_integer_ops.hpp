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

namespace nil::crypto3::multiprecision {
    namespace detail {
        template<typename T>
        constexpr bool is_modular_big_integer_v = false;

        template<const auto& modulus, template<typename> typename modular_ops_storage_t>
        constexpr bool
            is_modular_big_integer_v<modular_big_integer_ct_impl<modulus, modular_ops_storage_t>> =
                true;

        template<unsigned Bits, template<typename> typename modular_ops_storage_t>
        constexpr bool
            is_modular_big_integer_v<modular_big_integer_rt_impl<Bits, modular_ops_storage_t>> =
                true;

        template<typename T>
        constexpr bool is_modular_integral_v =
            std::is_integral_v<T> || detail::is_big_integer_v<T> || is_modular_big_integer_v<T>;
    }  // namespace detail

    // Comparison

// TODO(ioxid): comparison with big_integer and basic types (including signed)
#define CRYPTO3_MP_MODULAR_BIG_INTEGER_COMPARISON_IMPL(op)                 \
    template<typename T1, typename T2,                                     \
             std::enable_if_t<detail::is_modular_big_integer_v<T1> &&      \
                                  detail::is_modular_big_integer_v<T2>,    \
                              int> = 0>                                    \
    inline constexpr bool operator op(const T1& a, const T2& b) noexcept { \
        return a.compare_eq(b) op true;                                    \
    }

    CRYPTO3_MP_MODULAR_BIG_INTEGER_COMPARISON_IMPL(==)
    CRYPTO3_MP_MODULAR_BIG_INTEGER_COMPARISON_IMPL(!=)
#undef CRYPTO3_MP_MODULAR_BIG_INTEGER_COMPARISON_IMPL

    namespace detail {
        template<typename T, std::enable_if_t<detail::is_modular_big_integer_v<T>, int> = 0>
        constexpr std::size_t get_bits() {
            return T::Bits;
        }

        template<unsigned Bits, typename modular_ops_t>
        constexpr void subtract(
            modular_big_integer_impl<big_integer<Bits>, modular_ops_t>& result,
            const modular_big_integer_impl<big_integer<Bits>, modular_ops_t>& o) {
            if (result.base_data() < o.base_data()) {
                auto v = result.ops().get_mod();
                v -= o.base_data();
                result.base_data() += v;
            } else {
                result.base_data() -= o.base_data();
            }
        }
    }  // namespace detail

    // TODO(ioxid): choose result type
#define CRYPTO3_MP_MODULAR_BIG_INTEGER_INTEGRAL_TEMPLATE                                           \
    template<                                                                                      \
        typename T1, typename T2,                                                                  \
        std::enable_if_t<detail::is_modular_integral_v<T1> && detail::is_modular_integral_v<T2> && \
                             (detail::is_modular_big_integer_v<T1> ||                              \
                              detail::is_modular_big_integer_v<T2>),                               \
                         int> = 0,                                                                 \
        typename largest_t = T1>

#define CRYPTO3_MP_MODULAR_BIG_INTEGER_INTEGRAL_ASSIGNMENT_TEMPLATE                      \
    template<typename modular_big_integer_t, typename T,                                 \
             std::enable_if_t<detail::is_modular_big_integer_v<modular_big_integer_t> && \
                                  detail::is_modular_integral_v<T> &&                    \
                                  detail::get_bits<T>() <= modular_big_integer_t::Bits,  \
                              int> = 0>

#define CRYPTO3_MP_MODULAR_BIG_INTEGER_UNARY_TEMPLATE \
    template<typename modular_big_integer_t,          \
             std::enable_if_t<detail::is_modular_big_integer_v<modular_big_integer_t>, int> = 0>

    // Arithmetic operations

    CRYPTO3_MP_MODULAR_BIG_INTEGER_INTEGRAL_TEMPLATE
    inline constexpr auto operator+(const T1& a, const T2& b) noexcept {
        BOOST_ASSERT(a.ops().compare_eq(b.ops()));
        largest_t result = a;
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
        largest_t result = a;
        detail::subtract(result, b);
        return result;
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
        modular_big_integer_t result = a;
        result.negate();
        return result;
    }

    CRYPTO3_MP_MODULAR_BIG_INTEGER_INTEGRAL_TEMPLATE
    inline constexpr auto operator*(const T1& a, const T2& b) noexcept {
        BOOST_ASSERT(a.ops().compare_eq(b.ops()));
        largest_t result = a;
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
        largest_t result;
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
        // TODO(ioxid): also hash modulus for runtime type
        return hash_value(val.base_data());
    }

    // IO

    template<typename T, std::enable_if_t<detail::is_modular_big_integer_v<T>, int> = 0>
    std::ostream& operator<<(std::ostream& os, const T& value) {
        os << value.str();
        return os;
    }

#undef CRYPTO3_MP_MODULAR_BIG_INTEGER_UNARY_TEMPLATE
#undef CRYPTO3_MP_MODULAR_BIG_INTEGER_INTEGRAL_ASSIGNMENT_TEMPLATE
#undef CRYPTO3_MP_MODULAR_BIG_INTEGER_INTEGRAL_TEMPLATE
}  // namespace nil::crypto3::multiprecision
