#pragma once

#include <stdexcept>
#include <type_traits>

#include "nil/crypto3/multiprecision/detail/big_uint/type_traits.hpp"

namespace nil::crypto3::multiprecision::detail {
    template<typename T, std::enable_if_t<std::is_integral_v<T> && std::is_signed_v<T>, int> = 0>
    constexpr std::make_unsigned_t<T> unsigned_abs(T x) {
        std::make_unsigned_t<T> ux = x;
        return (x < 0) ? -ux : ux;  // compare signed x, negate unsigned x
    }

    template<typename T, std::enable_if_t<detail::is_big_uint_v<std::decay_t<T>> ||
                                              (std::is_integral_v<std::decay_t<T>> &&
                                               std::is_unsigned_v<std::decay_t<T>>),
                                          int> = 0>
    constexpr decltype(auto) unsigned_abs(T&& x) {
        return std::forward<T>(x);
    }

    template<typename T, std::enable_if_t<std::is_signed_v<T>, int> = 0>
    constexpr std::make_unsigned_t<T> unsigned_or_throw(const T& a) {
        if (a < 0) {
            throw std::range_error("nonnegative value expected");
        }
        return static_cast<std::make_unsigned_t<T>>(a);
    }

    template<typename T, std::enable_if_t<detail::is_big_uint_v<std::decay_t<T>> ||
                                              (std::is_integral_v<std::decay_t<T>> &&
                                               std::is_unsigned_v<std::decay_t<T>>),
                                          int> = 0>
    constexpr decltype(auto) unsigned_or_throw(T&& a) {
        return std::forward<T>(a);
    }
}  // namespace nil::crypto3::multiprecision::detail
