#pragma once

#include <limits>
#include <stdexcept>
#include <type_traits>

namespace nil::crypto3::multiprecision::detail {
    template<typename T>
    constexpr bool is_integer_v =
        std::numeric_limits<T>::is_specialized && std::numeric_limits<T>::is_integer;

    template<typename T>
    constexpr bool is_unsigned_integer_v = is_integer_v<T> && !std::numeric_limits<T>::is_signed;

    template<typename T, std::enable_if_t<is_unsigned_integer_v<std::decay_t<T>>, int> = 0>
    constexpr decltype(auto) unsigned_or_throw(T&& a) {
        return std::forward<T>(a);
    }

    template<typename T, std::enable_if_t<std::is_signed_v<T>, int> = 0>
    constexpr std::make_unsigned_t<T> unsigned_or_throw(const T& a) {
        if (a < 0) {
            throw std::range_error("nonnegative value expected");
        }
        return static_cast<std::make_unsigned_t<T>>(a);
    }
}  // namespace nil::crypto3::multiprecision::detail
