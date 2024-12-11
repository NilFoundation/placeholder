#pragma once

#include <limits>
#include <type_traits>

namespace nil::crypto3::multiprecision::detail {
    template<typename T>
    constexpr bool is_integer_v =
        std::numeric_limits<T>::is_specialized && std::numeric_limits<T>::is_integer;

    template<typename T>
    constexpr bool is_unsigned_integer_v = is_integer_v<T> && !std::numeric_limits<T>::is_signed;
}  // namespace nil::crypto3::multiprecision::detail
