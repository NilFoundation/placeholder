#pragma once

#include <type_traits>

namespace nil::crypto3::multiprecision::detail::constexpr_support {
    // std::abs is constexpr only in C++23
    template<typename T, std::enable_if_t<std::is_integral_v<T> && std::is_signed_v<T>, int> = 0>
    constexpr T abs(T val) {
        return val < 0 ? -val : val;
    }
}  // namespace nil::crypto3::multiprecision::detail::constexpr_support
