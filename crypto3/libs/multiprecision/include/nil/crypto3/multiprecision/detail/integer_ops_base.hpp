#pragma once

#include <cstddef>
#include <type_traits>

#include "nil/crypto3/multiprecision/detail/big_uint/big_uint_impl.hpp"
#include "nil/crypto3/multiprecision/detail/type_traits.hpp"

namespace nil::crypto3::multiprecision {
    template<typename T, std::enable_if_t<std::is_integral_v<T>, int> = 0>
    constexpr std::size_t msb(T a) {
        // TODO(ioxid): optimize
        return detail::as_big_uint(detail::unsigned_or_throw(a)).msb();
    }

    template<typename T, std::enable_if_t<std::is_integral_v<T>, int> = 0>
    constexpr std::size_t lsb(T a) {
        // TODO(ioxid): optimize
        return detail::as_big_uint(detail::unsigned_or_throw(a)).lsb();
    }

    template<typename T, std::enable_if_t<std::is_integral_v<T>, int> = 0>
    constexpr bool bit_test(T a, std::size_t index) {
        // TODO(ioxid): optimize
        return detail::as_big_uint(detail::unsigned_or_throw(a)).bit_test(index);
    }

    template<typename T, std::enable_if_t<std::is_integral_v<T>, int> = 0>
    constexpr bool is_zero(T a) {
        return a == 0;
    }
}  // namespace nil::crypto3::multiprecision
