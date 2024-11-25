#pragma once

#include <cstddef>
#include <type_traits>

#include "nil/crypto3/multiprecision/big_int/big_uint_impl.hpp"

namespace nil::crypto3::multiprecision {
    template<typename T, std::enable_if_t<std::is_integral_v<T>, int> = 0>
    constexpr std::size_t msb(T a) {
        // TODO(ioxid): optimize
        return static_cast<big_uint<detail::get_bits<T>()>>(a).msb();
    }

    template<typename T, std::enable_if_t<std::is_integral_v<T>, int> = 0>
    constexpr std::size_t lsb(T a) {
        // TODO(ioxid): optimize
        return static_cast<big_uint<detail::get_bits<T>()>>(a).lsb();
    }

    template<typename T, std::enable_if_t<std::is_integral_v<T>, int> = 0>
    constexpr bool bit_test(T a, std::size_t index) {
        // TODO(ioxid): optimize
        return static_cast<big_uint<detail::get_bits<T>()>>(a).bit_test(index);
    }

    template<typename T, std::enable_if_t<std::is_integral_v<T>, int> = 0>
    constexpr bool is_zero(T a) {
        return a == 0;
    }
}  // namespace nil::crypto3::multiprecision
