#pragma once

#include <cstddef>
#include <type_traits>

#include "nil/crypto3/multiprecision/big_int/big_uint.hpp"

namespace nil::crypto3::multiprecision {
    template<std::size_t Bits>
    constexpr std::size_t msb(const big_uint<Bits> &a) {
        return a.msb();
    }

    template<typename T, std::enable_if_t<std::is_integral_v<T>, int> = 0>
    constexpr std::size_t msb(T a) {
        return static_cast<big_uint<detail::get_bits<T>()>>(a).msb();
    }

    template<std::size_t Bits>
    constexpr std::size_t lsb(const big_uint<Bits> &a) {
        return a.lsb();
    }

    template<typename T, std::enable_if_t<std::is_integral_v<T>, int> = 0>
    constexpr std::size_t lsb(T a) {
        return static_cast<big_uint<detail::get_bits<T>()>>(a).lsb();
    }

    template<std::size_t Bits>
    constexpr bool bit_test(const big_uint<Bits> &a, std::size_t index) {
        return a.bit_test(index);
    }

    template<typename T, std::enable_if_t<std::is_integral_v<T>, int> = 0>
    constexpr bool bit_test(T a, std::size_t index) {
        return static_cast<big_uint<detail::get_bits<T>()>>(a).bit_test(index);
    }

    template<std::size_t Bits1, std::size_t Bits2>
    constexpr void divide_qr(big_uint<Bits1> a, big_uint<Bits2> b, big_uint<Bits1> &q,
                             big_uint<Bits1> &r) {
        // TODO(ioxid): make this efficient by using private `divide`
        q = a / b;
        r = a % b;
    }
}  // namespace nil::crypto3::multiprecision
