#pragma once

#include <climits>
#include <cstddef>
#include <stdexcept>

namespace nil::crypto3::multiprecision::detail {
    /*
     * Compute input^-1 mod 2^Bits. Throws an exception if input
     * is even. If input is odd, then input and 2^n are relatively prime
     * and an inverse exists.
     */
    template<typename T>
    constexpr T montgomery_inverse(const T &a) {
        constexpr std::size_t Bits = sizeof(T) * CHAR_BIT;

        if (a % 2 == 0) {
            throw std::invalid_argument("inverse does not exist");
        }

        T b = 1;
        T r = 0;

        for (std::size_t i = 0; i < Bits; ++i) {
            const T bi = b % 2;
            r >>= 1;
            r += bi << (Bits - 1);

            b -= a * bi;
            b >>= 1;
        }

        return r;
    }

}  // namespace nil::crypto3::multiprecision::detail
