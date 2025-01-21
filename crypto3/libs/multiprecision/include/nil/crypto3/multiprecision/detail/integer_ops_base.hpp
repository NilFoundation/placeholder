//---------------------------------------------------------------------------//
// Copyright (c) 2024 Andrey Nefedov <ioxid@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#pragma once

#include <climits>
#include <cstddef>
#include <stdexcept>
#include <type_traits>
#include <bit>

namespace nil::crypto3::multiprecision {

    template<typename T,
             std::enable_if_t<std::is_integral_v<T> && std::is_unsigned_v<T>, int> = 0>
    constexpr std::size_t lsb(T a) {
        if (a == 0) {
            throw std::invalid_argument("zero has no lsb");
        }
        return std::countr_zero(a);
    }

    template<typename T,
             std::enable_if_t<std::is_integral_v<T> && std::is_unsigned_v<T>, int> = 0>
    constexpr std::size_t msb(T a) {
        if (a == 0) {
            throw std::invalid_argument("zero has no msb");
        }
        return std::bit_width(a) - 1;
    }

    template<typename T,
             std::enable_if_t<std::is_integral_v<T> && std::is_unsigned_v<T>, int> = 0>
    constexpr bool bit_test(T a, std::size_t index) {
        if (index >= sizeof(T) * CHAR_BIT) {
            // NB: we assume there are infinite leading zeros
            return false;
        }
        auto mask = static_cast<T>(1u) << index;
        return static_cast<bool>(a & mask);
    }

    template<typename T,
             std::enable_if_t<std::is_integral_v<T> && std::is_unsigned_v<T>, int> = 0>
    constexpr T &bit_set(T &a, std::size_t index) {
        if (index >= sizeof(T) * CHAR_BIT) {
            throw std::invalid_argument("fixed precision overflow");
        }
        auto mask = static_cast<T>(1u) << index;
        a |= mask;
        return a;
    }

    template<typename T,
             std::enable_if_t<std::is_integral_v<T> && std::is_unsigned_v<T>, int> = 0>
    constexpr T &bit_unset(T &a, std::size_t index) {
        if (index >= sizeof(T) * CHAR_BIT) {
            throw std::invalid_argument("fixed precision overflow");
        }
        auto mask = static_cast<T>(1u) << index;
        a &= ~mask;
        return a;
    }

    template<typename T,
             std::enable_if_t<std::is_integral_v<T> && std::is_unsigned_v<T>, int> = 0>
    constexpr T &bit_flip(T &a, std::size_t index) {
        if (index >= sizeof(T) * CHAR_BIT) {
            throw std::invalid_argument("fixed precision overflow");
        }
        auto mask = static_cast<T>(1u) << index;
        a ^= mask;
        return a;
    }

    template<typename T, std::enable_if_t<std::is_integral_v<T>, int> = 0>
    constexpr bool is_zero(T a) {
        return a == 0;
    }
}  // namespace nil::crypto3::multiprecision
