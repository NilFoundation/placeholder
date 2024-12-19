#pragma once

#include <algorithm>
#include <climits>
#include <cstddef>
#include <type_traits>

#include "nil/crypto3/multiprecision/detail/big_uint/storage.hpp"

namespace nil::crypto3::multiprecision {
    template<std::size_t Bits>
    class big_uint;

    namespace detail {
        template<typename T>
        constexpr bool is_big_uint_v = false;

        template<std::size_t Bits>
        constexpr bool is_big_uint_v<big_uint<Bits>> = true;

        template<typename T>
        constexpr bool is_integral_v = std::is_integral_v<T> || is_big_uint_v<T>;

        template<typename T, std::enable_if_t<std::is_integral_v<T>, int> = 0>
        constexpr std::size_t get_bits() {
            return sizeof(T) * CHAR_BIT;
        }

        template<typename T, std::enable_if_t<is_big_uint_v<T>, int> = 0>
        constexpr std::size_t get_bits() {
            return T::Bits;
        }

        template<typename T1, typename T2>
        using largest_big_uint_t =
            std::conditional_t<is_big_uint_v<T1> && is_big_uint_v<T2>,
                               big_uint<std::max(get_bits<T1>(), get_bits<T2>())>,
                               std::conditional_t<is_big_uint_v<T1>, T1, T2>>;

        template<typename T,
                 std::enable_if_t<std::is_integral_v<T> && std::is_unsigned_v<T>, int> = 0>
        constexpr big_uint<sizeof(T) * CHAR_BIT> as_big_uint(const T& a) {
            return static_cast<big_uint<sizeof(T) * CHAR_BIT>>(a);
        }

        template<typename T, std::enable_if_t<is_big_uint_v<std::decay_t<T>>, int> = 0>
        constexpr decltype(auto) as_big_uint(T&& a) {
            return std::forward<T>(a);
        }

        template<typename T, std::enable_if_t<std::is_integral_v<T> && std::is_unsigned_v<T> &&
                                                  sizeof(T) * CHAR_BIT <= limb_bits,
                                              int> = 0>
        constexpr limb_type as_limb_type_or_big_uint(const T& a) {
            return static_cast<limb_type>(a);
        }

        template<typename T, std::enable_if_t<!(std::is_integral_v<T> && std::is_unsigned_v<T> &&
                                                sizeof(T) * CHAR_BIT <= limb_bits) &&
                                                  !is_big_uint_v<T>,
                                              int> = 0>
        constexpr auto as_limb_type_or_big_uint(const T& a) {
            return as_big_uint(a);
        }

        template<typename T, std::enable_if_t<is_big_uint_v<std::decay_t<T>>, int> = 0>
        constexpr decltype(auto) as_limb_type_or_big_uint(T&& a) {
            return std::forward<T>(a);
        }
    }  // namespace detail
}  // namespace nil::crypto3::multiprecision
