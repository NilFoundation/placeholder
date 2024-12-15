#pragma once

#include <cstddef>
#include <type_traits>

#include "nil/crypto3/multiprecision/detail/big_uint/big_uint_impl.hpp"

namespace nil::crypto3::multiprecision {
    template<std::size_t Bits_, typename modular_ops_storage_t_>
    class big_mod_impl;

    namespace detail {
        template<typename T>
        constexpr bool is_big_mod_v = false;

        template<std::size_t Bits_, typename modular_ops_storage_t_>
        constexpr bool is_big_mod_v<big_mod_impl<Bits_, modular_ops_storage_t_>> = true;

        template<typename T>
        constexpr bool is_modular_integral_v =
            std::is_integral_v<T> || is_big_uint_v<T> || is_big_mod_v<T>;

        template<typename T, std::enable_if_t<is_big_mod_v<T>, int> = 0>
        constexpr std::size_t get_bits() {
            return T::Bits;
        }
    }  // namespace detail
}  // namespace nil::crypto3::multiprecision
