//---------------------------------------------------------------------------//
// Copyright (c) 2018-2020 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2024 Andrey Nefedov <ioxid@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#pragma once

#include <cstddef>
#include <type_traits>

namespace nil::crypto3::multiprecision {
    template<std::size_t Bits>
    class big_uint;

    template<typename modular_ops_storage_t_>
    class big_mod_impl;

    template<typename T>
    struct is_big_uint : std::false_type {};

    template<std::size_t Bits>
    struct is_big_uint<big_uint<Bits>> : std::true_type {};

    template<typename T>
    constexpr bool is_big_uint_v = is_big_uint<T>::value;

    template<typename T>
    struct is_integral
        : std::integral_constant<bool, std::is_integral_v<T> || is_big_uint_v<T>> {};

    template<typename T>
    constexpr bool is_integral_v = is_integral<T>::value;

    template<typename T>
    concept integral = is_integral_v<T>;

    template<typename T>
    struct is_big_mod : std::false_type {};

    template<typename modular_ops_storage_t_>
    struct is_big_mod<big_mod_impl<modular_ops_storage_t_>> : std::true_type {};

    template<typename T>
    constexpr bool is_big_mod_v = is_big_mod<T>::value;
}  // namespace nil::crypto3::multiprecision
