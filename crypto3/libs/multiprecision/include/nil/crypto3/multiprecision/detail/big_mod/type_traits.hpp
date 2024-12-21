//---------------------------------------------------------------------------//
// Copyright (c) 2024 Andrey Nefedov <ioxid@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#pragma once

namespace nil::crypto3::multiprecision {
    template<typename modular_ops_storage_t_>
    class big_mod_impl;

    namespace detail {
        template<typename T>
        constexpr bool is_big_mod_v = false;

        template<typename modular_ops_storage_t_>
        constexpr bool is_big_mod_v<big_mod_impl<modular_ops_storage_t_>> = true;
    }  // namespace detail
}  // namespace nil::crypto3::multiprecision
