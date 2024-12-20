//---------------------------------------------------------------------------//
// Copyright (c) 2024 Andrey Nefedov <ioxid@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#pragma once

#include "nil/crypto3/multiprecision/detail/big_mod/type_traits.hpp"

namespace nil::crypto3::multiprecision::detail {
    // This should be used in tests or benchmarks only
    template<typename big_mod_t>
    constexpr const auto& get_raw_base(const big_mod_t& a) {
        static_assert(detail::is_big_mod_v<big_mod_t>);
        return a.raw_base();
    }
}  // namespace nil::crypto3::multiprecision::detail