//---------------------------------------------------------------------------//
// Copyright (c) 2012-2021 John Maddock
// Copyright (c) 2020 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020 Ilias Khairullin <ilias@nil.foundation>
// Copyright (c) 2021 Aleksei Moskvin <alalmoskvin@nil.foundation>
// Copyright (c) 2021 Matt Borland
// Copyright (c) 2024 Andrey Nefedov <ioxid@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#pragma once

#include <climits>
#include <cstddef>
#include <cstdint>

#include "nil/crypto3/multiprecision/detail/int128.hpp"

namespace nil::crypto3::multiprecision::detail {
#ifdef NIL_CO3_MP_HAS_INT128
    using limb_type = std::uint64_t;
    using double_limb_type = detail::uint128_t;
    using signed_limb_type = std::int64_t;
    using signed_double_limb_type = detail::int128_t;
#else
    using limb_type = std::uint32_t;
    using double_limb_type = std::uint64_t;
    using signed_limb_type = std::int32_t;
    using signed_double_limb_type = std::int64_t;
#endif

    using limb_pointer = limb_type *;
    using const_limb_pointer = const limb_type *;

    static constexpr std::size_t limb_bits = sizeof(limb_type) * CHAR_BIT;
    static constexpr limb_type max_limb_value = ~static_cast<limb_type>(0u);
    static constexpr double_limb_type max_double_limb_value = ~static_cast<double_limb_type>(0u);

    // Given a value represented in 'double_limb_type', decomposes it into
    // two 'limb_type' variables, based on high order bits and low order bits.
    // There 'a' receives high order bits of 'X', and 'b' receives the low order bits.
    static constexpr void dbl_limb_to_limbs(const double_limb_type &X, limb_type &a, limb_type &b) {
        b = X;
        a = X >> limb_bits;
    }
}  // namespace nil::crypto3::multiprecision::detail
