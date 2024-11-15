#pragma once

// IWYU pragma: private

#include <climits>
#include <cstddef>
#include <cstdint>

#include "nil/crypto3/multiprecision/big_int/detail/int128.hpp"

namespace nil::crypto3::multiprecision::detail {
#ifdef NIL_CO3_MP_HAS_INT128
    using limb_type = std::uint64_t;
    using double_limb_type = uint128_t;
    using signed_limb_type = std::int64_t;
    using signed_double_limb_type = int128_t;
#else
    using limb_type = std::uint32_t;
    using double_limb_type = std::uint64_t;
    using signed_limb_type = std::int32_t;
    using signed_double_limb_type = std::int64_t;
#endif

    using limb_type = limb_type;
    using double_limb_type = double_limb_type;
    using limb_pointer = limb_type *;
    using const_limb_pointer = const limb_type *;

    static constexpr std::size_t limb_bits = sizeof(limb_type) * CHAR_BIT;
    static constexpr limb_type max_limb_value = ~static_cast<limb_type>(0u);

    // Given a value represented in 'double_limb_type', decomposes it into
    // two 'limb_type' variables, based on high order bits and low order bits.
    // There 'a' receives high order bits of 'X', and 'b' receives the low order bits.
    static constexpr void dbl_limb_to_limbs(const double_limb_type &X, limb_type &a, limb_type &b) {
        b = X;
        a = X >> limb_bits;
    }
}  // namespace nil::crypto3::multiprecision::detail
