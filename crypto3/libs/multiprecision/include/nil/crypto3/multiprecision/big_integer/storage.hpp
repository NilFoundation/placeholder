#pragma once

#include <cstdint>

namespace nil::crypto3::multiprecision {
    using limb_type = std::uint32_t;
    using double_limb_type = std::uint64_t;
    using signed_limb_type = std::int32_t;
    using signed_double_limb_type = std::int64_t;
}  // namespace nil::crypto3::multiprecision
