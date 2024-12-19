#pragma once

#include "nil/crypto3/multiprecision/detail/big_uint/big_uint_impl.hpp"      // IWYU pragma: export
#include "nil/crypto3/multiprecision/detail/big_uint/limits.hpp"             // IWYU pragma: export
#include "nil/crypto3/multiprecision/detail/big_uint/ops/gcd_inverse.hpp"    // IWYU pragma: export
#include "nil/crypto3/multiprecision/detail/big_uint/ops/import_export.hpp"  // IWYU pragma: export
#include "nil/crypto3/multiprecision/detail/big_uint/ops/jacobi.hpp"         // IWYU pragma: export
#include "nil/crypto3/multiprecision/detail/big_uint/ops/powm.hpp"           // IWYU pragma: export
#include "nil/crypto3/multiprecision/detail/big_uint/ops/ressol.hpp"         // IWYU pragma: export
#include "nil/crypto3/multiprecision/detail/big_uint/ops/wnaf.hpp"           // IWYU pragma: export

namespace nil::crypto3::multiprecision {
    using uint128_t = big_uint<128>;
    using uint256_t = big_uint<256>;
    using uint512_t = big_uint<512>;
    using uint1024_t = big_uint<1024>;
}  // namespace nil::crypto3::multiprecision
