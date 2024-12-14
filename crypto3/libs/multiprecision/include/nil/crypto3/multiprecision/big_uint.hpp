#pragma once

#include "nil/crypto3/multiprecision/big_uint_impl.hpp"      // IWYU pragma: export
#include "nil/crypto3/multiprecision/limits.hpp"             // IWYU pragma: export
#include "nil/crypto3/multiprecision/ops/gcd_inverse.hpp"    // IWYU pragma: export
#include "nil/crypto3/multiprecision/ops/import_export.hpp"  // IWYU pragma: export
#include "nil/crypto3/multiprecision/ops/jacobi.hpp"         // IWYU pragma: export
#include "nil/crypto3/multiprecision/ops/powm.hpp"           // IWYU pragma: export
#include "nil/crypto3/multiprecision/ops/ressol.hpp"         // IWYU pragma: export
#include "nil/crypto3/multiprecision/ops/wnaf.hpp"           // IWYU pragma: export

namespace nil::crypto3::multiprecision {
    using uint128_t = big_uint<128>;
    using uint256_t = big_uint<256>;
    using uint512_t = big_uint<512>;
    using uint1024_t = big_uint<1024>;
}  // namespace nil::crypto3::multiprecision
