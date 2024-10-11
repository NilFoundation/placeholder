#pragma once

#include <type_traits>

#include "nil/crypto3/multiprecision/big_integer/big_integer.hpp"
#include "nil/crypto3/multiprecision/big_integer/modular/modular_big_integer_impl.hpp"  // IWYU pragma: export
#include "nil/crypto3/multiprecision/big_integer/modular/modular_big_integer_ops.hpp"  // IWYU pragma: export
#include "nil/crypto3/multiprecision/big_integer/modular/modular_params.hpp"

namespace nil::crypto3::multiprecision {
    template<const auto& modulus>
    using modular_big_integer_ct =
        modular_big_integer<std::decay_t<decltype(modulus)>,
                            modular_params_storage_ct<std::decay_t<decltype(modulus)>, modulus>>;

    // TODO(ioxid): modulus in constructor
    template<unsigned Bits>
    using modular_big_integer_rt =
        modular_big_integer<big_integer<Bits>, modular_params_storage_rt<big_integer<Bits>>>;
}  // namespace nil::crypto3::multiprecision
