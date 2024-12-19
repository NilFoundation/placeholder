//---------------------------------------------------------------------------//
// Copyright (c) 2019-2021 Aleksei Moskvin <alalmoskvin@nil.foundation>
// Copyright (c) 2020 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020 Ilias Khairullin <ilias@nil.foundation>
// Copyright (c) 2024 Andrey Nefedov <ioxid@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#pragma once

// IWYU pragma: private; include "nil/crypto3/multiprecision/big_mod.hpp"

#include <type_traits>

#include "nil/crypto3/multiprecision/detail/big_mod/big_mod_impl.hpp"
#include "nil/crypto3/multiprecision/detail/big_uint/ops/gcd_inverse.hpp"

namespace nil::crypto3::multiprecision {
    template<typename big_mod_t, std::enable_if_t<detail::is_big_mod_v<big_mod_t>, int> = 0>
    constexpr big_mod_t inverse(const big_mod_t &modular) {
        return big_mod_t(inverse_mod(modular.base(), modular.mod()), modular.ops_storage());
    }
}  // namespace nil::crypto3::multiprecision
