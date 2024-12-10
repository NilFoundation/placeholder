//---------------------------------------------------------------------------//
// Copyright (c) 2020 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2019-2021 Aleksei Moskvin <alalmoskvin@nil.foundation>
// Copyright (c) 2020 Ilias Khairullin <ilias@nil.foundation>
// Copyright (c) 2024 Andrey Nefedov <ioxid@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#pragma once

// IWYU pragma: private; include "nil/crypto3/multiprecision/big_mod.hpp"

#include <limits>
#include <type_traits>

#include "nil/crypto3/multiprecision/detail/big_mod/big_mod_impl.hpp"
#include "nil/crypto3/multiprecision/detail/big_mod/ops/inverse.hpp"

namespace nil::crypto3::multiprecision {
    template<typename big_mod_t, typename T,
             std::enable_if_t<detail::is_big_mod_v<big_mod_t> && std::numeric_limits<T>::is_integer,
                              int> = 0>
    constexpr big_mod_t pow(big_mod_t b, T e) {
        if constexpr (std::is_signed_v<T>) {
            if (e < 0) {
                b = inverse_extended_euclidean_algorithm(b);
                // TODO(ioxid): this won't work for e == min()
                e = -e;
            }
        }
        auto result = b;
        result.ops().exp(result.raw_base(), b.raw_base(), std::move(e));
        return result;
    }
}  // namespace nil::crypto3::multiprecision
