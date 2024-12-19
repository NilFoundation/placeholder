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

#include <limits>
#include <type_traits>

#include "nil/crypto3/multiprecision/detail/big_mod/big_mod_impl.hpp"
#include "nil/crypto3/multiprecision/detail/big_mod/ops/inverse.hpp"
#include "nil/crypto3/multiprecision/detail/integer_utils.hpp"

namespace nil::crypto3::multiprecision {
    template<typename big_mod_t, typename T,
             std::enable_if_t<detail::is_big_mod_v<big_mod_t> && detail::is_integral_v<T> &&
                                  !std::numeric_limits<T>::is_signed,
                              int> = 0>
    constexpr big_mod_t pow(const big_mod_t &b, const T &e) {
        return pow_unsigned(b, e);
    }

    template<typename big_mod_t, typename T,
             std::enable_if_t<detail::is_big_mod_v<big_mod_t> && detail::is_integral_v<T> &&
                                  std::numeric_limits<T>::is_signed,
                              int> = 0>
    constexpr big_mod_t pow(const big_mod_t &b, const T &e) {
        if (e < 0) {
            return pow_unsigned(inverse(b), detail::unsigned_abs(e));
        }
        return pow_unsigned(b, static_cast<std::make_unsigned_t<T>>(e));
    }
}  // namespace nil::crypto3::multiprecision
