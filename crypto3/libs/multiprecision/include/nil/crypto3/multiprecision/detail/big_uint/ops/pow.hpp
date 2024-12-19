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

// IWYU pragma: private; include "nil/crypto3/multiprecision/big_uint.hpp"

#include <type_traits>

#include "nil/crypto3/multiprecision/detail/big_uint/big_uint_impl.hpp"
#include "nil/crypto3/multiprecision/detail/integer_ops_base.hpp"

namespace nil::crypto3::multiprecision {
    template<typename T1, typename T2,
             std::enable_if_t<detail::is_integral_v<std::decay_t<T1>> &&
                                  detail::is_integral_v<std::decay_t<T2>>,
                              int> = 0>
    constexpr std::decay_t<T1> pow(T1 b, T2 e) {
        if (is_zero(e)) {
            return 1u;
        }

        T1 res = 1u;

        while (true) {
            bool lsb = bit_test(e, 0u);
            e >>= 1u;
            if (lsb) {
                res *= b;
                if (is_zero(e)) {
                    break;
                }
            }
            b *= b;
        }

        return res;
    }
}  // namespace nil::crypto3::multiprecision
