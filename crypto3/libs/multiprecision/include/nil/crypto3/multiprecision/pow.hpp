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

#include <limits>
#include <type_traits>

#include "nil/crypto3/multiprecision/big_mod.hpp"
#include "nil/crypto3/multiprecision/big_uint.hpp"
#include "nil/crypto3/multiprecision/detail/integer_ops_base.hpp"
#include "nil/crypto3/multiprecision/inverse.hpp"
#include "nil/crypto3/multiprecision/unsigned_utils.hpp"

namespace nil::crypto3::multiprecision {
    template<typename big_mod_t, typename T,
             std::enable_if_t<is_big_mod_v<big_mod_t> && is_integral_v<T> &&
                                  !std::numeric_limits<T>::is_signed,
                              int> = 0>
    constexpr big_mod_t pow(const big_mod_t &b, const T &e) {
        return pow_unsigned(b, e);
    }

    template<typename big_mod_t, typename T,
             std::enable_if_t<is_big_mod_v<big_mod_t> && is_integral_v<T> &&
                                  std::numeric_limits<T>::is_signed,
                              int> = 0>
    constexpr big_mod_t pow(const big_mod_t &b, const T &e) {
        if (e < 0) {
            return pow_unsigned(inverse(b), unsigned_abs(e));
        }
        return pow_unsigned(b, static_cast<std::make_unsigned_t<T>>(e));
    }

    template<
        typename T1, typename T2,
        std::enable_if_t<
            is_integral_v<std::decay_t<T1>> && is_integral_v<std::decay_t<T2>>, int> = 0>
    constexpr std::decay_t<T1> pow(T1 b, T2 e_original) {
        if (is_zero(e_original)) {
            return 1u;
        }

        auto e = unsigned_or_throw(e_original);

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

    template<typename T1, typename T2, typename T3,
             std::enable_if_t<is_integral_v<std::decay_t<T1>> &&
                                  is_integral_v<std::decay_t<T2>> &&
                                  is_integral_v<std::decay_t<T3>>,
                              int> = 0>
    constexpr std::decay_t<T3> powm(T1 &&b, T2 &&e, T3 &&m) {
        using big_mod_t = big_mod_rt<
            std::decay_t<decltype(detail::as_big_uint(unsigned_or_throw(m)))>::Bits>;
        return static_cast<std::decay_t<T3>>(
            pow(big_mod_t(std::forward<T1>(b), std::forward<T3>(m)), std::forward<T2>(e))
                .to_integral());
    }
}  // namespace nil::crypto3::multiprecision
