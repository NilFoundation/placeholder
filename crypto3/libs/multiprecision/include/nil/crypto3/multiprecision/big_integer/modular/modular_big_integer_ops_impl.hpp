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

#include <algorithm>
#include <cmath>
#include <cstddef>
#include <tuple>
#include <type_traits>
#include <vector>

#include <boost/predef.h>
#include <boost/cstdint.hpp>
#include <boost/functional/hash_fwd.hpp>

#include "nil/crypto3/multiprecision/big_integer/big_integer.hpp"
#include "nil/crypto3/multiprecision/big_integer/modular/modular_big_integer_impl.hpp"
#include "nil/crypto3/multiprecision/big_integer/modular/modular_ops.hpp"

namespace nil::crypto3::multiprecision::detail {
    template<unsigned Bits, typename modular_ops_t>
    constexpr void subtract(modular_big_integer_impl<big_integer<Bits>, modular_ops_t> &result,
                            const modular_big_integer_impl<big_integer<Bits>, modular_ops_t> &o) {
        if (result.base_data() < o.base_data()) {
            auto v = result.modular_ops().get_mod();
            v -= o.base_data();
            result.base_data() += v;
        } else {
            result.base_data() -= o.base_data();
        }
    }

    // template<unsigned Bits, typename big_integer_t, typename T, typename modular_ops_t>
    // constexpr void eval_powm(modular_big_integer_impl<big_integer<Bits>, modular_ops_t> &result,
    //                          const modular_big_integer_impl<big_integer_t, modular_ops_t> &b,
    //                          const T &e) {
    //     result.set_modular_ops(b.modular_ops());
    //     result.modular_ops().exp(result.base_data(), b.base_data(), e);
    // }

    // template<unsigned Bits, typename big_integer_t1, typename big_integer_t2,
    //          typename modular_ops_t>
    // constexpr void eval_powm(modular_big_integer_impl<big_integer<Bits>, modular_ops_t> &result,
    //                          const modular_big_integer_impl<big_integer_t1, modular_ops_t> &b,
    //                          const modular_big_integer_impl<big_integer_t2, modular_ops_t> &e) {
    //     using big_integer_t = big_integer<Bits>;

    //     big_integer_t exp;
    //     e.modular_ops().adjust_regular(exp, e.base_data());
    //     eval_powm(result, b, exp);
    // }

    // template<unsigned Bits, typename modular_ops_t>
    // constexpr void eval_inverse_mod(
    //     modular_big_integer_impl<big_integer<Bits>, modular_ops_t> &result,
    //     const modular_big_integer_impl<big_integer<Bits>, modular_ops_t> &input) {
    //     using big_integer_t = big_integer<Bits>;
    //     using big_integer_t_padded_limbs =
    //         typename modular_ops<big_integer_t>::policy_type::big_integer_padded_limbs;

    //     big_integer_t_padded_limbs new_base, res, tmp = input.modular_ops().get_mod();

    //     input.modular_ops().adjust_regular(new_base, input.base_data());
    //     eval_inverse_mod(res, new_base, tmp);
    //     assign_components(result, res, input.modular_ops().get_mod());
    // }

    // template<class big_integer_t1, class big_integer_t2>
    // constexpr void eval_redc(big_integer_t1 &result, const modular_ops<big_integer_t2> &mod) {
    //     mod.reduce(result);
    //     eval_modulus(result, mod.get_mod());
    // }

    // template<class big_integer_t, typename modular_ops_t>
    // constexpr void eval_multiply(modular_big_integer_impl<big_integer_t, modular_ops_t> &result,
    //                              const modular_big_integer_impl<big_integer_t, modular_ops_t> &o)
    //                              {
    //     eval_multiply(result.base_data(), o.base_data());
    //     eval_redc(result.base_data(), result.modular_ops());
    // }

    // template<class big_integer_t, typename modular_ops_t>
    // constexpr void eval_divide(modular_big_integer_impl<big_integer_t, modular_ops_t> &result,
    //                            const modular_big_integer_impl<big_integer_t, modular_ops_t> &o) {
    //     big_integer_t tmp1, tmp2;
    //     result.modular_ops().adjust_regular(tmp1, result.base_data());
    //     result.modular_ops().adjust_regular(tmp2, o.base_data());
    //     eval_divide(tmp1, tmp2);
    //     result.base_data() = tmp1;
    //     result.modular_ops().adjust_modular(result.base_data());
    //     result.modular_ops().adjust_regular(tmp2, result.base_data());
    // }

    // template<class big_integer_t, typename modular_ops_t>
    // constexpr void eval_sqrt(modular_big_integer_impl<big_integer_t, modular_ops_t> &result,
    //                          const modular_big_integer_impl<big_integer_t, modular_ops_t> &val) {
    //     eval_sqrt(result.base_data(), val.base_data());
    // }

    // inline size_t window_bits(size_t exp_bits) {
    //     constexpr static size_t wsize_count = 6;
    //     constexpr static size_t wsize[wsize_count][2] = {{1434, 7}, {539, 6}, {197, 4},
    //                                                      {70, 3},   {17, 2},  {0, 0}};

    //     size_t window_bits = 1;

    //     size_t j = wsize_count - 1;
    //     while (wsize[j][0] > exp_bits) {
    //         --j;
    //     }
    //     window_bits += wsize[j][1];

    //     return window_bits;
    // }

    // template<class big_integer_t, typename modular_ops_t>
    // inline void find_modular_pow(modular_big_integer_impl<big_integer_t, modular_ops_t> &result,
    //                              const modular_big_integer_impl<big_integer_t, modular_ops_t> &b,
    //                              const big_integer_t &exp) {
    //     modular_ops<big_integer_t> mod = b.modular_ops();
    //     size_t m_window_bits;
    //     unsigned long cur_exp_index;
    //     size_t exp_bits = eval_msb(exp);
    //     m_window_bits = window_bits(exp_bits + 1);

    //     std::vector<big_integer_t> m_g(1U << m_window_bits);
    //     big_integer_t *p_g = m_g.data();
    //     big_integer_t x(1, mod);
    //     big_integer_t nibble = exp;
    //     big_integer_t mask;
    //     eval_bit_set(mask, m_window_bits);
    //     eval_decrement(mask);
    //     *p_g = x;
    //     ++p_g;
    //     *p_g = b;
    //     ++p_g;
    //     for (size_t i = 2; i < (1U << m_window_bits); i++) {
    //         eval_multiply(*p_g, m_g[i - 1], b);
    //         ++p_g;
    //     }
    //     size_t exp_nibbles = (exp_bits + 1 + m_window_bits - 1) / m_window_bits;
    //     std::vector<size_t> exp_index;

    //     for (size_t i = 0; i < exp_nibbles; ++i) {
    //         big_integer_t tmp = nibble;
    //         eval_bitwise_and(tmp, mask);
    //         eval_convert_to(&cur_exp_index, tmp);
    //         eval_right_shift(nibble, m_window_bits);
    //         exp_index.push_back(cur_exp_index);
    //     }

    //     eval_multiply(x, m_g[exp_index[exp_nibbles - 1]]);
    //     for (size_t i = exp_nibbles - 1; i > 0; --i) {
    //         for (size_t j = 0; j != m_window_bits; ++j) {
    //             eval_multiply(x, x);
    //         }

    //         eval_multiply(x, m_g[exp_index[i - 1]]);
    //     }
    //     result = x;
    // }

    // template<class big_integer_t, typename modular_ops_t, typename T>
    // constexpr void eval_pow(modular_big_integer_impl<big_integer_t, modular_ops_t> &result,
    //                         const modular_big_integer_impl<big_integer_t, modular_ops_t> &b,
    //                         const T &e) {
    //     find_modular_pow(result, b, e);
    // }

    // template<class big_integer_t, typename modular_ops_t>
    // constexpr void eval_pow(modular_big_integer_impl<big_integer_t, modular_ops_t> &result,
    //                         const modular_big_integer_impl<big_integer_t, modular_ops_t> &b,
    //                         const modular_big_integer_impl<big_integer_t, modular_ops_t> &e) {
    //     big_integer_t exp;
    //     e.modular_ops().adjust_regular(exp, e.base_data());
    //     find_modular_pow(result, b, exp);
    // }

    // template<typename big_integer_t1, typename big_integer_t2, typename T, typename
    // modular_ops_t> constexpr void eval_powm(modular_big_integer_impl<big_integer_t1,
    // modular_ops_t> &result,
    //                          const modular_big_integer_impl<big_integer_t2, modular_ops_t> &b,
    //                          const T &e) {
    //     eval_pow(result, b, e);
    // }

    // template<typename big_integer_t1, typename big_integer_t2, typename big_integer_t3,
    //          typename modular_ops_t>
    // constexpr void eval_powm(modular_big_integer_impl<big_integer_t1, modular_ops_t> &result,
    //                          const modular_big_integer_impl<big_integer_t2, modular_ops_t> &b,
    //                          const modular_big_integer_impl<big_integer_t3, modular_ops_t> &e) {
    //     eval_pow(result, b, e);
    // }
}  // namespace nil::crypto3::multiprecision::detail
