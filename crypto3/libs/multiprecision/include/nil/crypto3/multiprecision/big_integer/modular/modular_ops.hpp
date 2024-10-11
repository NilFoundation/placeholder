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
#include <vector>

#include <boost/predef.h>
#include <boost/cstdint.hpp>
#include <boost/functional/hash_fwd.hpp>
#include <boost/lexical_cast.hpp>

#include "nil/crypto3/multiprecision/big_integer/big_integer.hpp"
#include "nil/crypto3/multiprecision/big_integer/modular/modular_big_integer_impl.hpp"
#include "nil/crypto3/multiprecision/big_integer/modular/modular_params.hpp"

namespace nil::crypto3::multiprecision {

    template<unsigned Bits, typename modular_params_t>
    constexpr void eval_add(modular_big_integer<big_integer<Bits>, modular_params_t> &result,
                            const modular_big_integer<big_integer<Bits>, modular_params_t> &o) {
        BOOST_ASSERT(eval_eq(result.mod_data().get_mod(), o.mod_data().get_mod()));
        result.mod_data().mod_add(result.base_data(), o.base_data());
    }

    template<unsigned Bits, typename big_integer_t, typename modular_params_t>
    constexpr void eval_add(modular_big_integer<big_integer<Bits>, modular_params_t> &result,
                            const modular_big_integer<big_integer_t, modular_params_t> &o) {
        result.mod_data().mod_add(result.base_data(), o.base_data());
    }

    template<typename big_integer_t, unsigned Bits, typename modular_params_t>
    constexpr void eval_add(modular_big_integer<big_integer_t, modular_params_t> &result,
                            const modular_big_integer<big_integer<Bits>, modular_params_t> &o) {
        o.mod_data().mod_add(result.base_data(), o.base_data());
    }

    template<unsigned Bits, typename modular_params_t>
    constexpr void eval_multiply(
        modular_big_integer<big_integer<Bits>, modular_params_t> &result,
        const modular_big_integer<big_integer<Bits>, modular_params_t> &o) {
        result.mod_data().mod_mul(result.base_data(), o.base_data());
    }

    template<unsigned Bits, typename big_integer_t, typename modular_params_t>
    constexpr void eval_multiply(modular_big_integer<big_integer<Bits>, modular_params_t> &result,
                                 const modular_big_integer<big_integer_t, modular_params_t> &o) {
        result.mod_data().mod_mul(result.base_data(), o.base_data());
    }

    template<typename big_integer_t, unsigned Bits, typename modular_params_t>
    constexpr void eval_multiply(
        modular_big_integer<big_integer_t, modular_params_t> &result,
        const modular_big_integer<big_integer<Bits>, modular_params_t> &o) {
        o.mod_data().mod_mul(result.base_data(), o.base_data());
    }

    template<unsigned Bits, typename big_integer_t, typename T, typename modular_params_t>
    constexpr void eval_powm(modular_big_integer<big_integer<Bits>, modular_params_t> &result,
                             const modular_big_integer<big_integer_t, modular_params_t> &b,
                             const T &e) {
        result.set_modular_params(b.mod_data());
        result.mod_data().mod_exp(result.base_data(), b.base_data(), e);
    }

    template<unsigned Bits, typename big_integer_t1, typename big_integer_t2,
             typename modular_params_t>
    constexpr void eval_powm(modular_big_integer<big_integer<Bits>, modular_params_t> &result,
                             const modular_big_integer<big_integer_t1, modular_params_t> &b,
                             const modular_big_integer<big_integer_t2, modular_params_t> &e) {
        using big_integer_t = big_integer<Bits>;

        big_integer_t exp;
        e.mod_data().adjust_regular(exp, e.base_data());
        eval_powm(result, b, exp);
    }

    template<unsigned Bits, typename modular_params_t>
    constexpr void eval_inverse_mod(
        modular_big_integer<big_integer<Bits>, modular_params_t> &result,
        const modular_big_integer<big_integer<Bits>, modular_params_t> &input) {
        using big_integer_t = big_integer<Bits>;
        using big_integer_t_padded_limbs =
            typename modular_params<big_integer_t>::policy_type::Backend_padded_limbs;

        big_integer_t_padded_limbs new_base, res, tmp = input.mod_data().get_mod();

        input.mod_data().adjust_regular(new_base, input.base_data());
        eval_inverse_mod(res, new_base, tmp);
        assign_components(result, res, input.mod_data().get_mod());
    }

    // Used for converting number<modular_big_integer<big_integer_t>> to number<big_integer_t>.
    // We cannot change the first argument to a reference...
    template<class big_integer_t, typename modular_params_t>
    constexpr void eval_convert_to(
        big_integer_t *result, const modular_big_integer<big_integer_t, modular_params_t> &val) {
        val.mod_data().adjust_regular(*result, val.base_data());
    }

    template<class big_integer_t, typename modular_params_t, class T>
    constexpr typename boost::enable_if<boost::is_arithmetic<T>, bool>::type eval_eq(
        const modular_big_integer<big_integer_t, modular_params_t> &a, const T &b) {
        return a.compare(b) == 0;
    }

    template<class big_integer_t1, class big_integer_t2>
    constexpr void eval_redc(big_integer_t1 &result, const modular_params<big_integer_t2> &mod) {
        mod.reduce(result);
        eval_modulus(result, mod.get_mod());
    }

    template<class big_integer_t, typename modular_params_t>
    constexpr void eval_add(modular_big_integer<big_integer_t, modular_params_t> &result,
                            const modular_big_integer<big_integer_t, modular_params_t> &o) {
        eval_add(result.base_data(), o.base_data());
        if (!eval_lt(result.base_data(), result.mod_data().get_mod())) {
            eval_subtract(result.base_data(), result.mod_data().get_mod());
        }
    }

    template<class big_integer_t, typename modular_params_t>
    constexpr void eval_subtract(modular_big_integer<big_integer_t, modular_params_t> &result,
                                 const modular_big_integer<big_integer_t, modular_params_t> &o) {
        using ui_type =
            typename std::tuple_element<0, typename big_integer_t::unsigned_types>::type;
        eval_subtract(result.base_data(), o.base_data());
        if (eval_lt(result.base_data(), ui_type(0u))) {
            eval_add(result.base_data(), result.mod_data().get_mod());
        }
    }

    template<unsigned Bits, typename modular_params_t>
    constexpr void eval_subtract(
        modular_big_integer<big_integer<Bits>, modular_params_t> &result,
        const modular_big_integer<big_integer<Bits>, modular_params_t> &o) {
        if (eval_lt(result.base_data(), o.base_data())) {
            auto v = result.mod_data().get_mod();
            eval_subtract(v, o.base_data());
            eval_add(result.base_data(), v);
        } else {
            eval_subtract(result.base_data(), o.base_data());
        }
    }

    template<class big_integer_t, typename modular_params_t>
    constexpr void eval_multiply(modular_big_integer<big_integer_t, modular_params_t> &result,
                                 const modular_big_integer<big_integer_t, modular_params_t> &o) {
        eval_multiply(result.base_data(), o.base_data());
        eval_redc(result.base_data(), result.mod_data());
    }

    template<class big_integer_t, typename modular_params_t>
    constexpr void eval_divide(modular_big_integer<big_integer_t, modular_params_t> &result,
                               const modular_big_integer<big_integer_t, modular_params_t> &o) {
        big_integer_t tmp1, tmp2;
        result.mod_data().adjust_regular(tmp1, result.base_data());
        result.mod_data().adjust_regular(tmp2, o.base_data());
        eval_divide(tmp1, tmp2);
        result.base_data() = tmp1;
        result.mod_data().adjust_modular(result.base_data());
        result.mod_data().adjust_regular(tmp2, result.base_data());
    }

    template<class big_integer_t, typename modular_params_t>
    constexpr void eval_modulus(modular_big_integer<big_integer_t, modular_params_t> &result,
                                const modular_big_integer<big_integer_t, modular_params_t> &o) {
        big_integer_t tmp1, tmp2;
        result.mod_data().adjust_regular(tmp1, result.base_data());
        result.mod_data().adjust_regular(tmp2, o.base_data());
        eval_modulus(tmp1, tmp2);
        result.base_data() = tmp1;
        result.mod_data().adjust_modular(result.base_data());
        // result.mod_data().adjust_regular(tmp2, result.base_data());
    }

    // If called with 3 arguments, delegate the call to the upper function.
    template<class big_integer_t, typename modular_params_t>
    constexpr void eval_modulus(modular_big_integer<big_integer_t, modular_params_t> &result,
                                const modular_big_integer<big_integer_t, modular_params_t> &u,
                                const modular_big_integer<big_integer_t, modular_params_t> &v) {
        result = std::move(u);
        eval_modulus(result, v);
    }

    template<class big_integer_t, typename modular_params_t>
    constexpr bool eval_is_zero(
        const modular_big_integer<big_integer_t, modular_params_t> &val) noexcept {
        return eval_is_zero(val.base_data());
    }

    template<class big_integer_t, typename modular_params_t>
    constexpr int eval_get_sign(
        const modular_big_integer<big_integer_t, modular_params_t> & /*unused*/) {
        return 1;
    }

    template<class big_integer_t, typename modular_params_t, class T, class V>
    constexpr void assign_components(modular_big_integer<big_integer_t, modular_params_t> &result,
                                     const T &a, const V &b) {
        result.base_data() = a;
        result.mod_data() = b;
        result.mod_data().adjust_modular(result.base_data());
    }

    template<class big_integer_t, typename modular_params_t>
    constexpr void eval_sqrt(modular_big_integer<big_integer_t, modular_params_t> &result,
                             const modular_big_integer<big_integer_t, modular_params_t> &val) {
        eval_sqrt(result.base_data(), val.base_data());
    }

    template<class big_integer_t, typename modular_params_t>
    constexpr void eval_abs(modular_big_integer<big_integer_t, modular_params_t> &result,
                            const modular_big_integer<big_integer_t, modular_params_t> &val) {
        result = val;
    }

    inline size_t window_bits(size_t exp_bits) {
        constexpr static size_t wsize_count = 6;
        constexpr static size_t wsize[wsize_count][2] = {{1434, 7}, {539, 6}, {197, 4},
                                                         {70, 3},   {17, 2},  {0, 0}};

        size_t window_bits = 1;

        size_t j = wsize_count - 1;
        while (wsize[j][0] > exp_bits) {
            --j;
        }
        window_bits += wsize[j][1];

        return window_bits;
    }

    template<class big_integer_t, typename modular_params_t>
    inline void find_modular_pow(modular_big_integer<big_integer_t, modular_params_t> &result,
                                 const modular_big_integer<big_integer_t, modular_params_t> &b,
                                 const big_integer_t &exp) {
        modular_params<big_integer_t> mod = b.mod_data();
        size_t m_window_bits;
        unsigned long cur_exp_index;
        size_t exp_bits = eval_msb(exp);
        m_window_bits = window_bits(exp_bits + 1);

        std::vector<big_integer_t> m_g(1U << m_window_bits);
        big_integer_t *p_g = m_g.data();
        big_integer_t x(1, mod);
        big_integer_t nibble = exp;
        big_integer_t mask;
        eval_bit_set(mask, m_window_bits);
        eval_decrement(mask);
        *p_g = x;
        ++p_g;
        *p_g = b;
        ++p_g;
        for (size_t i = 2; i < (1U << m_window_bits); i++) {
            eval_multiply(*p_g, m_g[i - 1], b);
            ++p_g;
        }
        size_t exp_nibbles = (exp_bits + 1 + m_window_bits - 1) / m_window_bits;
        std::vector<size_t> exp_index;

        for (size_t i = 0; i < exp_nibbles; ++i) {
            big_integer_t tmp = nibble;
            eval_bitwise_and(tmp, mask);
            eval_convert_to(&cur_exp_index, tmp);
            eval_right_shift(nibble, m_window_bits);
            exp_index.push_back(cur_exp_index);
        }

        eval_multiply(x, m_g[exp_index[exp_nibbles - 1]]);
        for (size_t i = exp_nibbles - 1; i > 0; --i) {
            for (size_t j = 0; j != m_window_bits; ++j) {
                eval_multiply(x, x);
            }

            eval_multiply(x, m_g[exp_index[i - 1]]);
        }
        result = x;
    }

    template<class big_integer_t, typename modular_params_t, typename T>
    constexpr void eval_pow(modular_big_integer<big_integer_t, modular_params_t> &result,
                            const modular_big_integer<big_integer_t, modular_params_t> &b,
                            const T &e) {
        find_modular_pow(result, b, e);
    }

    template<class big_integer_t, typename modular_params_t>
    constexpr void eval_pow(modular_big_integer<big_integer_t, modular_params_t> &result,
                            const modular_big_integer<big_integer_t, modular_params_t> &b,
                            const modular_big_integer<big_integer_t, modular_params_t> &e) {
        big_integer_t exp;
        e.mod_data().adjust_regular(exp, e.base_data());
        find_modular_pow(result, b, exp);
    }

    template<typename big_integer_t1, typename big_integer_t2, typename T,
             typename modular_params_t>
    constexpr void eval_powm(modular_big_integer<big_integer_t1, modular_params_t> &result,
                             const modular_big_integer<big_integer_t2, modular_params_t> &b,
                             const T &e) {
        eval_pow(result, b, e);
    }

    template<typename big_integer_t1, typename big_integer_t2, typename big_integer_t3,
             typename modular_params_t>
    constexpr void eval_powm(modular_big_integer<big_integer_t1, modular_params_t> &result,
                             const modular_big_integer<big_integer_t2, modular_params_t> &b,
                             const modular_big_integer<big_integer_t3, modular_params_t> &e) {
        eval_pow(result, b, e);
    }

    template<class big_integer_t, typename modular_params_t, class UI>
    inline constexpr void eval_left_shift(modular_big_integer<big_integer_t, modular_params_t> &t,
                                          UI i) noexcept {
        big_integer_t tmp;
        t.mod_data().adjust_regular(tmp, t.base_data());
        eval_left_shift(tmp, i);
        t.base_data() = tmp;
        t.mod_data().adjust_modular(t.base_data());
    }

    template<class big_integer_t, typename modular_params_t, class UI>
    constexpr void eval_right_shift(modular_big_integer<big_integer_t, modular_params_t> &t, UI i) {
        big_integer_t tmp;
        t.mod_data().adjust_regular(tmp, t.base_data());
        eval_right_shift(tmp, i);
        t.base_data() = tmp;
        t.mod_data().adjust_modular(t.base_data());
    }

    template<class big_integer_t, typename modular_params_t, class UI>
    constexpr void eval_left_shift(modular_big_integer<big_integer_t, modular_params_t> &t,
                                   const modular_big_integer<big_integer_t, modular_params_t> &v,
                                   UI i) {
        big_integer_t tmp1, tmp2;
        t.mod_data().adjust_regular(tmp1, t.base_data());
        t.mod_data().adjust_regular(tmp2, v.base_data());
        eval_left_shift(tmp1, tmp2, static_cast<unsigned long>(i));
        t.base_data() = tmp1;
        t.mod_data().adjust_modular(t.base_data());
    }

    template<class big_integer_t, typename modular_params_t, class UI>
    constexpr void eval_right_shift(modular_big_integer<big_integer_t, modular_params_t> &t,
                                    const modular_big_integer<big_integer_t, modular_params_t> &v,
                                    UI i) {
        big_integer_t tmp1, tmp2;
        t.mod_data().adjust_regular(tmp1, t.base_data());
        t.mod_data().adjust_regular(tmp2, v.base_data());
        eval_right_shift(tmp1, tmp2, static_cast<unsigned long>(i));
        t.base_data() = tmp1;
        t.mod_data().adjust_modular(t.base_data());
    }

    template<class big_integer_t, typename modular_params_t>
    constexpr void eval_bitwise_and(modular_big_integer<big_integer_t, modular_params_t> &result,
                                    const modular_big_integer<big_integer_t, modular_params_t> &v) {
        big_integer_t tmp1, tmp2;
        result.mod_data().adjust_regular(tmp1, result.base_data());
        v.mod_data().adjust_regular(tmp2, v.base_data());
        eval_bitwise_and(tmp1, tmp2);
        result.base_data() = tmp1;
        result.mod_data().adjust_modular(result.base_data());
    }

    template<class big_integer_t, typename modular_params_t>
    constexpr void eval_bitwise_or(modular_big_integer<big_integer_t, modular_params_t> &result,
                                   const modular_big_integer<big_integer_t, modular_params_t> &v) {
        big_integer_t tmp1, tmp2;
        result.mod_data().adjust_regular(tmp1, result.base_data());
        v.mod_data().adjust_regular(tmp2, v.base_data());
        eval_bitwise_or(tmp1, tmp2);
        result.base_data() = tmp1;
        result.mod_data().adjust_modular(result.base_data());
    }

    template<class big_integer_t, typename modular_params_t>
    constexpr void eval_bitwise_xor(modular_big_integer<big_integer_t, modular_params_t> &result,
                                    const modular_big_integer<big_integer_t, modular_params_t> &v) {
        big_integer_t tmp1, tmp2;
        result.mod_data().adjust_regular(tmp1, result.base_data());
        v.mod_data().adjust_regular(tmp2, v.base_data());
        eval_bitwise_xor(tmp1, tmp2);
        result.base_data() = tmp1;
        result.mod_data().adjust_modular(result.base_data());
    }

    template<typename big_integer_t, typename modular_params_t>
    constexpr int eval_msb(const modular_big_integer<big_integer_t, modular_params_t> &m) {
        big_integer_t tmp;
        m.mod_data().adjust_regular(tmp, m.base_data());
        return eval_msb(tmp);
    }

    template<typename big_integer_t, typename modular_params_t>
    constexpr unsigned eval_lsb(const modular_big_integer<big_integer_t, modular_params_t> &m) {
        big_integer_t tmp;
        m.mod_data().adjust_regular(tmp, m.base_data());
        return eval_lsb(tmp);
    }

    template<typename big_integer_t, typename modular_params_t>
    constexpr bool eval_bit_test(const modular_big_integer<big_integer_t, modular_params_t> &m,
                                 std::size_t index) {
        big_integer_t tmp;
        m.mod_data().adjust_regular(tmp, m.base_data());
        return eval_bit_test(tmp, index);
    }

    template<typename big_integer_t, typename modular_params_t>
    constexpr void eval_bit_set(modular_big_integer<big_integer_t, modular_params_t> &result,
                                std::size_t index) {
        big_integer_t tmp;
        result.mod_data().adjust_regular(tmp, result.base_data());
        eval_bit_set(tmp, index);
        result.mod_data().adjust_modular(result.base_data(), tmp);
    }

    // We must make sure any call with any integral type ends up here, if we use std::size_t
    // here, something this function is not preferred by the compiler and boost's version is
    // used, which is worse.
    template<typename big_integer_t, typename modular_params_t>
    constexpr void eval_bit_unset(modular_big_integer<big_integer_t, modular_params_t> &result,
                                  std::size_t index) {
        big_integer_t tmp;
        result.mod_data().adjust_regular(tmp, result.base_data());
        eval_bit_unset(tmp, index);
        result.mod_data().adjust_modular(result.base_data(), tmp);
    }

    template<typename big_integer_t, typename modular_params_t>
    constexpr void eval_bit_flip(modular_big_integer<big_integer_t, modular_params_t> &result,
                                 std::size_t index) {
        big_integer_t tmp;
        result.mod_data().adjust_regular(tmp, result.base_data());
        eval_bit_flip(tmp, index);
        result.mod_data().adjust_modular(result.base_data(), tmp);
    }

    template<typename big_integer_t, typename modular_params_t>
    constexpr modular_big_integer<big_integer_t, modular_params_t> eval_ressol(
        const modular_big_integer<big_integer_t, modular_params_t> &input) {
        big_integer_t new_base, res;
        modular_big_integer<big_integer_t, modular_params_t> res_mod;

        input.mod_data().adjust_regular(new_base, input.base_data());
        res = eval_ressol(new_base, input.mod_data().get_mod());
        assign_components(res_mod, res, input.mod_data().get_mod());

        return res_mod;
    }

    template<typename big_integer_t, typename modular_params_t>
    constexpr void eval_inverse_mod(
        modular_big_integer<big_integer_t, modular_params_t> &result,
        const modular_big_integer<big_integer_t, modular_params_t> &input) {
        big_integer_t new_base, res;

        input.mod_data().adjust_regular(new_base, input.base_data());
        eval_inverse_mod(res, new_base, input.mod_data().get_mod());
        assign_components(result, res, input.mod_data().get_mod());
    }

    template<typename big_integer_t, typename modular_params_t>
    inline constexpr std::size_t hash_value(
        const modular_big_integer<big_integer_t, modular_params_t> &val) noexcept {
        return hash_value(val.base_data());
    }
}  // namespace nil::crypto3::multiprecision
