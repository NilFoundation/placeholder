//---------------------------------------------------------------------------//
// Copyright (c) 2020 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020 Ilias Khairullin <ilias@nil.foundation>
// Copyright (c) 2021 Aleksei Moskvin <alalmoskvin@nil.foundation>
// Copyright (c) 2024 Andrey Nefedov <ioxid@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#pragma once

#include <climits>
#include <cstddef>
#include <limits>
#include <type_traits>

#include <boost/lexical_cast.hpp>
#include <boost/mpl/if.hpp>

#include "nil/crypto3/multiprecision/big_integer/big_integer.hpp"
#include "nil/crypto3/multiprecision/big_integer/modular/modular_policy.hpp"
#include "nil/crypto3/multiprecision/big_integer/storage.hpp"

namespace nil::crypto3::multiprecision {
    template<typename big_integer_t>
    constexpr bool check_montgomery_constraints(const big_integer_t &m) {
        // Check m % 2 == 0
        // It's important to have std::size_t on the next line,
        // otherwise a function from boost is called, which is not constexpr
        // on gcc.
        return eval_bit_test(m, std::size_t(0));
    }

    // TODO(ioxid): rewrite it
    //
    // a little trick to prevent error in constexpr execution of
    // eval_right_shift due to non-constexpr nature of right_shift_byte
    //
    template<typename big_integer_t>
    constexpr void custom_right_shift(big_integer_t &b, unsigned s) {
        if (!s) {
            return;
        }

        limb_type byte_shift_mask = CHAR_BIT - 1;
        if ((s & byte_shift_mask) == 0) {
            eval_right_shift(b, s - 1u);
            eval_right_shift(b, 1u);
        } else {
            eval_right_shift(b, s);
        }
    }

    template<typename big_integer_t>
    class modular_functions {
      public:
        constexpr static unsigned Bits = big_integer_t::Bits;
        using policy_type = modular_policy<Bits>;

      protected:
        using limb_type = typename policy_type::limb_type;
        using double_limb_type = typename policy_type::double_limb_type;

        using Backend_doubled_1 = typename policy_type::Backend_doubled_1;
        using Backend_quadruple_1 = typename policy_type::Backend_quadruple_1;
        using Backend_padded_limbs = typename policy_type::Backend_padded_limbs;
        using Backend_doubled_limbs = typename policy_type::Backend_doubled_limbs;
        using Backend_doubled_padded_limbs = typename policy_type::Backend_doubled_padded_limbs;

        constexpr static auto limbs_count = policy_type::limbs_count;
        constexpr static auto limb_bits = policy_type::limb_bits;

        constexpr void initialize_modulus(const big_integer_t &m) { m_mod = m; }

        constexpr void initialize_barrett_params() {
            m_barrett_mu = static_cast<limb_type>(0u);

            size_t bit = 2u * (1u + eval_msb(m_mod));
            eval_bit_set(m_barrett_mu, bit);

            // TODO(ioxid): not constexpr
            // m_barrett_mu /= m_mod;
        }

        constexpr void initialize_montgomery_params() { find_const_variables(); }

        /*
         * Compute -input^-1 mod 2^limb_bits. Throws an exception if input
         * is even. If input is odd, then input and 2^n are relatively prime
         * and an inverse exists.
         */
        constexpr limb_type monty_inverse(const limb_type &a) {
            limb_type b = 1;
            limb_type r = 0;

            for (size_t i = 0; i != limb_bits; ++i) {
                const limb_type bi = b % 2;
                r >>= 1;
                r += bi << (limb_bits - 1);

                b -= a * bi;
                b >>= 1;
            }

            // Now invert in addition space
            r = (~static_cast<limb_type>(0) - r) + 1;

            return r;
        }

        constexpr void find_const_variables() {
            if (check_montgomery_constraints(m_mod)) {
                m_montgomery_p_dash = monty_inverse(m_mod.limbs()[0]);

                Backend_doubled_padded_limbs r;
                eval_bit_set(r, 2 * m_mod.size() * limb_bits);
                barrett_reduce(r);

                // Here we are intentionally throwing away half of the bits of r, it's
                // correct.
                m_montgomery_r2 = static_cast<big_integer_t>(r);
            }

            // Compute 2^Bits - Modulus, no matter if modulus is even or odd.
            Backend_padded_limbs compliment = static_cast<limb_type>(1u), modulus = m_mod;
            eval_left_shift(compliment, Bits);
            eval_subtract(compliment, modulus);
            m_mod_compliment = compliment;
        }

        constexpr void initialize(const big_integer_t &m) {
            initialize_modulus(m);
            initialize_barrett_params();
            initialize_montgomery_params();

            m_no_carry_montgomery_mul_allowed = is_applicable_for_no_carry_montgomery_mul();
        }

      public:
        constexpr auto &get_mod() { return m_mod; }
        constexpr const auto &get_mod_compliment() const { return m_mod_compliment; }
        constexpr auto &get_mu() { return m_barrett_mu; }
        constexpr auto &get_r2() { return m_montgomery_r2; }
        constexpr auto &get_p_dash() { return m_montgomery_p_dash; }

        constexpr const auto &get_mod() const { return m_mod; }
        constexpr const auto &get_mu() const { return m_barrett_mu; }
        constexpr const auto &get_r2() const { return m_montgomery_r2; }
        constexpr auto get_p_dash() const { return m_montgomery_p_dash; }

        constexpr modular_functions() {}

        constexpr modular_functions(const big_integer_t &m) { initialize(m); }

        constexpr modular_functions(const modular_functions &o)
            : m_mod(o.get_mod()),
              m_mod_compliment(o.get_mod_compliment()),
              m_barrett_mu(o.get_mu()),
              m_montgomery_r2(o.get_r2()),
              m_montgomery_p_dash(o.get_p_dash()),
              m_no_carry_montgomery_mul_allowed(is_applicable_for_no_carry_montgomery_mul()) {}

        template<typename Backend1>
        constexpr void barrett_reduce(Backend1 &result) const {
            barrett_reduce(result, result);
        }

        //
        // this overloaded barrett_reduce is intended to work with built-in integral types
        //
        template<typename Backend1, typename Backend2>
        constexpr typename std::enable_if<std::is_integral<Backend2>::value &&
                                          std::is_unsigned<Backend2>::value>::type
        barrett_reduce(Backend1 &result, Backend2 input) const {
            using input_backend_type =
                typename std::conditional_t<bool(Backend2::Bits > Bits), Backend2, big_integer_t>;

            input_backend_type input_adjusted(input);
            barrett_reduce(result, input_adjusted);
        }

        //
        // this overloaded barrett_reduce is intended to work with input Backend2 type of
        // less precision than modular big_integer_t to satisfy constraints of core barrett_reduce
        // overloading
        //
        template<typename Backend1, typename Backend2,
                 std::enable_if_t<(Backend2::Bits < big_integer_t::Bits), bool> = true>
        constexpr void barrett_reduce(Backend1 &result, const Backend2 &input) const {
            big_integer_t input_adjusted(input);
            barrett_reduce(result, input_adjusted);
        }

        template<typename Backend1, typename Backend2,
                 std::enable_if_t<
                     /// result should fit in the output parameter
                     Backend1::Bits >= big_integer_t::Bits &&
                         /// to prevent problems with trivial cpp_int
                         Backend2::Bits >= big_integer_t::Bits,
                     bool> = true>
        constexpr void barrett_reduce(Backend1 &result, Backend2 input) const {
            //
            // to prevent problems with trivial cpp_int
            //
            Backend2 modulus(m_mod);

            if (eval_msb(input) < 2u * eval_msb(modulus) + 1u) {
                Backend_quadruple_1 t1(input);

                eval_multiply(t1, m_barrett_mu);
                std::size_t shift_size = 2u * (1u + eval_msb(modulus));
                custom_right_shift(t1, shift_size);
                eval_multiply(t1, modulus);

                // We do NOT allow subtracting a larger size number from a smaller one,
                // we need to cast to Backend2 here.
                eval_subtract(input, static_cast<Backend2>(t1));

                if (input >= modulus) {
                    eval_subtract(input, modulus);
                }
            } else {
                // TODO(ioxid): not constexpr
                // eval_modulus(input, modulus);
            }
            result = input;
        }

        template<unsigned Bits1,
                 // result should fit in the output parameter
                 typename = typename boost::enable_if_c<Bits1 >= Bits>::type>
        constexpr void montgomery_reduce(big_integer<Bits1> &result) const {
            Backend_doubled_padded_limbs accum(result);
            Backend_doubled_padded_limbs prod;

            for (size_t i = 0; i < m_mod.size(); ++i) {
                limb_type limb_accum = accum.limbs()[i];
                double_limb_type mult_res = limb_accum *
                                            /// to prevent overflow error in constexpr
                                            static_cast<double_limb_type>(m_montgomery_p_dash);
                limb_type mult_res_limb = static_cast<limb_type>(mult_res);

                eval_multiply(prod, m_mod, mult_res_limb);
                eval_left_shift(prod, i * limb_bits);
                eval_add(accum, prod);
            }
            custom_right_shift(accum, m_mod.size() * limb_bits);
            // We cannot use eval_subtract for numbers of difference sizes, so resizing
            // m_mod.
            Backend_doubled_padded_limbs large_mod = m_mod;
            if (accum >= large_mod) {
                eval_subtract(accum, large_mod);
            }
            // Here only the bytes that fit in sizeof result will be copied, and that's
            // intentional.
            result = accum;
        }

        template<unsigned Bits1, unsigned Bits2,
                 // result should fit in the output parameter
                 typename = typename boost::enable_if_c<Bits1 >= Bits2>::type>
        constexpr void regular_add(big_integer<Bits1> &result, const big_integer<Bits2> &y) const {
            BOOST_ASSERT(eval_lt(result, m_mod) && eval_lt(y, m_mod));

            eval_add(result, y);
            // If we overflow and set the carry, we need to subtract the modulus, which is
            // the same as adding 2 ^ Bits - Modulus to the remaining part of the number.
            // After this we know for sure that the result < Modulus, do not waste time on
            // checking again.
            if (result.has_carry()) {
                eval_add(result, m_mod_compliment);
                result.set_carry(false);
            } else if (!eval_lt(result, m_mod)) {
                eval_subtract(result, m_mod);
            }
        }

        template<
            typename Backend1, typename Backend2,
            /// result should fit in the output parameter
            typename = typename boost::enable_if_c<Backend1::Bits >= big_integer_t::Bits>::type>
        constexpr void regular_mul(Backend1 &result, const Backend2 &y) const {
            Backend_doubled_limbs tmp(result);
            eval_multiply(tmp, y);
            barrett_reduce(result, tmp);
        }

        // Delegates Montgomery multiplication to one of corresponding algorithms.
        constexpr void montgomery_mul(big_integer_t &result, const big_integer_t &y) const {
            if (m_no_carry_montgomery_mul_allowed) {
                montgomery_mul_no_carry_impl(result, y);
            } else {
                montgomery_mul_CIOS_impl(result, y);
            }
        }

        // Given a value represented in 'double_limb_type', decomposes it into
        // two 'limb_type' variables, based on high order bits and low order bits.
        // There 'a' receives high order bits of 'X', and 'b' receives the low order bits.
        static constexpr void dbl_limb_to_limbs(const double_limb_type &X, limb_type &a,
                                                limb_type &b) {
            b = X;
            a = X >> limb_bits;
        }

        // Tests if the faster implementation of Montgomery multiplication is possible.
        // We don't need the template argument Backend1, it's just here to enable
        // specialization.
        template<class Backend1 = big_integer_t>
        constexpr bool is_applicable_for_no_carry_montgomery_mul() const {
            // Check that
            // 1. The most significant bit of modulus is non-zero, meaning we have at least
            // 1 additional bit in the number. I.E. if modulus is 255 bits, then we have 1
            // additional "unused" bit in the number.
            // 2. Some other bit in modulus is 0.
            // 3. The number has < 12 limbs.
            return m_mod.internal_limb_count < 12 && (Bits % sizeof(limb_type) != 0) &&
                   m_mod_compliment != big_integer_t(limb_type(1u));
        }

        // Non-carry implementation of Montgomery multiplication.
        // Implemented from pseudo-code at
        //   "https://hackmd.io/@gnark/modular_multiplication".
        template<typename Backend1>
        constexpr void montgomery_mul_no_carry_impl(Backend1 &c, const Backend1 &b) const {
            BOOST_ASSERT(c < m_mod && b < m_mod);
            BOOST_ASSERT(is_applicable_for_no_carry_montgomery_mul());

            // Obtain number of limbs
            constexpr int N = Backend1::internal_limb_count;

            const Backend1 a(c);  // Copy the first argument, as the implemented
                                  // algorithm doesn't work in-place.

            // We cannot write directly to 'c', because b may be equal to c, and by changing
            // the value of 'c' we will change 'b' as well.
            Backend1 result = limb_type(0u);

            // Prepare temporary variables
            limb_type A(0u), C(0u);
            double_limb_type tmp(0u);
            limb_type dummy(0u);

            auto *a_limbs = a.limbs();
            auto *b_limbs = b.limbs();
            auto *result_limbs = result.limbs();
            auto *m_mod_limbs = m_mod.limbs();

            for (int i = 0; i < N; ++i) {
                // "(A,t[0]) := t[0] + a[0]*b[i]"
                tmp = a_limbs[0];
                tmp *= b_limbs[i];
                tmp += result_limbs[0];
                modular_functions::dbl_limb_to_limbs(tmp, A, result_limbs[0]);

                // "m := t[0]*q'[0] mod W"
                tmp = result_limbs[0];
                // tmp *= q.limbs()[0];
                tmp *= m_montgomery_p_dash;
                // tmp = -tmp;
                // Note that m is a shorter integer, and we are taking the last bits of tmp.
                limb_type m = tmp;

                // "(C,_) := t[0] + m*q[0]"
                tmp = m;
                tmp *= m_mod_limbs[0];
                tmp += result_limbs[0];
                modular_functions::dbl_limb_to_limbs(tmp, C, dummy);

                // The lower loop is unrolled. We want to do this for every 3, because
                // normally mod_size == 4.
                std::size_t j = 1;

#define MONTGOMERY_MUL_NO_CARRY_LOOP_BODY(X)                       \
    /* "(A,t[X])  := t[X] + a[X]*b[i] + A" */                      \
    tmp = a_limbs[X];                                              \
    tmp *= b_limbs[i];                                             \
    tmp += result_limbs[X];                                        \
    tmp += A;                                                      \
    modular_functions::dbl_limb_to_limbs(tmp, A, result_limbs[X]); \
                                                                   \
    /* "(C,t[X-1]) := t[X] + m*q[X] + C" */                        \
    tmp = m;                                                       \
    tmp *= m_mod_limbs[X];                                         \
    tmp += result_limbs[X];                                        \
    tmp += C;                                                      \
    modular_functions::dbl_limb_to_limbs(tmp, C, result_limbs[X - 1]);

                for (; j + 5 <= N; j += 5) {
                    MONTGOMERY_MUL_NO_CARRY_LOOP_BODY(j);
                    MONTGOMERY_MUL_NO_CARRY_LOOP_BODY(j + 1);
                    MONTGOMERY_MUL_NO_CARRY_LOOP_BODY(j + 2);
                    MONTGOMERY_MUL_NO_CARRY_LOOP_BODY(j + 3);
                    MONTGOMERY_MUL_NO_CARRY_LOOP_BODY(j + 4);
                }

                for (; j + 3 <= N; j += 3) {
                    MONTGOMERY_MUL_NO_CARRY_LOOP_BODY(j);
                    MONTGOMERY_MUL_NO_CARRY_LOOP_BODY(j + 1);
                    MONTGOMERY_MUL_NO_CARRY_LOOP_BODY(j + 2);
                }

                for (; j < N; ++j) {
                    MONTGOMERY_MUL_NO_CARRY_LOOP_BODY(j);
                }

                // "t[N-1] = C + A"
                result_limbs[N - 1] = C + A;
            }

            if (result >= m_mod) {
                eval_subtract(result, m_mod);
            }
            c = result;
        }

        // A specialization for non-trivial cpp_int_modular types only.
        template<typename Backend1>
        constexpr void montgomery_mul_CIOS_impl(Backend1 &result, const Backend1 &y) const {
            BOOST_ASSERT(result < m_mod && y < m_mod);

            big_integer_t A(limb_type(0u));
            const std::size_t mod_size = m_mod.size();
            auto *mod_limbs = m_mod.limbs();
            auto mod_last_limb = static_cast<double_limb_type>(mod_limbs[0]);
            auto y_last_limb = y.limbs()[0];
            auto *y_limbs = y.limbs();
            auto *x_limbs = result.limbs();
            auto *A_limbs = A.limbs();
            limb_type carry = 0;  // This is the highest limb of 'A'.

            limb_type x_i = 0;
            limb_type A_0 = 0;
            limb_type u_i = 0;

            // A += x[i] * y + u_i * m followed by a 1 limb-shift to the right
            limb_type k = 0;
            limb_type k2 = 0;

            double_limb_type z = 0;
            double_limb_type z2 = 0;

            for (std::size_t i = 0; i < mod_size; ++i) {
                x_i = x_limbs[i];
                A_0 = A_limbs[0];
                u_i = (A_0 + x_i * y_last_limb) * m_montgomery_p_dash;

                // A += x[i] * y + u_i * m followed by a 1 limb-shift to the right
                k = 0;
                k2 = 0;

                z = static_cast<double_limb_type>(y_last_limb) *
                        static_cast<double_limb_type>(x_i) +
                    A_0 + k;
                z2 = mod_last_limb * static_cast<double_limb_type>(u_i) +
                     static_cast<limb_type>(z) + k2;
                k = static_cast<limb_type>(z >> std::numeric_limits<limb_type>::digits);
                k2 = static_cast<limb_type>(z2 >> std::numeric_limits<limb_type>::digits);

                std::size_t j = 1;

                // The lower loop is unrolled. We want to do this for every 3, because
                // normally mod_size == 4.
                double_limb_type t = 0, t2 = 0;

#define MONTGOMERY_MUL_CIOS_LOOP_BODY(X)                                                    \
    t = static_cast<double_limb_type>(y_limbs[X]) * static_cast<double_limb_type>(x_i) +    \
        A_limbs[X] + k;                                                                     \
    t2 = static_cast<double_limb_type>(mod_limbs[X]) * static_cast<double_limb_type>(u_i) + \
         static_cast<limb_type>(t) + k2;                                                    \
    A_limbs[X - 1] = static_cast<limb_type>(t2);                                            \
    k = static_cast<limb_type>(t >> std::numeric_limits<limb_type>::digits);                \
    k2 = static_cast<limb_type>(t2 >> std::numeric_limits<limb_type>::digits);

                for (; j + 5 <= mod_size; j += 5) {
                    MONTGOMERY_MUL_CIOS_LOOP_BODY(j);
                    MONTGOMERY_MUL_CIOS_LOOP_BODY(j + 1);
                    MONTGOMERY_MUL_CIOS_LOOP_BODY(j + 2);
                    MONTGOMERY_MUL_CIOS_LOOP_BODY(j + 3);
                    MONTGOMERY_MUL_CIOS_LOOP_BODY(j + 4);
                }

                for (; j + 3 <= mod_size; j += 3) {
                    MONTGOMERY_MUL_CIOS_LOOP_BODY(j);
                    MONTGOMERY_MUL_CIOS_LOOP_BODY(j + 1);
                    MONTGOMERY_MUL_CIOS_LOOP_BODY(j + 2);
                }

                for (; j < mod_size; ++j) {
                    MONTGOMERY_MUL_CIOS_LOOP_BODY(j);
                }

                double_limb_type tmp = static_cast<double_limb_type>(carry) + k + k2;
                A_limbs[mod_size - 1] = static_cast<limb_type>(tmp);
                carry = static_cast<limb_type>(tmp >> std::numeric_limits<limb_type>::digits);
            }

            if (carry) {
                // The value of A is actually A + 2 ^ Bits, so remove that 2 ^ Bits.
                eval_add(A, m_mod_compliment);
            } else if (A >= m_mod) {
                eval_subtract(A, m_mod);
            }

            result = A;
        }

        template<
            typename Backend1, typename Backend2, typename Backend3,
            /// result should fit in the output parameter
            typename = typename boost::enable_if_c<Backend1::Bits >= big_integer_t::Bits>::type>
        constexpr void regular_exp(Backend1 &result, Backend2 &a, Backend3 exp) const {
            BOOST_ASSERT(eval_lt(a, m_mod));

            if (eval_eq(exp, static_cast<limb_type>(0u))) {
                result = static_cast<limb_type>(1u);
                return;
            }
            if (eval_eq(m_mod, static_cast<limb_type>(1u))) {
                result = static_cast<limb_type>(0u);
                return;
            }

            Backend_doubled_limbs base(a), res(static_cast<limb_type>(1u));

            while (true) {
                limb_type lsb = exp.limbs()[0] & 1u;
                custom_right_shift(exp, static_cast<limb_type>(1u));
                if (lsb) {
                    eval_multiply(res, base);
                    barrett_reduce(res);
                    if (eval_is_zero(exp)) {
                        break;
                    }
                }
                eval_multiply(base, base);
                barrett_reduce(base);
            }
            result = res;
        }

        template<
            typename Backend1, typename Backend2, typename Backend3,
            /// result should fit in the output parameter
            typename = typename boost::enable_if_c<Backend1::Bits >= big_integer_t::Bits>::type>
        constexpr void montgomery_exp(Backend1 &result, const Backend2 &a, Backend3 exp) const {
            /// input parameter should be lesser than modulus
            BOOST_ASSERT(eval_lt(a, m_mod));

            Backend_doubled_limbs tmp(static_cast<limb_type>(1u));
            eval_multiply(tmp, m_montgomery_r2);
            montgomery_reduce(tmp);
            big_integer_t R_mod_m(tmp);

            big_integer_t base(a);

            if (eval_eq(exp, static_cast<limb_type>(0u))) {
                result = static_cast<limb_type>(1u);
                //
                // TODO: restructure code
                // adjust_modular
                //
                eval_multiply(result, m_montgomery_r2);
                montgomery_reduce(result);
                return;
            }
            if (eval_eq(m_mod, static_cast<limb_type>(1u))) {
                result = static_cast<limb_type>(0u);
                return;
            }

            while (true) {
                limb_type lsb = exp.limbs()[0] & 1u;
                custom_right_shift(exp, static_cast<limb_type>(1u));
                if (lsb) {
                    montgomery_mul(R_mod_m, base);
                    if (eval_eq(exp, static_cast<limb_type>(0u))) {
                        break;
                    }
                }
                montgomery_mul(base, base);
            }
            result = R_mod_m;
        }

        constexpr modular_functions &operator=(const modular_functions &o) {
            m_mod = o.get_mod();
            m_barrett_mu = o.get_mu();
            m_montgomery_r2 = o.get_r2();
            m_montgomery_p_dash = o.get_p_dash();
            m_mod_compliment = o.get_mod_compliment();
            m_no_carry_montgomery_mul_allowed = is_applicable_for_no_carry_montgomery_mul();

            return *this;
        }

        constexpr modular_functions &operator=(const big_integer_t &m) {
            initialize(m);

            return *this;
        }

      protected:
        big_integer_t m_mod;
        // This is 2^Bits - m_mod, precomputed.
        big_integer_t m_mod_compliment;
        Backend_doubled_1 m_barrett_mu;
        big_integer_t m_montgomery_r2;
        limb_type m_montgomery_p_dash = 0;

        // If set, no-carry optimization is allowed. Must be initialized by function
        // is_applicable_for_no_carry_montgomery_mul() after initialization.
        bool m_no_carry_montgomery_mul_allowed = false;
    };
}  // namespace nil::crypto3::multiprecision
