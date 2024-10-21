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

#include <boost/mpl/if.hpp>

#include "nil/crypto3/multiprecision/big_integer/big_integer.hpp"
#include "nil/crypto3/multiprecision/big_integer/storage.hpp"

namespace nil::crypto3::multiprecision::detail {
    template<typename big_integer_t>
    constexpr bool check_montgomery_constraints(const big_integer_t &m) {
        // Check m % 2 == 0
        return bit_test(m, 0u);
    }

    template<unsigned Bits>
    struct modular_policy {
        using big_integer_t = big_integer<Bits>;

        constexpr static auto limbs_count = big_integer_t::internal_limb_count;
        constexpr static auto limb_bits = big_integer_t::limb_bits;

        constexpr static auto BitsCount_doubled = 2u * Bits;
        constexpr static auto BitsCount_doubled_1 = BitsCount_doubled + 1;
        constexpr static auto BitsCount_quadruple_1 = 2u * BitsCount_doubled + 1;
        constexpr static auto BitsCount_padded_limbs = limbs_count * limb_bits + limb_bits;
        constexpr static auto BitsCount_doubled_limbs = 2u * limbs_count * limb_bits;
        constexpr static auto BitsCount_doubled_padded_limbs = BitsCount_doubled_limbs + limb_bits;

        using big_integer_doubled = big_integer<BitsCount_doubled>;
        using big_integer_doubled_1 = big_integer<BitsCount_doubled_1>;
        using big_integer_quadruple_1 = big_integer<BitsCount_quadruple_1>;
        using big_integer_padded_limbs = big_integer<BitsCount_padded_limbs>;
        using big_integer_doubled_limbs = big_integer<BitsCount_doubled_limbs>;
        using big_integer_doubled_padded_limbs = big_integer<BitsCount_doubled_padded_limbs>;
    };

    template<typename big_integer_t>
    class modular_functions {
      public:
        constexpr static unsigned Bits = big_integer_t::Bits;
        using policy_type = modular_policy<Bits>;

      protected:
        using big_integer_doubled_1 = typename policy_type::big_integer_doubled_1;
        using big_integer_quadruple_1 = typename policy_type::big_integer_quadruple_1;
        using big_integer_padded_limbs = typename policy_type::big_integer_padded_limbs;
        using big_integer_doubled_limbs = typename policy_type::big_integer_doubled_limbs;
        using big_integer_doubled_padded_limbs = typename policy_type::big_integer_doubled_padded_limbs;

        constexpr static auto limbs_count = policy_type::limbs_count;
        constexpr static auto limb_bits = policy_type::limb_bits;

        constexpr void initialize_modulus(const big_integer_t &m) { m_mod = m; }

        constexpr void initialize_barrett_params() {
            m_barrett_mu = 0u;

            std::size_t bit = 2u * (1u + msb(m_mod));
            bit_set(m_barrett_mu, bit);

            m_barrett_mu /= m_mod;
        }

        constexpr void initialize_montgomery_params() { find_const_variables(); }

        // TODO(ioxid): no exception actually
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
            r = (~0u - r) + 1;

            return r;
        }

        constexpr void find_const_variables() {
            if (check_montgomery_constraints(m_mod)) {
                m_montgomery_p_dash = monty_inverse(m_mod.limbs()[0]);

                big_integer_doubled_padded_limbs r;
                bit_set(r, 2 * m_mod.size() * limb_bits);
                barrett_reduce(r);

                // Here we are intentionally throwing away half of the bits of r, it's
                // correct.
                m_montgomery_r2 = static_cast<big_integer_t>(r);
            }

            // Compute 2^Bits - Modulus, no matter if modulus is even or odd.
            big_integer_padded_limbs compliment = 1u, modulus = m_mod;
            compliment <<= Bits;
            compliment -= modulus;
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

        constexpr modular_functions(const big_integer_t &m) { initialize(m); }

        template<typename big_integer_t1>
        constexpr void barrett_reduce(big_integer_t1 &result) const {
            barrett_reduce(result, result);
        }

        // TODO(ioxid): something wrong with parameters here
        //
        // this overloaded barrett_reduce is intended to work with built-in integral types
        //
        template<typename big_integer_t1, typename big_integer_t2>
        constexpr typename std::enable_if<std::is_integral<big_integer_t2>::value &&
                                          std::is_unsigned<big_integer_t2>::value>::type
        barrett_reduce(big_integer_t1 &result, big_integer_t2 input) const {
            using input_big_integer_type =
                typename std::conditional_t<bool(big_integer_t2::Bits > Bits), big_integer_t2, big_integer_t>;

            input_big_integer_type input_adjusted(input);
            barrett_reduce(result, input_adjusted);
        }

        //
        // this overloaded barrett_reduce is intended to work with input big_integer_t2 type of
        // less precision than modular big_integer_t to satisfy constraints of core barrett_reduce
        // overloading
        //
        template<typename big_integer_t1, typename big_integer_t2,
                 std::enable_if_t<(big_integer_t2::Bits < big_integer_t::Bits), int> = 0>
        constexpr void barrett_reduce(big_integer_t1 &result, const big_integer_t2 &input) const {
            big_integer_t input_adjusted(input);
            barrett_reduce(result, input_adjusted);
        }

        template<typename big_integer_t1, typename big_integer_t2,
                 std::enable_if_t<
                     /// result should fit in the output parameter
                     big_integer_t1::Bits >= big_integer_t::Bits &&
                         /// to prevent problems with trivial cpp_int
                         big_integer_t2::Bits >= big_integer_t::Bits,
                     int> = 0>
        constexpr void barrett_reduce(big_integer_t1 &result, big_integer_t2 input) const {
            //
            // to prevent problems with trivial cpp_int
            //
            big_integer_t2 modulus(m_mod);

            if (msb(input) < 2u * msb(modulus) + 1u) {
                big_integer_quadruple_1 t1(input);

                t1 *= m_barrett_mu;
                std::size_t shift_size = 2u * (1u + msb(modulus));
                t1 >>= shift_size;
                t1 *= modulus;

                // We do NOT allow subtracting a larger size number from a smaller one,
                // we need to cast to big_integer_t2 here.
                input -= static_cast<big_integer_t2>(t1);

                if (input >= modulus) {
                    input -= modulus;
                }
            } else {
                input %= modulus;
            }
            result = input;
        }

        template<unsigned Bits1,
                 // result should fit in the output parameter
                 std::enable_if_t<Bits1 >= Bits, int> = 0>
        constexpr void montgomery_reduce(big_integer<Bits1> &result) const {
            big_integer_doubled_padded_limbs accum(result);
            big_integer_doubled_padded_limbs prod;

            for (size_t i = 0; i < m_mod.size(); ++i) {
                limb_type limb_accum = accum.limbs()[i];
                double_limb_type mult_res = limb_accum *
                                            /// to prevent overflow error in constexpr
                                            static_cast<double_limb_type>(m_montgomery_p_dash);
                limb_type mult_res_limb = static_cast<limb_type>(mult_res);

                prod = m_mod;
                prod *= mult_res_limb;
                prod <<= i * limb_bits;
                accum += prod;
            }
            accum >>= m_mod.size() * limb_bits;
            // TODO(ioxid): true?
            // We cannot use -= for numbers of difference sizes, so resizing
            // m_mod.
            big_integer_doubled_padded_limbs large_mod = m_mod;
            if (accum >= large_mod) {
                accum -= large_mod;
            }
            // Here only the bytes that fit in sizeof result will be copied, and that's
            // intentional.
            result = accum;
        }

        template<unsigned Bits1, unsigned Bits2,
                 // result should fit in the output parameter
                 std::enable_if_t<Bits1 >= Bits2, int> = 0>
        constexpr void regular_add(big_integer<Bits1> &result, const big_integer<Bits2> &y) const {
            BOOST_ASSERT(result < m_mod && y < m_mod);

            result += y;
            // If we overflow and set the carry, we need to subtract the modulus, which is
            // the same as adding 2 ^ Bits - Modulus to the remaining part of the number.
            // After this we know for sure that the result < Modulus, do not waste time on
            // checking again.
            if (result.has_carry()) {
                result += m_mod_compliment;
                result.set_carry(false);
            } else if (result >= m_mod) {
                result -= m_mod;
            }
        }

        template<typename big_integer_t1, typename big_integer_t2,
                 /// result should fit in the output parameter
                 std::enable_if_t<big_integer_t1::Bits >= big_integer_t::Bits, int> = 0>
        constexpr void regular_mul(big_integer_t1 &result, const big_integer_t2 &y) const {
            big_integer_doubled_limbs tmp = result;
            tmp *= y;
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

        // Tests if the faster implementation of Montgomery multiplication is possible.
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
        template<typename big_integer_t1>
        constexpr void montgomery_mul_no_carry_impl(big_integer_t1 &c, const big_integer_t1 &b) const {
            BOOST_ASSERT(c < m_mod && b < m_mod);
            BOOST_ASSERT(is_applicable_for_no_carry_montgomery_mul());

            // Obtain number of limbs
            constexpr int N = big_integer_t1::internal_limb_count;

            const big_integer_t1 a(c);  // Copy the first argument, as the implemented
                                  // algorithm doesn't work in-place.

            // We cannot write directly to 'c', because b may be equal to c, and by changing
            // the value of 'c' we will change 'b' as well.
            big_integer_t1 result = limb_type(0u);

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
                dbl_limb_to_limbs(tmp, A, result_limbs[0]);

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
                dbl_limb_to_limbs(tmp, C, dummy);

                // The lower loop is unrolled. We want to do this for every 3, because
                // normally mod_size == 4.
                std::size_t j = 1;

#define MONTGOMERY_MUL_NO_CARRY_LOOP_BODY(X)                       \
    /* "(A,t[X])  := t[X] + a[X]*b[i] + A" */                      \
    tmp = a_limbs[X];                                              \
    tmp *= b_limbs[i];                                             \
    tmp += result_limbs[X];                                        \
    tmp += A;                                                      \
    dbl_limb_to_limbs(tmp, A, result_limbs[X]); \
                                                                   \
    /* "(C,t[X-1]) := t[X] + m*q[X] + C" */                        \
    tmp = m;                                                       \
    tmp *= m_mod_limbs[X];                                         \
    tmp += result_limbs[X];                                        \
    tmp += C;                                                      \
    dbl_limb_to_limbs(tmp, C, result_limbs[(X) - 1]);

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
                result -= m_mod;
            }
            c = result;
        }

        // A specialization for non-trivial cpp_int_modular types only.
        template<typename big_integer_t1>
        constexpr void montgomery_mul_CIOS_impl(big_integer_t1 &result, const big_integer_t1 &y) const {
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
    A_limbs[(X) - 1] = static_cast<limb_type>(t2);                                          \
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
                A += m_mod_compliment;
            } else if (A >= m_mod) {
                A -= m_mod;
            }

            result = A;
        }

        template<typename big_integer_t1, typename big_integer_t2, typename big_integer_t3,
                 /// result should fit in the output parameter
                 std::enable_if_t<big_integer_t1::Bits >= big_integer_t::Bits, int> = 0>
        constexpr void regular_exp(big_integer_t1 &result, big_integer_t2 &a, big_integer_t3 exp) const {
            BOOST_ASSERT(a < m_mod);

            if (exp == 0u) {
                result = 1u;
                return;
            }
            if (m_mod == 1u) {
                result = 0u;
                return;
            }

            big_integer_doubled_limbs base(a), res(1u);

            while (true) {
                limb_type lsb = exp.limbs()[0] & 1u;
                exp >>= 1u;
                if (lsb) {
                    res *= base;
                    barrett_reduce(res);
                    if (is_zero(exp)) {
                        break;
                    }
                }
                base *= base;
                barrett_reduce(base);
            }
            result = res;
        }

        template<typename big_integer_t1, typename big_integer_t2, typename big_integer_t3,
                 /// result should fit in the output parameter
                 std::enable_if_t<big_integer_t1::Bits >= big_integer_t::Bits, int> = 0>
        constexpr void montgomery_exp(big_integer_t1 &result, const big_integer_t2 &a, big_integer_t3 exp) const {
            /// input parameter should be lesser than modulus
            BOOST_ASSERT(a < m_mod);

            big_integer_doubled_limbs tmp(1u);
            tmp *= m_montgomery_r2;
            montgomery_reduce(tmp);
            big_integer_t R_mod_m(tmp);

            big_integer_t base(a);

            if (exp == 0u) {
                result = 1u;
                //
                // TODO: restructure code
                // adjust_modular
                //
                result *= m_montgomery_r2;
                montgomery_reduce(result);
                return;
            }
            if (m_mod == 1u) {
                result = 0u;
                return;
            }

            while (true) {
                limb_type lsb = exp.limbs()[0] & 1u;
                exp >>= 1u;
                if (lsb) {
                    montgomery_mul(R_mod_m, base);
                    if (exp == 0u) {
                        break;
                    }
                }
                montgomery_mul(base, base);
            }
            result = R_mod_m;
        }

        constexpr modular_functions &operator=(const big_integer_t &m) {
            initialize(m);

            return *this;
        }

      protected:
        big_integer_t m_mod;
        // This is 2^Bits - m_mod, precomputed.
        big_integer_t m_mod_compliment;
        big_integer_doubled_1 m_barrett_mu;
        big_integer_t m_montgomery_r2;
        limb_type m_montgomery_p_dash = 0;

        // If set, no-carry optimization is allowed. Must be initialized by function
        // is_applicable_for_no_carry_montgomery_mul() after initialization.
        bool m_no_carry_montgomery_mul_allowed = false;
    };
}  // namespace nil::crypto3::multiprecision
