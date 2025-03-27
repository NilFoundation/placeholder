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
#include <stdexcept>
#include <type_traits>

#include <boost/assert.hpp>

#include "nil/crypto3/multiprecision/big_uint.hpp"
#include "nil/crypto3/multiprecision/detail/big_mod/modular_ops/barrett.hpp"
#include "nil/crypto3/multiprecision/detail/big_mod/modular_ops/montgomery_utils.hpp"
#include "nil/crypto3/multiprecision/detail/big_uint/storage.hpp"
#include "nil/crypto3/multiprecision/detail/integer_ops_base.hpp"

#include "nil/crypto3/bench/scoped_profiler.hpp"

namespace nil::crypto3::multiprecision::detail {
    template<typename T>
    constexpr bool modulus_supports_montgomery(const T &m) {
        static_assert(is_integral_v<T> && !std::numeric_limits<T>::is_signed);
        // Check m % 2 == 0
        return bit_test(m, 0u);
    }

    // Montgomery modular operations. Uses Barrett reduction internally and inherits
    // basic operations like negation and increment
    template<std::size_t Bits_>
    class montgomery_modular_ops : public barrett_modular_ops<Bits_> {
      public:
        static constexpr std::size_t Bits = Bits_;
        using big_uint_t = big_uint<Bits>;
        using base_type = big_uint<Bits>;
        using pow_unsigned_intermediate_type = base_type;

        static constexpr std::size_t limb_count = big_uint_t::static_limb_count;

        constexpr montgomery_modular_ops(const big_uint_t &m) : barrett_modular_ops<Bits_>(m) {
            if (!modulus_supports_montgomery(m)) {
                throw std::invalid_argument("module not usable with montgomery");
            }

            // This is negation modulo 2^limb_bits
            m_montgomery_p_dash = -montgomery_inverse(this->mod().limbs()[0]);

            big_uint<2 * limb_count * limb_bits + 1> r;
            r.bit_set(2 * limb_count * limb_bits);
            this->barrett_reduce(r, r);

            // Here we are intentionally throwing away half of the bits of r, it's
            // correct.
            m_montgomery_r2 = static_cast<big_uint_t>(r);

            m_no_carry_montgomery_mul_allowed = is_applicable_for_no_carry_montgomery_mul();

            m_one = 1u;
            adjust_modular(m_one, m_one);
        }

      private:
        template<std::size_t Bits2,
                 // result should fit in the output parameter
                 std::enable_if_t<Bits2 >= Bits, int> = 0>
        constexpr void montgomery_reduce(big_uint<Bits2> &result) const {
            big_uint<(2 * limb_count + 1) * limb_bits> accum(result), prod;

            for (std::size_t i = 0; i < limb_count; ++i) {
                limb_type limb_accum = accum.limbs()[i];
                double_limb_type mult_res = limb_accum * static_cast<double_limb_type>(p_dash());
                limb_type mult_res_limb = static_cast<limb_type>(mult_res);

                prod = this->mod();
                prod *= mult_res_limb;
                prod <<= i * limb_bits;
                accum += prod;
            }
            accum >>= limb_count * limb_bits;

            if (accum >= this->mod()) {
                accum -= this->mod();
            }

            result = static_cast<big_uint<Bits2>>(accum);
        }

        // Tests if the faster implementation of Montgomery multiplication is possible.
        constexpr bool is_applicable_for_no_carry_montgomery_mul() const {
            // Check that
            // 1. The most significant bit of modulus is non-zero, meaning we have at least
            // 1 additional bit in the number. E.g. if modulus is 255 bits, then we have 1
            // additional "unused" bit in the number.
            // 2. Some other bit in modulus is 0.
            // 3. The number has < 12 limbs.
            return limb_count < 12 && (Bits % sizeof(limb_type) != 0) &&
                   this->mod_compliment() != limb_type(1u);
        }

        // Non-carry implementation of Montgomery multiplication.
        // Implemented from pseudo-code at
        //   "https://hackmd.io/@gnark/modular_multiplication".
        template<std::size_t Bits2>
        constexpr void montgomery_mul_no_carry_impl(big_uint<Bits2> &c,
                                                    const big_uint<Bits2> &b) const {
            BOOST_ASSERT(c < this->mod() && b < this->mod());
            BOOST_ASSERT(is_applicable_for_no_carry_montgomery_mul());

            // Obtain number of limbs
            constexpr int N = big_uint<Bits2>::static_limb_count;

            const big_uint<Bits2> a(c);  // Copy the first argument, as the implemented
                                         // algorithm doesn't work in-place.

            // We cannot write directly to 'c', because b may be equal to c, and by changing
            // the value of 'c' we will change 'b' as well.
            big_uint<Bits2> result = limb_type(0u);

            // Prepare temporary variables
            limb_type A(0u), C(0u);
            double_limb_type tmp(0u);
            limb_type dummy(0u);

            auto *a_limbs = a.limbs();
            auto *b_limbs = b.limbs();
            auto *result_limbs = result.limbs();
            auto *m_mod_limbs = this->mod().limbs();

            for (int i = 0; i < N; ++i) {
                // "(A,t[0]) := t[0] + a[0]*b[i]"
                tmp = a_limbs[0];
                tmp *= b_limbs[i];
                tmp += result_limbs[0];
                dbl_limb_to_limbs(tmp, A, result_limbs[0]);

                // "m := t[0]*q'[0] mod W"
                tmp = result_limbs[0];
                // tmp *= q.limbs()[0];
                tmp *= p_dash();
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

#define NIL_CO3_MP_MONTGOMERY_MUL_NO_CARRY_LOOP_BODY(X) \
    /* "(A,t[X])  := t[X] + a[X]*b[i] + A" */           \
    tmp = a_limbs[X];                                   \
    tmp *= b_limbs[i];                                  \
    tmp += result_limbs[X];                             \
    tmp += A;                                           \
    dbl_limb_to_limbs(tmp, A, result_limbs[X]);         \
                                                        \
    /* "(C,t[X-1]) := t[X] + m*q[X] + C" */             \
    tmp = m;                                            \
    tmp *= m_mod_limbs[X];                              \
    tmp += result_limbs[X];                             \
    tmp += C;                                           \
    dbl_limb_to_limbs(tmp, C, result_limbs[(X) - 1]);

                for (; j + 5 <= N; j += 5) {
                    NIL_CO3_MP_MONTGOMERY_MUL_NO_CARRY_LOOP_BODY(j);
                    NIL_CO3_MP_MONTGOMERY_MUL_NO_CARRY_LOOP_BODY(j + 1);
                    NIL_CO3_MP_MONTGOMERY_MUL_NO_CARRY_LOOP_BODY(j + 2);
                    NIL_CO3_MP_MONTGOMERY_MUL_NO_CARRY_LOOP_BODY(j + 3);
                    NIL_CO3_MP_MONTGOMERY_MUL_NO_CARRY_LOOP_BODY(j + 4);
                }

                for (; j + 3 <= N; j += 3) {
                    NIL_CO3_MP_MONTGOMERY_MUL_NO_CARRY_LOOP_BODY(j);
                    NIL_CO3_MP_MONTGOMERY_MUL_NO_CARRY_LOOP_BODY(j + 1);
                    NIL_CO3_MP_MONTGOMERY_MUL_NO_CARRY_LOOP_BODY(j + 2);
                }

                for (; j < N; ++j) {
                    NIL_CO3_MP_MONTGOMERY_MUL_NO_CARRY_LOOP_BODY(j);
                }

                // "t[N-1] = C + A"
                result_limbs[N - 1] = C + A;
            }

            if (result >= this->mod()) {
                result -= this->mod();
            }
            c = result;
        }
#undef NIL_CO3_MP_MONTGOMERY_MUL_NO_CARRY_LOOP_BODY

        template<std::size_t Bits2>
        constexpr void montgomery_mul_CIOS_impl(big_uint<Bits2> &result,
                                                const big_uint<Bits2> &y) const {
            BOOST_ASSERT(result < this->mod() && y < this->mod());

            big_uint_t A(limb_type(0u));
            constexpr std::size_t mod_size = limb_count;
            auto *mod_limbs = this->mod().limbs();
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
                u_i = (A_0 + x_i * y_last_limb) * p_dash();

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

#define NIL_CO3_MP_MONTGOMERY_MUL_CIOS_LOOP_BODY(X)                                         \
    t = static_cast<double_limb_type>(y_limbs[X]) * static_cast<double_limb_type>(x_i) +    \
        A_limbs[X] + k;                                                                     \
    t2 = static_cast<double_limb_type>(mod_limbs[X]) * static_cast<double_limb_type>(u_i) + \
         static_cast<limb_type>(t) + k2;                                                    \
    A_limbs[(X) - 1] = static_cast<limb_type>(t2);                                          \
    k = static_cast<limb_type>(t >> std::numeric_limits<limb_type>::digits);                \
    k2 = static_cast<limb_type>(t2 >> std::numeric_limits<limb_type>::digits);

                for (; j + 5 <= mod_size; j += 5) {
                    NIL_CO3_MP_MONTGOMERY_MUL_CIOS_LOOP_BODY(j);
                    NIL_CO3_MP_MONTGOMERY_MUL_CIOS_LOOP_BODY(j + 1);
                    NIL_CO3_MP_MONTGOMERY_MUL_CIOS_LOOP_BODY(j + 2);
                    NIL_CO3_MP_MONTGOMERY_MUL_CIOS_LOOP_BODY(j + 3);
                    NIL_CO3_MP_MONTGOMERY_MUL_CIOS_LOOP_BODY(j + 4);
                }

                for (; j + 3 <= mod_size; j += 3) {
                    NIL_CO3_MP_MONTGOMERY_MUL_CIOS_LOOP_BODY(j);
                    NIL_CO3_MP_MONTGOMERY_MUL_CIOS_LOOP_BODY(j + 1);
                    NIL_CO3_MP_MONTGOMERY_MUL_CIOS_LOOP_BODY(j + 2);
                }

                for (; j < mod_size; ++j) {
                    NIL_CO3_MP_MONTGOMERY_MUL_CIOS_LOOP_BODY(j);
                }

                double_limb_type tmp = static_cast<double_limb_type>(carry) + k + k2;
                A_limbs[mod_size - 1] = static_cast<limb_type>(tmp);
                carry = static_cast<limb_type>(tmp >> std::numeric_limits<limb_type>::digits);
            }

            if (carry) {
                // The value of A is actually A + 2 ^ Bits, so remove that 2 ^ Bits.
                A += this->mod_compliment();
            } else if (A >= this->mod()) {
                A -= this->mod();
            }

            result = A;
        }
#undef NIL_CO3_MP_MONTGOMERY_MUL_CIOS_LOOP_BODY

      public:
        // Delegates Montgomery multiplication to one of corresponding algorithms.
        template<std::size_t Bits2>
        constexpr void mul(big_uint<Bits2> &result, const big_uint<Bits2> &y) const {
            bench::register_mul();
            if (m_no_carry_montgomery_mul_allowed) {
                montgomery_mul_no_carry_impl(result, y);
            } else {
                montgomery_mul_CIOS_impl(result, y);
            }
        }

        constexpr base_type one() const { return m_one; }

        constexpr void increment(base_type &a) const { this->add(a, m_one); }

        constexpr void decrement(base_type &a) const { this->sub(a, m_one); }

        // Adjust to/from modular form

        template<typename T,
                 std::enable_if_t<is_integral_v<T> && !std::numeric_limits<T>::is_signed,
                                  int> = 0>
        constexpr void adjust_modular(big_uint_t &result, const T &input) const {
            // TODO(ioxid): optimize for cases where input is 0 or 1
            big_uint<2 * Bits> tmp;
            this->barrett_reduce(tmp, detail::as_big_uint(input));
            tmp *= r2();
            montgomery_reduce(tmp);
            result = static_cast<big_uint_t>(tmp);
        }

        constexpr void adjust_regular(big_uint_t &result, const big_uint_t &input) const {
            result = input;
            montgomery_reduce(result);
        }

      private:
        constexpr const auto &r2() const { return m_montgomery_r2; }
        constexpr const auto &p_dash() const { return m_montgomery_p_dash; }

        big_uint_t m_montgomery_r2;
        limb_type m_montgomery_p_dash;
        big_uint_t m_one;

        // If set, no-carry optimization is allowed. Is set to
        // is_applicable_for_no_carry_montgomery_mul() after initialization.
        bool m_no_carry_montgomery_mul_allowed;
    };
}  // namespace nil::crypto3::multiprecision::detail
