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

// IWYU pragma: private

#include <climits>
#include <cstddef>
#include <limits>
#include <stdexcept>
#include <type_traits>

#include "nil/crypto3/multiprecision/big_int/big_uint_impl.hpp"
#include "nil/crypto3/multiprecision/big_int/detail/assert.hpp"
#include "nil/crypto3/multiprecision/big_int/storage.hpp"

namespace nil::crypto3::multiprecision::detail {
    template<std::size_t Bits>
    constexpr bool check_montgomery_constraints(const big_uint<Bits> &m) {
        // Check m % 2 == 0
        return bit_test(m, 0u);
    }

    template<std::size_t Bits>
    struct modular_policy {
        using big_uint_t = big_uint<Bits>;

        static constexpr std::size_t limbs_count = big_uint_t::internal_limb_count;
        static constexpr std::size_t limb_bits = big_uint_t::limb_bits;

        static constexpr std::size_t BitsCount_doubled = 2u * Bits;
        static constexpr std::size_t BitsCount_doubled_1 = BitsCount_doubled + 1;
        static constexpr std::size_t BitsCount_quadruple_1 = 2u * BitsCount_doubled + 1;
        static constexpr std::size_t BitsCount_padded_limbs = limbs_count * limb_bits + limb_bits;
        static constexpr std::size_t BitsCount_doubled_limbs = 2u * limbs_count * limb_bits;
        static constexpr std::size_t BitsCount_doubled_padded_limbs =
            BitsCount_doubled_limbs + limb_bits;

        using big_uint_doubled = big_uint<BitsCount_doubled>;
        using big_uint_doubled_1 = big_uint<BitsCount_doubled_1>;
        using big_uint_quadruple_1 = big_uint<BitsCount_quadruple_1>;
        using big_uint_padded_limbs = big_uint<BitsCount_padded_limbs>;
        using big_uint_doubled_limbs = big_uint<BitsCount_doubled_limbs>;
        using big_uint_doubled_padded_limbs = big_uint<BitsCount_doubled_padded_limbs>;
    };

    template<std::size_t Bits_>
    class barrett_modular_ops {
      public:
        static constexpr std::size_t Bits = Bits_;
        using big_uint_t = big_uint<Bits>;
        using policy_type = modular_policy<Bits>;

        using big_uint_doubled_1 = typename policy_type::big_uint_doubled_1;
        using big_uint_quadruple_1 = typename policy_type::big_uint_quadruple_1;
        using big_uint_padded_limbs = typename policy_type::big_uint_padded_limbs;
        using big_uint_doubled_limbs = typename policy_type::big_uint_doubled_limbs;
        using big_uint_doubled_padded_limbs = typename policy_type::big_uint_doubled_padded_limbs;

        static constexpr std::size_t limbs_count = policy_type::limbs_count;
        static constexpr std::size_t limb_bits = policy_type::limb_bits;

        constexpr barrett_modular_ops(const big_uint_t &m) : m_mod(m), m_barrett_mu(0u) {
            std::size_t bit = 2u * (1u + msb(m_mod));
            bit_set(m_barrett_mu, bit);

            m_barrett_mu /= m_mod;

            // Compute 2^Bits - Modulus, no matter if modulus is even or odd.
            big_uint_padded_limbs compliment = 1u, modulus = m_mod;
            compliment <<= Bits;
            compliment -= modulus;
            m_mod_compliment = compliment;
        }

        constexpr const auto &mod() const { return m_mod; }

      protected:
        constexpr const auto &mod_compliment() const { return m_mod_compliment; }

      private:
        constexpr const auto &mu() const { return m_barrett_mu; }

      public:
        template<std::size_t Bits2>
        constexpr void barrett_reduce(big_uint<Bits2> &result) const {
            barrett_reduce(result, result);
        }

        template<std::size_t Bits2, std::size_t Bits3,
                 std::enable_if_t<
                     /// result should fit in the output parameter
                     Bits2 >= big_uint_t::Bits, int> = 0>
        constexpr void barrett_reduce(big_uint<Bits2> &result, big_uint<Bits3> input) const {
            if (!is_zero(input)) {
                if (msb(input) < 2u * msb(mod()) + 1u) {
                    big_uint_quadruple_1 t1(input);

                    t1 *= m_barrett_mu;
                    std::size_t shift_size = 2u * (1u + msb(mod()));
                    t1 >>= shift_size;
                    t1 *= mod();

                    input -= t1;

                    if (input >= mod()) {
                        input -= mod();
                    }
                } else {
                    input %= mod();
                }
            }
            result = input;
        }

        template<std::size_t Bits2, std::size_t Bits3,
                 // result should fit in the output parameter
                 std::enable_if_t<Bits2 >= Bits3, int> = 0>
        constexpr void add(big_uint<Bits2> &result, const big_uint<Bits3> &y) const {
            NIL_CO3_MP_ASSERT(result < mod() && y < mod());

            result += y;
            // If we overflow and set the carry, we need to subtract the modulus, which is
            // the same as adding 2 ^ Bits - Modulus to the remaining part of the number.
            // After this we know for sure that the result < Modulus, do not waste time on
            // checking again.
            if (result.has_carry()) {
                result += mod_compliment();
                result.set_carry(false);
            } else if (result >= mod()) {
                result -= mod();
            }
        }

        template<std::size_t Bits2, std::size_t Bits3,
                 /// result should fit in the output parameter
                 std::enable_if_t<big_uint<Bits2>::Bits >= big_uint_t::Bits, int> = 0>
        constexpr void mul(big_uint<Bits2> &result, const big_uint<Bits3> &y) const {
            big_uint_doubled_limbs tmp = result;
            tmp *= y;
            barrett_reduce(result, tmp);
        }

        template<std::size_t Bits2, std::size_t Bits3, std::size_t Bits4,
                 /// result should fit in the output parameter
                 std::enable_if_t<big_uint<Bits2>::Bits >= big_uint_t::Bits, int> = 0>
        constexpr void exp(big_uint<Bits2> &result, const big_uint<Bits3> &a,
                           big_uint<Bits4> exp) const {
            NIL_CO3_MP_ASSERT(a < mod());

            if (exp == 0u) {
                result = 1u;
                return;
            }
            if (mod() == 1u) {
                result = 0u;
                return;
            }

            big_uint_doubled_limbs base(a), res(1u);

            while (true) {
                bool lsb = bit_test(exp, 0);
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

        // Adjust to/from modular form

        constexpr void adjust_modular(big_uint_t &result) const { adjust_modular(result, result); }

        template<std::size_t Bits2>
        constexpr void adjust_modular(big_uint_t &result, big_uint<Bits2> input) const {
            big_uint_doubled_limbs tmp;
            barrett_reduce(tmp, input);
            result = tmp;
        }

        [[nodiscard]] constexpr big_uint_t adjusted_regular(const big_uint_t &a) const {
            big_uint_t result;
            adjust_regular(result, a);
            return result;
        }

        template<std::size_t Bits2, std::size_t Bits3,
                 /// input number should fit in result
                 std::enable_if_t<Bits2 >= Bits3, int> = 0>
        constexpr void adjust_regular(big_uint<Bits2> &result, const big_uint<Bits3> &input) const {
            result = input;
        }

        constexpr bool compare_eq(const barrett_modular_ops &o) const { return mod() == o.mod(); }

      protected:
        big_uint_t m_mod;
        // This is 2^Bits - m_mod, precomputed.
        big_uint_t m_mod_compliment;
        big_uint_doubled_1 m_barrett_mu;
    };

    template<std::size_t Bits_>
    class montgomery_modular_ops : public barrett_modular_ops<Bits_> {
      public:
        static constexpr std::size_t Bits = Bits_;
        using big_uint_t = big_uint<Bits>;
        using policy_type = modular_policy<Bits>;

        using big_uint_doubled_1 = typename policy_type::big_uint_doubled_1;
        using big_uint_quadruple_1 = typename policy_type::big_uint_quadruple_1;
        using big_uint_padded_limbs = typename policy_type::big_uint_padded_limbs;
        using big_uint_doubled_limbs = typename policy_type::big_uint_doubled_limbs;
        using big_uint_doubled_padded_limbs = typename policy_type::big_uint_doubled_padded_limbs;

        static constexpr std::size_t limbs_count = policy_type::limbs_count;
        static constexpr std::size_t limb_bits = policy_type::limb_bits;

        constexpr montgomery_modular_ops(const big_uint_t &m) : barrett_modular_ops<Bits_>(m) {
            if (!check_montgomery_constraints(m)) {
                throw std::invalid_argument("module not usable with montgomery");
            }

            m_montgomery_p_dash = this->monty_inverse(this->m_mod.limbs()[0]);

            big_uint_doubled_padded_limbs r;
            bit_set(r, 2 * this->m_mod.limbs_count() * limb_bits);
            this->barrett_reduce(r);

            // Here we are intentionally throwing away half of the bits of r, it's
            // correct.
            m_montgomery_r2 = static_cast<big_uint_t>(r);

            m_no_carry_montgomery_mul_allowed = is_applicable_for_no_carry_montgomery_mul();
        }

      private:
        /*
         * Compute -input^-1 mod 2^limb_bits. Throws an exception if input
         * is even. If input is odd, then input and 2^n are relatively prime
         * and an inverse exists.
         */
        constexpr limb_type monty_inverse(const limb_type &a) {
            if (a % 2 == 0) {
                throw std::invalid_argument("inverse does not exist");
            }
            limb_type b = 1;
            limb_type r = 0;

            for (std::size_t i = 0; i != limb_bits; ++i) {
                const limb_type bi = b % 2;
                r >>= 1;
                r += bi << (limb_bits - 1);

                b -= a * bi;
                b >>= 1;
            }

            // Now invert in addition space
            r = (~static_cast<limb_type>(0u) - r) + 1;

            return r;
        }

        constexpr const auto &r2() const { return m_montgomery_r2; }
        constexpr const auto &p_dash() const { return m_montgomery_p_dash; }

      public:
        template<std::size_t Bits2,
                 // result should fit in the output parameter
                 std::enable_if_t<Bits2 >= Bits, int> = 0>
        constexpr void montgomery_reduce(big_uint<Bits2> &result) const {
            big_uint_doubled_padded_limbs accum(result);
            big_uint_doubled_padded_limbs prod;

            for (std::size_t i = 0; i < this->mod().limbs_count(); ++i) {
                limb_type limb_accum = accum.limbs()[i];
                double_limb_type mult_res = limb_accum *
                                            /// to prevent overflow error in constexpr
                                            static_cast<double_limb_type>(p_dash());
                limb_type mult_res_limb = static_cast<limb_type>(mult_res);

                prod = this->mod();
                prod *= mult_res_limb;
                prod <<= i * limb_bits;
                accum += prod;
            }
            accum >>= this->mod().limbs_count() * limb_bits;

            if (accum >= this->mod()) {
                accum -= this->mod();
            }

            result = accum;
        }

        // Delegates Montgomery multiplication to one of corresponding algorithms.
        template<std::size_t Bits2>
        constexpr void mul(big_uint<Bits2> &result, const big_uint<Bits2> &y) const {
            if (m_no_carry_montgomery_mul_allowed) {
                montgomery_mul_no_carry_impl(result, y);
            } else {
                montgomery_mul_CIOS_impl(result, y);
            }
        }

      private:
        // Tests if the faster implementation of Montgomery multiplication is possible.
        constexpr bool is_applicable_for_no_carry_montgomery_mul() const {
            // Check that
            // 1. The most significant bit of modulus is non-zero, meaning we have at least
            // 1 additional bit in the number. E.g. if modulus is 255 bits, then we have 1
            // additional "unused" bit in the number.
            // 2. Some other bit in modulus is 0.
            // 3. The number has < 12 limbs.
            return this->mod().limbs_count() < 12 && (Bits % sizeof(limb_type) != 0) &&
                   this->mod_compliment() != limb_type(1u);
        }

      public:
        // Non-carry implementation of Montgomery multiplication.
        // Implemented from pseudo-code at
        //   "https://hackmd.io/@gnark/modular_multiplication".
        template<std::size_t Bits2>
        constexpr void montgomery_mul_no_carry_impl(big_uint<Bits2> &c,
                                                    const big_uint<Bits2> &b) const {
            NIL_CO3_MP_ASSERT(c < this->mod() && b < this->mod());
            NIL_CO3_MP_ASSERT(is_applicable_for_no_carry_montgomery_mul());

            // Obtain number of limbs
            constexpr int N = big_uint<Bits2>::internal_limb_count;

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
            NIL_CO3_MP_ASSERT(result < this->mod() && y < this->mod());

            big_uint_t A(limb_type(0u));
            const std::size_t mod_size = this->mod().limbs_count();
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

        template<std::size_t Bits2, std::size_t Bits3, std::size_t Bits4,
                 /// result should fit in the output parameter
                 std::enable_if_t<big_uint<Bits2>::Bits >= big_uint_t::Bits, int> = 0>
        constexpr void exp(big_uint<Bits2> &result, const big_uint<Bits3> &a,
                           big_uint<Bits4> exp) const {
            /// input parameter should be less than modulus
            NIL_CO3_MP_ASSERT(a < this->mod());

            big_uint_t R_mod_m(1u);
            adjust_modular(R_mod_m);

            big_uint_t base(a);

            if (exp == 0u) {
                result = 1u;
                adjust_modular(result);
                return;
            }
            if (this->mod() == 1u) {
                result = 0u;
                return;
            }

            while (true) {
                bool lsb = bit_test(exp, 0);
                exp >>= 1u;
                if (lsb) {
                    mul(R_mod_m, base);
                    if (exp == 0u) {
                        break;
                    }
                }
                mul(base, base);
            }
            result = R_mod_m;
        }

        // Adjust to/from modular form

        constexpr void adjust_modular(big_uint_t &result) const { adjust_modular(result, result); }

        template<std::size_t Bits3>
        constexpr void adjust_modular(big_uint_t &result, const big_uint<Bits3> &input) const {
            big_uint_doubled_limbs tmp;
            this->barrett_reduce(tmp, input);
            tmp *= r2();
            montgomery_reduce(tmp);
            result = tmp;
        }

        [[nodiscard]] constexpr big_uint_t adjusted_regular(const big_uint_t &a) const {
            big_uint_t result;
            adjust_regular(result, a);
            return result;
        }

        template<std::size_t Bits2, std::size_t Bits3,
                 /// input number should fit in result
                 std::enable_if_t<Bits2 >= Bits3, int> = 0>
        constexpr void adjust_regular(big_uint<Bits2> &result, const big_uint<Bits3> &input) const {
            result = input;
            montgomery_reduce(result);
        }

      protected:
        big_uint_t m_montgomery_r2;
        limb_type m_montgomery_p_dash;

        // If set, no-carry optimization is allowed. Is set to
        // is_applicable_for_no_carry_montgomery_mul() after initialization.
        bool m_no_carry_montgomery_mul_allowed;
    };
}  // namespace nil::crypto3::multiprecision::detail
