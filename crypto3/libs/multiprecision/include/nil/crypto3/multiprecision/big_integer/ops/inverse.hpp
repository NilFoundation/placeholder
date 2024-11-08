//---------------------------------------------------------------------------//
// Copyright (c) 2020 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2021 Aleksei Moskvin <alalmoskvin@gmail.com>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#pragma once

#include <cstddef>

#include "nil/crypto3/multiprecision/big_integer/big_integer.hpp"
#include "nil/crypto3/multiprecision/big_integer/signed_big_integer.hpp"

namespace nil::crypto3::multiprecision {
    template<typename signed_big_integer_t>
    constexpr signed_big_integer_t extended_euclidean_algorithm(const signed_big_integer_t& num1,
                                                                const signed_big_integer_t& num2,
                                                                signed_big_integer_t& bezout_x,
                                                                signed_big_integer_t& bezout_y) {
        signed_big_integer_t x, y, tmp_num1 = num1, tmp_num2 = num2;
        y = 1u;
        x = 0u;

        bezout_x = 1u;
        bezout_y = 0u;

        // Extended Euclidean Algorithm
        while (!is_zero(tmp_num2)) {
            signed_big_integer_t quotient = tmp_num1;
            signed_big_integer_t remainder = tmp_num1;
            signed_big_integer_t placeholder;

            quotient /= tmp_num2;
            remainder %= tmp_num2;

            tmp_num1 = tmp_num2;
            tmp_num2 = remainder;

            signed_big_integer_t temp_x = x, temp_y = y;
            placeholder = quotient * x;
            placeholder = bezout_x - placeholder;
            x = placeholder;
            bezout_x = temp_x;

            placeholder = quotient * y;
            placeholder = bezout_y - placeholder;
            y = placeholder;
            bezout_y = temp_y;
        }
        return tmp_num1;
    }

    // a^(-1) mod p
    // http://www-math.ucdenver.edu/~wcherowi/courses/m5410/exeucalg.html
    template<typename signed_big_integer_t>
    constexpr void inverse_extended_euclidean_algorithm(signed_big_integer_t& result,
                                                        const signed_big_integer_t& a,
                                                        const signed_big_integer_t& m) {
        // TODO(ioxid): check if the number of bits is correct
        using signed_big_integer_doubled_t = signed_big_integer<signed_big_integer_t::Bits * 2>;

        signed_big_integer_t aa = a, mm = m, x, y, g;
        g = extended_euclidean_algorithm(aa, mm, x, y);
        if (g != 1u) {
            result = 0u;
        } else {
            x %= m;
            signed_big_integer_doubled_t tmp(x);
            tmp += m;
            tmp %= m;
            result = static_cast<signed_big_integer_t>(tmp);
        }
    }

    // Overload the above code for unsigned big integers.
    template<unsigned Bits>
    constexpr void inverse_extended_euclidean_algorithm(big_integer<Bits>& result,
                                                        const big_integer<Bits>& a,
                                                        const big_integer<Bits>& m) {
        // Careful here, we NEED signed magnitude numbers here.
        using signed_big_integer_t = signed_big_integer<Bits + 1>;

        signed_big_integer_t a_signed = a;
        signed_big_integer_t m_signed = m;
        signed_big_integer_t result_signed;
        inverse_extended_euclidean_algorithm(result_signed, a_signed, m_signed);

        result = static_cast<big_integer<Bits>>(result_signed);
    }

    template<typename big_integer_t>
    constexpr big_integer_t inverse_extended_euclidean_algorithm(const big_integer_t& n,
                                                                 const big_integer_t& mod) {
        big_integer_t result;
        inverse_extended_euclidean_algorithm(result, n, mod);
        return result;
    }

    template<typename signed_big_integer_t>
    constexpr void inverse_mod_pow2(signed_big_integer_t& result, const signed_big_integer_t& a,
                                    const size_t& k) {
        using ui_type = detail::limb_type;
        signed_big_integer_t tmp, zero, one, two;
        zero = ui_type(0u);
        one = ui_type(1u);
        two = ui_type(2u);

        tmp = a % two;
        if (is_zero(tmp) || k == 0) {
            result = zero;
            return;
        }

        if (k == 1) {
            result = one;
            return;
        }

        /*
         * From "A New Algorithm for Inversion mod p^k" by Çetin Kaya Koç
         * https://eprint.iacr.org/2017/411.pdf sections 5 and 7.
         */
        signed_big_integer_t b = one;
        signed_big_integer_t r;
        for (size_t i = 0; i < k; ++i) {
            if (bit_test(b, 0)) {
                b -= a;
                bit_set(r, i);
            }
            b >>= 1;
        }
        result = r;
    }

    template<typename signed_big_integer_t>
    constexpr signed_big_integer_t inverse_mod_odd(const signed_big_integer_t& n,
                                                   const signed_big_integer_t& mod) {
        using ui_type = detail::limb_type;
        signed_big_integer_t zero, one;
        zero = ui_type(0u);
        one = ui_type(1u);
        // Caller should assure these preconditions:
        BOOST_ASSERT(n > 0);
        BOOST_ASSERT(mod >= 0);
        BOOST_ASSERT(n < mod);
        BOOST_ASSERT(mod >= 3 && mod % 2 != 0);

        /*
        This uses a modular inversion algorithm designed by Niels Möller
        and implemented in Nettle. The same algorithm was later also
        adapted to GMP in mpn_sec_invert.

        There is also a description of the algorithm in Appendix 5 of "Fast
        Software Polynomial Multiplication on ARM Processors using the NEON Engine"
        by Danilo Câmara, Conrado P. L. Gouvêa, Julio López, and Ricardo
        Dahab in LNCS 8182
           https://conradoplg.cryptoland.net/files/2010/12/mocrysen13.pdf

        */

        signed_big_integer_t a = n;
        signed_big_integer_t b = mod;
        signed_big_integer_t u = one;
        signed_big_integer_t v = zero;

        size_t ell = msb(mod);
        for (size_t i = 0; i < 2 * ell; ++i) {
            size_t odd = bit_test(a, 0);
            size_t gteq = a >= b;
            if (odd && gteq) {
                a -= b;
            } else if (odd && !gteq) {
                signed_big_integer_t u_tmp = u;
                u = v;
                v = u_tmp;
                signed_big_integer_t tmp = a;
                a = b - a;
                b = tmp;
            }
            a >>= 1;
            size_t gteq2 = u >= v;
            if (odd && gteq2) {
                u -= v;
            } else if (odd && !gteq2) {
                u += mod;
                u -= v;
            }

            if (bit_test(u, 0)) {
                u = u + mod;
            }
            u >>= 1;
        }
        if (b != one) {  // if b != 1 then gcd(n,mod) > 1 and inverse does not exist
            return zero;
        }
        return v;
    }

    template<typename signed_big_integer_t>
    constexpr void inverse_mod(signed_big_integer_t& result, const signed_big_integer_t& n,
                               const signed_big_integer_t& mod) {
        using ui_type = detail::limb_type;
        signed_big_integer_t zero = ui_type(0u), one = ui_type(1u), tmp;

        BOOST_ASSERT(mod > ui_type(0u) && n > ui_type(0u));

        if (is_zero(n) || (!bit_test(n, 0) && !bit_test(mod, 0))) {
            result = zero;
            return;
        }

        if (bit_test(mod, 0)) {
            /*
            Fastpath for common case. This leaks if n is greater than mod or
            not, but we don't guarantee const time behavior in that case.
            */
            tmp = n % mod;
            result = inverse_mod_odd(tmp, mod);
            return;
        }

        // If n is even and mod is even we already returned 0
        // If n is even and mod is odd we jumped directly to odd-modulus algo
        const size_t mod_lz = lsb(mod);
        const size_t mod_mz = msb(mod);

        if (mod_lz == mod_mz) {
            // In this case we are performing an inversion modulo 2^k
            inverse_mod_pow2(result, n, mod_lz);
            return;
        }

        if (mod_lz == 1) {
            /*
            Inversion modulo 2*o is an easier special case of CRT

            This is exactly the main CRT flow below but taking advantage of
            the fact that any odd number ^-1 modulo 2 is 1. As a result both
            inv_2k and c can be taken to be 1, m2k is 2, and h is always
            either 0 or 1, and its value depends only on the low bit of inv_o.

            This is worth special casing because we generate RSA primes such
            that phi(n) is of this form. However this only works for keys
            that we generated in this way; pre-existing keys will typically
            fall back to the general algorithm below.
            */

            signed_big_integer_t o = mod;
            o >>= 1;
            signed_big_integer_t n_redc;
            n_redc = n % o;
            const signed_big_integer_t inv_o = inverse_mod_odd(n_redc, o);

            // No modular inverse in this case:
            if (is_zero(inv_o)) {
                result = zero;
                return;
            }

            signed_big_integer_t h = inv_o;

            if (!bit_test(inv_o, 0)) {
                h += o;
            }
            result = h;
            return;
        }

        /*
         * In this case we are performing an inversion modulo 2^k*o for
         * some k >= 2 and some odd (not necessarily prime) integer.
         * Compute the inversions modulo 2^k and modulo o, then combine them
         * using CRT, which is possible because 2^k and o are relatively prime.
         */

        signed_big_integer_t o = mod;
        o >>= mod_lz;
        signed_big_integer_t n_redc = n;
        n_redc %= o;
        const signed_big_integer_t inv_o = inverse_mod_odd(n_redc, o);
        signed_big_integer_t inv_2k;
        inverse_mod_pow2(inv_2k, n, mod_lz);

        // No modular inverse in this case:
        if (is_zero(inv_o) || is_zero(inv_2k)) {
            result = zero;
            return;
        }

        signed_big_integer_t m2k = one;
        left_shift(m2k, mod_lz);
        // Compute the CRT parameter
        signed_big_integer_t c;
        inverse_mod_pow2(c, o, mod_lz);

        // Compute h = c*(inv_2k-inv_o) mod 2^k
        signed_big_integer_t h;
        h = inv_2k - inv_o;
        h *= c;
        signed_big_integer_t tmp3 = one;
        left_shift(tmp3, mod_lz);
        tmp3 -= one;
        bitwise_and(h, tmp3);

        // Return result inv_o + h * o
        h *= o;
        h += inv_o;
        result = h;
    }

    // Overload the above code for unsigned big integers.
    template<unsigned Bits>
    constexpr void inverse_mod(big_integer<Bits>& result, const big_integer<Bits>& n,
                               const big_integer<Bits>& mod) {
        // Careful here, we NEED signed magnitude numbers here.
        using signed_big_integer_t = signed_big_integer<Bits + 1>;

        signed_big_integer_t n_signed = n;
        signed_big_integer_t mod_signed = mod;
        signed_big_integer_t result_signed;
        inverse_mod(result_signed, n_signed, mod_signed);

        result = static_cast<big_integer<Bits>>(result_signed);
    }

    template<typename big_integer_t>
    constexpr big_integer_t inverse_mod(const big_integer_t& a, const big_integer_t& p) {
        big_integer_t res;
        inverse_mod(res, a, p);
        return res;
    }

    /*
     * Compute the inversion number mod p^k.
     * From "A New Algorithm for Inversion mod p^k" by Çetin Kaya Koç.
     * @see https://eprint.iacr.org/2017/411.pdf sections 5 and 7.
     *
     * @param a is a non-negative integer
     * @param p is a prime number, where gcd(a,p) = 1
     * @param k is a non-negative integer, where a < p^k
     * @return x = a^(−1) mod p^k
     */
    template<typename signed_big_integer_t>
    constexpr void monty_inverse(signed_big_integer_t& res, const signed_big_integer_t& a,
                                 const signed_big_integer_t& p, const signed_big_integer_t& k) {
        using ui_type = detail::limb_type;
        signed_big_integer_t zero, one, two;
        zero = ui_type(0u);
        one = ui_type(1u);
        two = ui_type(2u);

        /*
         * From "A New Algorithm for Inversion mod p^k" by Çetin Kaya Koç
         * https://eprint.iacr.org/2017/411.pdf sections 5 and 7.
         */
        signed_big_integer_t c, tmp;

        // a^(-1) mod p:
        inverse_mod(c, a, p);

        signed_big_integer_t bi = one, bt, i = zero, xi, nextp = one;
        res = zero;

        while (i != k) {
            // xi:
            xi = bi;
            xi *= c;
            xi %= p;

            if (get_sign(xi) < 0) {
                tmp = xi;
                abs(tmp, tmp);
                tmp %= p;
                xi = p;
                xi -= tmp;
            }

            // bi:
            tmp = a;
            tmp *= xi;
            bi -= tmp;
            bi /= p;

            // res:
            tmp = xi;
            tmp *= nextp;
            nextp *= p;
            res += tmp;
            i += one;
        }
    }

    // Overload the above code for unsigned big integers.
    template<unsigned Bits>
    constexpr void monty_inverse(big_integer<Bits>& result, const big_integer<Bits>& a,
                                 const big_integer<Bits>& p, const big_integer<Bits>& k) {
        // Careful here, we NEED signed magnitude numbers here.
        using signed_big_integer_t = signed_big_integer<Bits + 1>;

        signed_big_integer_t a_signed = a;
        signed_big_integer_t p_signed = p;
        signed_big_integer_t k_signed = k;
        signed_big_integer_t result_signed;
        monty_inverse(result_signed, a_signed, p_signed, k_signed);

        result = static_cast<big_integer<Bits>>(result_signed);
    }

    template<typename big_integer_t>
    constexpr big_integer_t monty_inverse(const big_integer_t& a, const big_integer_t& p,
                                          const big_integer_t& k) {
        big_integer_t res;
        monty_inverse(res, a, p, k);
        return res;
    }
}  // namespace nil::crypto3::multiprecision
