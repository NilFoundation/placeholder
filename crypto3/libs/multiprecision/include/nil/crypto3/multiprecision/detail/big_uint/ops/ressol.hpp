//---------------------------------------------------------------------------//
// Copyright (c) 2018-2020 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2018-2020 Pavel Kharitonov <ipavrus@nil.foundation>
// Copyright (c) 2021 Aleksei Moskvin <alalmoskvin@gmail.com>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#pragma once

// IWYU pragma: private; include "nil/crypto3/multiprecision/big_uint.hpp"

#include <cstddef>
#include <stdexcept>

#include "nil/crypto3/multiprecision/detail/assert.hpp"
#include "nil/crypto3/multiprecision/detail/big_mod/big_mod_impl.hpp"
#include "nil/crypto3/multiprecision/detail/big_mod/ops/pow.hpp"
#include "nil/crypto3/multiprecision/detail/big_uint/big_uint_impl.hpp"
#include "nil/crypto3/multiprecision/detail/big_uint/ops/jacobi.hpp"
#include "nil/crypto3/multiprecision/detail/big_uint/storage.hpp"

namespace nil::crypto3::multiprecision {
    template<std::size_t Bits>
    constexpr big_uint<Bits> ressol(const big_uint<Bits> &a, const big_uint<Bits> &p) {
        /*
         * The implementation is split for two different cases:
         *   1. if p mod 4 == 3 we apply Handbook of Applied Cryptography algorithm 3.36 and compute
         * r directly as r = n(p+1)/4 mod p
         *   2. otherwise we use Tonelli-Shanks algorithm
         */
        using big_uint_t = big_uint<Bits>;
        using big_uint_padded_t = big_uint<Bits + 1>;

        using ui_type = detail::limb_type;

        big_uint_t two = ui_type(2u);
        big_uint_t res;

        if (a.is_zero()) {
            return 0u;
        }
        NIL_CO3_MP_ASSERT(a < p);

        if (p == two) {
            return a;
        }
        NIL_CO3_MP_ASSERT(p > 1u);
        NIL_CO3_MP_ASSERT(p % 2u != 0u);

        if (jacobi(a, p) != 1) {
            throw std::invalid_argument("Not a quadratic residue");
        }

        // We can use montgomery_big_mod because p is odd

        montgomery_big_mod_rt<Bits> a_mod(a, p);

        if (p % 4u == 3) {
            big_uint_padded_t exp_padded = p;

            ++exp_padded;
            exp_padded >>= 2u;

            return pow(a_mod, big_uint_t(exp_padded)).base();
        }

        big_uint_t p_negone = p;
        --p_negone;
        std::size_t s = p_negone.lsb();

        big_uint_t q = p;
        q >>= s;
        --q;
        q >>= 1u;

        montgomery_big_mod_rt<Bits> n_mod = a_mod;

        auto r_mod = pow(a_mod, q);
        auto r_sq_mod = pow(r_mod, two);
        n_mod *= r_sq_mod;
        r_mod *= a_mod;

        if (n_mod.base() == 1u) {
            return r_mod.base();
        }

        // find random quadratic nonresidue z
        big_uint_t z = two;
        while (jacobi(z, p) == 1) {
            if (z.is_zero()) {
                throw std::invalid_argument("No quadratic nonresidue");
            }
            ++z;
        }

        q <<= 1u;
        ++q;

        montgomery_big_mod_rt<Bits> z_mod(z, p);

        auto c_mod = pow(z_mod, q);

        while (n_mod.base() > 1u) {
            std::size_t i = 0u;

            auto q_mod = n_mod;

            while (q_mod.base() != 1u) {
                q_mod = pow(q_mod, two);
                ++i;

                if (i >= s) {
                    // TODO(ioxid): when can this happen? (jacobi said that this should not happen)
                    // Martun: the value now has a square root
                    throw std::invalid_argument("Not a quadratic residue");
                }
            }

            big_uint_t power_of_2;

            power_of_2.bit_set(s - i - 1);
            c_mod = pow(c_mod, power_of_2);
            r_mod *= c_mod;
            c_mod = pow(c_mod, two);
            n_mod *= c_mod;

            s = i;
        }

        return r_mod.base();
    }
}  // namespace nil::crypto3::multiprecision
