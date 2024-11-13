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

// IWYU pragma: private; include "nil/crypto3/multiprecision/big_integer/big_integer.hpp"

#include <cstddef>
#include <stdexcept>

#include "nil/crypto3/multiprecision/big_integer/big_integer_impl.hpp"
#include "nil/crypto3/multiprecision/big_integer/detail/assert.hpp"
#include "nil/crypto3/multiprecision/big_integer/modular/modular_big_integer_impl.hpp"
#include "nil/crypto3/multiprecision/big_integer/modular/ops/misc.hpp"
#include "nil/crypto3/multiprecision/big_integer/ops/jacobi.hpp"
#include "nil/crypto3/multiprecision/big_integer/storage.hpp"

namespace nil::crypto3::multiprecision {
    template<std::size_t Bits>
    constexpr big_integer<Bits> ressol(const big_integer<Bits> &a, const big_integer<Bits> &p) {
        /*
         * The implementation is split for two different cases:
         *   1. if p mod 4 == 3 we apply Handbook of Applied Cryptography algorithm 3.36 and compute
         * r directly as r = n(p+1)/4 mod p
         *   2. otherwise we use Tonelli-Shanks algorithm
         */
        using big_integer_t = big_integer<Bits>;
        using big_integer_padded_t = big_integer<Bits + 1>;

        using ui_type = detail::limb_type;

        big_integer_t two = ui_type(2u);
        big_integer_t res;

        if (is_zero(a)) {
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

        modular_big_integer_rt<Bits> a_mod(a, p);

        if (p % 4 == 3) {
            big_integer_padded_t exp_padded = p;

            ++exp_padded;
            exp_padded >>= 2u;

            return powm(a_mod, big_integer_t(exp_padded)).remove_modulus();
        }

        big_integer_t p_negone = p;
        --p_negone;
        std::size_t s = lsb(p_negone);

        big_integer_t q = p;
        q >>= s;
        --q;
        q >>= 1u;

        modular_big_integer_rt<Bits> n_mod = a_mod;

        auto r_mod = powm(a_mod, q);
        auto r_sq_mod = powm(r_mod, two);
        n_mod *= r_sq_mod;
        r_mod *= a_mod;

        if (n_mod.remove_modulus() == 1u) {
            return r_mod.remove_modulus();
        }

        // find random quadratic nonresidue z
        big_integer_t z = two;
        while (jacobi(z, p) == 1) {
            if (is_zero(z)) {
                throw std::invalid_argument("No quadratic nonresidue");
            }
            ++z;
        }

        q <<= 1u;
        ++q;

        modular_big_integer_rt<Bits> z_mod(z, p);

        auto c_mod = powm(z_mod, q);

        while (n_mod.remove_modulus() > 1u) {
            size_t i = 0u;

            auto q_mod = n_mod;

            while (q_mod.remove_modulus() != 1u) {
                q_mod = powm(q_mod, two);
                ++i;

                if (i >= s) {
                    // TODO(ioxid): what error exactly should be returned here?
                    throw std::invalid_argument("Not a quadratic residue");
                }
            }

            big_integer_t power_of_2;

            bit_set(power_of_2, s - i - 1);
            c_mod = powm(c_mod, power_of_2);
            r_mod *= c_mod;
            c_mod = powm(c_mod, two);
            n_mod *= c_mod;

            s = i;
        }

        return r_mod.remove_modulus();
    }
}  // namespace nil::crypto3::multiprecision
