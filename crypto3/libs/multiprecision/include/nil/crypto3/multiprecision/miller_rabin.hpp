//---------------------------------------------------------------------------//
// Copyright (c) 2012 John Maddock
// Copyright (c) 2024 Andrey Nefedov <ioxid@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#pragma once

#include <cstddef>
#include <cstdint>
#include <iterator>
#include <limits>
#include <random>
#include <type_traits>

#include <boost/assert.hpp>
#include <boost/random.hpp>

#include "nil/crypto3/multiprecision/big_uint.hpp"
#include "nil/crypto3/multiprecision/integer.hpp"
#include "nil/crypto3/multiprecision/pow.hpp"

namespace nil::crypto3::multiprecision {
    namespace detail {
        template<typename T1, typename T2>
        T2 integer_modulus(const T1& n, const T2& m) {
            // TODO(ioxid): optimize this
            return static_cast<T2>(n % m);
        }

        template<class I>
        bool check_small_factors(const I& n) {
            constexpr std::uint32_t small_factors1[] = {3u, 5u, 7u, 11u, 13u, 17u, 19u, 23u};
            constexpr std::uint32_t pp1 = 223092870u;

            std::uint32_t m1 = integer_modulus(n, pp1);

            for (std::size_t i = 0; i < sizeof(small_factors1) / sizeof(small_factors1[0]); ++i) {
                BOOST_ASSERT(pp1 % small_factors1[i] == 0);
                if (m1 % small_factors1[i] == 0) {
                    return false;
                }
            }

            constexpr std::uint32_t small_factors2[] = {29u, 31u, 37u, 41u, 43u, 47u};
            constexpr std::uint32_t pp2 = 2756205443u;

            m1 = integer_modulus(n, pp2);

            for (std::size_t i = 0; i < sizeof(small_factors2) / sizeof(small_factors2[0]); ++i) {
                BOOST_ASSERT(pp2 % small_factors2[i] == 0);
                if (m1 % small_factors2[i] == 0) {
                    return false;
                }
            }

            constexpr std::uint32_t small_factors3[] = {53u, 59u, 61u, 67u, 71u};
            constexpr std::uint32_t pp3 = 907383479u;

            m1 = integer_modulus(n, pp3);

            for (std::size_t i = 0; i < sizeof(small_factors3) / sizeof(small_factors3[0]); ++i) {
                BOOST_ASSERT(pp3 % small_factors3[i] == 0);
                if (m1 % small_factors3[i] == 0) {
                    return false;
                }
            }

            constexpr std::uint32_t small_factors4[] = {73u, 79u, 83u, 89u, 97u};
            constexpr std::uint32_t pp4 = 4132280413u;

            m1 = integer_modulus(n, pp4);

            for (std::size_t i = 0; i < sizeof(small_factors4) / sizeof(small_factors4[0]); ++i) {
                BOOST_ASSERT(pp4 % small_factors4[i] == 0);
                if (m1 % small_factors4[i] == 0) {
                    return false;
                }
            }

            constexpr std::uint32_t small_factors5[6][4] = {
                {101u, 103u, 107u, 109u}, {113u, 127u, 131u, 137u}, {139u, 149u, 151u, 157u},
                {163u, 167u, 173u, 179u}, {181u, 191u, 193u, 197u}, {199u, 211u, 223u, 227u}};
            constexpr std::uint32_t pp5[6] = {121330189u,
                                              113u * 127u * 131u * 137u,
                                              139u * 149u * 151u * 157u,
                                              163u * 167u * 173u * 179u,
                                              181u * 191u * 193u * 197u,
                                              199u * 211u * 223u * 227u};

            for (std::size_t k = 0; k < std::size(pp5); ++k) {
                m1 = integer_modulus(n, pp5[k]);

                for (std::size_t i = 0; i < 4; ++i) {
                    BOOST_ASSERT(pp5[k] % small_factors5[k][i] == 0);
                    if (m1 % small_factors5[k][i] == 0) {
                        return false;
                    }
                }
            }
            return true;
        }

        inline bool is_small_prime(std::size_t n) {
            constexpr unsigned char p[] = {
                3u,   5u,   7u,   11u,  13u,  17u,  19u,  23u,  29u,  31u,  37u,  41u,
                43u,  47u,  53u,  59u,  61u,  67u,  71u,  73u,  79u,  83u,  89u,  97u,
                101u, 103u, 107u, 109u, 113u, 127u, 131u, 137u, 139u, 149u, 151u, 157u,
                163u, 167u, 173u, 179u, 181u, 191u, 193u, 197u, 199u, 211u, 223u, 227u};
            for (std::size_t i = 0; i < std::size(p); ++i) {
                if (n == p[i]) {
                    return true;
                }
            }
            return false;
        }
    }  // namespace detail

    template<class I, class Engine>
    typename std::enable_if<std::numeric_limits<I>::is_integer, bool>::type miller_rabin_test(
        const I& n, std::size_t trials, Engine& gen) {
        using number_type = I;

        if (n == 2) {
            return true;  // Trivial special case.
        }
        if (bit_test(n, 0) == 0) {
            return false;  // n is even
        }
        if (n <= 227) {
            return detail::is_small_prime(static_cast<unsigned>(n));
        }

        if (!detail::check_small_factors(n)) {
            return false;
        }

        number_type nm1 = n - 1u;
        //
        // Begin with a single Fermat test - it excludes a lot of candidates:
        //
        number_type q(228), x,
            y;  // We know n is greater than this, as we've excluded small factors
        x = powm(q, nm1, n);
        if (x != 1u) {
            return false;
        }

        q = n - 1u;
        std::size_t k = lsb(q);
        q >>= k;

        // Declare our random number generator:
        boost::random::uniform_int_distribution<number_type> dist(2u, n - 2u);

        //
        // Execute the trials:
        //
        for (std::size_t i = 0; i < trials; ++i) {
            x = dist(gen);
            y = powm(x, q, n);
            std::size_t j = 0;
            while (true) {
                if (y == nm1) {
                    break;
                }
                if (y == 1) {
                    if (j == 0) {
                        break;
                    }
                    return false;  // test failed
                }
                if (++j == k) {
                    return false;  // failed
                }
                y = powm(y, 2, n);
            }
        }
        return true;  // Yeheh! probably prime.
    }

    template<class I>
    typename std::enable_if<std::numeric_limits<I>::is_integer, bool>::type miller_rabin_test(
        const I& x, std::size_t trials) {
        static std::mt19937 gen;
        return miller_rabin_test(x, trials, gen);
    }

}  // namespace nil::crypto3::multiprecision
