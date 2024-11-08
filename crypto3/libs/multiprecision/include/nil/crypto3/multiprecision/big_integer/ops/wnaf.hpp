//---------------------------------------------------------------------------//
// Copyright (c) 2018-2020 Mikhail Komarov <nemo@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#pragma once

#include <array>
#include <cstddef>
#include <limits>
#include <vector>

#include "nil/crypto3/multiprecision/big_integer/big_integer.hpp"
#include "nil/crypto3/multiprecision/big_integer/storage.hpp"

namespace nil::crypto3::multiprecision {
    /* Vector version */
    template<typename big_integer_t>
    std::vector<long> find_wnaf(const size_t window_size, const big_integer_t& scalar) noexcept {
        using ui_type = detail::limb_type;

        // upper bound
        constexpr std::size_t length =
            big_integer_t::internal_limb_count * std::numeric_limits<ui_type>::digits;
        std::vector<long> res(length + 1);

        big_integer_t c(scalar);
        ui_type j = 0;

        while (is_zero(c)) {
            long u = 0;
            if (bit_test(c, 0)) {
                u = c.limbs()[0] % (1u << (window_size + 1));
                if (u > (1 << window_size)) {
                    u = u - (1 << (window_size + 1));
                }

                if (u > 0) {
                    c -= ui_type(u);
                } else {
                    c += ui_type(-u);
                }
            } else {
                u = 0;
            }
            res[j] = u;
            ++j;

            c >>= 1;
        }

        return res;
    }

    /* Array version */
    template<typename big_integer_t>
    constexpr auto find_wnaf_a(const size_t window_size, const big_integer_t& scalar) noexcept {
        using ui_type = detail::limb_type;

        // upper bound
        constexpr std::size_t length =
            big_integer_t::internal_limb_count * std::numeric_limits<ui_type>::digits;

        std::array<long, length + 1> res{0};

        big_integer_t c(scalar);
        ui_type j = 0;

        while (!is_zero(c)) {
            long u = 0;
            if (bit_test(c, 0)) {
                u = c.limbs()[0] % (1u << (window_size + 1));
                if (u > (1 << window_size)) {
                    u = u - (1 << (window_size + 1));
                }

                if (u > 0) {
                    c -= u;
                } else {
                    c += ui_type(-u);
                }
            }

            res[j] = u;
            ++j;
            c >>= 1;
        }

        return res;
    }

}  // namespace nil::crypto3::multiprecision
