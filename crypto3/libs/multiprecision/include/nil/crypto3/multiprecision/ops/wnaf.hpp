//---------------------------------------------------------------------------//
// Copyright (c) 2018-2020 Mikhail Komarov <nemo@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#pragma once

// IWYU pragma: private; include "nil/crypto3/multiprecision/big_uint.hpp"

#include <array>
#include <cstddef>
#include <limits>
#include <vector>

#include "nil/crypto3/multiprecision/big_uint_impl.hpp"
#include "nil/crypto3/multiprecision/storage.hpp"

namespace nil::crypto3::multiprecision {
    /* Vector version */
    template<std::size_t Bits>
    std::vector<long> find_wnaf(const std::size_t window_size,
                                const big_uint<Bits>& scalar) noexcept {
        using big_uint_t = big_uint<Bits>;
        using ui_type = detail::limb_type;

        // upper bound
        constexpr std::size_t length =
            big_uint_t::internal_limb_count * std::numeric_limits<ui_type>::digits;
        std::vector<long> res(length + 1);

        big_uint_t c(scalar);
        ui_type j = 0;

        while (!c.is_zero()) {
            long u = 0;
            if (c.bit_test(0u)) {
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
    template<std::size_t Bits>
    constexpr auto find_wnaf_a(const std::size_t window_size,
                               const big_uint<Bits>& scalar) noexcept {
        using big_uint_t = big_uint<Bits>;
        using ui_type = detail::limb_type;

        // upper bound
        constexpr std::size_t length =
            big_uint_t::internal_limb_count * std::numeric_limits<ui_type>::digits;

        std::array<long, length + 1> res{0};

        big_uint_t c(scalar);
        ui_type j = 0;

        while (!c.is_zero()) {
            long u = 0;
            if (c.bit_test(0u)) {
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
