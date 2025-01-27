//---------------------------------------------------------------------------//
// Copyright (c) 2018-2020 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2024 Andrey Nefedov <ioxid@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//
// Functions for building w-ary Non-Adjacent Form of a multiprecision value
// for a given window size.
// https://en.wikipedia.org/wiki/Elliptic_curve_point_multiplication#w-ary_non-adjacent_form_(wNAF)_method

#pragma once

#include <array>
#include <cstddef>
#include <vector>

#include "nil/crypto3/multiprecision/big_uint.hpp"

namespace nil::crypto3::multiprecision {
    namespace detail {
        template<std::size_t Bits, typename T>
        constexpr void find_wnaf_impl(T& res, const std::size_t window_size,
                                      big_uint<Bits> c) noexcept {
            std::size_t j = 0;
            while (!c.is_zero()) {
                long u = 0;
                if (c.bit_test(0u)) {
                    u = static_cast<long>(c & ((1u << (window_size + 1)) - 1));
                    if (u > (1 << window_size)) {
                        u = u - (1 << (window_size + 1));
                    }
                    c -= u;
                }
                res[j] = u;
                ++j;
                c >>= 1;
            }
        }
    }  // namespace detail

    /* Vector version */
    template<std::size_t Bits>
    constexpr std::vector<long> find_wnaf(const std::size_t window_size,
                                          const big_uint<Bits>& c) noexcept {
        // upper bound
        constexpr std::size_t length = Bits + 1;
        std::vector<long> res(length);

        detail::find_wnaf_impl(res, window_size, c);

        return res;
    }

    /* Array version */
    template<std::size_t Bits>
    constexpr auto find_wnaf_a(const std::size_t window_size, const big_uint<Bits>& c) noexcept {
        // upper bound
        constexpr std::size_t length = Bits + 1;
        std::array<long, length> res{0};

        detail::find_wnaf_impl(res, window_size, c);

        return res;
    }
}  // namespace nil::crypto3::multiprecision
