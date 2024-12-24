//---------------------------------------------------------------------------//
// Copyright (c) 2020 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2021 Aleksei Moskvin <alalmoskvin@gmail.com>
// Copyright (c) 2024 Andrey Nefedov <ioxid@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#pragma once

#include <cstddef>

#include <boost/assert.hpp>

#include "nil/crypto3/multiprecision/big_uint.hpp"
#include "nil/crypto3/multiprecision/detail/big_int.hpp"
#include "nil/crypto3/multiprecision/detail/half_extended_euclidean_algorithm.hpp"

namespace nil::crypto3::multiprecision {
    template<std::size_t Bits>
    constexpr big_uint<Bits> gcd(const big_uint<Bits>& a, const big_uint<Bits>& b) {
        big_int<Bits> aa = a, bb = b, x, g;
        g = detail::half_extended_euclidean_algorithm(aa, bb, x);
        BOOST_ASSERT(!g.negative());
        return g.abs();
    }
}  // namespace nil::crypto3::multiprecision
