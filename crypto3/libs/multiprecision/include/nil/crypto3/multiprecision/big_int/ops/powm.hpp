//---------------------------------------------------------------------------//
// Copyright (c) 2020 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2019-2021 Aleksei Moskvin <alalmoskvin@nil.foundation>
// Copyright (c) 2020 Ilias Khairullin <ilias@nil.foundation>
// Copyright (c) 2024 Andrey Nefedov <ioxid@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#pragma once

// IWYU pragma: private; include "nil/crypto3/multiprecision/big_int/big_uint.hpp"

#include <cstddef>

#include "nil/crypto3/multiprecision/big_int/big_uint.hpp"
#include "nil/crypto3/multiprecision/big_int/modular/big_mod_impl.hpp"

namespace nil::crypto3::multiprecision {
    template<std::size_t Bits>
    constexpr big_uint<Bits> powm(const big_uint<Bits> &b, const big_uint<Bits> &e, const big_uint<Bits> &m) {
        return pow(big_mod_rt<Bits>(b, m), e).base();
    }
}  // namespace nil::crypto3::multiprecision
