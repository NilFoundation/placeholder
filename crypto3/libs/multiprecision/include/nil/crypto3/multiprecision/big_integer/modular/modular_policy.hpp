//---------------------------------------------------------------------------//
// Copyright (c) 2020 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020 Ilias Khairullin <ilias@nil.foundation>
// Copyright (c) 2024 Andrey Nefedov <ioxid@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#pragma once

#include <climits>

#include "nil/crypto3/multiprecision/big_integer/big_integer.hpp"

namespace nil::crypto3::multiprecision {
    // TODO(ioxid): maybe remove
    template<unsigned Bits>
    struct modular_policy {
        using Backend = big_integer<Bits>;

        using limb_type = limb_type;
        using double_limb_type = double_limb_type;

        constexpr static auto limbs_count = Backend::internal_limb_count;
        constexpr static auto limb_bits = Backend::limb_bits;

        constexpr static auto BitsCount_doubled = 2u * Bits;
        constexpr static auto BitsCount_doubled_1 = BitsCount_doubled + 1;
        constexpr static auto BitsCount_quadruple_1 = 2u * BitsCount_doubled + 1;
        constexpr static auto BitsCount_padded_limbs = limbs_count * limb_bits + limb_bits;
        constexpr static auto BitsCount_doubled_limbs = 2u * limbs_count * limb_bits;
        constexpr static auto BitsCount_doubled_padded_limbs = BitsCount_doubled_limbs + limb_bits;

        using Backend_doubled = big_integer<BitsCount_doubled>;
        using Backend_doubled_1 = big_integer<BitsCount_doubled_1>;
        using Backend_quadruple_1 = big_integer<BitsCount_quadruple_1>;
        using Backend_padded_limbs = big_integer<BitsCount_padded_limbs>;
        using Backend_doubled_limbs = big_integer<BitsCount_doubled_limbs>;
        using Backend_doubled_padded_limbs = big_integer<BitsCount_doubled_padded_limbs>;
    };
}  // namespace nil::crypto3::multiprecision
