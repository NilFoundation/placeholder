//---------------------------------------------------------------------------//
// Copyright (c) 2020 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020 Ilias Khairullin <ilias@nil.foundation>
// Copyright (c) 2021 Aleksei Moskvin <alalmoskvin@nil.foundation>
// Copyright (c) 2024 Andrey Nefedov <ioxid@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#pragma once

#include <climits>
#include <cstddef>
#include <type_traits>

#include <boost/assert.hpp>

#include "nil/crypto3/multiprecision/big_uint.hpp"
#include "nil/crypto3/multiprecision/detail/big_mod/modular_ops/common.hpp"

namespace nil::crypto3::multiprecision::detail {
    template<std::size_t Bits>
    struct modular_policy {
        using big_uint_t = big_uint<Bits>;

        static constexpr std::size_t limb_count = big_uint_t::static_limb_count;
        static constexpr std::size_t limb_bits = big_uint_t::limb_bits;

        static constexpr std::size_t BitsCount_doubled = 2u * Bits;
        static constexpr std::size_t BitsCount_doubled_1 = BitsCount_doubled + 1;
        static constexpr std::size_t BitsCount_quadruple_1 = 2u * BitsCount_doubled + 1;
        static constexpr std::size_t BitsCount_padded_limbs =
            limb_count * limb_bits + limb_bits;
        static constexpr std::size_t BitsCount_doubled_limbs =
            2u * limb_count * limb_bits;
        static constexpr std::size_t BitsCount_doubled_padded_limbs =
            BitsCount_doubled_limbs + limb_bits;

        using big_uint_doubled = big_uint<BitsCount_doubled>;
        using big_uint_doubled_1 = big_uint<BitsCount_doubled_1>;
        using big_uint_quadruple_1 = big_uint<BitsCount_quadruple_1>;
        using big_uint_padded_limbs = big_uint<BitsCount_padded_limbs>;
        using big_uint_doubled_limbs = big_uint<BitsCount_doubled_limbs>;
        using big_uint_doubled_padded_limbs = big_uint<BitsCount_doubled_padded_limbs>;
    };

    template<std::size_t Bits>
    class common_big_uint_modular_ops : public common_modular_ops<big_uint<Bits>> {
      public:
        using big_uint_t = big_uint<Bits>;

        constexpr common_big_uint_modular_ops(const big_uint_t &m)
            : common_modular_ops<big_uint<Bits>>(m),
              m_mod_compliment(this->m_mod.wrapping_neg()) {}

        template<std::size_t Bits2, std::size_t Bits3,
                 // result should fit in the output parameter
                 std::enable_if_t<Bits2 >= Bits3, int> = 0>
        constexpr void add(big_uint<Bits2> &result, const big_uint<Bits3> &y) const {
            BOOST_ASSERT(result < this->mod() && y < this->mod());

            bool carry = overflowing_add_assign(result, y);

            // If we overflow, we need to subtract the modulus, which is
            // the same as adding 2 ^ Bits - Modulus to the remaining part of the number.
            // After this we know for sure that the result < Modulus, do not waste time on
            // checking again.
            if (carry) {
                result += mod_compliment();
            } else if (result >= this->mod()) {
                result -= this->mod();
            }
        }

      protected:
        constexpr const auto &mod_compliment() const { return m_mod_compliment; }

        big_uint_t m_mod_compliment;
    };
}  // namespace nil::crypto3::multiprecision::detail
