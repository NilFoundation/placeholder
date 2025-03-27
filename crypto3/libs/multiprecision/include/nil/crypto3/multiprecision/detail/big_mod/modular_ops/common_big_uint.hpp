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

#include "nil/crypto3/bench/scoped_profiler.hpp"

namespace nil::crypto3::multiprecision::detail {
    template<std::size_t Bits_>
    class common_big_uint_modular_ops : public common_modular_ops<big_uint<Bits_>> {
      public:
        static constexpr std::size_t Bits = Bits_;
        using big_uint_t = big_uint<Bits>;

        constexpr common_big_uint_modular_ops(const big_uint_t &m)
            : common_modular_ops<big_uint<Bits>>(m),
              m_mod_compliment(this->mod().wrapping_neg()) {}

        template<std::size_t Bits2, std::size_t Bits3,
                 // result should fit in the output parameter
                 std::enable_if_t<Bits2 >= Bits3, int> = 0>
        constexpr void add(big_uint<Bits2> &result, const big_uint<Bits3> &y) const {
            bench::register_add();
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

      private:
        big_uint_t m_mod_compliment;
    };
}  // namespace nil::crypto3::multiprecision::detail
