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
#include <limits>
#include <type_traits>

#include <boost/assert.hpp>

#include "nil/crypto3/multiprecision/big_uint.hpp"
#include "nil/crypto3/multiprecision/detail/big_mod/modular_ops/common_big_uint.hpp"

namespace nil::crypto3::multiprecision::detail {
    // Barrett modular operations and basic operations like negation and increment
    template<std::size_t Bits_>
    class barrett_modular_ops : public common_big_uint_modular_ops<Bits_> {
      public:
        static constexpr std::size_t Bits = Bits_;
        using big_uint_t = big_uint<Bits>;
        using base_type = big_uint_t;
        using pow_unsigned_intermediate_type = big_uint<Bits * 2>;

        constexpr barrett_modular_ops(const big_uint_t &m)
            : common_big_uint_modular_ops<Bits_>(m), m_barrett_mu(0u) {
            std::size_t bit = 2u * (1u + this->mod().msb());
            m_barrett_mu.bit_set(bit);
            m_barrett_mu /= this->mod();
        }

      protected:
        template<std::size_t Bits2, std::size_t Bits3,
                 std::enable_if_t<
                     // result should fit in the output parameter
                     Bits2 >= Bits, int> = 0>
        constexpr void barrett_reduce(big_uint<Bits2> &result,
                                      big_uint<Bits3> input) const {
            if (!input.is_zero()) {
                if (input.msb() < 2u * this->mod().msb() + 1u) {
                    // NB: this should not overflow because we checked msb
                    big_uint<4 * Bits + 1> t1(input);

                    t1 *= mu();
                    std::size_t shift_size = 2u * (1u + this->mod().msb());
                    t1 >>= shift_size;
                    t1 *= this->mod();

                    input -= static_cast<big_uint<Bits3>>(t1);

                    if (input >= this->mod()) {
                        input -= static_cast<big_uint<Bits3>>(this->mod());
                    }
                } else {
                    input %= this->mod();
                }
            }
            result = static_cast<big_uint<Bits2>>(input);
        }

      public:
        template<std::size_t Bits2, std::size_t Bits3,
                 // result should fit in the output parameter
                 std::enable_if_t<Bits2 >= Bits * 2, int> = 0>
        constexpr void mul(big_uint<Bits2> &result, const big_uint<Bits3> &y) const {
            BOOST_ASSERT(result < this->mod() && y < this->mod());
            result *= y;
            barrett_reduce(result, result);
        }

        template<std::size_t Bits2, std::size_t Bits3,
                 // result should fit in the output parameter
                 std::enable_if_t<Bits2 >= Bits && (Bits2 < Bits * 2), int> = 0>
        constexpr void mul(big_uint<Bits2> &result, const big_uint<Bits3> &y) const {
            BOOST_ASSERT(result < this->mod() && y < this->mod());
            big_uint<2 * Bits> tmp = result;
            tmp *= y;
            barrett_reduce(result, tmp);
        }

        // Adjust to/from modular form

        template<typename T,
                 std::enable_if_t<is_integral_v<T> && !std::numeric_limits<T>::is_signed,
                                  int> = 0>
        constexpr void adjust_modular(big_uint_t &result, const T &input) const {
            // TODO(ioxid): optimize for cases where input is 1
            barrett_reduce(result, detail::as_big_uint(input));
        }

      private:
        constexpr const auto &mu() const { return m_barrett_mu; }

        big_uint<2 * Bits + 1> m_barrett_mu;
    };
}  // namespace nil::crypto3::multiprecision::detail
