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
#include "nil/crypto3/multiprecision/detail/integer_ops_base.hpp"

namespace nil::crypto3::multiprecision::detail {
    // Barrett modular operations and basic operations like negation and increment
    template<std::size_t Bits_>
    class barrett_modular_ops : public common_big_uint_modular_ops<Bits_> {
      public:
        static constexpr std::size_t Bits = Bits_;
        using big_uint_t = big_uint<Bits>;
        using base_type = big_uint_t;
        using policy_type = modular_policy<Bits>;

        using big_uint_doubled_1 = typename policy_type::big_uint_doubled_1;
        using big_uint_quadruple_1 = typename policy_type::big_uint_quadruple_1;
        using big_uint_padded_limbs = typename policy_type::big_uint_padded_limbs;
        using big_uint_doubled_limbs = typename policy_type::big_uint_doubled_limbs;
        using big_uint_doubled_padded_limbs =
            typename policy_type::big_uint_doubled_padded_limbs;

        static constexpr std::size_t limb_count = policy_type::limb_count;
        static constexpr std::size_t limb_bits = policy_type::limb_bits;

        constexpr barrett_modular_ops(const big_uint_t &m)
            : common_big_uint_modular_ops<Bits_>(m), m_barrett_mu(0u) {
            std::size_t bit = 2u * (1u + this->m_mod.msb());
            m_barrett_mu.bit_set(bit);
            m_barrett_mu /= this->m_mod;
        }

      private:
        constexpr const auto &mu() const { return m_barrett_mu; }

      protected:
        template<std::size_t Bits2>
        constexpr void barrett_reduce(big_uint<Bits2> &result) const {
            barrett_reduce(result, result);
        }

        template<std::size_t Bits2, std::size_t Bits3,
                 std::enable_if_t<
                     // result should fit in the output parameter
                     Bits2 >= Bits, int> = 0>
        constexpr void barrett_reduce(big_uint<Bits2> &result,
                                      big_uint<Bits3> input) const {
            if (!input.is_zero()) {
                if (input.msb() < 2u * this->mod().msb() + 1u) {
                    // NB: this should not overflow because we checked msb
                    big_uint_quadruple_1 t1(input);

                    t1 *= m_barrett_mu;
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
                 std::enable_if_t<big_uint<Bits2>::Bits >= big_uint_t::Bits, int> = 0>
        constexpr void mul(big_uint<Bits2> &result, const big_uint<Bits3> &y) const {
            big_uint_doubled_limbs tmp = result;
            tmp *= y;
            barrett_reduce(result, tmp);
        }

        template<
            std::size_t Bits2, std::size_t Bits3, typename T,
            // result should fit in the output parameter
            std::enable_if_t<big_uint<Bits2>::Bits >= big_uint_t::Bits &&
                                 is_integral_v<T> && !std::numeric_limits<T>::is_signed,
                             int> = 0>
        constexpr void pow(big_uint<Bits2> &result, const big_uint<Bits3> &a,
                           T exp) const {
            // input parameter should be less than modulus
            BOOST_ASSERT(a < this->mod());

            if (is_zero(exp)) {
                result = 1u;
                return;
            }
            if (this->mod() == 1u) {
                result = 0u;
                return;
            }

            big_uint_doubled_limbs base(a), res(1u);

            while (true) {
                bool lsb = bit_test(exp, 0u);
                exp >>= 1u;
                if (lsb) {
                    res *= base;
                    barrett_reduce(res);
                    if (is_zero(exp)) {
                        break;
                    }
                }
                base *= base;
                barrett_reduce(base);
            }
            result = static_cast<big_uint<Bits2>>(res);
        }

        // Adjust to/from modular form

        template<typename T,
                 std::enable_if_t<is_integral_v<T> && !std::numeric_limits<T>::is_signed,
                                  int> = 0>
        constexpr void adjust_modular(big_uint_t &result, const T &input) const {
            // TODO(ioxid): optimize for cases where input is 1
            barrett_reduce(result, detail::as_big_uint(input));
        }

        constexpr void adjust_regular(big_uint_t &result, const big_uint_t &input) const {
            BOOST_ASSERT(input < this->mod());
            result = input;
        }

      protected:
        big_uint_doubled_1 m_barrett_mu;
    };
}  // namespace nil::crypto3::multiprecision::detail
