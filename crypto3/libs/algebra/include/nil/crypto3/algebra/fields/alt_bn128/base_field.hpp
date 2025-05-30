//---------------------------------------------------------------------------//
// Copyright (c) 2020-2021 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020-2021 Nikita Kaskov <nbering@nil.foundation>
//
// MIT License
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_ALGEBRA_FIELDS_ALT_BN128_BASE_FIELD_HPP
#define CRYPTO3_ALGEBRA_FIELDS_ALT_BN128_BASE_FIELD_HPP

#include <nil/crypto3/algebra/fields/detail/element/fp.hpp>

#include <nil/crypto3/algebra/fields/params.hpp>
#include <nil/crypto3/algebra/fields/field.hpp>

namespace nil {
    namespace crypto3 {
        namespace algebra {
            namespace fields {

                /*!
                 * @brief IETF IPsec groups
                 * @tparam Version
                 */
                template<std::size_t Version>
                struct alt_bn128_base_field;

                template<>
                struct alt_bn128_base_field<254> : public field<254> {
                    typedef field<254> policy_type;

                    using small_subfield = alt_bn128_base_field;

                    constexpr static const std::size_t modulus_bits = policy_type::modulus_bits;
                    typedef typename policy_type::integral_type integral_type;

                    constexpr static const std::size_t number_bits = policy_type::number_bits;

                    constexpr static const integral_type modulus =
                        0x30644E72E131A029B85045B68181585D97816A916871CA8D3C208C16D87CFD47_big_uint254;

                    constexpr static const integral_type group_order_minus_one_half =
                        0x183227397098D014DC2822DB40C0AC2ECBC0B548B438E5469E10460B6C3E7EA3_big_uint254;

                    typedef nil::crypto3::multiprecision::auto_big_mod<modulus> modular_type;
                    constexpr static const integral_type mul_generator = 0x03;

                    typedef typename detail::element_fp<params<alt_bn128_base_field<254>>> value_type;

                    constexpr static const std::size_t value_bits = modulus_bits;
                    constexpr static const std::size_t arity = 1;
                };

                constexpr typename std::size_t const alt_bn128_base_field<254>::modulus_bits;

                constexpr typename std::size_t const alt_bn128_base_field<254>::number_bits;

                constexpr typename std::size_t const alt_bn128_base_field<254>::value_bits;

                constexpr typename alt_bn128_base_field<254>::integral_type const alt_bn128_base_field<254>::modulus;

                constexpr typename alt_bn128_base_field<254>::integral_type const alt_bn128_base_field<254>::group_order_minus_one_half;

                constexpr
                    typename alt_bn128_base_field<254>::integral_type const alt_bn128_base_field<254>::mul_generator;

                template<std::size_t Version = 254>
                using alt_bn128_fq = alt_bn128_base_field<Version>;

                template<std::size_t Version = 254>
                using alt_bn128 = alt_bn128_base_field<Version>;
            }    // namespace fields
        }        // namespace algebra
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_ALGEBRA_FIELDS_ALT_BN128_BASE_FIELD_HPP
