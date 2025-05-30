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

#ifndef CRYPTO3_ALGEBRA_FIELDS_ALT_BN128_SCALAR_FIELD_HPP
#define CRYPTO3_ALGEBRA_FIELDS_ALT_BN128_SCALAR_FIELD_HPP

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
                struct alt_bn128_scalar_field;

                template<>
                struct alt_bn128_scalar_field<254> : public field<254> {
                    typedef field<254> policy_type;

                    using small_subfield = alt_bn128_scalar_field;

                    constexpr static const std::size_t modulus_bits = policy_type::modulus_bits;
                    typedef typename policy_type::integral_type integral_type;

                    constexpr static const std::size_t number_bits = policy_type::number_bits;

                    constexpr static const integral_type modulus =
                        0x30644E72E131A029B85045B68181585D2833E84879B9709143E1F593F0000001_big_uint254;

                    constexpr static const integral_type group_order_minus_one_half =
                        0x183227397098d014dc2822db40c0ac2e9419f4243cdcb848a1f0fac9f8000000_big_uint254;

                    typedef nil::crypto3::multiprecision::auto_big_mod<modulus> modular_type;

                    constexpr static const integral_type mul_generator = 0x05;

                    typedef typename detail::element_fp<params<alt_bn128_scalar_field<254>>> value_type;

                    constexpr static const std::size_t value_bits = modulus_bits;
                    constexpr static const std::size_t arity = 1;
                };

                constexpr typename std::size_t const alt_bn128_scalar_field<254>::modulus_bits;

                constexpr typename std::size_t const alt_bn128_scalar_field<254>::number_bits;

                constexpr typename std::size_t const alt_bn128_scalar_field<254>::value_bits;

                constexpr typename alt_bn128_scalar_field<254>::integral_type const
                    alt_bn128_scalar_field<254>::modulus;

                constexpr typename alt_bn128_scalar_field<254>::integral_type const
                    alt_bn128_scalar_field<254>::group_order_minus_one_half;

                constexpr typename alt_bn128_scalar_field<254>::integral_type const
                    alt_bn128_scalar_field<254>::mul_generator;

                template<std::size_t Version = 254>
                using alt_bn128_fr = alt_bn128_scalar_field<Version>;

            }    // namespace fields
        }        // namespace algebra
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_ALGEBRA_FIELDS_ALT_BN128_SCALAR_FIELD_HPP
