//---------------------------------------------------------------------------//
// Copyright (c) 2021 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2021 Ilias Khairullin <ilias@nil.foundation>
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

#ifndef CRYPTO3_ALGEBRA_FIELDS_SECP_R1_BASE_FIELD_HPP
#define CRYPTO3_ALGEBRA_FIELDS_SECP_R1_BASE_FIELD_HPP

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
                struct secp_r1_base_field;

                template<>
                struct secp_r1_base_field<160> : public field<160> {
                    typedef field<160> policy_type;

                    constexpr static const std::size_t modulus_bits = policy_type::modulus_bits;
                    typedef typename policy_type::integral_type integral_type;

                    constexpr static const std::size_t number_bits = policy_type::number_bits;

                    constexpr static const integral_type modulus =
                        0xffffffffffffffffffffffffffffffff7fffffff_big_uint160;

                    constexpr static const integral_type group_order_minus_one_half = (modulus - 1) / 2;

                    typedef nil::crypto3::multiprecision::auto_big_mod<modulus> modular_type;
                    typedef typename detail::element_fp<params<secp_r1_base_field<160>>> value_type;

                    constexpr static const std::size_t value_bits = modulus_bits;
                    constexpr static const std::size_t arity = 1;
                };

                template<>
                struct secp_r1_base_field<192> : public field<192> {
                    typedef field<192> policy_type;

                    constexpr static const std::size_t modulus_bits = policy_type::modulus_bits;
                    typedef typename policy_type::integral_type integral_type;

                    constexpr static const std::size_t number_bits = policy_type::number_bits;

                    constexpr static const integral_type modulus =
                        0xfffffffffffffffffffffffffffffffeffffffffffffffff_big_uint192;

                    constexpr static const integral_type group_order_minus_one_half = (modulus - 1) / 2;

                    typedef nil::crypto3::multiprecision::auto_big_mod<modulus> modular_type;
                    typedef typename detail::element_fp<params<secp_r1_base_field<192>>> value_type;

                    constexpr static const std::size_t value_bits = modulus_bits;
                    constexpr static const std::size_t arity = 1;
                };

                template<>
                struct secp_r1_base_field<224> : public field<224> {
                    typedef field<224> policy_type;

                    constexpr static const std::size_t modulus_bits = policy_type::modulus_bits;
                    typedef typename policy_type::integral_type integral_type;

                    constexpr static const std::size_t number_bits = policy_type::number_bits;

                    constexpr static const integral_type modulus =
                        0xffffffffffffffffffffffffffffffff000000000000000000000001_big_uint224;

                    constexpr static const integral_type group_order_minus_one_half = (modulus - 1) / 2;

                    typedef nil::crypto3::multiprecision::auto_big_mod<modulus> modular_type;
                    typedef typename detail::element_fp<params<secp_r1_base_field<224>>> value_type;

                    constexpr static const std::size_t value_bits = modulus_bits;
                    constexpr static const std::size_t arity = 1;
                };

                template<>
                struct secp_r1_base_field<256> : public field<256> {
                    typedef field<256> policy_type;

                    constexpr static const std::size_t modulus_bits = policy_type::modulus_bits;
                    typedef typename policy_type::integral_type integral_type;

                    constexpr static const std::size_t number_bits = policy_type::number_bits;

                    constexpr static const integral_type modulus =
                        0xffffffff00000001000000000000000000000000ffffffffffffffffffffffff_big_uint256;

                    constexpr static const integral_type group_order_minus_one_half = (modulus - 1) / 2;

                    typedef nil::crypto3::multiprecision::auto_big_mod<modulus> modular_type;
                    typedef typename detail::element_fp<params<secp_r1_base_field<256>>> value_type;

                    constexpr static const std::size_t value_bits = modulus_bits;
                    constexpr static const std::size_t arity = 1;
                };

                template<>
                struct secp_r1_base_field<384> : public field<384> {
                    typedef field<384> policy_type;

                    constexpr static const std::size_t modulus_bits = policy_type::modulus_bits;
                    typedef typename policy_type::integral_type integral_type;

                    constexpr static const std::size_t number_bits = policy_type::number_bits;

                    constexpr static const integral_type modulus =
                        0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff0000000000000000ffffffff_big_uint384;

                    constexpr static const integral_type group_order_minus_one_half = (modulus - 1) / 2;

                    typedef nil::crypto3::multiprecision::auto_big_mod<modulus> modular_type;
                    typedef typename detail::element_fp<params<secp_r1_base_field<384>>> value_type;

                    constexpr static const std::size_t value_bits = modulus_bits;
                    constexpr static const std::size_t arity = 1;
                };

                template<>
                struct secp_r1_base_field<521> : public field<521> {
                    typedef field<521> policy_type;

                    constexpr static const std::size_t modulus_bits = policy_type::modulus_bits;
                    typedef typename policy_type::integral_type integral_type;

                    constexpr static const std::size_t number_bits = policy_type::number_bits;

                    constexpr static const integral_type modulus =
                        0x01ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff_big_uint521;

                    constexpr static const integral_type group_order_minus_one_half = (modulus - 1) / 2;

                    typedef nil::crypto3::multiprecision::auto_big_mod<modulus> modular_type;
                    typedef typename detail::element_fp<params<secp_r1_base_field<521>>> value_type;

                    constexpr static const std::size_t value_bits = modulus_bits;
                    constexpr static const std::size_t arity = 1;
                };

                template<std::size_t Version>
                using secp_r1_fq = secp_r1_base_field<Version>;

                constexpr typename std::size_t const secp_r1_fq<160>::modulus_bits;
                constexpr typename std::size_t const secp_r1_fq<160>::number_bits;
                constexpr typename std::size_t const secp_r1_fq<160>::value_bits;
                constexpr typename secp_r1_fq<160>::integral_type const secp_r1_fq<160>::modulus;
                constexpr typename secp_r1_fq<160>::integral_type const secp_r1_fq<160>::group_order_minus_one_half;

                constexpr typename std::size_t const secp_r1_fq<192>::modulus_bits;
                constexpr typename std::size_t const secp_r1_fq<192>::number_bits;
                constexpr typename std::size_t const secp_r1_fq<192>::value_bits;
                constexpr typename secp_r1_fq<192>::integral_type const secp_r1_fq<192>::modulus;
                constexpr typename secp_r1_fq<192>::integral_type const secp_r1_fq<192>::group_order_minus_one_half;

                constexpr typename std::size_t const secp_r1_fq<224>::modulus_bits;
                constexpr typename std::size_t const secp_r1_fq<224>::number_bits;
                constexpr typename std::size_t const secp_r1_fq<224>::value_bits;
                constexpr typename secp_r1_fq<224>::integral_type const secp_r1_fq<224>::modulus;
                constexpr typename secp_r1_fq<224>::integral_type const secp_r1_fq<224>::group_order_minus_one_half;

                constexpr typename std::size_t const secp_r1_fq<256>::modulus_bits;
                constexpr typename std::size_t const secp_r1_fq<256>::number_bits;
                constexpr typename std::size_t const secp_r1_fq<256>::value_bits;
                constexpr typename secp_r1_fq<256>::integral_type const secp_r1_fq<256>::modulus;
                constexpr typename secp_r1_fq<256>::integral_type const secp_r1_fq<256>::group_order_minus_one_half;

                constexpr typename std::size_t const secp_r1_fq<384>::modulus_bits;
                constexpr typename std::size_t const secp_r1_fq<384>::number_bits;
                constexpr typename std::size_t const secp_r1_fq<384>::value_bits;
                constexpr typename secp_r1_fq<384>::integral_type const secp_r1_fq<384>::modulus;
                constexpr typename secp_r1_fq<384>::integral_type const secp_r1_fq<384>::group_order_minus_one_half;

                constexpr typename std::size_t const secp_r1_fq<521>::modulus_bits;
                constexpr typename std::size_t const secp_r1_fq<521>::number_bits;
                constexpr typename std::size_t const secp_r1_fq<521>::value_bits;
                constexpr typename secp_r1_fq<521>::integral_type const secp_r1_fq<521>::modulus;
                constexpr typename secp_r1_fq<521>::integral_type const secp_r1_fq<521>::group_order_minus_one_half;
            }    // namespace fields
        }        // namespace algebra
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_ALGEBRA_FIELDS_NIST_BASE_FIELD_HPP
