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

#ifndef CRYPTO3_ALGEBRA_FIELDS_CURVE25519_BASE_FIELD_HPP
#define CRYPTO3_ALGEBRA_FIELDS_CURVE25519_BASE_FIELD_HPP

#include <nil/crypto3/algebra/fields/detail/element/fp.hpp>

#include <nil/crypto3/algebra/fields/params.hpp>
#include <nil/crypto3/algebra/fields/field.hpp>



namespace nil {
    namespace crypto3 {
        namespace algebra {
            namespace fields {
                /**
                 * @brief A struct representing a curve25519 curve.
                 * https://datatracker.ietf.org/doc/html/rfc7748#section-4.1
                 * https://neuromancer.sk/std/other/Curve25519#
                 * https://neuromancer.sk/std/other/Ed25519#
                 */
                class curve25519_base_field : public field<255> {
                public:
                    typedef field<255> policy_type;

                    using small_subfield = curve25519_base_field;

                    constexpr static const std::size_t modulus_bits = policy_type::modulus_bits;
                    constexpr static const std::size_t number_bits = policy_type::number_bits;
                    constexpr static const std::size_t value_bits = modulus_bits;
                    constexpr static const std::size_t arity = 1;
                    using extended_integral_type = nil::crypto3::multiprecision::big_uint<2 * policy_type::modulus_bits>;

                    typedef typename policy_type::integral_type integral_type;
                    constexpr static const integral_type modulus =
                        0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed_big_uint255;
                    constexpr static const integral_type group_order_minus_one_half =
                        0x3ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff6_big_uint255;

                    typedef nil::crypto3::multiprecision::auto_big_mod<modulus> modular_type;
                    typedef typename detail::element_fp<params<curve25519_base_field>> value_type;
                };

                constexpr typename std::size_t const curve25519_base_field::modulus_bits;
                constexpr typename std::size_t const curve25519_base_field::number_bits;
                constexpr typename std::size_t const curve25519_base_field::value_bits;

                constexpr typename curve25519_base_field::integral_type const curve25519_base_field::modulus;
                using curve25519_fq = curve25519_base_field;

                using ed25519 = curve25519_base_field;

            }    // namespace fields
        }        // namespace algebra
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_ALGEBRA_FIELDS_CURVE25519_BASE_FIELD_HPP
