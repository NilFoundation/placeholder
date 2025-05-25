//---------------------------------------------------------------------------//
// Copyright (c) 2024 Alexey Kokoshnikov <alexeikokoshnikov@nil.foundation>
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

#ifndef CRYPTO3_ALGEBRA_FIELDS_GOLDILOCKS_HPP
#define CRYPTO3_ALGEBRA_FIELDS_GOLDILOCKS_HPP

#include <nil/crypto3/algebra/fields/detail/element/fp.hpp>
#include <nil/crypto3/algebra/fields/detail/element/fpn.hpp>

#include <nil/crypto3/algebra/fields/fpn.hpp>

#include <nil/crypto3/algebra/fields/params.hpp>
#include <nil/crypto3/algebra/fields/field.hpp>

namespace nil {
    namespace crypto3 {
        namespace algebra {
            namespace fields {
                /**
                 * @brief A struct representing a goldilocks 64 bit field.
                 * https://polygon.technology/blog/plonky2-a-deep-dive#:~:text=Hamish%20Ivey%2DLaw.-,The%20Goldilocks%20Field%C2%A0,-p%20%3D%202%2064
                 */
                class goldilocks : public field<64> {
                public:
                    typedef field<64> policy_type;

                    using small_subfield = goldilocks;

                    constexpr static const std::size_t modulus_bits = policy_type::modulus_bits;
                    constexpr static const std::size_t number_bits = policy_type::number_bits;
                    constexpr static const std::size_t value_bits = modulus_bits;
                    constexpr static const std::size_t arity = 1;

                    typedef typename policy_type::integral_type integral_type;
                    // 2^64 - 2^32 + 1
                    constexpr static const integral_type modulus =
                        0xFFFFFFFF00000001_big_uint64;
                    constexpr static const integral_type group_order_minus_one_half = (modulus - 1u) / 2;

                    typedef nil::crypto3::multiprecision::auto_big_mod<modulus> modular_type;
                    typedef typename detail::element_fp<params<goldilocks>> value_type;
                };

                namespace detail {
                    template<typename FieldType>
                    struct goldilocks_fp2_binomial_extension_params {
                        constexpr static std::size_t dimension = 2;
                        using field_type = FieldType;
                        using base_field_type = goldilocks;
                        constexpr static base_field_type::value_type non_residue = 7;
                        constexpr static base_field_type::value_type dim_unity_root = 18446744069414584320ull;
                    };
                }  // namespace detail

                struct goldilocks_fp2
                    : public fpn<detail::goldilocks_fp2_binomial_extension_params<goldilocks_fp2>> {
                    using small_subfield = goldilocks;
                };

            }    // namespace fields
        }        // namespace algebra
    }            // namespace crypto3
}    // namespace nil

#endif  // CRYPTO3_ALGEBRA_FIELDS_GOLDILOCKS_HPP
