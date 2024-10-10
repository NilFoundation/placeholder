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

#ifndef CRYPTO3_ALGEBRA_PAIRING_ALT_BN128_BASIC_POLICY_HPP
#define CRYPTO3_ALGEBRA_PAIRING_ALT_BN128_BASIC_POLICY_HPP

#include <nil/crypto3/algebra/curves/detail/alt_bn128/basic_policy.hpp>

namespace nil {
    namespace crypto3 {
        namespace algebra {
            namespace pairing {
                namespace detail {

                    template<std::size_t Version = 254>
                    struct alt_bn128_basic_policy;

                    template<>
                    struct alt_bn128_basic_policy<254> {
                        using policy_type = curves::detail::alt_bn128_basic_policy<254>;

                    public:
                        typedef typename policy_type::integral_type integral_type;

                        using fp_type = typename policy_type::scalar_field_type;
                        using fq_type = typename policy_type::g1_field_type;
                        using fqe_type = typename policy_type::g2_field_type;
                        using fqk_type = typename policy_type::gt_field_type;

                        using g1_type = policy_type::g1_field_type;
                        using g2_type = policy_type::g2_field_type;
                        using gt_type = typename policy_type::gt_field_type;

                        constexpr static const std::size_t base_field_bits = policy_type::base_field_type::modulus_bits;
                        constexpr static const integral_type base_field_modulus = policy_type::base_field_type::modulus;
                        constexpr static const std::size_t scalar_field_bits =
                            policy_type::scalar_field_type::modulus_bits;
                        constexpr static const integral_type scalar_field_modulus =
                            policy_type::scalar_field_type::modulus;

                        constexpr static const std::size_t integral_type_max_bits = base_field_bits;

                        constexpr static const integral_type ate_loop_count = 0x19D797039BE763BA8_cppui_modular254;
                        constexpr static const bool ate_is_loop_count_neg = false;

                        constexpr static const integral_type final_exponent_z = integral_type(0x44E992B44A6909F1);
                        constexpr static const integral_type final_exponent_is_z_neg = false;
                    };

                    constexpr typename alt_bn128_basic_policy<254>::integral_type const
                        alt_bn128_basic_policy<254>::ate_loop_count;
                }    // namespace detail
            }        // namespace pairing
        }            // namespace algebra
    }                // namespace crypto3
}    // namespace nil
#endif    // CRYPTO3_ALGEBRA_PAIRING_ALT_BN128_BASIC_POLICY_HPP
