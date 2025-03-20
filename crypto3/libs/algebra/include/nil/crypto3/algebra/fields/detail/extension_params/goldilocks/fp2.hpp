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

#ifndef CRYPTO3_ALGEBRA_FIELDS_GOLDILOCKS_FP2_EXTENSION_PARAMS_HPP
#define CRYPTO3_ALGEBRA_FIELDS_GOLDILOCKS_FP2_EXTENSION_PARAMS_HPP

#include <nil/crypto3/algebra/fields/goldilocks.hpp>
#include <nil/crypto3/algebra/fields/params.hpp>

namespace nil::crypto3::algebra::fields {

    template<typename BaseField>
    class fp2;

    namespace detail {

        template<typename BaseField>
        class fp2_extension_params;

        /************************* GOLDILOCKS ***********************************/

        template<>
        class fp2_extension_params<fields::goldilocks>
            : public params<fields::goldilocks> {
            typedef fields::goldilocks base_field_type;
            typedef params<base_field_type> policy_type;

          public:
            using field_type = fields::fp2<base_field_type>;

            typedef typename policy_type::integral_type integral_type;

            typedef nil::crypto3::multiprecision::big_uint<2 * policy_type::modulus_bits>
                extended_integral_type;

            constexpr static const integral_type modulus = policy_type::modulus;

            typedef base_field_type non_residue_field_type;
            typedef typename non_residue_field_type::value_type non_residue_type;
            typedef base_field_type underlying_field_type;
            typedef typename underlying_field_type::value_type underlying_type;

            constexpr static const std::size_t two_adicity = 33;
            // constexpr static const extended_integral_type t =
            //     0x1;
            // constexpr static const extended_integral_type t_minus_1_over_2 =
            //     0x0;
            // constexpr static const std::array<integral_type, 2> nqr = {0x08, 0x01};
            // constexpr static const std::array<integral_type, 2> nqr_to_t = {
            //     0x00,
            //     0x00};

            // constexpr static const extended_integral_type group_order_minus_one_half =
            //     0x00;

            /*constexpr static const std::array<non_residue_type, 2> Frobenius_coeffs_c1 =
               {non_residue_type(0x01),
                non_residue_type(0x3BCF7BCD473A266249DA7B0548ECAEEC9635D1330EA41A9E35E51200E12C90CD65A71660000_big_uint298)};*/

            // constexpr static const std::array<integral_type, 2> Frobenius_coeffs_c1 = {
            //     0x01,
            //     0x00};

            constexpr static const non_residue_type non_residue = non_residue_type(7u);
        };
    }
}

#endif  // CRYPTO3_ALGEBRA_FIELDS_GOLDILOCKS_FP2_EXTENSION_PARAMS_HPP
