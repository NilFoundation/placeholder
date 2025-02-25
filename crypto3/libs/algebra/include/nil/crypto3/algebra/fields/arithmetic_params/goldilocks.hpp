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

#ifndef CRYPTO3_ALGEBRA_FIELDS_GOLDILOCKS_ARITHMETIC_PARAMS_HPP
#define CRYPTO3_ALGEBRA_FIELDS_GOLDILOCKS_ARITHMETIC_PARAMS_HPP

#include <nil/crypto3/algebra/fields/params.hpp>

#include <nil/crypto3/algebra/fields/goldilocks/base_field.hpp>

namespace nil {
    namespace crypto3 {
        namespace algebra {
            namespace fields {

                template<>
                struct arithmetic_params<goldilocks> : public params<goldilocks> {
                  private:
                    typedef params<goldilocks> policy_type;

                  public:
                    typedef typename policy_type::modular_type modular_type;
                    typedef typename policy_type::integral_type integral_type;

                    constexpr static const std::size_t two_adicity = 0x20;
                    constexpr static const integral_type arithmetic_generator = 0x01;
                    constexpr static const integral_type geometric_generator = 0x02;
                    constexpr static const integral_type multiplicative_generator = 0x07;
                    constexpr static const integral_type root_of_unity =
                        0x185629DCDA58878C_big_uint64;
                };

                constexpr std::size_t const arithmetic_params<goldilocks>::two_adicity;

                constexpr typename arithmetic_params<goldilocks>::integral_type const
                    arithmetic_params<goldilocks>::root_of_unity;

                constexpr typename arithmetic_params<goldilocks>::integral_type const
                    arithmetic_params<goldilocks>::arithmetic_generator;

                constexpr typename arithmetic_params<goldilocks>::integral_type const
                    arithmetic_params<goldilocks>::geometric_generator;

                constexpr typename arithmetic_params<goldilocks>::integral_type const
                    arithmetic_params<goldilocks>::multiplicative_generator;
            }    // namespace fields
        }        // namespace algebra
    }            // namespace crypto3
}    // namespace nil

#endif  // CRYPTO3_ALGEBRA_FIELDS_GOLDILOCKS_ARITHMETIC_PARAMS_HPP
