//---------------------------------------------------------------------------//
<<<<<<<< HEAD:crypto3/libs/blueprint/include/nil/blueprint/components/systems/snark/plonk/kimchi/types/alpha_argument_type.hpp
// Copyright (c) 2022 Ilia Shirobokov <i.shirobokov@nil.foundation>
========
// Copyright (c) 2020-2021 Mikhail Komarov <nemo@nil.foundation>
>>>>>>>> parallel-crypto3/migration:parallel-crypto3/libs/parallel-math/include/nil/crypto3/math/coset.hpp
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

<<<<<<<< HEAD:crypto3/libs/blueprint/include/nil/blueprint/components/systems/snark/plonk/kimchi/types/alpha_argument_type.hpp
#ifndef CRYPTO3_BLUEPRINT_COMPONENTS_PLONK_KIMCHI_TYPES_ALPHA_ARGUMENT_TYPE_HPP
#define CRYPTO3_BLUEPRINT_COMPONENTS_PLONK_KIMCHI_TYPES_ALPHA_ARGUMENT_TYPE_HPP

#include <nil/blueprint/blueprint/plonk/circuit.hpp>
#include <nil/blueprint/component.hpp>

namespace nil {
    namespace crypto3 {
        namespace blueprint {
            namespace components {
                enum argument_type {
                    Permutation,
                    Generic,
                    Zero,
                    Lookup,
                };
            }    // namespace components
        }        // namespace blueprint
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_BLUEPRINT_COMPONENTS_PLONK_KIMCHI_TYPES_ALPHA_ARGUMENT_TYPE_HPP
========
#ifndef CRYPTO3_MATH_COSET_HPP
#define CRYPTO3_MATH_COSET_HPP

#include <vector>

namespace nil {
    namespace crypto3 {
        namespace math {
            /**
             * Translate the vector a to a coset defined by g.
             */
            template<typename Range, typename FieldValueType>
            void multiply_by_coset(Range &a, const FieldValueType &g) {
                FieldValueType u = g;
                for (std::size_t i = 1; i < a.size(); ++i) {
                    a[i] *= u;
                    u *= g;
                }
            }
        }    // namespace fft
    }        // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_COSET_HPP
>>>>>>>> parallel-crypto3/migration:parallel-crypto3/libs/parallel-math/include/nil/crypto3/math/coset.hpp
