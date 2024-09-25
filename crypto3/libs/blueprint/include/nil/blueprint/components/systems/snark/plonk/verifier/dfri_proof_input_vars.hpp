//---------------------------------------------------------------------------//
// Copyright (c) 2024 Valeh Farzaliyev <estoniaa@nil.foundation>
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
// @file Object, that helps to transform dfri proof to public input column for dfri recursive circuit
//---------------------------------------------------------------------------//
#ifndef BLUEPRINT_COMPONENTS_FLEXIBLE_VERIFIER_DFRI_PROOF_INPUT_TYPE_HPP
#define BLUEPRINT_COMPONENTS_FLEXIBLE_VERIFIER_DFRI_PROOF_INPUT_TYPE_HPP

#include <map>

#include <nil/crypto3/math/polynomial/polynomial.hpp>
#include <nil/crypto3/math/algorithms/calculate_domain_set.hpp>

#include <nil/crypto3/zk/snark/arithmetization/plonk/constraint_system.hpp>
#include <nil/crypto3/zk/snark/systems/plonk/placeholder/preprocessor.hpp>
#include <nil/crypto3/zk/snark/systems/plonk/placeholder/proof.hpp>

namespace nil {
    namespace blueprint {
        namespace components {
            namespace detail {
                template <typename BlueprintFieldType>
                class dfri_proof_input_vars{
                public:
                    using var = nil::crypto3::zk::snark::plonk_variable<typename BlueprintFieldType::value_type>;

                    dfri_proof_input_vars() : _all_vars({}) {}

                    // Information of dFRI test setup or result of earlier placeholder work.
                    var              initial_transcript_state;
                    std::vector<var> commitments;
                    std::vector<var> evaluation_points;

                    // Proof itself.
                    std::vector<var> fri_roots;
                    std::vector<var> evaluations;
                    std::vector<std::vector<var>> merkle_tree_positions; // Lambda merkle positions
                    std::vector<std::vector<var>> initial_proof_values;  // 2 x Lambda x |bathes_sizes_sum| initial proof values
                    std::vector<std::vector<var>> initial_proof_hashes;  // 2 x Lambda x batches_num initial proof hashes
                    std::vector<var> round_proof_values;                 // Keep all values for all rounds into single array
                    std::vector<var> round_proof_hashes;                 // Keep all hashes for all rounds into single array,=

                    std::vector<std::reference_wrapper<var>> all_vars(){
                        return _all_vars;
                    }
                private:
                    std::vector<std::reference_wrapper<var>> _all_vars;   // Just all variables
                    std::size_t length;
                };
            }    // namespace detail
        }    // namespace components
    }    // namespace blueprint
}    // namespace nil

#endif
