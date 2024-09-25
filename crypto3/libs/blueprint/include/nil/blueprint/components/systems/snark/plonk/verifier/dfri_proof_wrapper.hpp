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
// @file Object, that helps to transform dfri proof to public input column for recursive circuit
//---------------------------------------------------------------------------//
#ifndef BLUEPRINT_COMPONENTS_FLEXIBLE_VERIFIER_DFRI_PROOF_WRAPPER_HPP
#define BLUEPRINT_COMPONENTS_FLEXIBLE_VERIFIER_DFRI_PROOF_WRAPPER_HPP

#include <map>

#include <nil/crypto3/math/polynomial/polynomial.hpp>
#include <nil/crypto3/math/algorithms/calculate_domain_set.hpp>

#include <nil/crypto3/zk/snark/arithmetization/plonk/constraint_system.hpp>
#include <nil/crypto3/zk/snark/systems/plonk/placeholder/preprocessor.hpp>
#include <nil/crypto3/zk/snark/systems/plonk/placeholder/proof.hpp>

namespace nil {
    namespace blueprint {
        namespace components {
            namespace detail{
                template <typename BlueprintFieldType>
                class dfri_proof_wrapper{
                    using val = typename BlueprintFieldType::value_type;
                    public:
                        dfri_proof_wrapper(){}
                        const std::vector<val> &vector() const{
                            return full_input;
                        }
                    private:
                        val              initial_transcript_state;
                        std::vector<val> commitments;
                        std::vector<val> evaluation_points;

                        // Proof itself.
                        std::vector<val> fri_roots;
                        std::vector<val> evaluations;
                        std::vector<std::vector<val>> merkle_tree_positions; // Lambda merkle positions
                        std::vector<std::vector<val>> initial_proof_values;  // 2 x Lambda x |bathes_sizes_sum| initial proof values
                        std::vector<std::vector<val>> initial_proof_hashes;  // 2 x Lambda x batches_num initial proof hashes
                        std::vector<val> round_proof_values;                 // Keep all values for all rounds into single array
                        std::vector<val> round_proof_hashes;                 // Keep all hashes for all rounds into single array
                        std::vector<val> full_input;
                };
            }
        }
    }
}

#endif
