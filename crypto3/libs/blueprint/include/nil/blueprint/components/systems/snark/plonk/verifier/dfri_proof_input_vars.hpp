//---------------------------------------------------------------------------//
// Copyright (c) 2024 Valeh Farzaliyev <estoniaa@nil.foundation>
// Copyright (c) 2024 Elena Tatuzova <e.tatuzova@nil.foundation>
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
                // Internal structure that doesn't depend on commitment scheme types
                // Parts from fri_params that are useful for this component
                template <typename BlueprintFieldType>
                struct dfri_component_params{
                    using val = typename BlueprintFieldType::value_type;

                    template<typename FRIParamsType>
                    dfri_component_params(const FRIParamsType &other):
                        r(other.r), lambda(other.lambda), omega(other.D[0]->get_domain_element(1)),
                        domain_size(other.D[0]->size()), max_degree(other.max_degree)
                    {}

                    dfri_component_params(){}
                    std::size_t r;
                    std::size_t lambda;
                    val         omega;
                    std::size_t domain_size;
                    std::size_t initial_merkle_proof_size;
                    std::size_t max_degree;
                };

                template <typename BlueprintFieldType>
                class dfri_proof_input_vars{
                public:
                    using val = typename BlueprintFieldType::value_type;
                    using var = nil::crypto3::zk::snark::plonk_variable<val>;

                    template <typename FRIParamsType>
                    dfri_proof_input_vars(
                        const FRIParamsType                      &fri_params,
                        const std::map<std::size_t, std::size_t> &batches_sizes,
                        std::size_t evaluation_points_amount,
                        const std::map<std::pair<std::size_t, std::size_t>, std::vector<std::size_t>> &eval_map
                    ) : var_vector({}) {
                        std::size_t cur = 0;

                        // transcript initial state
                        initial_transcript_state = var(0, cur++, false, var::column_type::public_input);
                        var_vector.push_back(initial_transcript_state);

                        // commitments
                        for( const auto& [k,v]:batches_sizes){
                            commitments[k] = var(0, cur++, false, var::column_type::public_input);
                            commitments_vector.push_back(commitments[k]);
                            var_vector.push_back(commitments[k]);
                        }
                        // evaluation points
                        for( std::size_t i = 0; i < evaluation_points_amount; i++){
                            evaluation_points.push_back(var(0, cur++, false, var::column_type::public_input));
                            var_vector.push_back(evaluation_points[i]);
                        }

                        // evaluations
                        for( const auto&[k,v]: batches_sizes){
                            for( std::size_t i = 0; i < v; i++ ){
                                for( std::size_t j = 0; j < eval_map.at({k,i}).size(); j++ ){
                                    evaluations.push_back(var(0, cur++, false, var::column_type::public_input));
                                    var_vector.push_back(evaluations[evaluations.size()-1]);
                                }
                            }
                        }
                        // FRI roots
                        for(std::size_t i = 0; i < fri_params.r; i++){
                            fri_roots.push_back(var(0, cur++, false, var::column_type::public_input));
                            var_vector.push_back(fri_roots[i]);
                        }
                        // Final polynomial
                        std::size_t final_polynomial_size = std::pow(2, std::log2(fri_params.max_degree + 1) - fri_params.r + 1) - 2;
                        for( std::size_t i = 0; i < final_polynomial_size; i++){
                            final_polynomial.push_back(var(0, cur++, false, var::column_type::public_input));
                            var_vector.push_back(final_polynomial[i]);
                        }

                        // Query proofs
                        merkle_tree_positions.resize(fri_params.lambda);
                        initial_proof_values.resize(fri_params.lambda);
                        initial_proof_hashes.resize(fri_params.lambda);
                        round_proof_values.resize(fri_params.lambda);
                        round_proof_hashes.resize(fri_params.lambda);
                        for( std::size_t q = 0; q < fri_params.lambda; q++){
                            // Initial proof values
                            initial_proof_values[q] = {};
                            for( const auto &[k,v]: batches_sizes ){
                                for( std::size_t i = 0; i < v; i++ ){
                                    auto val0 = var(0, cur++, false, var::column_type::public_input);
                                    auto val1 = var(0, cur++, false, var::column_type::public_input);
                                    initial_proof_values[q].push_back(val0);
                                    initial_proof_values[q].push_back(val1);
                                    var_vector.push_back(val0);
                                    var_vector.push_back(val1);
                                }
                            }
                            // Initial proof positions
                            merkle_tree_positions[q].resize(log2(fri_params.domain_size) - 1);
                            for( std::size_t j = 0; j < log2(fri_params.domain_size) - 1; j++ ){
                                var pos_var = var(0, cur++, false, var::column_type::public_input);
                                merkle_tree_positions[q][j] = pos_var;
                                var_vector.push_back(pos_var);
                            }
                            // Initial proof hashes
                            for( std::size_t j = 0; j < batches_sizes.size() * (log2(fri_params.domain_size) - 1); j++ ){
                                var hash_var = var(0, cur++, false, var::column_type::public_input);
                                var_vector.push_back(hash_var);
                                initial_proof_hashes[q].push_back(hash_var);
                            }
                            // Round proof values
                            for( std::size_t j = 0; j < fri_params.r; j++){
                                var y0_var = var(0, cur++, false, var::column_type::public_input);
                                var y1_var = var(0, cur++, false, var::column_type::public_input);
                                var_vector.push_back(y0_var);
                                var_vector.push_back(y1_var);
                                round_proof_values[q].push_back(y0_var);
                                round_proof_values[q].push_back(y1_var);
                            }
                            // Round proof hashes
                            for( std::size_t i = 0; i < fri_params.r; i++){
                                for( std::size_t j = 0; j < log2(fri_params.domain_size) - 1 - i; j++){
                                    var hash_var = var(0, cur++, false, var::column_type::public_input);
                                    var_vector.push_back(hash_var);
                                    round_proof_hashes[q].push_back(hash_var);
                                }
                            }
                        }
                    }

                    dfri_proof_input_vars() : var_vector({}) {}

                    // Information of dFRI test setup or result of earlier placeholder work.
                    var              initial_transcript_state;
                    std::map<std::size_t, var> commitments; // Reserved for placeholder compatibility.
                    std::vector<var> commitments_vector;    // It's more convenient for hash computation
                    std::vector<var> evaluation_points;

                    // Proof itself.
                    std::vector<var> fri_roots;
                    std::vector<var> evaluations;
                    std::vector<std::vector<var>> merkle_tree_positions; // Lambda merkle positions
                    std::vector<std::vector<var>> initial_proof_values;  // 2 x Lambda x |bathes_sizes_sum| initial proof values
                    std::vector<std::vector<var>> initial_proof_hashes;  // 2 x Lambda x (exteneded_domain size log - 1) initial proof hashes
                    std::vector<std::vector<var>> round_proof_values;    // Keep all values for all rounds into single array
                    std::vector<std::vector<var>> round_proof_hashes;    // Keep all hashes for all rounds into single array,=
                    std::vector<var> final_polynomial;                   // Keep all hashes for all rounds into single array,=

                    std::vector<std::reference_wrapper<var>> all_vars(){
                        return var_vector;
                    }
                private:
                    std::vector<std::reference_wrapper<var>> var_vector;   // Just all variables
                    std::size_t length;
                };
            }    // namespace detail
        }    // namespace components
    }    // namespace blueprint
}    // namespace nil

#endif
