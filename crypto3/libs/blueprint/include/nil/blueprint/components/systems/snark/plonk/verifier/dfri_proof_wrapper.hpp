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
                        template<typename ProofType>
                        dfri_proof_wrapper(
                            val                         transcript_initial_state,
                            const std::map<std::size_t, val> &_commitments,
                            const std::vector<val>      &evaluation_points,
                            const ProofType             &proof
                        ){
                            // initial transcript state
                            full_input.push_back(transcript_initial_state);

                            // commitments
                            for( const auto &[k,v]: _commitments ) full_input.push_back(v);

                            // evaluation points
                            for( std::size_t i = 0; i < evaluation_points.size(); i++ ) full_input.push_back(evaluation_points[i]);

                            // evaluations
                            auto batch_info = proof.z.get_batch_info();
                            for(const auto& [k, v]: batch_info){
                                for(std::size_t i = 0; i < v; i++){
                                    BOOST_ASSERT(proof.z.get_poly_points_number(k, i) != 0);
                                    for(std::size_t j = 0; j < proof.z.get_poly_points_number(k, i); j++){
                                        full_input.push_back(proof.z.get(k, i, j));
                                    }
                                }
                            }

                            // fri roots
                            for( std::size_t i = 0; i < proof.fri_proof.fri_roots.size(); i++){
                                full_input.push_back(proof.fri_proof.fri_roots[i]);
                            }
                            // final polynomials
                            for( std::size_t i = 0; i < proof.fri_proof.final_polynomial.size(); i++){
                                full_input.push_back(proof.fri_proof.final_polynomial[i]);
                            }
                            // query proofs
                            for( std::size_t q = 0; q < proof.fri_proof.query_proofs.size(); q++){
                                const auto &query_proof = proof.fri_proof.query_proofs[q];
                                // initial proof values
                                for( const auto &[j, initial_proof]: query_proof.initial_proof){
                                    for( std::size_t k = 0; k < initial_proof.values.size(); k++){
                                        full_input.push_back(initial_proof.values[k][0][0]);
                                        full_input.push_back(initial_proof.values[k][0][1]);
                                    }
                                }
                                // merkle tree positions is stored only for the first initial proof
                                for( const auto &[j, initial_proof]: query_proof.initial_proof){
                                    for( std::size_t k = 0; k < initial_proof.p.path().size(); k++){
                                        full_input.push_back(initial_proof.p.path()[k][0].position());
                                    }
                                    break;
                                }

                                // initial proof hashes are stored for all hashes.
                                for( const auto &[j, initial_proof]: query_proof.initial_proof){
                                    for( std::size_t k = 0; k < initial_proof.p.path().size(); k++){
                                        full_input.push_back(initial_proof.p.path()[k][0].hash());
                                    }
                                }

                                // round proof values
                                for( std::size_t j = 0; j < query_proof.round_proofs.size(); j++){
                                    const auto &round_proof = query_proof.round_proofs[j];
                                    full_input.push_back(round_proof.y[0][0]);
                                    full_input.push_back(round_proof.y[0][1]);
                                }

                                // round proof hashes
                                for( std::size_t j = 0; j < query_proof.round_proofs.size(); j++){
                                    const auto& p = query_proof.round_proofs[j].p;
                                    for( std::size_t k = 0; k < p.path().size(); k++){
                                        full_input.push_back(p.path()[k][0].hash());
                                    }
                                }
                            }
                        }
                        const std::vector<val> &vector() const{
                            return full_input;
                        }
                    private:
                        // Just for testing purposes. Remove later.
                        val                         initial_transcript_state;
                        std::map<std::size_t, val>  commitments;             // Just for placeholder compatibility
                        std::vector<val>            evaluation_points;

                        // Proof itself.
                        std::vector<val> evaluations;
                        std::vector<val> fri_roots;
                        std::vector<val> final_polynomial;
                        std::vector<std::vector<val>> merkle_tree_positions; // Lambda merkle positions
                        std::vector<std::vector<val>> initial_proof_values;  // 2 x Lambda x |bathes_sizes_sum| initial proof values
                        std::vector<std::vector<val>> initial_proof_hashes;  // 2 x Lambda x batches_num initial proof hashes
                        std::vector<std::vector<val>> round_proof_values;    // Keep all values for all rounds into single vector
                        std::vector<std::vector<val>> round_proof_hashes;    // Keep all hashes for all rounds into single vector
                        std::vector<val> full_input;
                };
            }
        }
    }
}

#endif
