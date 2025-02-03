//---------------------------------------------------------------------------//
// Copyright (c) 2025 Martun Karapetyan <martun@nil.foundation>
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

#ifndef CRYPTO3_ZK_PLONK_PLACEHOLDER_DFRI_VERIFIER_HPP
#define CRYPTO3_ZK_PLONK_PLACEHOLDER_DFRI_VERIFIER_HPP

#include <boost/log/trivial.hpp>

#include <nil/crypto3/math/polynomial/polynomial.hpp>

#include <nil/crypto3/zk/commitments/polynomial/lpc.hpp>
#include <nil/crypto3/zk/snark/arithmetization/plonk/constraint_system.hpp>
#include <nil/crypto3/zk/snark/systems/plonk/placeholder/detail/placeholder_policy.hpp>
#include <nil/crypto3/zk/snark/systems/plonk/placeholder/params.hpp>
#include <nil/crypto3/zk/snark/systems/plonk/placeholder/preprocessor.hpp>
#include <nil/crypto3/zk/snark/systems/plonk/placeholder/verifier.hpp>
#include <nil/crypto3/zk/snark/arithmetization/plonk/table_description.hpp>

#include <nil/crypto3/bench/scoped_profiler.hpp>

namespace nil {
    namespace crypto3 {
        namespace zk {
            namespace snark {
                // Verifier for Distributed FRI aggregated proofs. Will use normal verifier to check parts of proofs.
                template<typename FieldType, typename ParamsType>
                class placeholder_DFRI_verifier {
                    using value_type = typename FieldType::value_type;
                    using verifier_type = placeholder_verifier<FieldType, ParamsType>; 
                    using public_input_type = std::vector<std::vector<value_type>>;
                    using transcript_hash_type = typename ParamsType::transcript_hash_type;
                    using policy_type = detail::placeholder_policy<FieldType, ParamsType>;
                    using public_preprocessor_type = placeholder_public_preprocessor<FieldType, ParamsType>;
                    using common_data_type = typename public_preprocessor_type::preprocessed_data_type::common_data_type;
                    using commitment_scheme_type = typename ParamsType::commitment_scheme_type;
                    using commitment_type = typename commitment_scheme_type::commitment_type;
                    using transcript_type = typename commitment_scheme_type::transcript_type;
                    using fri_type = typename commitment_scheme_type::fri_type;

                public:

                    /** Checks the aggregated proof. We shall accept shared pointers here to help proof-producer with its resource providers. 
                     *
                     *  param[in] public_inputs - Can be empty, in which case they are not checked.
                     */
                    static inline bool process(
                             const std::vector<std::shared_ptr<common_data_type>> &common_datas,
                             const placeholder_aggregated_proof<FieldType, ParamsType> &agg_proof,
                             const std::vector<std::shared_ptr<plonk_table_description<FieldType>>> &table_descriptions,
                             const std::vector<std::shared_ptr<plonk_constraint_system<FieldType>>> &constraint_systems,
                             std::vector<std::shared_ptr<commitment_scheme_type>>& commitment_schemes,
                             const std::vector<std::shared_ptr<public_input_type>> &public_inputs
                    ) {
                        const size_t N = agg_proof.partial_proofs.size();
                        // Everything must have the same size N, the number of provers. Except public inputs, which can be empty, in which case we don't check them.
                        if (common_datas.size() != N || table_descriptions.size() != N || constraint_systems.size() != N || commitment_schemes.size() != N || 
                            (public_inputs.size() != N && public_inputs.size() != 0)) {
                            throw std::invalid_argument("Invalid size for verification input arguments.");
                        }
 
                        // fri params must be the same for all provers.
                        // TODO: add a check that they are the same!!
                        auto fri_params = commitment_schemes[0]->get_fri_params();
                        std::size_t domain_size = fri_params.D[0]->size();
                        std::size_t coset_size = 1 << fri_params.step_list[0];

                        std::vector<transcript::fiat_shamir_heuristic_sequential<transcript_hash_type>> transcripts(N, std::vector<std::uint8_t>({}));

                        std::vector<placeholder_proof<FieldType, ParamsType>> proofs;
                        std::vector<value_type> F_consolidated(N);
                        // Verify partial proofs.
                        for (size_t i = 0; i < N; i++) {
                            // Create a proof from aggregated_proof.
                            typename placeholder_proof<FieldType, ParamsType>::evaluation_proof eval_proof;
                            eval_proof.eval_proof.z = agg_proof.aggregated_proof.initial_proofs_per_prover[i].z;

                            const auto& initial_fri_proofs = agg_proof.aggregated_proof.initial_proofs_per_prover[i].initial_fri_proofs.initial_proofs;
                            eval_proof.eval_proof.fri_proof.query_proofs.resize(initial_fri_proofs.size()); 
                            for (size_t j = 0; j < initial_fri_proofs.size(); ++j) {
                                eval_proof.eval_proof.fri_proof.query_proofs[j].initial_proof = initial_fri_proofs[j];
                            }

                            proofs.push_back(placeholder_proof<FieldType, ParamsType>(agg_proof.partial_proofs[i], eval_proof));
                            
                            // We cannot re-use transcripts[i] here, since 'fill_challenge_queue' changes the transcript passed into it.
                            transcript::fiat_shamir_heuristic_sequential<transcript_hash_type> empty_transcript(std::vector<std::uint8_t>({}));

                            // Get the evaluation challenge. The queue is not used so far.
                            value_type evaluation_challenge;
                            [[maybe_unused]] std::queue<value_type> queue;
                            verifier_type::fill_challenge_queue(
                                *common_datas[i], proofs[i], *constraint_systems[i], *commitment_schemes[i], empty_transcript, queue, evaluation_challenge);

                            // F_consolidated[i] is an out parameter here. If public inputs were passed, we shall check them, if not, we will not.
                            if (public_inputs.size() != 0) {
                                if (!verifier_type::verify_partial_proof(
                                        *common_datas[i], proofs[i], *table_descriptions[i], *constraint_systems[i], *commitment_schemes[i],
                                        *public_inputs[i], transcripts[i], F_consolidated[i], evaluation_challenge)) 
                                {
                                    BOOST_LOG_TRIVIAL(info) << "dFRI Verification failed: partial proof #" << i << " failed.";
                                    return false;
                                }
                            } else {
                                if (!verifier_type::verify_partial_proof(
                                        *common_datas[i], proofs[i], *table_descriptions[i], *constraint_systems[i], *commitment_schemes[i],
                                        transcripts[i], F_consolidated[i], evaluation_challenge)) 
                                {
                                    BOOST_LOG_TRIVIAL(info) << "dFRI Verification failed: partial proof #" << i << " failed.";
                                    return false;
                                }
                            }
                        }


                        // Create the commitments for each prover.
                        std::vector<std::map<std::size_t, typename commitment_scheme_type::commitment_type>> commitments(N);
                        for (size_t i = 0; i < N; i++) {
                            commitments[i] = agg_proof.partial_proofs[i].commitments;
                            commitments[i][FIXED_VALUES_BATCH] = common_datas[i]->commitments.fixed_values;
                        }

                        for (size_t i = 0; i < N; i++) {
                            commitment_schemes[i]->_z = proofs[i].eval_proof.eval_proof.z;
                            // This is similar to 'eval_polys_and_add_roots_to_transcipt' call in partial proof from prover.
                            for (auto const &it: commitments[i]) {
                                transcripts[i](commitments[i].at(it.first));
                            }
                        }

                        std::vector<std::size_t> starting_indexes(N);
                        for (size_t i = 1; i < N; i++) {
                            starting_indexes[i] = starting_indexes[i-1] + commitment_schemes[i-1]->compute_theta_power_for_combined_Q();
                        }

                        // Create the aggregated challenge point.
                        transcript_type transcript_for_aggregation;
                
                        for (size_t i = 0; i < N; i++) {
                            transcript_for_aggregation(transcripts[i].template challenge<FieldType>());
                        }

                        // produce the aggregated challenge
                        auto aggregated_challenge = transcript_for_aggregation.template challenge<FieldType>();

                        // This the transcript that our provers will use, it's not the same as 'transcript_for_aggregation', it's the transcript that
                        // you get after injesting the aggregated challenge.
                        transcript_type aggregated_transcript;
                        aggregated_transcript(aggregated_challenge);

                        value_type theta = aggregated_transcript.template challenge<FieldType>();

                        const auto& fri_roots = agg_proof.aggregated_proof.fri_proof.fri_commitments_proof_part.fri_roots;
                        std::vector<value_type> alphas = nil::crypto3::zk::algorithms::generate_alphas<fri_type>(
                            fri_roots, fri_params, aggregated_transcript);

                        if (fri_params.use_grinding && fri_type::grinding_type::verify(
                                aggregated_transcript, agg_proof.aggregated_proof.proof_of_work, fri_params.grinding_parameter)) {
                            BOOST_LOG_TRIVIAL(info) << "dFRI Verification failed: wrong grinding.";
                            return false;
                        }

                        std::vector<std::vector<value_type>> Us(N);
                        // V is product of (x - eval_point) polynomial for each eval_point
                        std::vector<std::vector<math::polynomial<value_type>>> Vs(N);

                        // List of involved polynomials for each eval point [batch_id, poly_id, point_id]
                        std::vector<std::vector<std::vector<std::tuple<std::size_t, std::size_t>>>> poly_maps(N);

                        for (size_t i = 0; i < N; i++) {
                            size_t total_points = commitment_schemes[i]->get_total_points();
                            Us[i].resize(total_points);
                            Vs[i].resize(total_points);
                            poly_maps[i].resize(total_points);

                            value_type theta_acc = theta.pow(starting_indexes[i]);
                            commitment_schemes[i]->generate_U_V_polymap(
                                Us[i], Vs[i], poly_maps[i], proofs[i].eval_proof.eval_proof.z, theta, theta_acc, total_points);
                        }

                        // Make a separate copy of the aggregated transcript for each prover.
                        std::vector<transcript_type> aggregated_transcripts(N, aggregated_transcript);

                        std::vector<value_type> xs;
                        std::vector<std::uint64_t> x_indexs;
                        // Combined Q values
                        std::vector<typename fri_type::polynomial_values_type> ys;

                        // Verify initial proofs for each prover. This checks the consistency.
                        // This checks the proofs generated by 'proof_eval_lpc_proof' in prover.
                        for (size_t i = 0; i < N; i++) {
                            for (size_t query_id = 0; query_id < fri_params.lambda; query_id++) {
                                value_type x;
                                std::uint64_t x_index;
                                // Combined Q values
                                typename fri_type::polynomial_values_type y;

                                if (!nil::crypto3::zk::algorithms::verify_initial_proof_and_return_combined_Q_values<fri_type>(
                                        agg_proof.aggregated_proof.initial_proofs_per_prover[i].initial_fri_proofs.initial_proofs[query_id], Us[i], poly_maps[i], Vs[i], 
                                        fri_params, commitments[i], theta, coset_size, domain_size, starting_indexes[i], aggregated_transcripts[i], y, x, x_index 
                                        )) {
                                    BOOST_LOG_TRIVIAL(info) << "dFRI Verification failed: initial FRI proof/consistency check verification failed for prover #" << i << ".";
                                    return false;
                                }

                                // Here I assumed that the values of X must match.
                                // For all the provers the values of x and x_index must match, since we're using the same transcript for each prover.
                                // That also means that evaluation points must match for all the circuits.
                                // For example if some circuit has a lookup argument, and another one has not, we can't work with that circuits.
                                if (i == 0) {
                                    xs.push_back(x);
                                    x_indexs.push_back(x_index);
                                    ys.push_back(y);
                                } else {
                                    if (x != xs[query_id]) {
                                        BOOST_LOG_TRIVIAL(info) << "dFRI Verification failed: initial FRI proof/consistency check verification failed for prover #" << i 
                                            << " with challenge x mismatch.";
                                        return false;
                                    }
                                    if (x_index != x_indexs[query_id]) {
                                        BOOST_LOG_TRIVIAL(info) << "dFRI Verification failed: initial FRI proof/consistency check verification failed for prover #" << i 
                                            << " with challenge x_index mismatch.";
                                        return false;
                                    }
                                    if (y.size() != ys[query_id].size()) {
                                        BOOST_LOG_TRIVIAL(info) << "dFRI Verification failed: initial FRI proof/consistency check verification failed for prover #" << i 
                                            << " with mismatch in size of Y.";
                                        return false;
                                    }
                                    // for y we need to sum up, since FRI was ran on the sum of polynomials combined Q.
                                    for (size_t j = 0; j < y.size(); ++j) {
                                        for (size_t k = 0; k < y[j].size(); ++k)
                                            ys[query_id][j][k] += y[j][k];
                                    }
                                }
                            }
                        }

                        // Now run the round proofs once for the summed polynomial combined_Q.
                        for (size_t query_id = 0; query_id < fri_params.lambda; query_id++) {
                            size_t t = 0;
                            // Domain size changes during checks of 'verify_round_proof'.
                            size_t domain_size_for_rounds = domain_size;
                            for (size_t i = 0; i < fri_params.step_list.size(); i++) {
                                if (!nil::crypto3::zk::algorithms::verify_round_proof<fri_type>(
                                        agg_proof.aggregated_proof.fri_proof.fri_round_proof.round_proofs[query_id][i], ys[query_id], fri_params,
                                        alphas, fri_roots[i], i, x_indexs[query_id], domain_size_for_rounds, t)) {
                                    BOOST_LOG_TRIVIAL(info) << "dFRI Verification failed: final FRI proof round proof failed for query "
                                        << query_id << " and step " << i << ".";
                                    return false;
                                }
                            }

                            if (!nil::crypto3::zk::algorithms::check_final_polynomial<fri_type>(
                                    agg_proof.aggregated_proof.fri_proof.fri_commitments_proof_part.final_polynomial, ys[query_id], fri_params,
                                    x_indexs[query_id], t)) {
                                BOOST_LOG_TRIVIAL(info) << "dFRI Verification failed: final polynomial check failed.";
                                return false;
                            }
                        }

                        return true;
                    }
                };
            }    // namespace snark
        }        // namespace zk
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_ZK_PLONK_PLACEHOLDER_DFRI_VERIFIER_HPP
