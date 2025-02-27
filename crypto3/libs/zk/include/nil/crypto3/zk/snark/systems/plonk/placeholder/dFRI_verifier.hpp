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
                    using verifier_type = placeholder_verifier<FieldType, ParamsType>; 
                    using public_input_type = std::vector<std::vector<typename FieldType::value_type>>;
                    using transcript_hash_type = typename ParamsType::transcript_hash_type;
                    using policy_type = detail::placeholder_policy<FieldType, ParamsType>;
                    using public_preprocessor_type = placeholder_public_preprocessor<FieldType, ParamsType>;

                    using commitment_scheme_type = typename ParamsType::commitment_scheme_type;
                    using commitment_type = typename commitment_scheme_type::commitment_type;
                    using transcript_type = typename commitment_scheme_type::transcript_type;

                public:

                   static inline bool process(
                            const std::vector<typename public_preprocessor_type::preprocessed_data_type::common_data_type> &common_datas,
                            const placeholder_aggregated_proof<FieldType, ParamsType> &agg_proof,
                            const std::vector<plonk_table_description<FieldType>> &table_descriptions,
                            const std::vector<plonk_constraint_system<FieldType>> &constraint_systems,
                            std::vector<commitment_scheme_type>& commitment_schemes,
                            std::vector<public_input_type> &public_inputs
                   ) {
                        const size_t N = agg_proof.partial_proofs.size();
                        std::vector<transcript::fiat_shamir_heuristic_sequential<transcript_hash_type>> transcripts(N, std::vector<std::uint8_t>({}));

                        std::vector<placeholder_proof<FieldType, ParamsType>> proofs;
                        std::vector<typename FieldType::value_type> F_consolidated;
                        // Verify partial proofs.
                        for (size_t i = 0; i < N; i++) {
                            // Create a proof from aggregated_proof.
                            typename placeholder_proof<FieldType, ParamsType>::evaluation_proof eval_proof;
                            eval_proof.eval_proof = agg_proof.aggregated_proof.initial_proofs_per_prover[i];
                            proofs.push_back(placeholder_proof<FieldType, ParamsType>(agg_proof.partial_proofs[i], eval_proof));
                            
                            if (!verifier_type::verify_partial_proof(
                                    common_datas[i], proofs[i], table_descriptions[i], constraint_systems[i], commitment_schemes[i],
                                    public_inputs[i], transcripts[i], F_consolidated[i])) 
                            {
                                BOOST_LOG_TRIVIAL(info) << "dFRI Verification failed: partial proof #" << i << " failed.";
                                return false;
                            }
                        }

                        // Create the aggregated challenge point.
                        transcript_type transcript_for_aggregation;
                
                        for (size_t i = 0; i < N; i++) {
                            transcript_for_aggregation(transcripts[i].challenge());
                        }

                        // produce the aggregated challenge
                        auto aggregated_challenge = transcript_for_aggregation.template challenge<FieldType>();

                        // This the transcript that our provers will use, it's not the same as 'transcript_for_aggregation', it's the transcript that
                        // you get after injesting the aggregated challenge.
                        transcript_type aggregated_transcript;
                        aggregated_transcript(aggregated_challenge);

                        std::vector<std::size_t> starting_indexes(N);

                        for (size_t i = 0; i < N; i++) {
                            // We need a fresh copy of this transcript for each prover.
                            transcript_type aggregated_transcript_copy = aggregated_transcript;
                            if (!verifier_type::verify_consolidated_polynomial(common_datas[i], proofs[i], F_consolidated, aggregated_transcript_copy))
                                return false;

                            verifier_type::prepare_polynomials(
                                proofs[i].eval_proof,
                                common_datas[i],
                                constraint_systems[i],
                                commitment_schemes[i]);

                            starting_indexes[i] = i == 0 ? 0 : starting_indexes[i-1];
                            starting_indexes[i] += commitment_schemes[i].compute_theta_power_for_combined_Q();
                        }

                        typename std::vector<typename FieldType::value_type> U_combined;
                        // V is product of (x - eval_point) polynomial for each eval_point
                        typename std::vector<math::polynomial<typename FieldType::value_type>> V_expected;

                        // List of involved polynomials for each eval point [batch_id, poly_id, point_id]
                        typename std::vector<std::vector<std::tuple<std::size_t, std::size_t>>> poly_map_expected;

                        typename FieldType::value_type theta = aggregated_transcript.template challenge<FieldType>();
                        for (size_t i = 0; i < N; i++) {
                            size_t total_points = commitment_schemes[i].get_total_points();
                            typename std::vector<typename FieldType::value_type> U(total_points);

                            // V is product of (x - eval_point) polynomial for each eval_point
                            typename std::vector<math::polynomial<typename FieldType::value_type>> V(total_points);

                            // List of involved polynomials for each eval point [batch_id, poly_id, point_id]
                            typename std::vector<std::vector<std::tuple<std::size_t, std::size_t>>> poly_map(total_points);

                            typename FieldType::value_type theta_acc = theta.pow(starting_indexes[i]);
                            commitment_schemes[i].generate_U_V_polymap(U, V, poly_map, proofs[i].eval_proof.z, theta, theta_acc, starting_indexes[i]);

                            // We shall sum up the values in U, and the values in V and poly_map must be the same for each prover.
                            if (i == 0) {
                                U_combined = U;
                                V_expected = V;
                                poly_map_expected = poly_map;
                            } else {
                                if (V != V_expected) {
                                    BOOST_LOG_TRIVIAL(info) << "dFRI Verification failed: Polynomial V does not match for different provers.";
                                    return false;
                                }
                                if (poly_map != poly_map_expected) {
                                    BOOST_LOG_TRIVIAL(info) << "dFRI Verification failed: Poly map does not match for different provers.";
                                    return false;
                                }
                                if (U_combined.size() != U.size()) {
                                    BOOST_LOG_TRIVIAL(info) << "dFRI Verification failed: Size of polynomial U does not match.";
                                    return false;
                                }
                                for (size_t i = 0; i < U.size(); ++i) {
                                    U_combined[i] += U[i];
                                }
                            }
                        }

                        // TODO: finalize the last FRI part.
                        //if (!nil::crypto3::zk::algorithms::verify_eval<fri_type>(
                        //        proof.aggregated_proof.fri_proof,
                        //        commitment_schemes[i].get_commitment_params(),
                        //        fri_proof.commitments, // TODO or fri_proof.fri_roots instead? which one's which?
                        //        theta,
                        //        poly_map_expected,
                        //        U_combined,
                        //        V_expected,
                        //        aggregated_challenge_transcript)) {
                        //    BOOST_LOG_TRIVIAL(info) << "dFRI Verification failed: final FRI proof failed.";
                        //    return false;
                        //}
                        return true;
                    }
                };
            }    // namespace snark
        }        // namespace zk
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_ZK_PLONK_PLACEHOLDER_DFRI_VERIFIER_HPP
