//---------------------------------------------------------------------------//
// Copyright (c) 2021 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2021 Nikita Kaskov <nbering@nil.foundation>
// Copyright (c) 2022 Ilia Shirobokov <i.shirobokov@nil.foundation>
// Copyright (c) 2022 Alisa Cherniaeva <a.cherniaeva@nil.foundation>
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

#ifndef CRYPTO3_ZK_PLONK_PLACEHOLDER_VERIFIER_HPP
#define CRYPTO3_ZK_PLONK_PLACEHOLDER_VERIFIER_HPP

#include <boost/log/trivial.hpp>
#include <queue>

#include <nil/crypto3/math/polynomial/polynomial.hpp>

#include <nil/crypto3/zk/commitments/polynomial/lpc.hpp>
#include <nil/crypto3/zk/snark/arithmetization/plonk/constraint_system.hpp>
#include <nil/crypto3/zk/snark/systems/plonk/placeholder/detail/placeholder_policy.hpp>
#include <nil/crypto3/zk/snark/systems/plonk/placeholder/permutation_argument.hpp>
#include <nil/crypto3/zk/snark/systems/plonk/placeholder/lookup_argument.hpp>
#include <nil/crypto3/zk/snark/systems/plonk/placeholder/gates_argument.hpp>
#include <nil/crypto3/zk/snark/systems/plonk/placeholder/params.hpp>
#include <nil/crypto3/zk/snark/systems/plonk/placeholder/preprocessor.hpp>
#include <nil/crypto3/zk/snark/arithmetization/plonk/table_description.hpp>

#include <nil/crypto3/bench/scoped_profiler.hpp>

namespace nil {
    namespace crypto3 {
        namespace zk {
            namespace snark {
                template<typename FieldType, typename ParamsType>
                class placeholder_verifier {
                    using SmallFieldType = typename FieldType::small_subfield;
                    using transcript_hash_type =
                        typename ParamsType::transcript_hash_type;
                    using policy_type = detail::placeholder_policy<FieldType, ParamsType>;
                    using public_preprocessor_type =
                        placeholder_public_preprocessor<SmallFieldType, ParamsType>;

                    using proof_type = placeholder_proof<FieldType, ParamsType>;
                    using commitment_scheme_type =
                        typename ParamsType::commitment_scheme_type;
                    using commitment_type =
                        typename commitment_scheme_type::commitment_type;
                    using eval_storage_type = commitments::eval_storage<FieldType>;
                    using transcript_type =
                        typename commitment_scheme_type::transcript_type;

                    constexpr static const std::size_t gate_parts = 1;
                    constexpr static const std::size_t permutation_parts = 3;
                    constexpr static const std::size_t lookup_parts = 4;
                    constexpr static const std::size_t f_parts = 8;

                  public:
                    // TODO(martun): this function is pretty similar to the one in prover,
                    // we should de-duplicate it.
                    static void generate_evaluation_points(
                        commitment_scheme_type &_commitment_scheme,
                        const typename public_preprocessor_type::preprocessed_data_type::common_data_type &common_data,
                        const plonk_constraint_system<SmallFieldType> &constraint_system,
                        const plonk_table_description<SmallFieldType> &table_description,
                        const typename FieldType::value_type& challenge,
                        bool _is_lookup_enabled
                    ) {
                        const std::size_t witness_columns = table_description.witness_columns;
                        const std::size_t public_input_columns = table_description.public_input_columns;
                        const std::size_t constant_columns = table_description.constant_columns;
                        const std::size_t selector_columns = table_description.selector_columns;

                        auto _omega = common_data.basic_domain->get_domain_element(1);

                        // variable_values' rotations
                        for (std::size_t variable_values_index = 0;
                             variable_values_index < witness_columns + public_input_columns;
                             variable_values_index++
                        ) {
                            const std::set<int>& variable_values_rotation =
                                common_data.columns_rotations[variable_values_index];

                            for (int rotation: variable_values_rotation) {
                                _commitment_scheme.append_eval_point(
                                    VARIABLE_VALUES_BATCH,
                                    variable_values_index,
                                    challenge * _omega.pow(rotation)
                                );
                            }
                        }

                        if (_is_lookup_enabled || constraint_system.copy_constraints().size() > 0)
                            _commitment_scheme.append_eval_point(PERMUTATION_BATCH, challenge);

                        if (constraint_system.copy_constraints().size() > 0)
                            _commitment_scheme.append_eval_point(PERMUTATION_BATCH, 0 , challenge * _omega);

                        if (_is_lookup_enabled) {
                            // For polynomail U, we need the shifted value as well.
                            _commitment_scheme.append_eval_point(PERMUTATION_BATCH, common_data.permutation_parts , challenge * _omega);
                            _commitment_scheme.append_eval_point(LOOKUP_BATCH, challenge);
                        }

                        _commitment_scheme.append_eval_point(QUOTIENT_BATCH, challenge);


                        // fixed values' rotations (table columns)
                        std::size_t i = 0;
                        std::size_t start_index = common_data.permuted_columns.size() * 2 + 2;

                        for (i = 0; i < start_index; i++) {
                            _commitment_scheme.append_eval_point(FIXED_VALUES_BATCH, i, challenge);
                        }

                        // for special selectors
                        _commitment_scheme.append_eval_point(FIXED_VALUES_BATCH, start_index - 2, challenge * _omega);
                        _commitment_scheme.append_eval_point(FIXED_VALUES_BATCH, start_index - 1, challenge * _omega);

                        for (std::size_t ind = 0;
                            ind < constant_columns + selector_columns;
                            ind++, i++
                        ) {
                            const std::set<int>& fixed_values_rotation =
                                common_data.columns_rotations[witness_columns + public_input_columns + ind];

                            for (int rotation: fixed_values_rotation) {
                                _commitment_scheme.append_eval_point(
                                    FIXED_VALUES_BATCH,
                                    start_index + ind,
                                    challenge * _omega.pow(rotation)
                                );
                            }
                        }
                    }

                    static inline bool process(
                        const typename public_preprocessor_type::preprocessed_data_type::common_data_type &common_data,
                        const proof_type &proof,
                        const plonk_table_description<FieldType> &table_description,
                        const plonk_constraint_system<FieldType> &constraint_system,
                        commitment_scheme_type& commitment_scheme,
                        const std::vector<std::vector<typename FieldType::value_type>> &public_input
                    ) {
                        PROFILE_SCOPE("Verifier with public input");
                        transcript::fiat_shamir_heuristic_sequential<transcript_hash_type> transcript(std::vector<std::uint8_t>({}));
                        typename FieldType::value_type F_consolidated;

                        typename FieldType::value_type evaluation_challenge;
                        std::queue<typename FieldType::value_type> queue;
                        fill_challenge_queue(common_data, proof, constraint_system, commitment_scheme, transcript, queue, evaluation_challenge);

                        if (!verify_partial_proof(
                                common_data, proof, table_description, constraint_system,
                                commitment_scheme, public_input, transcript, F_consolidated, evaluation_challenge))
                        {
                            BOOST_LOG_TRIVIAL(info) << "Verification failed: partial proof failed.";
                            return false;
                        }

                        std::map<std::size_t, typename commitment_scheme_type::commitment_type> commitments = proof.commitments;
                        commitments[FIXED_VALUES_BATCH] = common_data.commitments.fixed_values;

                        if (!commitment_scheme.verify_eval(proof.eval_proof.eval_proof, commitments, transcript)) {
                            BOOST_LOG_TRIVIAL(info) << "Verification failed: LPC proof failed.";
                            return false;
                        }
                        return true;
                    }

                    // Takes out values of different polynomials at challenge point 'Y' from the evaluation proofs.
                    // All arguments except 'Z' and 'constraint_system' are output arguments.
                    static inline void prepare_verifier_inputs(
                        const eval_storage_type &Z,
                        const plonk_constraint_system<SmallFieldType> &constraint_system,
                        const typename public_preprocessor_type::preprocessed_data_type::
                            common_data_type &common_data,
                        std::vector<typename FieldType::value_type> &counts,
                        typename FieldType::value_type &U_value,
                        typename FieldType::value_type &U_shifted_value,
                        std::vector<typename FieldType::value_type> &hs,
                        std::vector<typename FieldType::value_type> &gs) {
                        // Get lookup inputs and lookup values sizes from the constraint system.
                        size_t lookup_inputs_count = 0;
                        for (const auto& gate: constraint_system.lookup_gates()) {
                            lookup_inputs_count += gate.constraints.size();
                        }

                        size_t lookup_values_count = 0;
                        for (const auto& table: constraint_system.lookup_tables()) {
                            lookup_values_count += table.lookup_options.size();
                        }

                        // LOOKUP_BATCH consists of evaluations of 'counts' polynomial only.
                        BOOST_ASSERT(lookup_values_count == Z.get_batch_size(LOOKUP_BATCH));

                        for (std::size_t i = 0; i < lookup_values_count; i++) {
                            counts.push_back(Z.get(LOOKUP_BATCH, i, 0));
                        }

                        U_value = Z.get(PERMUTATION_BATCH, common_data.permutation_parts)[0];
                        U_shifted_value = Z.get(PERMUTATION_BATCH, common_data.permutation_parts)[1];

                        // On the next lines +1 stands for polynomial U.
                        for (std::size_t i = common_data.permutation_parts + 1;
                             i < common_data.permutation_parts + 1 + lookup_inputs_count;
                             i++) {
                            hs.push_back(Z.get(PERMUTATION_BATCH, i, 0));
                        }

                        for (std::size_t i = common_data.permutation_parts + 1 + lookup_inputs_count;
                             i < common_data.permutation_parts + 1 + lookup_inputs_count + lookup_values_count;
                             i++) {
                            gs.push_back(Z.get(PERMUTATION_BATCH, i, 0));
                        }
                    }

                    static inline bool process(
                        const typename public_preprocessor_type::preprocessed_data_type::
                            common_data_type &common_data,
                        const proof_type &proof,
                        const plonk_table_description<SmallFieldType> &table_description,
                        const plonk_constraint_system<SmallFieldType> &constraint_system,
                        commitment_scheme_type &commitment_scheme) {
                        PROFILE_SCOPE("Verifier");
                        auto& Z = proof.eval_proof.eval_proof.z;
                        transcript::fiat_shamir_heuristic_sequential<transcript_hash_type> transcript(std::vector<std::uint8_t>({}));
                        typename FieldType::value_type F_consolidated;

                        auto transcript_copy = transcript;

                        typename FieldType::value_type evaluation_challenge;
                        std::queue<typename FieldType::value_type> queue;
                        fill_challenge_queue(common_data, proof, constraint_system, commitment_scheme, transcript_copy, queue, evaluation_challenge);

                        // TODO(martun): remove all usage of transcript from the verification code. We already have all the challenges in a queue.
                        // Not doing it now to have a smaller PR.
                        if (!verify_partial_proof(
                                common_data, proof, table_description, constraint_system,
                                commitment_scheme, transcript, F_consolidated, evaluation_challenge))
                        {
                            BOOST_LOG_TRIVIAL(info) << "Verification failed: partial proof failed.";
                            return false;
                        }

                        std::map<std::size_t, typename commitment_scheme_type::commitment_type> commitments = proof.commitments;
                        commitments[FIXED_VALUES_BATCH] = common_data.commitments.fixed_values;

                        if (!commitment_scheme.verify_eval(proof.eval_proof.eval_proof, commitments, transcript)) {
                            BOOST_LOG_TRIVIAL(info) << "Verification failed: LPC proof failed.";
                            return false;
                        }
                        return true;
                    }

                    static inline bool verify_partial_proof(
                        const typename public_preprocessor_type::preprocessed_data_type::
                            common_data_type &common_data,
                        const proof_type &proof,
                        const plonk_table_description<SmallFieldType> &table_description,
                        const plonk_constraint_system<SmallFieldType> &constraint_system,
                        commitment_scheme_type &commitment_scheme,
                        const std::vector<std::vector<typename FieldType::value_type>>
                            &public_input,
                        transcript_type &transcript,
                        typename FieldType::value_type &F_consolidated_out,
                        const typename FieldType::value_type &evaluation_challenge) {
                        // TODO: process rotations for public input.

                        // If public input sizes are set, all of them should be set.
                        if (constraint_system.public_input_sizes_num() != 0 &&
                            constraint_system.public_input_sizes_num() != table_description.public_input_columns) {
                            BOOST_LOG_TRIVIAL(info) << "Verification failed: If public input sizes are set, all of them should be set.";
                            return false;
                        }

                        if (!verify_partial_proof(
                                common_data, proof, table_description, constraint_system,
                                commitment_scheme, transcript, F_consolidated_out, evaluation_challenge))
                            return false;

                        auto omega = common_data.basic_domain->get_domain_element(1);
                        auto numerator = evaluation_challenge.pow(table_description.rows_amount) - FieldType::value_type::one();
                        numerator *= typename FieldType::value_type(table_description.rows_amount).inversed();

                        for (size_t i = 0; i < public_input.size(); ++i) {
                            typename FieldType::value_type value = FieldType::value_type::zero();
                            std::size_t max_size = public_input[i].size();
                            if (constraint_system.public_input_sizes_num() != 0)
                                max_size = std::min(max_size, constraint_system.public_input_size(i));
                            auto omega_pow = FieldType::value_type::one();
                            for (size_t j = 0; j < max_size; ++j) {
                                value += (public_input[i][j] * omega_pow) * (evaluation_challenge - omega_pow).inversed();
                                omega_pow *= omega;
                            }
                            value *= numerator;
                            if (value != proof.eval_proof.eval_proof.z.get(VARIABLE_VALUES_BATCH, table_description.witness_columns + i, 0))
                            {
                                BOOST_LOG_TRIVIAL(info) << "Verification failed: evaluation proof failed.";
                                return false;
                            }
                        }
                        return true;
                    }

                    /** Generates the queue containing all the challenges which will be required for evaluation. Separately returns evaluation
                     *  point challenge for convenience.
                     */
                    static inline void fill_challenge_queue(
                        const typename public_preprocessor_type::preprocessed_data_type::
                            common_data_type &common_data,
                        const proof_type &proof,
                        const plonk_constraint_system<SmallFieldType> &constraint_system,
                        commitment_scheme_type &commitment_scheme,
                        transcript_type &transcript,
                        std::queue<typename FieldType::value_type> &queue,
                        typename FieldType::value_type &evaluation_challenge_out) {
                        transcript(common_data.vk.constraint_system_with_params_hash);
                        transcript(common_data.vk.fixed_values_commitment);

                        std::map<std::size_t, typename commitment_scheme_type::commitment_type> commitments = proof.commitments;
                        commitments[FIXED_VALUES_BATCH] = common_data.commitments.fixed_values;

                        // Setup commitment scheme. LPC adds an additional point here.
                        commitment_scheme.fill_challenge_queue_for_setup(transcript, queue);

                        // 3. append witness commitments to transcript
                        transcript(proof.commitments.at(VARIABLE_VALUES_BATCH));

                        if (constraint_system.copy_constraints().size() > 0) {
                            placeholder_permutation_argument<FieldType, ParamsType>::fill_challenge_queue(common_data, transcript, queue);
                        }
                        // 6. lookup argument
                        bool is_lookup_enabled = (constraint_system.lookup_gates().size() > 0);
                        if (is_lookup_enabled) {
                            placeholder_lookup_argument_verifier<FieldType, commitment_scheme_type, ParamsType> lookup_argument_verifier;
                            lookup_argument_verifier.fill_challenge_queue(
                                common_data,
                                constraint_system,
                                proof.eval_proof.eval_proof.z.get(LOOKUP_BATCH),
                                proof.commitments.at(LOOKUP_BATCH),
                                transcript, queue);
                        }
                        if (constraint_system.copy_constraints().size() > 0 || constraint_system.lookup_gates().size() > 0) {
                            transcript(proof.commitments.at(PERMUTATION_BATCH));
                        }

                        // 7. gate argument
                        placeholder_gates_argument<FieldType, ParamsType>::fill_challenge_queue(
                            transcript, queue
                        );

                        std::array<typename FieldType::value_type, f_parts> alphas =
                            transcript.template challenges<FieldType, f_parts>();
                        for (auto& a: alphas) {
                            queue.push(a);
                        }

                        // 9. IOP checks
                        transcript(proof.commitments.at(QUOTIENT_BATCH));

                        evaluation_challenge_out = transcript.template challenge<FieldType>();
                        queue.push(evaluation_challenge_out);

                        // TODO(martun): consider filling the queue for commitment scheme as well here.
                        // Currently we don't use the queue yet, just the evaluation challenge, so I'm skipping this.
                    }

                    /** Even though this function accepts the full proof, it does only partial verifications.
                     *  FRI proof and evaluation proofs will be checked separately.
                     *  \param[out] F_consolidated_out - F Consolidated polynomial output argument, will be used to check
                     *                                   evaluation proofs in a given challenge point later.
                     *  \param[in] evaluation_challenge - The last challenge used by partial proof, the evaluation point challenge.
                     *  \returns true if partial proof passes, false otherwise.
                     */
                    static inline bool verify_partial_proof(
                        const typename public_preprocessor_type::preprocessed_data_type::
                            common_data_type &common_data,
                        const proof_type &proof,
                        const plonk_table_description<SmallFieldType> &table_description,
                        const plonk_constraint_system<SmallFieldType> &constraint_system,
                        commitment_scheme_type &commitment_scheme,
                        transcript_type &transcript,
                        typename FieldType::value_type &F_consolidated_out,
                        const typename FieldType::value_type &evaluation_challenge) {
                        auto& Z = proof.eval_proof.eval_proof.z;

                        // We cannot add eval points unless everything is committed, so when verifying assume it's committed.
                        commitment_scheme.state_commited(FIXED_VALUES_BATCH);
                        commitment_scheme.state_commited(VARIABLE_VALUES_BATCH);
                        commitment_scheme.state_commited(PERMUTATION_BATCH);
                        commitment_scheme.state_commited(QUOTIENT_BATCH);
                        commitment_scheme.state_commited(LOOKUP_BATCH);
                        commitment_scheme.mark_batch_as_fixed(FIXED_VALUES_BATCH);

                        commitment_scheme.set_fixed_polys_values(common_data.commitment_scheme_data);

                        const std::size_t witness_columns = table_description.witness_columns;
                        const std::size_t public_input_columns = table_description.public_input_columns;
                        const std::size_t constant_columns = table_description.constant_columns;
                        const std::size_t selector_columns = table_description.selector_columns;

                        transcript(common_data.vk.constraint_system_with_params_hash);
                        transcript(common_data.vk.fixed_values_commitment);

                        // Setup commitment scheme. LPC adds an additional point here.
                        commitment_scheme.setup(transcript, common_data.commitment_scheme_data);

                        // 3. append witness commitments to transcript
                        transcript(proof.commitments.at(VARIABLE_VALUES_BATCH));

                        std::vector<typename FieldType::value_type>
                            special_selector_values(3);
                        PROFILE_SCOPE("Evaluate lagrange_0 at challenge");
                        special_selector_values[0] =
                            common_data.lagrange_0.evaluate(evaluation_challenge);
                        PROFILE_SCOPE_END();
                        special_selector_values[1] = Z.get(
                            FIXED_VALUES_BATCH, 2*common_data.permuted_columns.size(), 0);
                        special_selector_values[2] = Z.get(
                            FIXED_VALUES_BATCH, 2*common_data.permuted_columns.size() + 1, 0);

                        // 4. prepare evaluations of the polynomials that are copy-constrained
                        std::array<typename FieldType::value_type, f_parts> F;
                        std::size_t permutation_size = (Z.get_batch_size(FIXED_VALUES_BATCH) - 2 - constant_columns - selector_columns) / 2;
                        if (constraint_system.copy_constraints().size() > 0) {
                            // Permutation polys
                            std::vector<std::size_t> permuted_polys_global_indices = common_data.permuted_columns;
                            std::vector<typename FieldType::value_type> f(permutation_size);
                            std::vector<typename FieldType::value_type> S_id;
                            std::vector<typename FieldType::value_type> S_sigma;

                            for (std::size_t perm_i = 0; perm_i < permutation_size; perm_i++) {
                                S_id.push_back(Z.get(FIXED_VALUES_BATCH, perm_i, 0));
                                S_sigma.push_back(Z.get(FIXED_VALUES_BATCH, permutation_size + perm_i, 0));

                                std::size_t i = permuted_polys_global_indices[perm_i];
                                std::size_t zero_index = 0;
                                for (int v: common_data.columns_rotations[i]) {
                                    if (v == 0){
                                        break;
                                    }
                                    zero_index++;
                                }
                                if (i < witness_columns + public_input_columns) {
                                    f[perm_i] = Z.get(VARIABLE_VALUES_BATCH,i,zero_index);
                                } else if (i >= witness_columns + public_input_columns ) {
                                    std::size_t idx = i - witness_columns - public_input_columns + permutation_size*2 + 2;
                                    f[perm_i] = Z.get(FIXED_VALUES_BATCH,idx,zero_index);
                                }
                            }

                            // 5. permutation argument
                            std::vector<typename FieldType::value_type> perm_partitions;
                            for( std::size_t i = 1; i < common_data.permutation_parts; i++ ){
                                perm_partitions.push_back(Z.get(PERMUTATION_BATCH, i, 0));
                            }
                            std::array<typename FieldType::value_type, permutation_parts> permutation_argument =
                                placeholder_permutation_argument<FieldType, ParamsType>::verify_eval(
                                    common_data,
                                    S_id, S_sigma, special_selector_values,
                                    evaluation_challenge, f,
                                    Z.get(PERMUTATION_BATCH, 0, 0),
                                    Z.get(PERMUTATION_BATCH, 0, 1),
                                    perm_partitions,
                                    transcript
                                );
                            F[0] = permutation_argument[0];
                            F[1] = permutation_argument[1];
                            F[2] = permutation_argument[2];
                        }

                        typename policy_type::evaluation_map columns_at_y;
                        for (std::size_t i = 0; i < witness_columns; i++) {
                            std::size_t i_global_index = i;
                            std::size_t j = 0;
                            for (int rotation: common_data.columns_rotations[i_global_index]) {
                                auto key = std::make_tuple(
                                    i,
                                    rotation,
                                    plonk_variable<typename FieldType::value_type>::column_type::witness);
                                columns_at_y[key] = Z.get(VARIABLE_VALUES_BATCH, i, j);
                                ++j;
                            }
                        }

                        for (std::size_t i = 0; i < public_input_columns; i++) {
                            std::size_t i_global_index = witness_columns + i;

                            std::size_t j = 0;
                            for (int rotation: common_data.columns_rotations[i_global_index]) {
                                auto key = std::make_tuple(
                                    i,
                                    rotation,
                                    plonk_variable<typename FieldType::value_type>::column_type::public_input);
                                columns_at_y[key] = Z.get(VARIABLE_VALUES_BATCH, witness_columns + i, j);
                                ++j;
                            }
                        }

                        for (std::size_t i = 0; i < 0 + constant_columns; i++) {
                            std::size_t i_global_index = witness_columns + public_input_columns + i;
                            std::size_t j = 0;
                            for (int rotation: common_data.columns_rotations[i_global_index]) {
                                auto key = std::make_tuple(
                                    i,
                                    rotation,
                                    plonk_variable<typename FieldType::value_type>::column_type::constant);
                                columns_at_y[key] = Z.get(FIXED_VALUES_BATCH, i + permutation_size*2 + 2, j);
                                ++j;
                            }
                        }

                        for (std::size_t i = 0; i < selector_columns; i++) {
                            std::size_t i_global_index = witness_columns + constant_columns + public_input_columns + i;
                            std::size_t j = 0;
                            for (int rotation: common_data.columns_rotations[i_global_index]) {
                                auto key = std::make_tuple(
                                    i,
                                    rotation,
                                    plonk_variable<typename FieldType::value_type>::column_type::selector);
                                columns_at_y[key] = Z.get(FIXED_VALUES_BATCH, i + permutation_size*2 + 2 + constant_columns, j);
                                ++j;
                            }
                        }

                        typename FieldType::value_type mask_value = FieldType::value_type::one() -
                            Z.get(FIXED_VALUES_BATCH, common_data.permuted_columns.size() * 2, 0) -
                            Z.get(FIXED_VALUES_BATCH, common_data.permuted_columns.size() * 2 + 1, 0);
                        typename FieldType::value_type shifted_mask_value = FieldType::value_type::one() -
                            Z.get(FIXED_VALUES_BATCH, common_data.permuted_columns.size() * 2, 1) -
                            Z.get(FIXED_VALUES_BATCH, common_data.permuted_columns.size() * 2 + 1, 1);

                        // All rows selector
                        {
                            auto key = std::make_tuple(
                                PLONK_SPECIAL_SELECTOR_ALL_USABLE_ROWS_SELECTED, 0,
                                plonk_variable<typename FieldType::value_type>::column_type::selector
                            );
                            columns_at_y[key] = mask_value;
                        }
                        {
                            auto key = std::make_tuple(
                                PLONK_SPECIAL_SELECTOR_ALL_USABLE_ROWS_SELECTED, 1,
                                plonk_variable<typename FieldType::value_type>::column_type::selector
                            );
                            columns_at_y[key] = shifted_mask_value;
                        }
                        // All rows selector
                        {
                            auto key = std::make_tuple(
                                PLONK_SPECIAL_SELECTOR_ALL_NON_FIRST_USABLE_ROWS_SELECTED, 0,
                                plonk_variable<typename FieldType::value_type>::column_type::selector
                            );
                            PROFILE_SCOPE("Evaluate lagrange_0 for selectors 0");
                            columns_at_y[key] = mask_value - common_data.lagrange_0.evaluate(evaluation_challenge);
                        }
                        {
                            auto key = std::make_tuple(
                                PLONK_SPECIAL_SELECTOR_ALL_NON_FIRST_USABLE_ROWS_SELECTED, 1,
                                plonk_variable<typename FieldType::value_type>::column_type::selector
                            );
                            PROFILE_SCOPE("Evaluate lagrange_0 for selectors 1");
                            columns_at_y[key] = shifted_mask_value - common_data.lagrange_0.evaluate(
                                evaluation_challenge * common_data.basic_domain->get_domain_element(1));
                        }

                        {
                            auto key = std::make_tuple(
                                PLONK_SPECIAL_SELECTOR_ALL_ROWS_SELECTED, 0,
                                plonk_variable<typename FieldType::value_type>::column_type::selector
                            );
                            columns_at_y[key] = FieldType::value_type::one();
                        }
                        { // ????
                            auto key = std::make_tuple(
                                PLONK_SPECIAL_SELECTOR_ALL_ROWS_SELECTED, 1,
                                plonk_variable<typename FieldType::value_type>::column_type::selector
                            );
                            columns_at_y[key] = FieldType::value_type::one() - common_data.lagrange_0.evaluate(
                                evaluation_challenge * common_data.basic_domain->get_domain_element(1));
                        }

                        // 6. lookup argument
                        bool is_lookup_enabled = (constraint_system.lookup_gates().size() > 0);
                        std::array<typename FieldType::value_type, lookup_parts> lookup_argument;
                        if (is_lookup_enabled) {
                            // Prepare values of different polynomials required for lookup argument verification.
                            std::vector<typename FieldType::value_type> counts;
                            typename FieldType::value_type U_value;
                            typename FieldType::value_type U_shifted_value;
                            std::vector<typename FieldType::value_type> hs;
                            std::vector<typename FieldType::value_type> gs;

                            prepare_verifier_inputs(Z, constraint_system, common_data, counts, U_value, U_shifted_value, hs, gs);

                            placeholder_lookup_argument_verifier<FieldType, commitment_scheme_type, ParamsType> lookup_argument_verifier;
                            lookup_argument = lookup_argument_verifier.verify_eval(
                                common_data,
                                special_selector_values,
                                constraint_system,
                                evaluation_challenge,
                                columns_at_y,
                                counts,
                                U_value,
                                U_shifted_value,
                                hs,
                                gs,
                                proof.commitments.at(LOOKUP_BATCH),
                                transcript
                            );
                        }
                        if (constraint_system.copy_constraints().size() > 0 || constraint_system.lookup_gates().size() > 0) {
                            transcript(proof.commitments.at(PERMUTATION_BATCH));
                        }

                        // 7. gate argument
                        std::array<typename FieldType::value_type, 1> gate_argument =
                        placeholder_gates_argument<FieldType, ParamsType>::verify_eval(
                            constraint_system.gates(), columns_at_y, evaluation_challenge,
                            mask_value,
                            transcript
                        );

                        std::array<typename FieldType::value_type, f_parts> alphas =
                            transcript.template challenges<FieldType, f_parts>();

                        // 9. IOP checks
                        transcript(proof.commitments.at(QUOTIENT_BATCH));

                        if (evaluation_challenge != transcript.template challenge<FieldType>())
                            return false;

                        F[3] = lookup_argument[0];
                        F[4] = lookup_argument[1];
                        F[5] = lookup_argument[2];
                        F[6] = lookup_argument[3];
                        F[7] = gate_argument[0];

                        F_consolidated_out = FieldType::value_type::zero();
                        for (std::size_t i = 0; i < f_parts; i++) {
                            F_consolidated_out += alphas[i] * F[i];
                        }

                        prepare_polynomials(proof.eval_proof, common_data, table_description, constraint_system, commitment_scheme, evaluation_challenge);

                        if (!verify_consolidated_polynomial(common_data, proof, F_consolidated_out, evaluation_challenge))
                            return false;

                        return true;
                    }

                    static inline bool verify_consolidated_polynomial(
                        const typename public_preprocessor_type::preprocessed_data_type::common_data_type &common_data,
                        const proof_type &proof,
                        const typename FieldType::value_type& F_consolidated,
                        const typename FieldType::value_type& challenge)
                    {

                        typename FieldType::value_type T_consolidated = FieldType::value_type::zero();
                        for (std::size_t i = 0; i < proof.eval_proof.eval_proof.z.get_batch_size(QUOTIENT_BATCH); i++) {
                            T_consolidated += proof.eval_proof.eval_proof.z.get(QUOTIENT_BATCH, i, 0) *
                                challenge.pow((common_data.desc.rows_amount) * i);
                        }

                        PROFILE_SCOPE("Final check");

                        // Z is polynomial -1, 0 ...., 0, 1
                        typename FieldType::value_type Z_at_challenge = common_data.Z.evaluate(challenge);
                        if (F_consolidated != Z_at_challenge * T_consolidated) {
                            BOOST_LOG_TRIVIAL(info) << "Verification failed: F consolidated polynomial mismatch.";
                            return false;
                        }

                        return true;
                    }

                    // maybe rename this to something like prepare_batches_and_eval_points?
                    static inline void prepare_polynomials(
                        const typename proof_type::evaluation_proof &eval_proof,
                        const typename public_preprocessor_type::preprocessed_data_type::
                            common_data_type &common_data,
                        const plonk_table_description<SmallFieldType> &table_description,
                        const plonk_constraint_system<SmallFieldType> &constraint_system,
                        commitment_scheme_type &commitment_scheme,
                        const typename FieldType::value_type &evaluation_challenge) {
                        commitment_scheme.set_batch_size(VARIABLE_VALUES_BATCH,
                            eval_proof.eval_proof.z.get_batch_size(VARIABLE_VALUES_BATCH));
                        commitment_scheme.set_batch_size(FIXED_VALUES_BATCH,
                            eval_proof.eval_proof.z.get_batch_size(FIXED_VALUES_BATCH));
                        bool is_lookup_enabled = (constraint_system.lookup_gates().size() > 0);

                        if (is_lookup_enabled || constraint_system.copy_constraints().size())
                            commitment_scheme.set_batch_size(PERMUTATION_BATCH,
                                eval_proof.eval_proof.z.get_batch_size(PERMUTATION_BATCH));

                        commitment_scheme.set_batch_size(QUOTIENT_BATCH,
                            eval_proof.eval_proof.z.get_batch_size(QUOTIENT_BATCH));

                        if (is_lookup_enabled)
                            commitment_scheme.set_batch_size(LOOKUP_BATCH,
                                eval_proof.eval_proof.z.get_batch_size(LOOKUP_BATCH));

                        generate_evaluation_points(
                            commitment_scheme, common_data, constraint_system,
                            table_description, evaluation_challenge, is_lookup_enabled);
                    }
                };
            }    // namespace snark
        }        // namespace zk
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_ZK_PLONK_PLACEHOLDER_VERIFIER_HPP
