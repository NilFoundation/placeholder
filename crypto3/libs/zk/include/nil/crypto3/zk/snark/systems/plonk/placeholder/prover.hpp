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

#ifndef CRYPTO3_ZK_PLONK_PLACEHOLDER_PROVER_HPP
#define CRYPTO3_ZK_PLONK_PLACEHOLDER_PROVER_HPP

#include <set>

#include <nil/crypto3/zk/math/cached_assignment_table.hpp>
#include <nil/crypto3/zk/math/centralized_expression_evaluator.hpp>

#include <nil/crypto3/zk/commitments/polynomial/lpc.hpp>
#include <nil/crypto3/zk/transcript/fiat_shamir.hpp>
#include <nil/crypto3/zk/snark/arithmetization/plonk/assignment.hpp>
#include <nil/crypto3/zk/snark/systems/plonk/placeholder/detail/placeholder_policy.hpp>
#include <nil/crypto3/zk/snark/systems/plonk/placeholder/permutation_argument.hpp>
#include <nil/crypto3/zk/snark/systems/plonk/placeholder/lookup_argument.hpp>
#include <nil/crypto3/zk/snark/systems/plonk/placeholder/gates_argument.hpp>
#include <nil/crypto3/zk/snark/systems/plonk/placeholder/params.hpp>
#include <nil/crypto3/zk/snark/systems/plonk/placeholder/preprocessor.hpp>

#include <nil/crypto3/bench/scoped_profiler.hpp>

namespace nil::crypto3::zk::snark {
    namespace detail {
        template<typename FieldType>
        static inline std::vector<math::polynomial<typename FieldType::value_type>>
            split_polynomial(const math::polynomial<typename FieldType::value_type> &f,
                             std::size_t max_degree) {
            std::vector<math::polynomial<typename FieldType::value_type>> f_splitted;

            std::size_t chunk_size = max_degree + 1;    // polynomial contains max_degree + 1 coeffs
            for (size_t i = 0; i < f.size(); i += chunk_size) {
                auto last = std::min(f.size(), i + chunk_size);
                f_splitted.emplace_back(f.begin() + i, f.begin() + last);
            }
            return f_splitted;
        }
    }    // namespace detail

    template<typename FieldType, typename ParamsType>
    class placeholder_prover {
        using SmallFieldType = typename FieldType::small_subfield;
        using value_type = typename FieldType::value_type;
        using small_field_value_type = typename SmallFieldType::value_type;
        using transcript_hash_type = typename ParamsType::transcript_hash_type;
        using transcript_type = transcript::fiat_shamir_heuristic_sequential<transcript_hash_type>;

        using policy_type = detail::placeholder_policy<FieldType, ParamsType>;

        typedef typename math::polynomial<small_field_value_type>
            small_field_polynomial_type;
        typedef typename math::polynomial_dfs<small_field_value_type>
            small_field_polynomial_dfs_type;

        typedef typename math::polynomial<value_type> polynomial_type;
        typedef typename math::polynomial_dfs<value_type> polynomial_dfs_type;

        using commitment_scheme_type = typename ParamsType::commitment_scheme_type;
        using commitment_type = typename commitment_scheme_type::commitment_type;

        using public_preprocessor_type =
            placeholder_public_preprocessor<SmallFieldType, ParamsType>;
        using private_preprocessor_type =
            placeholder_private_preprocessor<SmallFieldType, ParamsType>;

        using central_evaluator_type =
            CentralAssignmentTableExpressionEvaluator<SmallFieldType>;
        using lookup_argument_type = placeholder_lookup_argument_prover<FieldType, commitment_scheme_type, ParamsType>;

        constexpr static const std::size_t gate_parts = 1;
        constexpr static const std::size_t permutation_parts = 3;
        constexpr static const std::size_t lookup_parts = 6;
        constexpr static const std::size_t f_parts = 8;

                public:
                public:

      public:

        static inline placeholder_proof<FieldType, ParamsType> process(
            const typename public_preprocessor_type::preprocessed_data_type&
                preprocessed_public_data,
            typename private_preprocessor_type::preprocessed_data_type
                preprocessed_private_data,
            const plonk_table_description<SmallFieldType>& table_description,
            const plonk_constraint_system<SmallFieldType>& constraint_system,
            commitment_scheme_type& commitment_scheme,
            bool skip_commitment_scheme_eval_proofs = false) {
            auto prover = placeholder_prover<FieldType, ParamsType>(
                preprocessed_public_data, std::move(preprocessed_private_data),
                table_description, constraint_system, commitment_scheme,
                skip_commitment_scheme_eval_proofs);
            return prover.process();
        }

        placeholder_prover(
            const typename public_preprocessor_type::preprocessed_data_type&
                preprocessed_public_data,
            const typename private_preprocessor_type::preprocessed_data_type&
                preprocessed_private_data,
            const plonk_table_description<SmallFieldType>& table_description,
            const plonk_constraint_system<SmallFieldType>& constraint_system,
            commitment_scheme_type& commitment_scheme,
            bool skip_commitment_scheme_eval_proofs = false)
            : preprocessed_public_data(preprocessed_public_data),
              table_description(table_description),
              constraint_system(constraint_system),
              _polynomial_table(
                  std::make_shared<plonk_polynomial_dfs_table<SmallFieldType>>(
                      preprocessed_private_data.private_polynomial_table,
                      preprocessed_public_data.public_polynomial_table)),
              transcript(std::vector<std::uint8_t>({})),
              _is_lookup_enabled(constraint_system.lookup_gates().size() > 0),
              _commitment_scheme(commitment_scheme),
              _skip_commitment_scheme_eval_proofs(skip_commitment_scheme_eval_proofs) {
            // Initialize transcript.
            transcript(preprocessed_public_data.common_data->vk
                           .constraint_system_with_params_hash);
            transcript(preprocessed_public_data.common_data->vk.fixed_values_commitment);

            // Setup commitment scheme. LPC adds an additional point here.
            _commitment_scheme.setup(
                transcript, preprocessed_public_data.common_data->commitment_scheme_data);
        }

        placeholder_proof<FieldType, ParamsType> process() {
            PROFILE_SCOPE("Placeholder prover");

            small_field_polynomial_dfs_type mask_polynomial(
                0, preprocessed_public_data.common_data->basic_domain->m,
                small_field_value_type(1u));
            mask_polynomial -= preprocessed_public_data.q_last;
            mask_polynomial -= preprocessed_public_data.q_blind;

            std::unique_ptr<central_evaluator_type> central_evaluator = std::make_unique<central_evaluator_type>(
                _polynomial_table,
                mask_polynomial,
                preprocessed_public_data.common_data->lagrange_0
            );

            SCOPED_LOG(
                "Assignment table statistics: total columns: {}, witnesses: "
                "{}, constants: {}, public inputs: {}, selectors: {}",
                _polynomial_table->size(),
                _polynomial_table->witnesses_amount(),
                _polynomial_table->constants_amount(),
                _polynomial_table->public_inputs_amount(),
                _polynomial_table->selectors_amount());

            // 2. Commit witness columns and public_input columns
            _commitment_scheme.append_many_to_batch(VARIABLE_VALUES_BATCH, _polynomial_table->witnesses());
            _commitment_scheme.append_many_to_batch(VARIABLE_VALUES_BATCH, _polynomial_table->public_inputs());
            TAGGED_PROFILE_SCOPE("{high level} FRI", "Variable values precommit");
            _proof.commitments[VARIABLE_VALUES_BATCH] =
                _commitment_scheme.commit(VARIABLE_VALUES_BATCH);
            PROFILE_SCOPE_END();
            transcript(_proof.commitments[VARIABLE_VALUES_BATCH]);

            // 4. permutation_argument
            if (constraint_system.copy_constraints().size() > 0) {
                auto permutation_argument = placeholder_permutation_argument<FieldType, ParamsType>::prove_eval(
                    constraint_system,
                    preprocessed_public_data,
                    table_description,
                    *_polynomial_table,
                    _commitment_scheme,
                    transcript);

                _F_dfs[0] = std::move(permutation_argument.F_dfs[0]);
                _F_dfs[1] = std::move(permutation_argument.F_dfs[1]);
                _F_dfs[2] = std::move(permutation_argument.F_dfs[2]);
            }
            _polynomial_table.reset(); // We don't need it anymore, release memory

            // 5. lookup_argument
            auto lookup_argument_result = lookup_argument(*central_evaluator);
            _F_dfs[3] = std::move(lookup_argument_result.F_dfs[0]);
            _F_dfs[4] = std::move(lookup_argument_result.F_dfs[1]);
            _F_dfs[5] = std::move(lookup_argument_result.F_dfs[2]);
            _F_dfs[6] = std::move(lookup_argument_result.F_dfs[3]);

            central_evaluator->reset_expressions();

            if (constraint_system.copy_constraints().size() > 0 || constraint_system.lookup_gates().size() > 0) {
                TAGGED_PROFILE_SCOPE("{high level} lookup",
                                     "Permutation batch precommit");
                _proof.commitments[PERMUTATION_BATCH] = _commitment_scheme.commit(PERMUTATION_BATCH);
                transcript(_proof.commitments[PERMUTATION_BATCH]);
            }

            // 6. circuit-satisfability

            value_type theta = transcript.template challenge<FieldType>();
            _F_dfs[7] = placeholder_gates_argument<FieldType, ParamsType>::prove_eval(
                constraint_system, *central_evaluator, theta
            )[0];

            central_evaluator.reset();

#ifdef ZK_PLACEHOLDER_DEBUG_ENABLED
            placeholder_debug_output();
#endif

            // 7. Aggregate quotient polynomial
            {
                std::vector<polynomial_dfs_type> T_splitted_dfs =
                    quotient_polynomial_split_dfs();

                _proof.commitments[QUOTIENT_BATCH] = T_commit(T_splitted_dfs);
            }
            transcript(_proof.commitments[QUOTIENT_BATCH]);

            // 8. Run evaluation proofs
            value_type evaluation_challenge = transcript.template challenge<FieldType>();
            generate_evaluation_points(evaluation_challenge);

            if (!_skip_commitment_scheme_eval_proofs) {
                _proof.eval_proof.eval_proof = _commitment_scheme.proof_eval(transcript);
            } else {
                if constexpr (nil::crypto3::zk::is_lpc<commitment_scheme_type>) {
                    // This is required for aggregated prover. If we do not run the LPC proof right now,
                    // we still need to push the merkle tree roots into the transcript.
                    _commitment_scheme.convert_polys_to_coefficients_form();
                    _commitment_scheme.eval_polys_and_add_roots_to_transcipt(transcript);
                }
            }

            return _proof;
        }

        commitment_scheme_type& get_commitment_scheme() {
            return _commitment_scheme;
        }

    private:
        std::vector<polynomial_dfs_type> quotient_polynomial_split_dfs() {
            PROFILE_SCOPE("Quotient polynomial split dfs");

            const auto& assignment_desc = preprocessed_public_data.common_data->desc;

            // TODO: pass max_degree parameter placeholder
            std::vector<polynomial_type> T_splitted = detail::split_polynomial<FieldType>(
                quotient_polynomial(), table_description.rows_amount - 1
            );

            std::size_t split_polynomial_size = std::max(
                (preprocessed_public_data.identity_polynomials.size() + 2) * (assignment_desc.rows_amount - 1),
                (constraint_system.lookup_poly_degree_bound() + 1) * (assignment_desc.rows_amount -1)
            );
            split_polynomial_size = std::max(
                split_polynomial_size,
                (preprocessed_public_data.common_data->max_gates_degree + 1) * (assignment_desc.rows_amount - 1)
            );
            split_polynomial_size = (split_polynomial_size % assignment_desc.rows_amount != 0)?
                (split_polynomial_size / assignment_desc.rows_amount + 1):
                (split_polynomial_size / assignment_desc.rows_amount);

            if (preprocessed_public_data.common_data->max_quotient_chunks != 0 &&
                split_polynomial_size > preprocessed_public_data.common_data->max_quotient_chunks) {
                split_polynomial_size = preprocessed_public_data.common_data->max_quotient_chunks;
            }

            // We need split_polynomial_size computation because proof size shouldn't depend on public input size.
            // we set this size as maximum of
            //      F[2] (from permutation argument)
            //      F[5] (from lookup argument)
            //      F[7] (from gates argument)
            // If some columns used in permutation or lookup argument are zero, real quotient polynomial degree
            //      may be less than split_polynomial_size.
            std::vector<polynomial_dfs_type> T_splitted_dfs(T_splitted.size());

            parallel_for(0, T_splitted.size(), [&T_splitted, &T_splitted_dfs](std::size_t k) {
                T_splitted_dfs[k].from_coefficients(T_splitted[k]);
            }, ThreadPool::PoolLevel::HIGH);

            // DO NOT CHANGE, sizes are different by design
            T_splitted_dfs.resize(split_polynomial_size);

            return T_splitted_dfs;
        }

        polynomial_type quotient_polynomial() {
            PROFILE_SCOPE("Quotient polynomial");

            // 7.1. Get $\alpha_0, \dots, \alpha_8 \in \mathbb{F}$ from $hash(\text{transcript})$
            std::array<value_type, f_parts> alphas =
                transcript.template challenges<FieldType, f_parts>();

            // 7.2. Compute F_consolidated
            std::vector<polynomial_dfs_type> F_consolidated_dfs_parts(_F_dfs.size(), polynomial_dfs_type());
            parallel_for(0, F_consolidated_dfs_parts.size(),
                [this, &F_consolidated_dfs_parts, &alphas](std::size_t i) {
                    F_consolidated_dfs_parts[i] = _F_dfs[i];
                    if (_F_dfs[i].is_zero()) {
                        return;
                    }
                    F_consolidated_dfs_parts[i] *= alphas[i];
            }, ThreadPool::PoolLevel::HIGH);

            polynomial_dfs_type F_consolidated_dfs = polynomial_sum<FieldType>(std::move(F_consolidated_dfs_parts));

            polynomial_type F_consolidated_normal(F_consolidated_dfs.coefficients());

            polynomial_type T_consolidated =
                F_consolidated_normal /
                polynomial_type(preprocessed_public_data.common_data->Z);

            // We can remove this check later, it's fairly fast and makes sure that prover succeeded.
            if (T_consolidated * preprocessed_public_data.common_data->Z != F_consolidated_normal) {
                //BOOST_LOG_TRIVIAL(info) << "F_consolidated_normal = " << F_consolidated_normal << std::endl;
                //BOOST_LOG_TRIVIAL(info) << "Z = " << preprocessed_public_data.common_data->Z << std::endl;
                throw std::logic_error("Can't divide F Consolidated on Z. Prover failed.");
            }

            return T_consolidated;
        }

        typename lookup_argument_type::prover_lookup_result lookup_argument(
            central_evaluator_type& central_evaluator) {
            typename lookup_argument_type::prover_lookup_result lookup_argument_result;

            lookup_argument_result.F_dfs[0] = lookup_argument_result.F_dfs[1] = lookup_argument_result.F_dfs[2] =
            lookup_argument_result.F_dfs[3] = polynomial_dfs_type(0, table_description.rows_amount, value_type::zero());

            if (_is_lookup_enabled) {
                lookup_argument_type lookup_argument_prover(
                    constraint_system,
                    preprocessed_public_data,
                    central_evaluator,
                    *_polynomial_table,
                    _commitment_scheme,
                    transcript
                );

                lookup_argument_result = lookup_argument_prover.prove_eval();
                _proof.commitments[LOOKUP_BATCH] = lookup_argument_result.lookup_commitment;
            }
            return lookup_argument_result;
        }

        commitment_type T_commit(const std::vector<polynomial_dfs_type>& T_splitted_dfs) {
            PROFILE_SCOPE("T split precommit");
            _commitment_scheme.append_many_to_batch(QUOTIENT_BATCH, T_splitted_dfs);
            return _commitment_scheme.commit(QUOTIENT_BATCH);
        }

        void placeholder_debug_output() {
            for (std::size_t i = 0; i < f_parts; i++) {
                for (std::size_t j = 0; j < table_description.rows_amount; j++) {
                    if (_F_dfs[i].evaluate(preprocessed_public_data.common_data->basic_domain->get_domain_element(j)) != value_type::zero()) {
                        std::cout << "_F_dfs[" << i << "] on row " << j << " = " << _F_dfs[i].evaluate(preprocessed_public_data.common_data->basic_domain->get_domain_element(j)) << std::endl;
                    }
                }
            }

            const auto& gates = constraint_system.gates();

            for (std::size_t i = 0; i < gates.size(); i++) {
                for (std::size_t j = 0; j < gates[i].constraints.size(); j++) {
                    polynomial_dfs_type constraint_result =
                        gates[i].constraints[j].evaluate(
                            _polynomial_table, preprocessed_public_data.common_data->basic_domain) *
                        _polynomial_table.selector(gates[i].selector_index);
                    // for (std::size_t k = 0; k < table_description.rows_amount; k++) {
                    if (constraint_result.evaluate(
                            preprocessed_public_data.common_data->basic_domain->get_domain_element(253)) !=
                        value_type::zero()) {
                    }
                }
            }
        }

        void generate_evaluation_points(const value_type& evaluation_challenge) {
            const auto& assignment_desc = preprocessed_public_data.common_data->desc;

            _omega = preprocessed_public_data.common_data->basic_domain->get_domain_element(1);

            const std::size_t witness_columns = table_description.witness_columns;
            const std::size_t public_input_columns = table_description.public_input_columns;
            const std::size_t constant_columns = table_description.constant_columns;

            // variable_values' rotations
            for (std::size_t variable_values_index = 0;
                 variable_values_index < witness_columns + public_input_columns;
                 variable_values_index++
            ) {
                const std::set<int>& variable_values_rotation =
                    preprocessed_public_data.common_data->columns_rotations[variable_values_index];

                for (int rotation: variable_values_rotation) {
                    _commitment_scheme.append_eval_point(
                        VARIABLE_VALUES_BATCH,
                        variable_values_index,
                        evaluation_challenge * _omega.pow(rotation)
                    );
                }
            }

            if (_is_lookup_enabled || constraint_system.copy_constraints().size() > 0) {
                _commitment_scheme.append_eval_point(PERMUTATION_BATCH, evaluation_challenge);
            }

            if (constraint_system.copy_constraints().size() > 0)
                _commitment_scheme.append_eval_point(PERMUTATION_BATCH, 0, evaluation_challenge * _omega);

            if (_is_lookup_enabled) {
                // For polynomial U, we need the shifted value as well.
                _commitment_scheme.append_eval_point(PERMUTATION_BATCH, preprocessed_public_data.common_data->permutation_parts,
                    evaluation_challenge * _omega);
                _commitment_scheme.append_eval_point(LOOKUP_BATCH, evaluation_challenge);
            }

            _commitment_scheme.append_eval_point(QUOTIENT_BATCH, evaluation_challenge);

            // fixed values' rotations (table columns)
            std::size_t i = 0;
            std::size_t start_index = preprocessed_public_data.identity_polynomials.size() +
                preprocessed_public_data.permutation_polynomials.size() + 2;

            for (i = 0; i < start_index; i++) {
                _commitment_scheme.append_eval_point(FIXED_VALUES_BATCH, i, evaluation_challenge);
            }

            // For special selectors
            _commitment_scheme.append_eval_point(FIXED_VALUES_BATCH, start_index - 2, evaluation_challenge * _omega);
            _commitment_scheme.append_eval_point(FIXED_VALUES_BATCH, start_index - 1, evaluation_challenge * _omega);

            for (std::size_t ind = 0;
                ind < constant_columns + preprocessed_public_data.public_polynomial_table->selectors().size();
                ind++, i++
            ) {
                const std::set<int>& fixed_values_rotation =
                    preprocessed_public_data.common_data->columns_rotations[witness_columns + public_input_columns + ind];

                for (int rotation: fixed_values_rotation) {
                    _commitment_scheme.append_eval_point(
                        FIXED_VALUES_BATCH,
                        start_index + ind,
                        evaluation_challenge * _omega.pow(rotation)
                    );
                }
            }
        }

    public:
        // Transcript is used from the outside to generate an aggregated challenge for dFRI.
        transcript::fiat_shamir_heuristic_sequential<transcript_hash_type> transcript;

    private:
        // Structures passed from outside by reference.
        const typename public_preprocessor_type::preprocessed_data_type &preprocessed_public_data;
        const plonk_table_description<SmallFieldType>& table_description;
        const plonk_constraint_system<SmallFieldType>& constraint_system;

        // Members created during proof generation.
        std::shared_ptr<plonk_polynomial_dfs_table<SmallFieldType>> _polynomial_table;

        placeholder_proof<FieldType, ParamsType> _proof;
        std::array<polynomial_dfs_type, f_parts> _F_dfs;
        bool _is_lookup_enabled;
        value_type _omega;
        std::vector<value_type> _challenge_point;
        commitment_scheme_type& _commitment_scheme;
        bool _skip_commitment_scheme_eval_proofs;
    };
}    // namespace snark

#endif    // CRYPTO3_ZK_PLONK_PLACEHOLDER_PROVER_HPP
