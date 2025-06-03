//---------------------------------------------------------------------------//
// Copyright (c) 2022 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2022 Nikita Kaskov <nbering@nil.foundation>
// Copyright (c) 2022 Ilia Shirobokov <i.shirobokov@nil.foundation>
// Copyright (c) 2022 Alisa Cherniaeva <a.cherniaeva@nil.foundation>
// Copyright (c) 2022 Ilias Khairullin <ilias@nil.foundation>
// Copyright (c) 2023 Elena Tatuzova <e.tatuzova@nil.foundation>
// Copyright (c) 2024 Vasiliy Olekhov <vasiliy.olekhov@nil.foundation>
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
// Lookup argument test for circuits circuit3 and circuit4

#define BOOST_TEST_MODULE placeholder_lookup_argument_test

#include <boost/test/unit_test.hpp>
#include <boost/test/data/test_case.hpp>

#include <nil/crypto3/algebra/curves/pallas.hpp>
#include <nil/crypto3/algebra/fields/arithmetic_params/pallas.hpp>

#include <nil/crypto3/math/algorithms/unity_root.hpp>
#include <nil/crypto3/math/polynomial/lagrange_interpolation.hpp>
#include <nil/crypto3/math/algorithms/calculate_domain_set.hpp>

#include <nil/crypto3/hash/algorithm/hash.hpp>
#include <nil/crypto3/hash/sha2.hpp>
#include <nil/crypto3/hash/keccak.hpp>
#include <nil/crypto3/hash/poseidon.hpp>

#include <nil/crypto3/zk/math/centralized_expression_evaluator.hpp>

#include <nil/crypto3/zk/snark/systems/plonk/placeholder/verifier.hpp>
#include <nil/crypto3/zk/snark/systems/plonk/placeholder/lookup_argument.hpp>

#include <nil/crypto3/zk/snark/systems/plonk/placeholder/preprocessor.hpp>
#include <nil/crypto3/zk/snark/systems/plonk/placeholder/detail/placeholder_policy.hpp>
#include <nil/crypto3/zk/snark/arithmetization/plonk/constraint_system.hpp>
#include <nil/crypto3/zk/snark/arithmetization/plonk/gate.hpp>
#include <nil/crypto3/zk/transcript/fiat_shamir.hpp>
#include <nil/crypto3/zk/commitments/polynomial/fri.hpp>
#include <nil/crypto3/zk/commitments/polynomial/lpc.hpp>
#include <nil/crypto3/zk/commitments/batched_commitment.hpp>

#include <nil/crypto3/test_tools/random_test_initializer.hpp>

#include "circuits.hpp"

using namespace nil::crypto3;
using namespace nil::crypto3::zk;
using namespace nil::crypto3::zk::snark;


template<typename FieldType,
        typename merkle_hash_type,
        typename transcript_hash_type,
        typename CurveType>
struct lookup_argument_test_runner {
    using field_type = FieldType;
    using value_type = typename field_type::value_type;
    using curve_type = CurveType;
    using polynomial_dfs_type = typename math::polynomial_dfs<typename FieldType::value_type>;

    struct placeholder_test_params {
        constexpr static const std::size_t lambda = 40;
        constexpr static const std::size_t m = 2;
    };

    typedef placeholder_circuit_params<field_type> circuit_params;
    using transcript_type = typename transcript::fiat_shamir_heuristic_sequential<transcript_hash_type>;

    using lpc_params_type = commitments::list_polynomial_commitment_params<
            merkle_hash_type,
            transcript_hash_type,
            placeholder_test_params::m
    >;

    using lpc_type = commitments::list_polynomial_commitment<field_type, lpc_params_type>;
    using lpc_scheme_type = typename commitments::lpc_commitment_scheme<lpc_type>;
    using lpc_placeholder_params_type = nil::crypto3::zk::snark::placeholder_params<circuit_params, lpc_scheme_type>;
    using policy_type = zk::snark::detail::placeholder_policy<field_type, lpc_placeholder_params_type>;
    using circuit_type = circuit_description<field_type, placeholder_circuit_params<field_type>>;
    using central_evaluator_type = CentralAssignmentTableExpressionEvaluator<field_type>;

    lookup_argument_test_runner(const circuit_type &circuit_in)
        : circuit(circuit_in), desc(circuit_in.table.witnesses().size(),
                                        circuit_in.table.public_inputs().size(),
                                        circuit_in.table.constants().size(),
                                        circuit_in.table.selectors().size(),
                                        circuit_in.usable_rows,
                                        circuit_in.table_rows),
              constraint_system(circuit.gates, circuit.copy_constraints, circuit.lookup_gates, circuit.lookup_tables),
              assignments(circuit.table), table_rows_log(std::log2(circuit_in.table_rows)),
              fri_params(1, table_rows_log, placeholder_test_params::lambda, 4) {
    }

    bool run_test() {
        lpc_scheme_type lpc_scheme(fri_params);

        typename placeholder_public_preprocessor<field_type, lpc_placeholder_params_type>::preprocessed_data_type
                preprocessed_public_data = placeholder_public_preprocessor<field_type, lpc_placeholder_params_type>::process(
                constraint_system, assignments.public_table(), desc, lpc_scheme);

        typename placeholder_private_preprocessor<field_type, lpc_placeholder_params_type>::preprocessed_data_type
                preprocessed_private_data = placeholder_private_preprocessor<field_type, lpc_placeholder_params_type>::process(
                constraint_system, assignments.private_table(), desc);

        auto polynomial_table = std::make_shared<plonk_polynomial_dfs_table<field_type>>(
            preprocessed_private_data.private_polynomial_table,
            preprocessed_public_data.public_polynomial_table);

        std::vector<std::uint8_t> init_blob{0, 1, 2, 3, 4, 5, 6, 7, 8, 9};
        transcript_type prover_transcript(init_blob);

        polynomial_dfs_type mask_polynomial(
            0, preprocessed_public_data.common_data->basic_domain->m,
            typename FieldType::value_type(1u)
        );
        mask_polynomial -= preprocessed_public_data.q_last;
        mask_polynomial -= preprocessed_public_data.q_blind;

        std::unique_ptr<central_evaluator_type> central_evaluator = std::make_unique<central_evaluator_type>(
            polynomial_table,
            mask_polynomial,
            preprocessed_public_data.common_data->lagrange_0
        );

        placeholder_lookup_argument_prover<field_type, lpc_scheme_type, lpc_placeholder_params_type> lookup_prover(
                constraint_system, preprocessed_public_data, *central_evaluator, *polynomial_table, lpc_scheme, prover_transcript);
        auto prover_res = lookup_prover.prove_eval();
        auto omega = preprocessed_public_data.common_data->basic_domain->get_domain_element(1);

        // Challenge phase
        value_type y = algebra::random_element<field_type>();
        typename policy_type::evaluation_map columns_at_y;
        for (std::size_t i = 0; i < desc.witness_columns; i++) {

            std::size_t i_global_index = i;

            for (int rotation: preprocessed_public_data.common_data->columns_rotations[i_global_index]) {
                auto key = std::make_tuple(i, rotation,
                                           plonk_variable<value_type>::column_type::witness);
                columns_at_y[key] = polynomial_table->witness(i).evaluate(y * omega.pow(rotation));
            }
        }

        for (std::size_t i = 0; i < 0 + desc.constant_columns; i++) {

            std::size_t i_global_index = desc.witness_columns +
                                         desc.public_input_columns + i;

            for (int rotation: preprocessed_public_data.common_data->columns_rotations[i_global_index]) {
                auto key = std::make_tuple(i, rotation,
                                           plonk_variable<value_type>::column_type::constant);

                columns_at_y[key] = polynomial_table->constant(i).evaluate(y * omega.pow(rotation));
            }
        }

        for (std::size_t i = 0; i < desc.selector_columns; i++) {

            std::size_t i_global_index = desc.witness_columns +
                                         desc.constant_columns +
                                         desc.public_input_columns + i;

            for (int rotation: preprocessed_public_data.common_data->columns_rotations[i_global_index]) {
                auto key = std::make_tuple(i, rotation,
                                           plonk_variable<value_type>::column_type::selector);

                columns_at_y[key] = polynomial_table->selector(i).evaluate(y * omega.pow(rotation));
            }
        }

        lpc_scheme.append_eval_point(LOOKUP_BATCH, y);

        lpc_scheme.commit(PERMUTATION_BATCH);
        lpc_scheme.append_eval_point(PERMUTATION_BATCH, y);
        lpc_scheme.append_eval_point(PERMUTATION_BATCH, preprocessed_public_data.common_data->permutation_parts,
                                     y * omega);

        transcript_type transcript;
        lpc_scheme.setup(transcript, preprocessed_public_data.common_data->commitment_scheme_data);
        auto lpc_proof = lpc_scheme.proof_eval(transcript);

        std::vector<value_type> special_selector_values(3);
        special_selector_values[0] = preprocessed_public_data.common_data->lagrange_0.evaluate(y);
        special_selector_values[1] = preprocessed_public_data.q_last.evaluate(y);
        special_selector_values[2] = preprocessed_public_data.q_blind.evaluate(y);

        // Prepare values of different polynomials required for lookup argument verification.
        std::vector<typename FieldType::value_type> counts;
        typename FieldType::value_type U_value;
        typename FieldType::value_type U_shifted_value;
        std::vector<typename FieldType::value_type> hs;
        std::vector<typename FieldType::value_type> gs;

        placeholder_verifier<field_type, lpc_placeholder_params_type>::prepare_verifier_inputs(
            lpc_proof.z, constraint_system, *preprocessed_public_data.common_data, counts, U_value, U_shifted_value, hs, gs);

        // All rows selector
        {
            auto key = std::make_tuple( PLONK_SPECIAL_SELECTOR_ALL_USABLE_ROWS_SELECTED, 0, plonk_variable<value_type>::column_type::selector);
            columns_at_y[key] = 1 - preprocessed_public_data.q_last.evaluate(y) -preprocessed_public_data.q_blind.evaluate(y) ;
        }
        {
            auto key = std::make_tuple( PLONK_SPECIAL_SELECTOR_ALL_USABLE_ROWS_SELECTED, 1, plonk_variable<value_type>::column_type::selector);
            columns_at_y[key] = 1 - preprocessed_public_data.q_last.evaluate(y * omega) -preprocessed_public_data.q_blind.evaluate(y * omega) ;
        }
        // All rows selector
        {
            auto key = std::make_tuple( -2, 0, plonk_variable<value_type>::column_type::selector);
            columns_at_y[key] = 1 - preprocessed_public_data.q_last.evaluate(y) -preprocessed_public_data.q_blind.evaluate(y) - preprocessed_public_data.common_data->lagrange_0.evaluate(y);
        }
        {
            auto key = std::make_tuple( -2, 1, plonk_variable<value_type>::column_type::selector);
            columns_at_y[key] = 1 - preprocessed_public_data.q_last.evaluate(y * omega) -preprocessed_public_data.q_blind.evaluate(y * omega) - preprocessed_public_data.common_data->lagrange_0.evaluate(y * omega);
        }

        transcript_type verifier_transcript(init_blob);

        placeholder_lookup_argument_verifier<field_type, lpc_type, lpc_placeholder_params_type> lookup_verifier;
        std::array<value_type, argument_size> verifier_res = lookup_verifier.verify_eval(
                *preprocessed_public_data.common_data,
                special_selector_values,
                constraint_system,
                y, columns_at_y,
                counts,
                U_value,
                U_shifted_value,
                hs,
                gs,
                prover_res.lookup_commitment,
                verifier_transcript
        );

        value_type verifier_next_challenge = verifier_transcript.template challenge<field_type>();
        value_type prover_next_challenge = prover_transcript.template challenge<field_type>();
        if (verifier_next_challenge != prover_next_challenge) {
            std::cout << "Challenge mismatch between prover/verifier.";
            return false;
        }

        for (int i = 0; i < argument_size; i++) {
            if (prover_res.F_dfs[i].evaluate(y) != verifier_res[i]) {
                std::cout << prover_res.F_dfs[i].evaluate(y) << "!=" << verifier_res[i] << std::endl;
            }
            for (std::size_t j = 0; j < desc.rows_amount; j++) {
                if (prover_res.F_dfs[i].evaluate(
                        preprocessed_public_data.common_data->basic_domain->get_domain_element(j)) !=
                    field_type::value_type::zero()) {
                    std::cout << "![" << i << "][" << j << "]" << std::endl;
                    return false;
                }
            }
        }
        return true;
    }

private:
    static constexpr std::size_t argument_size = 4;
    circuit_type circuit;
    plonk_table_description<field_type> desc;
    typename policy_type::constraint_system_type constraint_system;
    typename policy_type::variable_assignment_type assignments;
    std::size_t table_rows_log;
    typename lpc_type::fri_type::params_type fri_params;
};

BOOST_AUTO_TEST_SUITE(placeholder_circuit4_lookup_test)
    using curve_type = algebra::curves::pallas;
    using field_type = typename curve_type::base_field_type;
    using hash_type = hashes::keccak_1600<256>;
    using test_runner_type = lookup_argument_test_runner<field_type, hash_type, hash_type, curve_type>;

    BOOST_AUTO_TEST_CASE(circuit3)
    {
        test_tools::random_test_initializer<field_type> random_test_initializer;
        auto circuit = circuit_test_3<field_type>(
                random_test_initializer.alg_random_engines.template get_alg_engine<field_type>(),
                random_test_initializer.generic_random_engine
        );
        test_runner_type test_runner(circuit);
        BOOST_CHECK(test_runner.run_test());
    }

    BOOST_AUTO_TEST_CASE(circuit4)
    {
        test_tools::random_test_initializer<field_type> random_test_initializer;
        auto circuit = circuit_test_4<field_type>(
                random_test_initializer.alg_random_engines.template get_alg_engine<field_type>(),
                random_test_initializer.generic_random_engine
        );
        test_runner_type test_runner(circuit);
        BOOST_CHECK(test_runner.run_test());
    }

BOOST_AUTO_TEST_SUITE_END()
