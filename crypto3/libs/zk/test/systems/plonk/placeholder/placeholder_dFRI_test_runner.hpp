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
#ifndef CRYPTO3_ZK_TEST_PLACEHOLDER_DFRI_TEST_RUNNER_HPP
#define CRYPTO3_ZK_TEST_PLACEHOLDER_DFRI_TEST_RUNNER_HPP

#include <cmath>
#include <utility>

#include <nil/crypto3/zk/snark/systems/plonk/placeholder/prover.hpp>
#include <nil/crypto3/zk/snark/systems/plonk/placeholder/verifier.hpp>
#include <nil/crypto3/zk/snark/systems/plonk/placeholder/dFRI_verifier.hpp>

#include <nil/crypto3/zk/transcript/fiat_shamir.hpp>

#include <nil/crypto3/zk/commitments/polynomial/fri.hpp>
#include <nil/crypto3/zk/commitments/polynomial/lpc.hpp>
#include <nil/crypto3/zk/commitments/polynomial/kzg.hpp>
#include <nil/crypto3/zk/commitments/polynomial/kzg_v2.hpp>

#include "circuits.hpp"

using namespace nil;
using namespace nil::crypto3;
using namespace nil::crypto3::zk;
using namespace nil::crypto3::zk::snark;

template<typename field_type,
        typename merkle_hash_type,
        typename transcript_hash_type,
        bool UseGrinding = false,
        std::size_t max_quotient_poly_chunks = 0>
struct placeholder_dFRI_test_runner {
    struct placeholder_test_params {
        constexpr static const std::size_t lambda = 40;
        constexpr static const std::size_t m = 2;
    };

    using circuit_params = placeholder_circuit_params<field_type>;
    using transcript_type = typename transcript::fiat_shamir_heuristic_sequential<transcript_hash_type>;

    using lpc_params_type = commitments::list_polynomial_commitment_params<
            merkle_hash_type,
            transcript_hash_type,
            placeholder_test_params::m
    >;

    using lpc_type = commitments::list_polynomial_commitment<field_type, lpc_params_type>;
    using lpc_scheme_type = typename commitments::lpc_commitment_scheme<lpc_type>;
    using lpc_proof_type = typename lpc_scheme_type::lpc_proof_type;
    using lpc_placeholder_params_type = nil::crypto3::zk::snark::placeholder_params<circuit_params, lpc_scheme_type>;
    using policy_type = zk::snark::detail::placeholder_policy<field_type, lpc_placeholder_params_type>;
    using circuit_type = circuit_description<field_type, placeholder_circuit_params<field_type>>;
    using fri_type = typename lpc_scheme_type::fri_type;
    using proof_of_work_type = typename fri_type::grinding_type::output_type;
    using polynomial_type = typename lpc_scheme_type::polynomial_type;
    using public_input_type = std::vector<std::vector<typename field_type::value_type>>;
    using public_preprocessor_type = placeholder_public_preprocessor<field_type, lpc_placeholder_params_type>;
    using private_preprocessor_type = placeholder_private_preprocessor<field_type, lpc_placeholder_params_type>;
    using common_data_type = typename public_preprocessor_type::preprocessed_data_type::common_data_type;

    using placeholder_aggregated_proof_type = nil::crypto3::zk::snark::
                    placeholder_aggregated_proof<field_type, lpc_placeholder_params_type>;

    placeholder_dFRI_test_runner(const circuit_type &circuit1_in, const circuit_type &circuit2_in)
            : circuit1(circuit1_in), desc1(circuit1_in.table.witnesses().size(),
                                        circuit1_in.table.public_inputs().size(),
                                        circuit1_in.table.constants().size(),
                                        circuit1_in.table.selectors().size(),
                                        circuit1_in.usable_rows,
                                        circuit1_in.table_rows),
              circuit2(circuit2_in), desc2(circuit2_in.table.witnesses().size(),
                                        circuit2_in.table.public_inputs().size(),
                                        circuit2_in.table.constants().size(),
                                        circuit2_in.table.selectors().size(),
                                        circuit2_in.usable_rows,
                                        circuit2_in.table_rows),
              constraint_system1(circuit1_in.gates, circuit1_in.copy_constraints, circuit1_in.lookup_gates, circuit1_in.lookup_tables),
              constraint_system2(circuit2_in.gates, circuit2_in.copy_constraints, circuit2_in.lookup_gates, circuit2_in.lookup_tables),
              assignments1(circuit1_in.table),
              assignments2(circuit2_in.table),
              table_rows_log(std::log2(circuit1_in.table_rows)),
              fri_params(1, table_rows_log, placeholder_test_params::lambda, 4) {
        if (circuit1_in.table_rows != circuit2_in.table_rows)
            throw "Tables of different sizes not permitted.";
    }

    // The code in this function generates an aggregated dFRI proof using the provided 2 circuits.
    // It is very similar to the code in the proof-producer. Should something change in the algorithm,
    // The corresponding changes must be made both here and in the proof-producer.
    bool run_test() {
        lpc_scheme_type lpc_scheme1(fri_params);

        typename public_preprocessor_type::preprocessed_data_type
                preprocessed_public_data1 = placeholder_public_preprocessor<field_type, lpc_placeholder_params_type>::process(
                constraint_system1, assignments1.public_table(), desc1, lpc_scheme1, max_quotient_poly_chunks);

        typename private_preprocessor_type::preprocessed_data_type
                preprocessed_private_data1 = placeholder_private_preprocessor<field_type, lpc_placeholder_params_type>::process(
                constraint_system1, assignments1.private_table(), desc1);

        auto prover1 = placeholder_prover<field_type, lpc_placeholder_params_type>(
                preprocessed_public_data1, std::move(preprocessed_private_data1), desc1, constraint_system1,
                lpc_scheme1, true);
        auto partial_proof1 = prover1.process();

        lpc_scheme_type lpc_scheme2(fri_params);

        typename public_preprocessor_type::preprocessed_data_type
                preprocessed_public_data2 = placeholder_public_preprocessor<field_type, lpc_placeholder_params_type>::process(
                constraint_system2, assignments2.public_table(), desc2, lpc_scheme2, max_quotient_poly_chunks);

        typename private_preprocessor_type::preprocessed_data_type
                preprocessed_private_data2 = placeholder_private_preprocessor<field_type, lpc_placeholder_params_type>::process(
                constraint_system2, assignments2.private_table(), desc2);

        auto prover2 = placeholder_prover<field_type, lpc_placeholder_params_type>(
                preprocessed_public_data2, std::move(preprocessed_private_data2), desc2, constraint_system2,
                lpc_scheme2, true);
        auto partial_proof2 = prover2.process();
        
        // Create the aggregated challenge.
        transcript_type transcript_for_aggregation;

        transcript_for_aggregation(prover1.transcript.template challenge<field_type>());
        transcript_for_aggregation(prover2.transcript.template challenge<field_type>());

        // produce the aggregated challenge
        auto aggregated_challenge = transcript_for_aggregation.template challenge<field_type>();

        // This the transcript that our provers will use, it's not the same as 'transcript_for_aggregation', it's the transcript that
        // you get after injesting the aggregated challenge.
        transcript_type aggregated_transcript;
        aggregated_transcript(aggregated_challenge);

        // Set the batches as fixed and states as committed, take the values of theta powers used.
        // lpc_scheme1.set_fixed_polys_values(preprocessed_public_data1.common_data->commitment_scheme_data);
        // lpc_scheme2.set_fixed_polys_values(preprocessed_public_data2.common_data->commitment_scheme_data);

        std::size_t theta_power1 = lpc_scheme1.compute_theta_power_for_combined_Q();

        // We don't use the 'theta_power2' here, but let's keep this code.
        std::size_t theta_power2 = lpc_scheme2.compute_theta_power_for_combined_Q();

        // Calculate combined Q values.
        auto challenge_from_aggregated_transcript = aggregated_transcript.template challenge<field_type>();

        polynomial_type combined_Q1 = lpc_scheme1.prepare_combined_Q(
                    challenge_from_aggregated_transcript, 0);
        polynomial_type combined_Q2 = lpc_scheme2.prepare_combined_Q(
                    challenge_from_aggregated_transcript, theta_power1);

        polynomial_type sum_poly = combined_Q1 + combined_Q2;
        
        lpc_scheme_type lpc_scheme_for_FRI(fri_params);

        typename lpc_scheme_type::fri_proof_type fri_proof;
        std::vector<typename fri_type::field_type::value_type> consistency_checks_challenges;
        proof_of_work_type proof_of_work;
        lpc_scheme_for_FRI.proof_eval_FRI_proof(
            sum_poly, fri_proof, consistency_checks_challenges, proof_of_work,
            aggregated_transcript);

        // Generate consistency check proofs.
        lpc_proof_type initial_proof1 = lpc_scheme1.proof_eval_lpc_proof(consistency_checks_challenges);
        lpc_proof_type initial_proof2 = lpc_scheme2.proof_eval_lpc_proof(consistency_checks_challenges);

        // Aggregate all the parts of proofs into 1 aggregated proof.
        placeholder_aggregated_proof_type agg_proof;
        agg_proof.partial_proofs.emplace_back(partial_proof1);
        agg_proof.partial_proofs.emplace_back(partial_proof2);
        agg_proof.aggregated_proof.initial_proofs_per_prover.emplace_back(initial_proof1);
        agg_proof.aggregated_proof.initial_proofs_per_prover.emplace_back(initial_proof2);
        agg_proof.aggregated_proof.fri_proof = fri_proof;
        agg_proof.aggregated_proof.proof_of_work = proof_of_work;

        // Create LPC schemes for the verifiers.
        lpc_scheme_type verifier_lpc_scheme1(fri_params);
        lpc_scheme_type verifier_lpc_scheme2(fri_params);

        std::vector<std::shared_ptr<common_data_type>> common_datas = {
            std::make_shared<common_data_type>(*preprocessed_public_data1.common_data),
            std::make_shared<common_data_type>(*preprocessed_public_data2.common_data)};
        std::vector<std::shared_ptr<plonk_table_description<field_type>>> table_descriptions = {
            std::make_shared<plonk_table_description<field_type>>(desc1),
            std::make_shared<plonk_table_description<field_type>>(desc2)};
        std::vector<std::shared_ptr<plonk_constraint_system<field_type>>> constraint_systems = {
            std::make_shared<plonk_constraint_system<field_type>>(constraint_system1),
            std::make_shared<plonk_constraint_system<field_type>>(constraint_system2)};
        std::vector<std::shared_ptr<lpc_scheme_type>> commitment_schemes = {
            std::make_shared<lpc_scheme_type>(verifier_lpc_scheme1),
            std::make_shared<lpc_scheme_type>(verifier_lpc_scheme2)};
        std::vector<std::shared_ptr<public_input_type>> public_inputs = {
            std::make_shared<public_input_type>(assignments1.public_inputs()),
            std::make_shared<public_input_type>(assignments2.public_inputs())};

        bool verifier_res = placeholder_DFRI_verifier<field_type, lpc_placeholder_params_type>::process(
                common_datas, agg_proof, table_descriptions, constraint_systems, commitment_schemes, public_inputs);
        return verifier_res;
    }

    // Fields for circuit 1.
    circuit_type circuit1;
    plonk_table_description<field_type> desc1;
    typename policy_type::constraint_system_type constraint_system1;
    typename policy_type::variable_assignment_type assignments1;

    // Fields for circuit 2.
    circuit_type circuit2;
    plonk_table_description<field_type> desc2;
    typename policy_type::constraint_system_type constraint_system2;
    typename policy_type::variable_assignment_type assignments2;

    // Shared parameters, these must match.
    std::size_t table_rows_log;
    typename lpc_type::fri_type::params_type fri_params;
};

#endif // CRYPTO3_ZK_TEST_PLACEHOLDER_DFRI_TEST_RUNNER_HPP
