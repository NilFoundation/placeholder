// Copyright (c) 2018-2021 Mikhail Komarov <nemo@nil.foundation>
//---------------------------------------------------------------------------//
// Copyright (c) 2022 Aleksei Moskvin <alalmoskvin@nil.foundation>
// Copyright (c) 2022 Ilia Shirobokov <i.shirobokov@nil.foundation>
// Copyright (c) 2024 Iosif (x-mass) <x-mass@nil.foundation>
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//    http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//---------------------------------------------------------------------------//

#include <optional>

#include <arg_parser.hpp>
#include <nil/proof-generator/file_operations.hpp>
#include <nil/proof-generator/prover.hpp>

// commands for prover
#include <nil/proof-generator/commands/preset_command.hpp>
#include <nil/proof-generator/commands/fill_assignment_command.hpp>
#include <nil/proof-generator/commands/preprocess_command.hpp>
#include <nil/proof-generator/commands/gen_proof_command.hpp>
#include <nil/proof-generator/commands/gen_partial_proof_command.hpp>
#include <nil/proof-generator/commands/gen_fast_partial_proof_command.hpp>
#include <nil/proof-generator/commands/verify_command.hpp>
#include <nil/proof-generator/commands/all_command.hpp>
#include <nil/proof-generator/commands/agg_challenge_command.hpp>
#include <nil/proof-generator/commands/merge_proofs_command.hpp>
#include <nil/proof-generator/commands/compute_combined_q_command.hpp>
#include <nil/proof-generator/commands/aggregated_fri_proof_command.hpp>
#include <nil/proof-generator/commands/gen_consistency_check_command.hpp>
#include "nil/proof-generator/command_step.hpp"

using namespace nil::proof_producer;

template<typename CurveType, typename HashType>
int run_prover(const nil::proof_producer::ProverOptions& prover_options) {
    auto prover_task = [&] {
        CommandResult prover_result = CommandResult::Ok();
        try {
            // TODO parse args individually
            switch (nil::proof_producer::detail::prover_stage_from_string(prover_options.stage)) {
                case nil::proof_producer::detail::ProverStage::ALL:
                {
                    using Command = AllCommand<CurveType, HashType>;
                    using Args = typename Command::Args;
                    Command cmd(Args{
                        .config = PlaceholderConfig{
                            .max_quotient_chunks = prover_options.max_quotient_chunks,
                            .expand_factor = prover_options.expand_factor,
                            .lambda = prover_options.lambda,
                            .grind = prover_options.grind
                        },
                        .in_circuit_file_path = prover_options.circuit_file_path,
                        .in_assignment_table_file_path = prover_options.assignment_table_file_path,
                        .out_assignment_debug_opts = prover_options.output_artifacts,
                        .out_public_preprocessed_data_file_path = prover_options.preprocessed_public_data_path,
                        .out_common_data_file_path = prover_options.preprocessed_common_data_path,
                        .out_lpc_scheme_file_path = prover_options.commitment_scheme_state_path,
                        .out_evm_verifier_dir_path = prover_options.evm_verifier_path,
                        .out_proof_file_path = prover_options.proof_file_path,
                        .out_json_proof_file_path = prover_options.json_file_path
                    });
                    prover_result = cmd.execute();
                    break;
                }
                case nil::proof_producer::detail::ProverStage::PRESET:
                {
                    using Command = PresetCommand<CurveType, HashType>;
                    using Args = typename Command::Args;
                    Command cmd(Args{
                        .circuit_name = prover_options.circuit_name,
                        .out_circuit_file_path = prover_options.circuit_file_path,
                        .out_assignment_table_file_path = prover_options.assignment_table_file_path,
                        .output_artifacts = prover_options.output_artifacts,
                        .circuit_limits = prover_options.circuits_limits
                    });
                    prover_result = cmd.execute();
                    break;
                }
                case nil::proof_producer::detail::ProverStage::ASSIGNMENT:
                {
                    using Command = FillAssignmentCommand<CurveType, HashType>;
                    using Args = typename Command::Args;
                    Command cmd(Args{
                        .circuit_name = prover_options.circuit_name,
                        .in_trace_file_path = prover_options.trace_base_path,
                        .out_circuit_file_path = prover_options.circuit_file_path,
                        .out_assignment_table_file_path = prover_options.assignment_table_file_path,
                        .out_assignment_description_file_path = prover_options.assignment_description_file_path,
                        .output_artifacts = prover_options.output_artifacts,
                        .circuit_limits = prover_options.circuits_limits
                    });
                    prover_result = cmd.execute();
                    break;
                }
                case nil::proof_producer::detail::ProverStage::PREPROCESS:
                {
                    using Command = PreprocessCommand<CurveType, HashType>;
                    using Args = typename Command::Args;
                    Command cmd(Args{
                        .in_circuit_file_path = prover_options.circuit_file_path,
                        .in_assignment_table_file_path = prover_options.assignment_table_file_path,
                        .out_assignment_desc_file_path = prover_options.assignment_description_file_path,
                        .out_public_preprocessed_data_file_path = prover_options.preprocessed_public_data_path,
                        .out_common_data_file_path = prover_options.preprocessed_common_data_path,
                        .out_lpc_scheme_file_path = prover_options.commitment_scheme_state_path,
                        .out_evm_verifier_dir_path = prover_options.evm_verifier_path, // TODO check what is wrong
                        .assignment_debug_opts = prover_options.output_artifacts,
                        .placeholder_config = PlaceholderConfig{
                            .max_quotient_chunks = prover_options.max_quotient_chunks,
                            .expand_factor = prover_options.expand_factor,
                            .lambda = prover_options.lambda,
                            .grind = prover_options.grind
                        }
                    });
                    prover_result = cmd.execute();
                    break;
                }
                case nil::proof_producer::detail::ProverStage::PROVE:
                {
                    using Command = ProveCommand<CurveType, HashType>;
                    using Args = typename Command::Args;
                    Command cmd(Args{
                        .in_circuit_file_path = prover_options.circuit_file_path,
                        .in_assignment_table_file_path = prover_options.assignment_table_file_path,
                        .in_public_preprocessed_data_file_path = prover_options.preprocessed_public_data_path,
                        .in_lpc_scheme_file_path = prover_options.commitment_scheme_state_path,
                        .out_assignment_debug_opts = prover_options.output_artifacts,
                        .out_evm_verifier_dir_path = prover_options.evm_verifier_path,
                        .out_assignment_desc_file_path = prover_options.assignment_description_file_path,
                        .out_proof_file_path = prover_options.proof_file_path,
                        .out_proof_json_file_path = prover_options.json_file_path
                    });
                    prover_result = cmd.execute();
                    break;
                }
                case nil::proof_producer::detail::ProverStage::GENERATE_PARTIAL_PROOF:
                {
                    using Command = PartialProofCommand<CurveType, HashType>;
                    using Args = typename Command::Args;
                    Command cmd(Args{
                        .in_circuit_file_path = prover_options.circuit_file_path,
                        .in_assignment_table_file_path = prover_options.assignment_table_file_path,
                        .in_public_preprocessed_data_file_path = prover_options.preprocessed_public_data_path,
                        .in_lpc_scheme_file_path = prover_options.commitment_scheme_state_path,
                        .out_assignment_debug_opts = prover_options.output_artifacts,
                        .out_evm_verifier_dir_path = prover_options.evm_verifier_path,
                        .out_assignment_desc_file_path = prover_options.assignment_description_file_path,
                        .out_proof_file_path = prover_options.proof_file_path,
                        .out_challenge_file_path = prover_options.challenge_file_path,
                        .out_theta_power_file_path = prover_options.theta_power_file_path,
                        .out_updated_lpc_scheme_file_path = prover_options.updated_commitment_scheme_state_path
                    });
                    prover_result = cmd.execute();
                    break;
                }
                case nil::proof_producer::detail::ProverStage::FAST_GENERATE_PARTIAL_PROOF:
                {
                    using Command = FastPartialProofCommand<CurveType, HashType>;
                    using Args = typename Command::Args;
                    Command cmd(Args{
                        .config = PlaceholderConfig{
                            .max_quotient_chunks = prover_options.max_quotient_chunks,
                            .expand_factor = prover_options.expand_factor,
                            .lambda = prover_options.lambda,
                            .grind = prover_options.grind
                        },
                        .circuit_name = prover_options.circuit_name,
                        .circuit_limits = prover_options.circuits_limits,
                        .in_trace_file_path = prover_options.trace_base_path,
                        .out_proof_file_path = prover_options.proof_file_path,
                        .out_challenge_file_path = prover_options.challenge_file_path,
                        .out_theta_power_file_path = prover_options.theta_power_file_path,
                        .out_updated_lpc_scheme_file_path = prover_options.updated_commitment_scheme_state_path,
                        .out_common_data_file_path = prover_options.preprocessed_common_data_path,
                        .out_assignment_desc_file_path = prover_options.assignment_description_file_path
                    });
                    prover_result = cmd.execute();
                    break;
                }
                case nil::proof_producer::detail::ProverStage::VERIFY:
                {
                    using Command = VerifyCommand<CurveType, HashType>;
                    using Args = typename Command::Args;
                    Command cmd(Args{
                        .in_circuit_file_path = prover_options.circuit_file_path,
                        .in_assignment_description_file_path  = prover_options.assignment_description_file_path,
                        .in_common_data_file_path = prover_options.preprocessed_common_data_path,
                        .in_proof_file_path = prover_options.proof_file_path
                    });
                    prover_result = cmd.execute();
                    break;
                }
                case nil::proof_producer::detail::ProverStage::GENERATE_AGGREGATED_CHALLENGE:
                {
                    using Command = AggregatedChallengeCommand<CurveType, HashType>;
                    using Args = typename Command::Args;
                    Command cmd(Args{
                        .in_aggregate_files = prover_options.input_challenge_files,
                        .out_aggregated_challenge_file = prover_options.aggregated_challenge_file
                    });
                    prover_result = cmd.execute();
                    break;
                }
                case nil::proof_producer::detail::ProverStage::MERGE_PROOFS:
                {
                    using Command = MergeProofsCommand<CurveType, HashType>;
                    using Args = typename Command::Args;
                    Command cmd(Args{
                        .in_partial_proof_files = prover_options.partial_proof_files,
                        .in_initial_proof_files = prover_options.initial_proof_files,
                        .in_aggregated_FRI_proof_file = prover_options.aggregated_FRI_proof_file,
                        .out_merged_proof_file = prover_options.proof_file_path
                    });
                    prover_result = cmd.execute();
                    break;
                }
                case nil::proof_producer::detail::ProverStage::COMPUTE_COMBINED_Q:
                {
                    using Command = CombinedQGeneratorCommand<CurveType, HashType>;
                    using Args = typename Command::Args;
                    Command cmd(Args{
                        .in_lpc_scheme_file = prover_options.commitment_scheme_state_path,
                        .in_aggregated_challenge_file = prover_options.aggregated_challenge_file,
                        .combined_Q_starting_power = prover_options.combined_Q_starting_power,
                        .out_combined_Q_polynomial_file = prover_options.combined_Q_polynomial_file
                    });
                    prover_result = cmd.execute();
                    break;
                }
                case nil::proof_producer::detail::ProverStage::GENERATE_AGGREGATED_FRI_PROOF:
                {
                    using Command = AggregatedFriProofCommand<CurveType, HashType>;
                    using Args = typename Command::Args;
                    Command cmd(Args{
                        .config = PlaceholderConfig{
                            .max_quotient_chunks = prover_options.max_quotient_chunks,
                            .expand_factor = prover_options.expand_factor,
                            .lambda = prover_options.lambda,
                            .grind = prover_options.grind
                        },
                        .in_table_description_file = prover_options.assignment_description_file_path,
                        .in_aggregated_challenge_file = prover_options.aggregated_challenge_file,
                        .in_combined_Q_polynomial_files = prover_options.input_combined_Q_polynomial_files,
                        .out_aggregated_fri_proof_file = prover_options.proof_file_path,
                        .out_proof_of_work_file = prover_options.proof_of_work_output_file,
                        .out_consistency_checks_challenges_file = prover_options.consistency_checks_challenges_file
                    });
                    prover_result = cmd.execute();
                    break;
                }
                case nil::proof_producer::detail::ProverStage::GENERATE_CONSISTENCY_CHECKS_PROOF:
                {
                    using Command = GenerateConsistencyCheckCommand<CurveType, HashType>;
                    using Args = typename Command::Args;
                    Command cmd(Args{
                        .in_lpc_scheme_file = prover_options.commitment_scheme_state_path,
                        .in_combined_Q_file = prover_options.combined_Q_polynomial_file,
                        .out_consistency_checks_challenges_file = prover_options.consistency_checks_challenges_file,
                        .out_proof_file = prover_options.proof_file_path
                    });
                    prover_result = cmd.execute();
                    break;
                }
            }
        } catch (const std::exception& e) {
            BOOST_LOG_TRIVIAL(error) << "Unhandled exception: " << e.what();
            return static_cast<int>(ResultCode::UnknownError);
        }
        return static_cast<int>(prover_result.result_code());
    };
    return prover_task();
}

// We could either make lambdas for generating Cartesian products of templates,
// but this would lead to callback hell. Instead, we declare extra function for
// each factor. Last declared function starts the chain.
template<typename CurveType>
int hash_wrapper(const ProverOptions& prover_options) {
    int ret;
    if (prover_options.hash_type_str == "keccak") {
        ret = run_prover<CurveType, nil::crypto3::hashes::keccak_1600<256>>(prover_options);
    } else if (prover_options.hash_type_str == "sha256") {
        ret = run_prover<CurveType, nil::crypto3::hashes::sha2<256>>(prover_options);
    } else if (prover_options.hash_type_str == "poseidon") {
        if constexpr (std::is_same<CurveType,nil::crypto3::algebra::curves::pallas>::value) {
            ret = run_prover<CurveType,
                nil::crypto3::hashes::poseidon<nil::crypto3::hashes::detail::pasta_poseidon_policy<typename CurveType::scalar_field_type>>>(prover_options);
        } else {
            ret = run_prover<CurveType,
                nil::crypto3::hashes::poseidon<nil::crypto3::hashes::detail::poseidon_policy<typename CurveType::scalar_field_type, 128, 2>>>(prover_options);
        }
    } else {
        BOOST_LOG_TRIVIAL(error) << "Unknown hash type " << prover_options.hash_type_str;
        return static_cast<int>(ResultCode::InvalidInput);
    }
    return ret;
}

int curve_wrapper(const ProverOptions& prover_options) {
    int ret;
    auto curves_wrapper_void = [&prover_options, &ret]<typename CurveTypeIdentity>() {
        using CurveType = typename CurveTypeIdentity::type;
        ret = hash_wrapper<CurveType>(prover_options);
    };
    pass_variant_type_to_template_func<CurvesVariant>(prover_options.elliptic_curve_type, curves_wrapper_void);
    return ret;
}

int initial_wrapper(const ProverOptions& prover_options) {
    return curve_wrapper(prover_options);
}

int main(int argc, char* argv[]) {
    std::optional<nil::proof_producer::ProverOptions> prover_options = nil::proof_producer::parse_args(argc, argv);
    if (!prover_options) {
        // Action has already taken a place (help, version, etc.)
        return 0;
    }
    return initial_wrapper(*prover_options);
}
