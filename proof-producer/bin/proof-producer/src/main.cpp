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
#include <nil/proof-generator/commands/verify_command.hpp>
#include <nil/proof-generator/commands/all_command.hpp>
#include <nil/proof-generator/commands/agg_challenge_command.hpp>
#include <nil/proof-generator/commands/merge_proofs_command.hpp>
#include <nil/proof-generator/commands/compute_combined_q_command.hpp>
#include <nil/proof-generator/commands/aggregated_fri_proof_command.hpp>
#include <nil/proof-generator/commands/gen_consistency_check_command.hpp>



#undef B0

using namespace nil::proof_generator;

template<typename CurveType, typename HashType>
int run_prover(const nil::proof_generator::ProverOptions& prover_options) {
    auto prover_task = [&] {
        CommandResult prover_result = CommandResult::Ok();
        try {
            // TODO parse args individually
            switch (nil::proof_generator::detail::prover_stage_from_string(prover_options.stage)) {
                case nil::proof_generator::detail::ProverStage::ALL:
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
                        .circuit_file_path = prover_options.circuit_file_path,
                        .assignment_table_file_path = prover_options.assignment_table_file_path,
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
                case nil::proof_generator::detail::ProverStage::PRESET:
                {
                    using Command = PresetCommand<CurveType, HashType>;
                    using Args = typename Command::Args;
                    Command cmd(Args{
                        .circuit_name = prover_options.circuit_name,
                        .circuit_file_path = prover_options.circuit_file_path,
                        .assignment_table_file_path = prover_options.assignment_table_file_path,
                        .output_artifacts = prover_options.output_artifacts
                    });
                    prover_result = cmd.execute();
                    break;
                }
                case nil::proof_generator::detail::ProverStage::ASSIGNMENT:
                {
                    using Command = FillAssignmentCommand<CurveType, HashType>;
                    using Args = typename Command::Args;
                    Command cmd(Args{
                        .circuit_name = prover_options.circuit_name,
                        .trace_file_path = prover_options.trace_base_path,
                        .circuit_file_path = prover_options.circuit_file_path,
                        .assignment_table_file_path = prover_options.assignment_table_file_path,
                        .assignment_description_file_path = prover_options.assignment_description_file_path,
                        .output_artifacts = prover_options.output_artifacts
                    });
                    prover_result = cmd.execute();
                    break;
                }
                case nil::proof_generator::detail::ProverStage::PREPROCESS:
                {
                    using Command = PreprocessCommand<CurveType, HashType>;
                    using Args = typename Command::Args;
                    Command cmd(Args{
                        .circuit_file_path = prover_options.circuit_file_path,
                        .assignment_table_file_path = prover_options.assignment_table_file_path,
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
                case nil::proof_generator::detail::ProverStage::PROVE:
                {
                    using Command = ProveCommand<CurveType, HashType>;
                    using Args = typename Command::Args;
                    Command cmd(Args{
                        .circuit_file_path = prover_options.circuit_file_path,
                        .assignment_table_file_path = prover_options.assignment_table_file_path,
                        .public_preprocessed_data_file_path = prover_options.preprocessed_public_data_path,
                        .lpc_scheme_file_path = prover_options.commitment_scheme_state_path,
                        .out_assignment_debug_opts = prover_options.output_artifacts,
                        .out_evm_verifier_dir_path = prover_options.evm_verifier_path,
                        .out_assignment_desc_file_path = prover_options.assignment_description_file_path,
                        .out_proof_file_path = prover_options.proof_file_path,
                        .out_proof_json_file_path = prover_options.json_file_path
                    });
                    prover_result = cmd.execute();
                    break;
                }
                case nil::proof_generator::detail::ProverStage::GENERATE_PARTIAL_PROOF:
                {
                    using Command = PartialProofCommand<CurveType, HashType>;
                    using Args = typename Command::Args;
                    Command cmd(Args{
                        .circuit_file_path = prover_options.circuit_file_path,
                        .assignment_table_file_path = prover_options.assignment_table_file_path,
                        .public_preprocessed_data_file_path = prover_options.preprocessed_public_data_path,
                        .lpc_scheme_file_path = prover_options.commitment_scheme_state_path,
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
                case nil::proof_generator::detail::ProverStage::FAST_GENERATE_PARTIAL_PROOF:
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
                        .trace_file_path = prover_options.trace_base_path,
                        .out_proof_file_path = prover_options.proof_file_path,
                        .out_challenge_file_path = prover_options.challenge_file_path,
                        .out_theta_power_file_path = prover_options.theta_power_file_path,
                        .out_updated_lpc_scheme_file_path = prover_options.updated_commitment_scheme_state_path,
                    });
                    prover_result = cmd.execute();
                    break;
                }
                case nil::proof_generator::detail::ProverStage::VERIFY:
                {
                    using Command = VerifyCommand<CurveType, HashType>;
                    using Args = typename Command::Args;
                    Command cmd(Args{
                        .circuit_file_path = prover_options.circuit_file_path,
                        .assignment_description_file_path  = prover_options.assignment_description_file_path,
                        .common_data_file_path = prover_options.preprocessed_common_data_path,
                        .proof_file_path = prover_options.proof_file_path
                    });
                    prover_result = cmd.execute();
                    break;
                }
                case nil::proof_generator::detail::ProverStage::GENERATE_AGGREGATED_CHALLENGE:
                {
                    using Command = AggregatedChallengeCommand<CurveType, HashType>;
                    using Args = typename Command::Args;
                    Command cmd(Args{
                        .aggregate_input_files = prover_options.input_challenge_files,
                        .aggregated_challenge_file = prover_options.aggregated_challenge_file
                    });
                    prover_result = cmd.execute();
                    break;
                }
                case nil::proof_generator::detail::ProverStage::MERGE_PROOFS:
                {
                    using Command = MergeProofsCommand<CurveType, HashType>;
                    using Args = typename Command::Args;
                    Command cmd(Args{
                        .partial_proof_files = prover_options.partial_proof_files,
                        .initial_proof_files = prover_options.initial_proof_files,
                        .aggregated_FRI_proof_file = prover_options.aggregated_FRI_proof_file,
                        .merged_proof_file = prover_options.proof_file_path
                    });
                    prover_result = cmd.execute();
                    break;
                }
                case nil::proof_generator::detail::ProverStage::COMPUTE_COMBINED_Q:
                {
                    using Command = CombinedQGeneratorCommand<CurveType, HashType>;
                    using Args = typename Command::Args;
                    Command cmd(Args{
                        .lpc_scheme_file = prover_options.commitment_scheme_state_path,
                        .aggregated_challenge_file = prover_options.aggregated_challenge_file,
                        .combined_Q_starting_power = prover_options.combined_Q_starting_power,
                        .combined_Q_polynomial_file = prover_options.combined_Q_polynomial_file
                    });
                    prover_result = cmd.execute();
                    break;
                }
                case nil::proof_generator::detail::ProverStage::GENERATE_AGGREGATED_FRI_PROOF:
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
                        .table_description_file = prover_options.commitment_scheme_state_path,
                        .aggregated_challenge_file = prover_options.aggregated_challenge_file,
                        .input_combined_Q_polynomial_files = prover_options.input_combined_Q_polynomial_files,
                        .aggregated_fri_proof_output_file = prover_options.proof_file_path,
                        .proof_of_work_output_file = prover_options.proof_of_work_output_file,
                        .consistency_checks_challenges_output_file = prover_options.consistency_checks_challenges_file
                    });
                    prover_result = cmd.execute();
                    break;
                }
                case nil::proof_generator::detail::ProverStage::GENERATE_CONSISTENCY_CHECKS_PROOF:
                {
                    using Command = GenerateConsistencyCheckCommand<CurveType, HashType>;
                    using Args = typename Command::Args;
                    Command cmd(Args{
                        .lpc_scheme_file = prover_options.commitment_scheme_state_path,
                        .combined_Q_file = prover_options.combined_Q_polynomial_file,
                        .consistency_checks_challenges_output_file = prover_options.consistency_checks_challenges_file,
                        .output_proof_file = prover_options.proof_file_path
                    });
                    prover_result = cmd.execute();
                    break;
                }
            }
        } catch (const std::exception& e) {
            BOOST_LOG_TRIVIAL(error) << e.what();
            throw e;
            return 1;
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
    auto run_prover_wrapper_void = [&prover_options, &ret]<typename HashTypeIdentity>() {
        using HashType = typename HashTypeIdentity::type;
        ret = run_prover<CurveType, HashType>(prover_options);
    };
    pass_variant_type_to_template_func<HashesVariant>(prover_options.hash_type, run_prover_wrapper_void);
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
    std::optional<nil::proof_generator::ProverOptions> prover_options = nil::proof_generator::parse_args(argc, argv);
    if (!prover_options) {
        // Action has already taken a place (help, version, etc.)
        return 0;
    }
    return initial_wrapper(*prover_options);
}
