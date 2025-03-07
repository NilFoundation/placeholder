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
#include "nil/proof-generator/output_artifacts/output_artifacts.hpp"


#include <concepts>
#include <unordered_map>

using namespace nil::proof_producer;

template <typename T>
concept ProofProducerStage =
    std::is_base_of_v<command_step, T> && // it is a command
    requires {
        typename T::Args; // it has Args
    } &&
    std::constructible_from<typename T::Args, boost::program_options::options_description&> && // Args can be parsed from boost program options
    std::constructible_from<T, const typename T::Args&>;  // command accepts Args


template <
    template <typename CurveType, typename HashType> typename Command,
    typename CurveType, typename HashType
> requires ProofProducerStage<Command<CurveType, HashType>>
CommandResult run_command(const ProverOptions& opts) {
    namespace po = boost::program_options;

    using CommandType = Command<CurveType, HashType>;

    po::options_description desc("Command options");

    typename CommandType::Args args(desc);

    if (opts.help_mode) {
        std::cout << desc << std::endl;
        return CommandResult::Ok();
    }

    po::variables_map vm;

    auto parsed =
        po::command_line_parser(opts.stage_args)
            .options(desc)
            .run();

    po::store(parsed, vm);
    po::notify(vm);

    CommandType cmd(args);
    return cmd.execute();
}


template<typename CurveType, typename HashType>
int run_prover(const nil::proof_producer::ProverOptions& prover_options) {

    using ProverStage = nil::proof_producer::detail::ProverStage;
    using StageMap = std::unordered_map<ProverStage, std::function<CommandResult(const ProverOptions&)>>;

    static const StageMap stage_map = {
        {ProverStage::ALL, run_command<AllCommand, CurveType, HashType>},
        {ProverStage::PRESET, run_command<PresetCommand, CurveType, HashType>},
        {ProverStage::ASSIGNMENT, run_command<FillAssignmentCommand, CurveType, HashType>},
        {ProverStage::PREPROCESS, run_command<PreprocessCommand, CurveType, HashType>},
        {ProverStage::PROVE, run_command<ProveCommand, CurveType, HashType>},
        {ProverStage::GENERATE_PARTIAL_PROOF, run_command<PartialProofCommand, CurveType, HashType>},
        {ProverStage::FAST_GENERATE_PARTIAL_PROOF, run_command<FastPartialProofCommand, CurveType, HashType>},
        {ProverStage::VERIFY, run_command<VerifyCommand, CurveType, HashType>},
        {ProverStage::GENERATE_AGGREGATED_CHALLENGE, run_command<AggregatedChallengeCommand, CurveType, HashType>},
        {ProverStage::MERGE_PROOFS, run_command<MergeProofsCommand, CurveType, HashType>},
        {ProverStage::COMPUTE_COMBINED_Q, run_command<CombinedQGeneratorCommand, CurveType, HashType>},
        {ProverStage::GENERATE_AGGREGATED_FRI_PROOF, run_command<AggregatedFriProofCommand, CurveType, HashType>},
        {ProverStage::GENERATE_CONSISTENCY_CHECKS_PROOF, run_command<GenerateConsistencyCheckCommand, CurveType, HashType>}
    };

    auto prover_task = [&] {
        CommandResult prover_result = CommandResult::Ok();
        try {
            auto const stage = nil::proof_producer::detail::prover_stage_from_string(prover_options.stage);
            prover_result = stage_map.at(stage)(prover_options);
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
