//---------------------------------------------------------------------------//
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

#ifndef PROOF_GENERATOR_ARG_PARSER_HPP
#define PROOF_GENERATOR_ARG_PARSER_HPP

#include <optional>
#include <string>

#include <boost/filesystem/path.hpp>
#include <boost/log/trivial.hpp>

#include <nil/proof-generator/arithmetization_params.hpp>
#include <nil/proof-generator/meta_utils.hpp>

namespace nil {
    namespace proof_generator {

        using CurvesVariant =
            typename tuple_to_variant<typename transform_tuple<CurveTypes, to_type_identity>::type>::type;
        using HashesVariant =
            typename tuple_to_variant<typename transform_tuple<HashTypes, to_type_identity>::type>::type;

        struct ProverOptions {
            std::string stage = "all";
            boost::filesystem::path proof_file_path = "proof.bin";
            boost::filesystem::path json_file_path = "proof.json";
            boost::filesystem::path preprocessed_common_data_path = "preprocessed_common_data.dat";
            boost::filesystem::path preprocessed_public_data_path = "preprocessed_data.dat";
            boost::filesystem::path commitment_scheme_state_path = "commitment_scheme_state.dat";
            boost::filesystem::path updated_commitment_scheme_state_path = "updated_commitment_scheme_state.dat";
            boost::filesystem::path circuit_file_path;
            boost::filesystem::path assignment_table_file_path;
            boost::filesystem::path assignment_description_file_path;
            boost::filesystem::path challenge_file_path;
            boost::filesystem::path theta_power_file_path;
            std::vector<boost::filesystem::path> input_challenge_files;
            std::vector<boost::filesystem::path> partial_proof_files;
            std::vector<boost::filesystem::path> initial_proof_files;
            std::vector<boost::filesystem::path> aggregated_proof_files;
            boost::filesystem::path aggregated_FRI_proof_file = "aggregated_FRI_proof.bin";
            boost::filesystem::path aggregated_challenge_file = "aggregated_challenge.dat";
            boost::filesystem::path consistency_checks_challenges_file = "consistency_check_challenges.dat";
            boost::filesystem::path combined_Q_polynomial_file = "combined_Q.dat";
            std::size_t combined_Q_starting_power;
            std::vector<boost::filesystem::path> input_combined_Q_polynomial_files;
            boost::filesystem::path proof_of_work_output_file = "proof_of_work.dat";
            boost::log::trivial::severity_level log_level = boost::log::trivial::severity_level::info;
            CurvesVariant elliptic_curve_type = type_identity<nil::crypto3::algebra::curves::pallas>{};
            HashesVariant hash_type = type_identity<nil::crypto3::hashes::keccak_1600<256>>{};
            boost::filesystem::path execution_traces_path;

            std::size_t lambda = 9;
            std::size_t grind = 0;
            std::size_t expand_factor = 2;
            std::size_t max_quotient_chunks = 0;
        };

        std::optional<ProverOptions> parse_args(int argc, char* argv[]);

    } // namespace proof_generator
} // namespace nil

#endif // PROOF_GENERATOR_ARG_PARSER_HPP
