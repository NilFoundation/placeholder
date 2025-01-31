#pragma once

#include <optional>

#include <boost/filesystem.hpp>
#include <boost/log/trivial.hpp>

#include <nil/crypto3/marshalling/algebra/types/field_element.hpp>

#include <nil/proof-generator/types/type_system.hpp>
#include <nil/proof-generator/command_step.hpp>
#include <nil/proof-generator/commands/detail/io/challenge_io.hpp>
#include <nil/proof-generator/file_operations.hpp>
#include <nil/proof-generator/marshalling_utils.hpp>
#include <nil/proof-generator/resources.hpp>

namespace nil {
    namespace proof_generator {

        template <typename CurveType, typename HashType>
        struct AggregatedChallengeCommand: public command_step {

            using Types                  = TypeSystem<CurveType, HashType>;
            using BlueprintField         = typename Types::BlueprintField;
            using PlaceholderParams      = typename Types::PlaceholderParams;

            struct Args {
                std::vector<boost::filesystem::path> in_aggregate_files;
                boost::filesystem::path out_aggregated_challenge_file;
            };

            AggregatedChallengeCommand(const Args& args): args_(args) {}

            CommandResult execute() override {
                return generate_aggregated_challenge_to_file(
                    args_.in_aggregate_files,
                    args_.out_aggregated_challenge_file
                );
            }

        private:
            Args args_;

        private:
            static CommandResult generate_aggregated_challenge_to_file(
                    const std::vector<boost::filesystem::path> &aggregate_input_files,
                    const boost::filesystem::path &aggregated_challenge_file
                )
            {
                using ChallengeIO = ChallengeIO<CurveType, HashType>;

                if (aggregate_input_files.empty()) {
                    return CommandResult::UnknownError("No input files for challenge aggregation");
                }
                BOOST_LOG_TRIVIAL(info) << "Generating aggregated challenge to " << aggregated_challenge_file;

                // create the transcript
                using transcript_hash_type = typename PlaceholderParams::transcript_hash_type;
                using transcript_type = crypto3::zk::transcript::fiat_shamir_heuristic_sequential<transcript_hash_type>;
                transcript_type transcript;

                // read challenges from input files and add them to the transcript
                for (const auto &input_file : aggregate_input_files) {
                    std::optional<typename BlueprintField::value_type> challenge = ChallengeIO::read_challenge(input_file);
                    if (!challenge) {
                        return CommandResult::UnknownError("Failed to read challenge from {}", input_file.string());
                    }
                    transcript(challenge.value());
                }

                // produce the aggregated challenge
                auto output_challenge = transcript.template challenge<BlueprintField>();

                auto const res = ChallengeIO::save_challenge(aggregated_challenge_file, output_challenge);
                if (!res) {
                    return CommandResult::UnknownError("Failed to write aggregated challenge to {}", aggregated_challenge_file.string());
                }
                return CommandResult::Ok();
            }
        };
    } // namespace proof_generator
} // namespace nil
