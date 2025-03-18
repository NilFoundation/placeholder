#pragma once

#include <memory>
#include <optional>

#include <boost/filesystem.hpp>
#include <boost/log/trivial.hpp>
#include <boost/assert.hpp>
#include <boost/program_options.hpp>

#include <nil/proof-generator/types/type_system.hpp>
#include <nil/proof-generator/resources.hpp>
#include <nil/proof-generator/command_step.hpp>
#include <nil/proof-generator/file_operations.hpp>
#include <nil/proof-generator/marshalling_utils.hpp>
#include <nil/proof-generator/commands/detail/io/challenge_io.hpp>
#include <nil/proof-generator/commands/detail/io/lpc_scheme_io.hpp>
#include <nil/proof-generator/commands/detail/io/polynomial_io.hpp>

namespace nil {
    namespace proof_producer {

        template <typename CurveType, typename HashType>
        struct ConsistencyChecksGenerator: public command_step {
            using Types           = TypeSystem<CurveType, HashType>;
            using BlueprintField  = typename Types::BlueprintField;
            using Endianness      = typename Types::Endianness;
            using TTypeBase       = typename Types::TTypeBase;
            using LpcScheme       = typename Types::LpcScheme;
            using LpcProofType    = typename LpcScheme::lpc_proof_type;
            using polynomial_type = typename Types::polynomial_type;

            ConsistencyChecksGenerator(
                resources::resource_provider<LpcScheme>& lpc_scheme_provider,
                const boost::filesystem::path& consistency_checks_challenges_output_file,
                const boost::filesystem::path& output_proof_file
            ) : consistency_checks_challenges_output_file_(consistency_checks_challenges_output_file),
                output_proof_file_(output_proof_file)
            {
                resources::subscribe_value<LpcScheme>(lpc_scheme_provider, lpc_scheme_);
            }

            CommandResult execute() override {
                BOOST_ASSERT(lpc_scheme_);
                return generate_consistency_checks_to_file(
                    lpc_scheme_,
                    consistency_checks_challenges_output_file_,
                    output_proof_file_
                );
            }

            static bool save_lpc_consistency_proof_to_file(
                    const LpcProofType& lpc_consistency_proof,
                    const boost::filesystem::path &output_file
                ) {

                namespace marshalling_types = nil::crypto3::marshalling::types;

                // TODO(martun): consider changinge the class name 'inital_eval_proof'.
                using lpc_consistency_proof_marshalling_type = marshalling_types::inital_eval_proof<TTypeBase, LpcScheme>;

                BOOST_LOG_TRIVIAL(info) << "Writing LPC consistency proof to " << output_file;

                lpc_consistency_proof_marshalling_type marshalled_proof = marshalling_types::fill_initial_eval_proof<Endianness, LpcScheme>(lpc_consistency_proof);

                return detail::encode_marshalling_to_file<lpc_consistency_proof_marshalling_type>(
                    output_file, marshalled_proof);
            }

            static CommandResult generate_consistency_checks_to_file(
                std::shared_ptr<LpcScheme> lpc_scheme,
                const boost::filesystem::path& consistency_checks_challenges_output_file,
                const boost::filesystem::path& output_proof_file)
           {
                using ChallengeIO     = ChallengeIO<CurveType, HashType>;
                using PolynomialIO    = PolynomialIO<CurveType, HashType>;
                using Challenge = typename ChallengeIO::Challenge;

                std::optional<std::vector<Challenge>> challenges = ChallengeIO::read_challenge_vector_from_file(
                    consistency_checks_challenges_output_file);
                if (!challenges)
                    return CommandResult::Error(ResultCode::IOError, "Failed to read challenges from {}", consistency_checks_challenges_output_file.string());

                LpcProofType proof = lpc_scheme->proof_eval_lpc_proof(challenges.value());

                auto const res = save_lpc_consistency_proof_to_file(proof, output_proof_file);
                if (!res)
                    return CommandResult::Error(ResultCode::IOError, "Failed to write proof to file {}", output_proof_file.string());

                return CommandResult::Ok();
            }

        private:
            std::shared_ptr<LpcScheme> lpc_scheme_;

            boost::filesystem::path consistency_checks_challenges_output_file_;
            boost::filesystem::path output_proof_file_;
        };


        template <typename CurveType, typename HashType>
        struct GenerateConsistencyCheckCommand: public command_chain {
            struct Args {
                boost::filesystem::path in_lpc_scheme_file;
                boost::filesystem::path out_consistency_checks_challenges_file;
                boost::filesystem::path out_proof_file;

                Args(boost::program_options::options_description& desc) {
                    namespace po = boost::program_options;

                    desc.add_options()
                        ("commitment-state-file", po::value(&in_lpc_scheme_file)->required(),
                            "Commitment state data input file")
                        ("consistency-checks-challenges-file", po::value(&out_consistency_checks_challenges_file),
                        "A file containing 'lambda' challenges")
                        ("proof", po::value(&out_proof_file)->required(), "Proof output file");
                }
            };

            GenerateConsistencyCheckCommand(const Args& args) {
                using LpcSchemeReader = LpcSchemeIO<CurveType, HashType>::Reader;
                using Generator = ConsistencyChecksGenerator<CurveType, HashType>;

                auto& lpc_scheme_reader = add_step<LpcSchemeReader>(args.in_lpc_scheme_file);
                add_step<Generator>(
                    lpc_scheme_reader,
                    args.out_consistency_checks_challenges_file,
                    args.out_proof_file
                );
            }
        };

    } // namespace proof_producer
} // namespace nil
