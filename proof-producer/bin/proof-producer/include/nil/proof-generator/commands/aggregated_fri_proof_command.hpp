#pragma once

#include <memory>
#include <vector>

#include <boost/filesystem.hpp>
#include <boost/assert.hpp>
#include <boost/log/trivial.hpp>

#include <nil/proof-generator/types/type_system.hpp>
#include <nil/proof-generator/resources.hpp>
#include <nil/proof-generator/command_step.hpp>
#include <nil/proof-generator/commands/detail/io/lpc_scheme_io.hpp>
#include <nil/proof-generator/commands/detail/io/challenge_io.hpp>
#include <nil/proof-generator/commands/detail/io/assignment_table_io.hpp>
#include <nil/proof-generator/commands/detail/commitment_scheme_factory.hpp>

#include <nil/proof-generator/commands/preprocess_command.hpp>

#include <nil/crypto3/marshalling/math/types/polynomial.hpp>
#include "nil/proof-generator/commands/detail/io/polynomial_io.hpp"


namespace nil {
    namespace proof_producer {

            template <typename CurveType, typename HashType>
            struct AggregatedFriProofGenerator: public command_step
            {
                using Types                   = TypeSystem<CurveType, HashType>;
                using BlueprintField          = typename Types::BlueprintField;
                using Endianness              = typename Types::Endianness;
                using TTypeBase               = typename Types::TTypeBase;
                using TableDescription        = typename Types::TableDescription;
                using LpcScheme               = typename Types::LpcScheme;
                using FriType                 = typename Types::FriType;
                using PlaceholderParams       = typename Types::PlaceholderParams;
                using polynomial_type         = typename Types::polynomial_type;
                using CommitmentSchemeFac     = CommitmentSchemeFactory<CurveType, HashType>;
                using FriProof                = typename LpcScheme::fri_proof_type;
                using ProofOfWork             = typename FriType::grinding_type::output_type;

                AggregatedFriProofGenerator(
                    PlaceholderConfig config,
                    resources::resource_provider<TableDescription>& table_description_provider,
                    const boost::filesystem::path &aggregated_challenge_file,
                    const std::vector<boost::filesystem::path>& input_combined_Q_polynomial_files,
                    const boost::filesystem::path& aggregated_fri_proof_output_file,
                    const boost::filesystem::path& proof_of_work_output_file,
                    const boost::filesystem::path& consistency_checks_challenges_output_file
                ): commitment_scheme_fac_(config),
                   aggregated_challenge_file_(aggregated_challenge_file),
                   input_combined_Q_polynomial_files_(input_combined_Q_polynomial_files),
                   aggregated_fri_proof_output_file_(aggregated_fri_proof_output_file),
                   proof_of_work_output_file_(proof_of_work_output_file),
                   consistency_checks_challenges_output_file_(consistency_checks_challenges_output_file)
                {
                    resources::subscribe_value<TableDescription>(table_description_provider, table_description_);
                }

                CommandResult execute() override {
                    return generate_aggregated_FRI_proof_to_file(
                        aggregated_challenge_file_,
                        input_combined_Q_polynomial_files_,
                        aggregated_fri_proof_output_file_,
                        proof_of_work_output_file_,
                        consistency_checks_challenges_output_file_);
                }

            private:
                bool save_fri_proof_to_file(
                        const FriProof& fri_proof,
                        const boost::filesystem::path &output_file)
                {
                    using fri_proof_marshalling_type = nil::crypto3::marshalling::types::initial_fri_proof_type<
                        TTypeBase, LpcScheme>;

                    BOOST_LOG_TRIVIAL(info) << "Writing aggregated FRI proof to " << output_file;

                    fri_proof_marshalling_type marshalled_proof = nil::crypto3::marshalling::types::fill_initial_fri_proof<Endianness, LpcScheme>(fri_proof);

                    return detail::encode_marshalling_to_file<fri_proof_marshalling_type>(
                        output_file, marshalled_proof);
                }

                bool save_proof_of_work(
                    const ProofOfWork& proof_of_work,
                    const boost::filesystem::path& output_file
                ) {
                    using POW_marshalling_type = nil::crypto3::marshalling::types::integral<TTypeBase, ProofOfWork>;
                    BOOST_LOG_TRIVIAL(info) << "Writing proof of work to " << output_file;

                    POW_marshalling_type marshalled_pow(proof_of_work);

                    return detail::encode_marshalling_to_file<POW_marshalling_type>(
                        output_file, marshalled_pow);
                }


                CommandResult generate_aggregated_FRI_proof_to_file(
                    const boost::filesystem::path &aggregated_challenge_file,
                    const std::vector<boost::filesystem::path>& input_combined_Q_polynomial_files,
                    const boost::filesystem::path& aggregated_fri_proof_output_file,
                    const boost::filesystem::path& proof_of_work_output_file,
                    const boost::filesystem::path& consistency_checks_challenges_output_file)
                {
                    using ChallengeIO  = ChallengeIO<CurveType, HashType>;
                    using PolynomialIO = PolynomialIO<CurveType, HashType>;

                    BOOST_ASSERT(table_description_);

                    std::optional<typename BlueprintField::value_type> aggregated_challenge = ChallengeIO::read_challenge(
                        aggregated_challenge_file);
                    if (!aggregated_challenge) {
                        return CommandResult::Error(ResultCode::IOError, "Failed to read aggregated challenge from {}", aggregated_challenge_file.string());
                    }

                    // create the transcript
                    using transcript_hash_type = typename PlaceholderParams::transcript_hash_type;
                    using transcript_type = crypto3::zk::transcript::fiat_shamir_heuristic_sequential<transcript_hash_type>;
                    transcript_type transcript;

                    transcript(aggregated_challenge.value());

                    // Sum up all the polynomials from the files.
                    polynomial_type sum_poly;
                    for (const auto& path : input_combined_Q_polynomial_files) {
                        std::optional<polynomial_type> next_combined_Q = PolynomialIO::read_poly_from_file(path);
                        if (!next_combined_Q) {
                            return CommandResult::Error(ResultCode::IOError, "Failed to read next combined Q from {}", path.string());
                        }
                        sum_poly += next_combined_Q.value();
                    }
                    auto lpc_scheme = commitment_scheme_fac_.make_lpc_scheme(table_description_->rows_amount);
                    auto [fri_proof, challenges] = lpc_scheme->proof_eval_FRI_proof(sum_poly, transcript);

                    // And finally run proof of work.
                    ProofOfWork proof_of_work = nil::crypto3::zk::algorithms::run_grinding<FriType>(lpc_scheme->get_fri_params(), transcript);

                    auto res = save_fri_proof_to_file(fri_proof, aggregated_fri_proof_output_file);
                    if (!res) {
                        return CommandResult::Error(ResultCode::IOError, "Failed to write aggregated FRI proof to file.");
                    }

                    res = save_proof_of_work(proof_of_work, proof_of_work_output_file);
                    if (!res) {
                        return CommandResult::Error(ResultCode::IOError, "Failed to write proof of work to file.");
                    }

                    res = ChallengeIO::save_challenge_vector_to_file(challenges, consistency_checks_challenges_output_file);
                    if (!res) {
                        return CommandResult::Error(ResultCode::IOError, "Failed to write consistency checks challenges to file.");
                    }

                    return CommandResult::Ok();
                }

            private:
                std::shared_ptr<TableDescription> table_description_;

                CommitmentSchemeFac commitment_scheme_fac_;

                boost::filesystem::path aggregated_challenge_file_;
                std::vector<boost::filesystem::path> input_combined_Q_polynomial_files_;
                boost::filesystem::path aggregated_fri_proof_output_file_;
                boost::filesystem::path proof_of_work_output_file_;
                boost::filesystem::path consistency_checks_challenges_output_file_;
            };

        template <typename CurveType, typename HashType>
        struct AggregatedFriProofCommand: public command_chain {

            struct Args {
                PlaceholderConfig config;
                boost::filesystem::path in_table_description_file;
                boost::filesystem::path in_aggregated_challenge_file;
                std::vector<boost::filesystem::path> in_combined_Q_polynomial_files;
                boost::filesystem::path out_aggregated_fri_proof_file;
                boost::filesystem::path out_proof_of_work_file;
                boost::filesystem::path out_consistency_checks_challenges_file;
            };

            AggregatedFriProofCommand(const Args& args) {
                using TableDescriptionReader = AssignmentTableIO<CurveType, HashType>::DescriptionReader;

                // TODO(oclaw) this command may be splitted to steps if some of the steps are reusable (or operate large data)
                using AggregatedFriProofGenerator = AggregatedFriProofGenerator<CurveType, HashType>;

                auto& table_description_provider = add_step<TableDescriptionReader>(args.in_table_description_file);
                add_step<AggregatedFriProofGenerator>(
                    args.config,
                    table_description_provider,
                    args.in_aggregated_challenge_file,
                    args.in_combined_Q_polynomial_files,
                    args.out_aggregated_fri_proof_file,
                    args.out_proof_of_work_file,
                    args.out_consistency_checks_challenges_file
                );
            }
        };

    } // namespace proof_producer
} // namespace nil
