#pragma once

#include <optional>

#include <boost/filesystem.hpp>
#include <boost/log/trivial.hpp>
#include <boost/program_options.hpp>

#include <nil/crypto3/marshalling/algebra/types/field_element.hpp>

#include <nil/proof-generator/types/type_system.hpp>
#include <nil/proof-generator/command_step.hpp>
#include <nil/proof-generator/file_operations.hpp>
#include <nil/proof-generator/marshalling_utils.hpp>
#include <nil/proof-generator/resources.hpp>

namespace nil {
    namespace proof_producer {

        template <typename CurveType, typename HashType>
        struct MergeProofsCommand: public command_step {

            using Types                  = TypeSystem<CurveType, HashType>;
            using BlueprintField         = typename Types::BlueprintField;
            using Endianness             = typename Types::Endianness;
            using PlaceholderParams      = typename Types::PlaceholderParams;
            using LpcScheme              = typename Types::LpcScheme;
            using TTypeBase              = typename Types::TTypeBase;
            using Proof                  = typename Types::Proof;
            using FriType                = typename Types::FriType;
            using ProofOfWork            = typename FriType::grinding_type::output_type;

            struct Args {
                std::vector<boost::filesystem::path> in_partial_proof_files;
                std::vector<boost::filesystem::path> in_initial_proof_files;
                boost::filesystem::path in_aggregated_FRI_proof_file;
                boost::filesystem::path in_proof_of_work_file;
                boost::filesystem::path out_merged_proof_file;

                Args(boost::program_options::options_description &desc) {
                    namespace po = boost::program_options;

                    desc.add_options()
                        ("partial-proof", po::value<std::vector<boost::filesystem::path>>(&in_partial_proof_files)->multitoken()->required())
                        ("initial-proof", po::value<std::vector<boost::filesystem::path>>(&in_initial_proof_files)->multitoken()->required())
                        ("aggregated-FRI-proof", po::value<boost::filesystem::path>(&in_aggregated_FRI_proof_file)->required())
                        ("proof-of-work", po::value<boost::filesystem::path>(&in_proof_of_work_file)->required())
                        ("proof", po::value<boost::filesystem::path>(&out_merged_proof_file)->required());
                }
            };

            MergeProofsCommand(Args args): args_(args) {}

            CommandResult execute() override {
                return merge_proofs(
                    args_.in_partial_proof_files,
                    args_.in_initial_proof_files,
                    args_.in_aggregated_FRI_proof_file,
                    args_.in_proof_of_work_file,
                    args_.out_merged_proof_file
                );
            }

        private:
            Args args_;

        private:
            static CommandResult merge_proofs(
                const std::vector<boost::filesystem::path> &partial_proof_files,
                const std::vector<boost::filesystem::path> &initial_proof_files,
                const boost::filesystem::path &aggregated_FRI_file,
                const boost::filesystem::path &proof_of_work_file,
                const boost::filesystem::path &merged_proof_file)
            {
                /* ZK types */
                using placeholder_aggregated_proof_type = nil::crypto3::zk::snark::
                    placeholder_aggregated_proof<BlueprintField, PlaceholderParams>;

                using partial_proof_type = Proof;

                using initial_proof_type = typename LpcScheme::lpc_proof_type;

                /* Marshalling types */
                using partial_proof_marshalled_type = nil::crypto3::marshalling::types::
                    placeholder_proof<TTypeBase, Proof>;

                using initial_proof_marshalling_type = nil::crypto3::marshalling::types::
                    inital_eval_proof<TTypeBase, LpcScheme>;

                using fri_proof_marshalling_type = nil::crypto3::marshalling::types::
                    initial_fri_proof_type<TTypeBase, LpcScheme>;

                using POW_marshalling_type = nil::crypto3::marshalling::types::
                    integral<TTypeBase, ProofOfWork>;

                using merged_proof_marshalling_type = nil::crypto3::marshalling::types::
                    placeholder_aggregated_proof_type<TTypeBase, placeholder_aggregated_proof_type>;

                placeholder_aggregated_proof_type merged_proof;

                if (partial_proof_files.size() != initial_proof_files.size() ) {
                    return CommandResult::Error(ResultCode::ProverError, "Number of partial and initial proof files should match (got {} vs {})",
                        partial_proof_files.size(), initial_proof_files.size());
                }

                // TODO use proof readers?
                for(auto const& partial_proof_file: partial_proof_files) {
                    BOOST_LOG_TRIVIAL(info) << "Reading partial proof from file \"" << partial_proof_file << "\"";
                    auto marshalled_partial_proof = detail::decode_marshalling_from_file<partial_proof_marshalled_type>(partial_proof_file, true);
                    if (!marshalled_partial_proof) {
                        return CommandResult::Error(ResultCode::IOError, "Error reading partial_proof from from {}", partial_proof_file.string());
                    }

                    partial_proof_type partial_proof = nil::crypto3::marshalling::types::
                        make_placeholder_proof<Endianness, Proof>(*marshalled_partial_proof);

                    merged_proof.partial_proofs.emplace_back(partial_proof);
                }

                for(auto const& initial_proof_file: initial_proof_files) {

                    BOOST_LOG_TRIVIAL(info) << "Reading initial proof from file \"" << initial_proof_file << "\"";
                    auto initial_proof =
                        detail::decode_marshalling_from_file<initial_proof_marshalling_type>(initial_proof_file);
                    if (!initial_proof) {
                        return CommandResult::Error(ResultCode::IOError, "Error reading lpc_consistency_proof from from {}", initial_proof_file.string());
                    }

                    merged_proof.aggregated_proof.initial_proofs_per_prover.emplace_back(
                        nil::crypto3::marshalling::types::make_initial_eval_proof<Endianness, LpcScheme>(*initial_proof)
                    );
                }

                BOOST_LOG_TRIVIAL(info) << "Reading aggregated FRI proof from file \"" << aggregated_FRI_file << "\"";

                auto marshalled_fri_proof = detail::decode_marshalling_from_file<fri_proof_marshalling_type>(aggregated_FRI_file);

                if (!marshalled_fri_proof) {
                    return CommandResult::Error(ResultCode::IOError, "Error reading fri_proof from from {}", aggregated_FRI_file.string());
                }
                merged_proof.aggregated_proof.fri_proof =
                    nil::crypto3::marshalling::types::make_initial_fri_proof<Endianness, LpcScheme>(*marshalled_fri_proof);
                
                BOOST_LOG_TRIVIAL(info) << "Reading proof of work from file \"" << proof_of_work_file << "\"";

                auto marshalled_proof_of_work = detail::decode_marshalling_from_file<POW_marshalling_type>(proof_of_work_file);

                if (!marshalled_proof_of_work) {
                    return CommandResult::Error(ResultCode::IOError, "Error reading proof of work from from {}", proof_of_work_file.string());
                }

                merged_proof.aggregated_proof.proof_of_work = marshalled_proof_of_work.value().value();

                BOOST_LOG_TRIVIAL(info) << "Writing merged proof to \"" << merged_proof_file << "\"";

                auto marshalled_proof = nil::crypto3::marshalling::types::fill_placeholder_aggregated_proof
                    <Endianness, placeholder_aggregated_proof_type, partial_proof_type> (merged_proof);

                const auto res = detail::encode_marshalling_to_file<merged_proof_marshalling_type>(merged_proof_file, marshalled_proof);
                if (!res) {
                    return CommandResult::Error(ResultCode::IOError, "Failed to write merged proof to file {}", merged_proof_file.string());
                }

                return CommandResult::Ok();
            }
        };
    } // namespace proof_producer
} // namespace nil
