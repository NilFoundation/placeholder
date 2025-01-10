#pragma once

#include <memory>

#include <boost/filesystem.hpp>
#include <boost/log/trivial.hpp>

#include <nil/proof-generator/types/type_system.hpp>
#include <nil/proof-generator/command_step.hpp>
#include <nil/proof-generator/file_operations.hpp>
#include <nil/proof-generator/marshalling_utils.hpp>
#include <nil/proof-generator/resources.hpp>

#include <nil/proof-generator/commands/detail/io/circuit_io.hpp>
#include <nil/proof-generator/commands/detail/io/assignment_table_io.hpp>
#include <nil/proof-generator/commands/detail/io/preprocessed_data_io.hpp>
#include <nil/proof-generator/commands/detail/io/lpc_scheme_io.hpp>
#include <nil/proof-generator/commands/detail/commitment_scheme_factory.hpp>

#include <nil/proof-generator/commands/preprocess_command.hpp>
#include <nil/proof-generator/commands/gen_proof_command.hpp>
#include <nil/proof-generator/output_artifacts/output_artifacts.hpp>



namespace nil {
    namespace proof_generator {

        template<typename CurveType, typename HashType>
        struct VerifyStep {
            using Types                   = TypeSystem<CurveType, HashType>;
            using BlueprintField          = typename Types::BlueprintField;
            using PlaceholderParams       = typename Types::PlaceholderParams;
            using ConstraintSystem        = typename Types::ConstraintSystem;
            using TableDescription        = typename Types::TableDescription;
            using PublicPreprocessedData  = typename Types::PublicPreprocessedData;
            using CommonData              = typename Types::CommonData;
            using LpcScheme               = typename Types::LpcScheme;
            using Proof                   = typename Types::Proof;
            using CommitmentSchemeFac = CommitmentSchemeFactory<CurveType, HashType>;

            struct Verifier: public command_step
            {
                Verifier(
                    PlaceholderConfig config,
                    resources::resource_provider<ConstraintSystem>& constraint_system_provider,
                    resources::resource_provider<TableDescription>& desc_provider,
                    resources::resource_provider<CommonData>& common_data_provider,
                    resources::resource_provider<Proof>& proof_provider
                ): commitment_scheme_fac_(config)
                {
                    using resources::subscribe_value;
                    subscribe_value<ConstraintSystem>(constraint_system_provider, constraint_system_);
                    subscribe_value<TableDescription>(desc_provider, table_description_);
                    subscribe_value<CommonData>(common_data_provider, common_data_);
                    subscribe_value<Proof>(proof_provider, proof_);
                }

                CommandResult execute() override {
                    BOOST_ASSERT(proof_);
                    BOOST_ASSERT(common_data_);
                    BOOST_ASSERT(constraint_system_);
                    BOOST_ASSERT(table_description_);

                    BOOST_LOG_TRIVIAL(info) << "Verifying proof...";

                    auto lpc_scheme = commitment_scheme_fac_.make_lpc_scheme(table_description_->rows_amount);
                    bool verification_result = nil::crypto3::zk::snark::placeholder_verifier<BlueprintField, PlaceholderParams>::process(
                            *common_data_,
                            *proof_,
                            *table_description_,
                            *constraint_system_,
                            *lpc_scheme
                        );

                    if (verification_result) {
                        BOOST_LOG_TRIVIAL(info) << "Proof is verified";
                        return CommandResult::Ok();
                    }
                    return CommandResult::UnknownError("Proof verification failed");
                }

            private:
                CommitmentSchemeFac commitment_scheme_fac_;

                std::shared_ptr<ConstraintSystem> constraint_system_;
                std::shared_ptr<TableDescription> table_description_;
                std::shared_ptr<CommonData> common_data_;
                std::shared_ptr<Proof> proof_;
            };
        };

        template<typename CurveType, typename HashType>
        class VerifyCommand: public command_chain {
        public:
            struct Args {
                PlaceholderConfig config;
                boost::filesystem::path in_circuit_file_path;
                boost::filesystem::path in_assignment_description_file_path;
                boost::filesystem::path in_common_data_file_path;
                boost::filesystem::path in_proof_file_path;
            };

            VerifyCommand(const Args& args) {
                using CircuitReader                = CircuitIO<CurveType, HashType>::Reader;
                using AssignmentDescriptionReader  = AssignmentTableIO<CurveType, HashType>::DescriptionReader;
                using CommonDataReader             = PreprocessedPublicDataIO<CurveType, HashType>::CommonDataReader;
                using ProofReader                  = ProveStep<CurveType, HashType>::ProofReader;
                using Verifier                     = VerifyStep<CurveType, HashType>::Verifier;

                auto& circuit_reader           = add_step<CircuitReader>(args.in_circuit_file_path);
                auto& table_description_reader = add_step<AssignmentDescriptionReader>(args.in_assignment_description_file_path);
                auto& common_data_reader       = add_step<CommonDataReader>(args.in_common_data_file_path);
                auto& proof_reader             = add_step<ProofReader>(args.in_proof_file_path);
                add_step<Verifier>(
                    args.config,
                    circuit_reader,
                    table_description_reader,
                    common_data_reader,
                    proof_reader
                );
            }
        };
    } // namespace proof_generator
} // namespace nil
