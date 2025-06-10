#pragma once

#include <memory>
#include <boost/log/trivial.hpp>
#include <boost/filesystem.hpp>

#include <nil/crypto3/bench/scoped_profiler.hpp>

#include <nil/proof-generator/types/type_system.hpp>
#include <nil/proof-generator/command_step.hpp>
#include <nil/proof-generator/commands/detail/io/circuit_io.hpp>
#include <nil/proof-generator/commands/detail/io/assignment_table_io.hpp>
#include <nil/proof-generator/commands/detail/io/preprocessed_data_io.hpp>
#include <nil/proof-generator/commands/detail/io/lpc_scheme_io.hpp>
#include <nil/proof-generator/evm_verifier_print.hpp>
#include <nil/proof-generator/commands/preset_command.hpp>
#include <nil/proof-generator/marshalling_utils.hpp>
#include <nil/proof-generator/resources.hpp>
#include <nil/proof-generator/output_artifacts/output_artifacts.hpp>
#include <nil/proof-generator/commands/detail/commitment_scheme_factory.hpp>

#include <nil/crypto3/zk/snark/systems/plonk/placeholder/preprocessor.hpp>


namespace nil {
    namespace proof_producer {

        template <typename CurveType, typename HashType>
        struct PublicPreprocessStep {
            using Types                   = TypeSystem<CurveType, HashType>;
            using BlueprintField          = typename Types::BlueprintField;
            using PublicPreprocessedData  = typename Types::PublicPreprocessedData;
            using CommonData              = typename Types::CommonData;
            using ConstraintSystem        = typename Types::ConstraintSystem;
            using LpcScheme               = typename Types::LpcScheme;
            using AssignmentTable         = typename Types::AssignmentTable;
            using AssignmentPublicTable   = typename Types::AssignmentPublicTable;
            using TableDescription        = typename Types::TableDescription;
            using PlaceholderParams       = typename Types::PlaceholderParams;
            using CommitmentSchemeFac = CommitmentSchemeFactory<CurveType, HashType>;

            struct Executor: public command_step,
                public resources::resources_provider<PublicPreprocessedData, CommonData, LpcScheme>
            {
                Executor(
                    PlaceholderConfig config,
                    resources::resource_provider<TableDescription>& desc_provider,
                    resources::resource_provider<AssignmentTable>& table_provider,
                    resources::resource_provider<ConstraintSystem>& constraint_provider
                ): commitment_scheme_fac_(config)
                {
                    resources::subscribe_value<TableDescription>(desc_provider, table_description_);
                    resources::subscribe_value<ConstraintSystem>(constraint_provider, constraint_system_);
                    resources::subscribe<AssignmentTable>(table_provider, [&] (std::shared_ptr<AssignmentTable> table) {
                        assignment_public_table_ = table->public_table();
                    });
                }


                CommandResult execute() override {
                    BOOST_ASSERT(table_description_);
                    BOOST_ASSERT(assignment_public_table_);
                    BOOST_ASSERT(constraint_system_);

                    using resources::notify;

                    auto lpc_scheme = commitment_scheme_fac_.make_lpc_scheme(table_description_->rows_amount);

                    BOOST_LOG_TRIVIAL(info) << "Preprocessing public data";

                    PROFILE_SCOPE("Preprocess public data");
                    auto public_preprocessed_data = std::make_shared<PublicPreprocessedData>(
                        nil::crypto3::zk::snark::placeholder_public_preprocessor<BlueprintField, PlaceholderParams>::
                            process(
                                *constraint_system_,
                                assignment_public_table_,
                                *table_description_,
                                *lpc_scheme,
                                commitment_scheme_fac_.config_.max_quotient_chunks
                            )
                    );
                    PROFILE_SCOPE_END();

                    notify<PublicPreprocessedData>(*this, public_preprocessed_data);
                    notify<CommonData>(*this, public_preprocessed_data->common_data);
                    notify<LpcScheme>(*this, lpc_scheme);

                    return CommandResult::Ok();
                }

                CommitmentSchemeFac commitment_scheme_fac_;

                std::shared_ptr<TableDescription> table_description_;
                std::shared_ptr<AssignmentPublicTable> assignment_public_table_;
                std::shared_ptr<ConstraintSystem> constraint_system_;
            };
        };


        template <typename CurveType, typename HashType>
        struct PrivatePreprocessStep {
            using Types = TypeSystem<CurveType, HashType>;
            using BlueprintField = typename Types::BlueprintField;
            using ConstraintSystem = typename Types::ConstraintSystem;
            using AssignmentTable = typename Types::AssignmentTable;
            using AssignmentPrivateTable = typename Types::AssignmentPrivateTable;
            using TableDescription = typename Types::TableDescription;
            using PrivatePreprocessedData = typename Types::PrivatePreprocessedData;
            using PlaceholderParams = typename Types::PlaceholderParams;

            struct Executor:
                public command_step,
                public resources::resource_provider<PrivatePreprocessedData>
            {
                Executor(
                    resources::resource_provider<ConstraintSystem>& constraint_provider,
                    resources::resource_provider<AssignmentTable>& table_provider,
                    resources::resource_provider<TableDescription>& desc_provider
                ) {
                    resources::subscribe_value<ConstraintSystem>(constraint_provider, constraint_system_);
                    resources::subscribe_value<TableDescription>(desc_provider, table_description_);
                    resources::subscribe<AssignmentTable>(table_provider, [&] (std::shared_ptr<AssignmentTable> table) {
                        assignment_private_table_ = table->private_table();
                    });
                }

                CommandResult execute() override {
                    using resources::notify;

                    BOOST_ASSERT(constraint_system_);
                    BOOST_ASSERT(table_description_);
                    BOOST_ASSERT(assignment_private_table_);

                    BOOST_LOG_TRIVIAL(info) << "Preprocessing private data";

                    PROFILE_SCOPE("Preprocess private data");
                    auto private_preprocessed_data = std::make_shared<PrivatePreprocessedData>(
                        nil::crypto3::zk::snark::placeholder_private_preprocessor<BlueprintField, PlaceholderParams>::
                            process(*constraint_system_, assignment_private_table_, *table_description_)
                    );
                    PROFILE_SCOPE_END();

                    notify<PrivatePreprocessedData>(*this, private_preprocessed_data);

                    return CommandResult::Ok();
                }

            private:
                std::shared_ptr<ConstraintSystem> constraint_system_;
                std::shared_ptr<AssignmentPrivateTable> assignment_private_table_;
                std::shared_ptr<TableDescription> table_description_;
            };
        };

        template <typename CurveType, typename HashType>
        struct PreprocessCommand: public command_chain {
            struct Args {
                boost::filesystem::path in_circuit_file_path;
                boost::filesystem::path in_assignment_table_file_path;
                boost::filesystem::path out_assignment_desc_file_path{"assignment_description.desc"};
                boost::filesystem::path out_public_preprocessed_data_file_path{"preprocessed_data.dat"};
                boost::filesystem::path out_common_data_file_path{"preprocessed_common_data.dat"};
                boost::filesystem::path out_lpc_scheme_file_path{"commitment_scheme_state.dat"};
                boost::filesystem::path out_evm_verifier_dir_path;
                OutputArtifacts assignment_debug_opts;
                PlaceholderConfig placeholder_config;

                Args(boost::program_options::options_description& config) {
                    config.add_options()
                        ("circuit", po::value(&in_circuit_file_path)->required(), "Circuit input file")
                        ("assignment-table,t", po::value(&in_assignment_table_file_path)->required(), "Assignment table input file")
                        ("assignment-description-file", make_defaulted_option(out_assignment_desc_file_path), "Assignment table description file")
                        ("public-preprocessed-data", make_defaulted_option(out_public_preprocessed_data_file_path), "Public preprocessed output data file")
                        ("common-data", make_defaulted_option(out_common_data_file_path), "Common data output file")
                        ("commitment-state-file", make_defaulted_option(out_lpc_scheme_file_path), "Commitment state data output file")
                        ("evm-verifier", po::value(&out_evm_verifier_dir_path), "Output folder for EVM verifier");

                    register_output_artifacts_cli_args(assignment_debug_opts, config);
                    register_placeholder_config_cli_args(placeholder_config, config);
                }
            };

            PreprocessCommand(const Args& args) {
                using CircuitReader      = CircuitIO<CurveType, HashType>::Reader;
                using TableReader        = AssignmentTableIO<CurveType, HashType>::TableReader;
                using DescriptionWriter  = AssignmentTableIO<CurveType, HashType>::DescriptionWriter;
                using DebugPrinter       = AssignmentTableIO<CurveType, HashType>::DebugPrinter;
                using PublicPreprocessor = PublicPreprocessStep<CurveType, HashType>::Executor;
                using PublicDataWriter   = PreprocessedPublicDataIO<CurveType, HashType>::Writer;
                using CommonDataWriter   = PreprocessedPublicDataIO<CurveType, HashType>::CommonDataWriter;
                using LpcSchemeWriter    = LpcSchemeIO<CurveType, HashType>::Writer;
                using EvmVerifierPrinter = EvmVerifierDebug<CurveType, HashType>::Printer;

                auto& circuit_reader = add_step<CircuitReader>(args.in_circuit_file_path);             // read circuit file
                auto& table_reader = add_step<TableReader>(args.in_assignment_table_file_path);        // read table file
                if (!args.out_assignment_desc_file_path.empty()) {
                    add_step<DescriptionWriter>(table_reader, args.out_assignment_desc_file_path);  // optional: write table description
                }
                if (!args.assignment_debug_opts.empty()) {
                    add_step<DebugPrinter>(table_reader, table_reader, args.assignment_debug_opts); // optional: print table in debug format
                }

                auto& preprocessor = add_step<PublicPreprocessor>(args.placeholder_config, table_reader, table_reader, circuit_reader); // preprocess public data

                if (!args.out_public_preprocessed_data_file_path.empty()) {
                    add_step<PublicDataWriter>(preprocessor, args.out_public_preprocessed_data_file_path); // optional: write public preprocessed data
                }
                if (!args.out_common_data_file_path.empty()) {
                    add_step<CommonDataWriter>(preprocessor, args.out_common_data_file_path);               // optional: write common data
                }
                if (!args.out_lpc_scheme_file_path.empty()) {
                    add_step<LpcSchemeWriter>(preprocessor, args.out_lpc_scheme_file_path);                 // optional: write lpc scheme
                }

                // TODO it does not seem to be working
                if (!args.out_evm_verifier_dir_path.empty()) {
                    add_step<EvmVerifierPrinter>(circuit_reader, preprocessor, args.out_evm_verifier_dir_path); // optional: print evm verifier
                }
            }
       };
    } // namespace proof_producer
} // namespace nil
