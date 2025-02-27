#pragma once

#include <boost/assert.hpp>
#include <boost/filesystem.hpp>
#include <boost/log/trivial.hpp>

#include <nil/proof-generator/types/type_system.hpp>
#include <nil/proof-generator/command_step.hpp>
#include <nil/proof-generator/commands/detail/io/circuit_io.hpp>
#include <nil/proof-generator/commands/detail/io/assignment_table_io.hpp>
#include <nil/proof-generator/evm_verifier_print.hpp>
#include <nil/proof-generator/commands/preprocess_command.hpp>
#include <nil/proof-generator/commands/gen_proof_command.hpp>
#include <nil/proof-generator/commands/verify_command.hpp>
#include <nil/proof-generator/output_artifacts/output_artifacts.hpp>
#include <nil/proof-generator/cli_arg_utils.hpp>

namespace nil {
    namespace proof_producer {

        template<typename CurveType, typename HashType>
        class AllCommand: public command_chain {
        public:
            struct Args {
                PlaceholderConfig config;
                boost::filesystem::path in_circuit_file_path;
                boost::filesystem::path in_assignment_table_file_path;

                OutputArtifacts out_assignment_debug_opts;
                boost::filesystem::path out_public_preprocessed_data_file_path{"preprocessed_data.dat"};
                boost::filesystem::path out_common_data_file_path{"preprocessed_common_data.dat"};
                boost::filesystem::path out_lpc_scheme_file_path{"commitment_scheme_state.dat"};
                boost::filesystem::path out_evm_verifier_dir_path;
                boost::filesystem::path out_proof_file_path{"proof.bin"};
                boost::filesystem::path out_json_proof_file_path{"proof.json"};

                Args(boost::program_options::options_description& config) {
                    namespace po = boost::program_options;

                    config.add_options()
                        ("circuit", po::value(&in_circuit_file_path)->required(), "Circuit input file")
                        ("assignment-table,t", po::value(&in_assignment_table_file_path)->required(), "Assignment table input file")
                        ("public-preprocessed-data", make_defaulted_option(out_public_preprocessed_data_file_path), "Public preprocessed output data file")
                        ("common-data", make_defaulted_option(out_common_data_file_path), "Common data output file")
                        ("commitment-state-file", make_defaulted_option(out_lpc_scheme_file_path), "Commitment state data output file")
                        ("evm-verifier", po::value(&out_evm_verifier_dir_path), "Output folder for EVM verifier")
                        ("proof",  make_defaulted_option(out_proof_file_path), "Proof output file")
                        ("proof-json",  make_defaulted_option(out_json_proof_file_path), "Proof JSON output file");

                    register_output_artifacts_cli_args(out_assignment_debug_opts, config);
                    register_placeholder_config_cli_args(this->config, config);
                }
            };

            AllCommand(const Args& args) {
                using CircuitReader               = CircuitIO<CurveType, HashType>::Reader;
                using AssignmentTableReader       = AssignmentTableIO<CurveType, HashType>::TableReader;
                using AssignmentTableDebugPrinter = AssignmentTableIO<CurveType, HashType>::DebugPrinter;
                using EvmVerifierDebug            = EvmVerifierDebug<CurveType, HashType>;
                using PublicPreprocessor          = PublicPreprocessStep<CurveType, HashType>::Executor;
                using PublicDataWriter            = PreprocessedPublicDataIO<CurveType, HashType>::Writer;
                using CommonDataWriter            = PreprocessedPublicDataIO<CurveType, HashType>::CommonDataWriter;
                using PrivatePreprocessor         = PrivatePreprocessStep<CurveType, HashType>::Executor;
                using LpcSchemeWriter             = LpcSchemeIO<CurveType, HashType>::Writer;
                using Prover                      = ProveStep<CurveType, HashType>::ProofGenerator;
                using Verifier                    = VerifyStep<CurveType, HashType>::Verifier;

                auto& circuit_reader = add_step<CircuitReader>(args.in_circuit_file_path);                // read circuit file
                auto& table_reader = add_step<AssignmentTableReader>(args.in_assignment_table_file_path); // read table file

                // optional: print table in debug format
                if (!args.out_assignment_debug_opts.empty()) {
                    add_step<AssignmentTableDebugPrinter>(table_reader, table_reader, args.out_assignment_debug_opts);
                }

                // optional: print public input for evm verifier
                if (!args.out_evm_verifier_dir_path.empty()) {
                    add_step<typename EvmVerifierDebug::PublicInputPrinter>(args.out_evm_verifier_dir_path, table_reader, table_reader);
                }

                auto& public_preprocessor = add_step<PublicPreprocessor>( // preprocess public data
                    args.config,
                    table_reader,
                    table_reader,
                    circuit_reader
                );
                auto& private_preprocessor = add_step<PrivatePreprocessor>(circuit_reader, table_reader, table_reader); // preprocess private data
                auto& prover = add_step<Prover>(                                                                             // generate proof
                    circuit_reader,
                    table_reader,           // for table
                    table_reader,           // for table description
                    public_preprocessor,    // for public data
                    public_preprocessor,    // for LPC scheme
                    private_preprocessor,
                    args.out_proof_file_path,
                    args.out_json_proof_file_path
                );
                add_step<Verifier>(
                    args.config,
                    circuit_reader,
                    table_reader,
                    public_preprocessor,
                    prover
                );

                // optional: write public preprocessed data
                if (!args.out_public_preprocessed_data_file_path.empty()) {
                    add_step<PublicDataWriter>(public_preprocessor, args.out_public_preprocessed_data_file_path);
                }

                // optional: write common data
                if (!args.out_common_data_file_path.empty()) {
                    add_step<CommonDataWriter>(public_preprocessor, args.out_common_data_file_path);
                }

                // optional: write lpc scheme
                if (!args.out_lpc_scheme_file_path.empty()) {
                    add_step<LpcSchemeWriter>(public_preprocessor, args.out_lpc_scheme_file_path);
                }

                // optional: print evm verifier
                if (!args.out_evm_verifier_dir_path.empty()) {
                    add_step<typename EvmVerifierDebug::Printer>(circuit_reader, public_preprocessor, args.out_evm_verifier_dir_path);
                }
            }
        };
    } // namespace proof_producer
} // namespace nil
