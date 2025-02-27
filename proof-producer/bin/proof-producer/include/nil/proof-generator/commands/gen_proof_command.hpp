#pragma once

#include <boost/filesystem.hpp>
#include <boost/log/trivial.hpp>

#include <nil/proof-generator/types/type_system.hpp>
#include <nil/proof-generator/command_step.hpp>
#include <nil/proof-generator/resources.hpp>

#include <nil/proof-generator/commands/detail/io/circuit_io.hpp>
#include <nil/proof-generator/commands/detail/io/assignment_table_io.hpp>
#include <nil/proof-generator/commands/detail/io/preprocessed_data_io.hpp>
#include <nil/proof-generator/commands/detail/io/lpc_scheme_io.hpp>
#include <nil/proof-generator/commands/preprocess_command.hpp>
#include <nil/proof-generator/commands/detail/proof_gen.hpp>
#include <nil/proof-generator/commands/fill_assignment_command.hpp>
#include <nil/proof-generator/output_artifacts/output_artifacts.hpp>
#include <nil/proof-generator/cli_arg_utils.hpp>

namespace nil {
    namespace proof_producer {

        template<typename CurveType, typename HashType>
        class ProveCommand: public command_chain {
        public:
            struct Args {
                boost::filesystem::path in_circuit_file_path;
                boost::filesystem::path in_assignment_table_file_path;
                boost::filesystem::path in_public_preprocessed_data_file_path;
                boost::filesystem::path in_lpc_scheme_file_path;

                OutputArtifacts out_assignment_debug_opts;
                boost::filesystem::path out_evm_verifier_dir_path;
                boost::filesystem::path out_assignment_desc_file_path{"assignment_description.desc"};
                boost::filesystem::path out_proof_file_path{"proof.bin"};
                boost::filesystem::path out_proof_json_file_path{"proof.json"};

                Args(boost::program_options::options_description& config) {
                    namespace po = boost::program_options;

                    config.add_options()
                        ("circuit", po::value(&in_circuit_file_path)->required(), "Circuit input file")
                        ("assignment-table,t", po::value(&in_assignment_table_file_path)->required(), "Assignment table input file")
                        ("public-preprocessed-data", po::value(&in_public_preprocessed_data_file_path)->required(), "Public preprocessed data input file")
                        ("commitment-state-file", po::value(&in_lpc_scheme_file_path)->required(), "Commitment state data input file")
                        ("evm-verifier-dir", po::value(&out_evm_verifier_dir_path), "EVM verifier directory")
                        ("assignment-description-file", make_defaulted_option(out_assignment_desc_file_path), "Assignment description output file")
                        ("proof",  make_defaulted_option(out_proof_file_path), "Proof output file")
                        ("proof-json",  make_defaulted_option(out_proof_json_file_path), "Proof JSON output file");

                    register_output_artifacts_cli_args(out_assignment_debug_opts, config);
                }
            };

            ProveCommand(const Args& args) {
                using CircuitReader                = CircuitIO<CurveType, HashType>::Reader;
                using AssignmentTableReader        = AssignmentTableIO<CurveType, HashType>::TableReader;
                using AssignmentDescriptionWriter  = AssignmentTableIO<CurveType, HashType>::DescriptionWriter;
                using AssignmentDebugPrinter       = AssignmentTableIO<CurveType, HashType>::DebugPrinter;
                using PreprocessedPublicDataReader = PreprocessedPublicDataIO<CurveType, HashType>::Reader;
                using LpcSchemeReader              = LpcSchemeIO<CurveType, HashType>::Reader;
                using Prover                       = ProveStep<CurveType, HashType>::ProofGenerator;
                using EvmVerifierDebug             = EvmVerifierDebug<CurveType, HashType>;
                using PrivatePreprocessor          = PrivatePreprocessStep<CurveType, HashType>::Executor;

                auto& circuit_reader = add_step<CircuitReader>(args.in_circuit_file_path);
                auto& table_reader = add_step<AssignmentTableReader>(args.in_assignment_table_file_path);
                if (!args.out_assignment_desc_file_path.empty()) {
                    add_step<AssignmentDescriptionWriter>(table_reader, args.out_assignment_desc_file_path);
                }
                if (!args.out_assignment_debug_opts.empty()) {
                    add_step<AssignmentDebugPrinter>(table_reader, table_reader, args.out_assignment_debug_opts);
                }
                if (!args.out_evm_verifier_dir_path.empty()) {
                    add_step<typename EvmVerifierDebug::PublicInputPrinter>(args.out_evm_verifier_dir_path, table_reader, table_reader);
                }

                auto& public_data_reader   = add_step<PreprocessedPublicDataReader>(args.in_public_preprocessed_data_file_path);
                auto& lpc_scheme_reader    = add_step<LpcSchemeReader>(args.in_lpc_scheme_file_path);
                auto& private_preprocessor = add_step<PrivatePreprocessor>(circuit_reader, table_reader, table_reader);
                add_step<Prover>(
                    circuit_reader,
                    table_reader,
                    table_reader,
                    public_data_reader,
                    lpc_scheme_reader,
                    private_preprocessor,
                    args.out_proof_file_path,
                    args.out_proof_json_file_path
                );
                if (!args.out_evm_verifier_dir_path.empty()) {
                    add_step<typename EvmVerifierDebug::Printer>(circuit_reader, public_data_reader, args.out_evm_verifier_dir_path);
                }
            }
        };
    } // namespace proof_producer
} // namespace nil
