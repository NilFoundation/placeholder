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
#include <nil/proof-generator/assigner/options.hpp>
#include <nil/proof-generator/cli_arg_utils.hpp>


namespace nil {
    namespace proof_producer {

        template<typename CurveType, typename HashType>
        class FastPartialProofCommand: public command_chain {
        public:
            struct Args {
                PlaceholderConfig config;
                std::string circuit_name;
                CircuitsLimits circuit_limits;
                boost::filesystem::path in_trace_file_path;

                boost::filesystem::path out_proof_file_path{"proof.bin"};
                boost::filesystem::path out_challenge_file_path{"challenge.dat"};
                boost::filesystem::path out_theta_power_file_path{"theta_power.dat"};
                boost::filesystem::path out_updated_lpc_scheme_file_path{"updated_commitment_scheme_state.bin"};
                boost::filesystem::path out_common_data_file_path{"preprocessed_common_data.dat"};
                boost::filesystem::path out_assignment_desc_file_path{"assignment_description.desc"};

                Args(boost::program_options::options_description& desc) {
                    namespace po = boost::program_options;

                    desc.add_options()
                        ("circuit-name", po::value(&circuit_name)->required(), "Target circuit name")
                        ("trace", po::value(&in_trace_file_path)->required(), "Base path for EVM trace input files")
                        ("proof", make_defaulted_option(out_proof_file_path), "Proof output file")
                        ("challenge-file", make_defaulted_option(out_challenge_file_path), "Challenge output file")
                        ("theta-power-file", make_defaulted_option(out_theta_power_file_path), "Theta power output file")
                        ("updated-lpc-scheme-file", make_defaulted_option(out_updated_lpc_scheme_file_path), "Updated commitment scheme state output file")
                        ("common-data-file", make_defaulted_option(out_common_data_file_path), "Common data output file")
                        ("assignment-desc-file", make_defaulted_option(out_assignment_desc_file_path), "Assignment description output file");

                    register_placeholder_config_cli_args(config, desc);
                    register_circuits_limits_cli_args(circuit_limits, desc);
                }
            };

            FastPartialProofCommand(const Args& args) {
                using Preset                = PresetStep<CurveType, HashType>::Executor;
                using Assigner              = FillAssignmentStep<CurveType, HashType>::Executor;
                using PublicPreprocessor    = PublicPreprocessStep<CurveType, HashType>::Executor;
                using PrivatePreprocessor   = PrivatePreprocessStep<CurveType, HashType>::Executor;
                using Prover                = ProveStep<CurveType, HashType>::PartialProofGenerator;
                using LpcSchemeWriter       = LpcSchemeIO<CurveType, HashType>::Writer;
                using CommonDataWriter      = PreprocessedPublicDataIO<CurveType, HashType>::CommonDataWriter;
                using AssignmentDescriptionWriter = AssignmentTableIO<CurveType, HashType>::DescriptionWriter;


                auto& circuit_maker        = add_step<Preset>(args.circuit_name, args.circuit_limits);
                auto& assigner             = add_step<Assigner>(circuit_maker, circuit_maker, args.circuit_name, args.in_trace_file_path, AssignerOptions(false, args.circuit_limits));
                auto& public_preprocessor  = add_step<PublicPreprocessor>(args.config, assigner, assigner, circuit_maker);
                auto& private_preprocessor = add_step<PrivatePreprocessor>(circuit_maker, assigner, assigner);

                add_step<Prover>(
                    circuit_maker,
                    assigner,            // for table
                    assigner,            // for table description
                    public_preprocessor, // for public data
                    public_preprocessor, // for LPC scheme
                    private_preprocessor,

                    args.out_proof_file_path,
                    args.out_challenge_file_path,
                    args.out_theta_power_file_path
                );
                add_step<LpcSchemeWriter>(public_preprocessor, args.out_updated_lpc_scheme_file_path);
                add_step<CommonDataWriter>(public_preprocessor, args.out_common_data_file_path);
                add_step<AssignmentDescriptionWriter>(assigner, args.out_assignment_desc_file_path);
            }
        };
    } // namespace proof_producer
} // namespace nil
