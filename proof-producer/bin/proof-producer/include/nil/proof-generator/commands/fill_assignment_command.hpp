#pragma once

#include <memory>
#include <boost/log/trivial.hpp>
#include <boost/filesystem.hpp>

#include <nil/crypto3/bench/scoped_profiler.hpp>

#include <nil/proof-generator/assigner/assigner.hpp>
#include <nil/proof-generator/types/type_system.hpp>
#include <nil/proof-generator/command_step.hpp>
#include <nil/proof-generator/commands/detail/io/circuit_io.hpp>
#include <nil/proof-generator/commands/detail/io/assignment_table_io.hpp>
#include <nil/proof-generator/commands/preset_command.hpp>
#include <nil/proof-generator/resources.hpp>
#include <nil/proof-generator/output_artifacts/output_artifacts.hpp>
#include "nil/proof-generator/preset/limits.hpp"

namespace nil {
    namespace proof_producer {

        template<typename CurveType, typename HashType>
        struct FillAssignmentStep {
            using Types            = TypeSystem<CurveType, HashType>;
            using ConstraintSystem = typename Types::ConstraintSystem;
            using AssignmentTable  = typename Types::AssignmentTable;
            using TableDescription = typename Types::TableDescription;

            struct Executor:
                public command_step,
                public resources::resources_provider<AssignmentTable, TableDescription>
            {

                Executor(
                    resources::resource_provider<AssignmentTable>& table_provider,
                    resources::resource_provider<TableDescription>& desc_provider,
                    const std::string& circuit_name,
                    boost::filesystem::path trace_base_path,
                    const AssignerOptions& assigner_options
                ): circuit_name_(circuit_name),
                   trace_base_path_(trace_base_path),
                   assigner_opts_(assigner_options)
                {
                    resources::subscribe_value<AssignmentTable>(table_provider, assignment_table_);
                    resources::subscribe_value<TableDescription>(desc_provider, table_description_);
                }

                CommandResult execute() override {
                    using resources::notify;

                    if (!assignment_table_ || !table_description_) {
                        return CommandResult::Error(ResultCode::ProverError, "Assignment table is not initialized");
                    }

                    try {
                        PROFILE_SCOPE("Fill assignment table");
                        const auto err = fill_assignment_table_single_thread(*assignment_table_, *table_description_, circuit_name_, trace_base_path_, assigner_opts_);
                        if (err) {
                            return CommandResult::UnknownError("Can't fill assignment table from trace '{}', err: {}" , trace_base_path_.string(), err.value());
                        }
                    } catch (trace_io_error& e) {
                        return CommandResult::Error(ResultCode::IOError, "Can't read trace file: {}", e.what());
                    } catch (trace_parse_error& e) {
                        return CommandResult::Error(ResultCode::InvalidInput, "Can't parse trace file: {}", e.what());
                    } catch (trace_index_mismatch& e) {
                        return CommandResult::Error(ResultCode::InvalidInput, "Trace index mismatch: {}", e.what());
                    } catch (trace_hash_mismatch& e) {
                        return CommandResult::Error(ResultCode::InvalidInput, "Trace hash mismatch in file err: {}", e.what());
                    }

                    notify<AssignmentTable> (*this, assignment_table_);
                    notify<TableDescription>(*this, table_description_);

                    return CommandResult::Ok();
                }

            private:
                const std::string circuit_name_;
                const boost::filesystem::path trace_base_path_;
                const AssignerOptions assigner_opts_;

                std::shared_ptr<AssignmentTable> assignment_table_;
                std::shared_ptr<TableDescription> table_description_;
            };
        };


        template <typename CurveType, typename HashType>
        class FillAssignmentCommand: public command_chain {
        public:
            struct Args {
                std::string circuit_name;
                boost::filesystem::path in_trace_file_path;
                boost::filesystem::path out_circuit_file_path;
                boost::filesystem::path out_assignment_table_file_path;
                boost::filesystem::path out_assignment_description_file_path;
                nil::proof_producer::OutputArtifacts output_artifacts;
                nil::proof_producer::CircuitsLimits circuit_limits;

                Args(boost::program_options::options_description& config) {
                    config.add_options()
                        ("circuit-name", po::value(&circuit_name)->required(), "Target circuit name")
                        ("circuit", po::value(&out_circuit_file_path)->required(), "Circuit output file")
                        ("assignment-table,t", po::value(&out_assignment_table_file_path)->required(), "Assignment table output file")
                        ("assignment-description-file", po::value(&out_assignment_description_file_path)->required(), "Assignment table description output file")
                        ("trace", po::value(&in_trace_file_path), "Base path for EVM trace files");
                    register_output_artifacts_cli_args(output_artifacts, config);
                    register_circuits_limits_cli_args(circuit_limits, config);
                }
            };

            FillAssignmentCommand(const Args& args) {
                using PresetStep                       = typename PresetStep<CurveType, HashType>::Executor;
                using Assigner                         = typename FillAssignmentStep<CurveType, HashType>::Executor;
                using CircuitWriteStep                 = typename CircuitIO<CurveType, HashType>::Writer;
                using AssignmentTableBinaryWriter      = typename AssignmentTableIO<CurveType, HashType>::BinaryWriter;
                using AssignmentTableDescriptionWriter = typename AssignmentTableIO<CurveType, HashType>::DescriptionWriter;
                using AssignmentTableDebugPrinter      = typename AssignmentTableIO<CurveType, HashType>::DebugPrinter;

                // init circuit for the given name
                auto& circuit_maker = add_step<PresetStep>(args.circuit_name, args.circuit_limits);

                // write circuit to file if needed
                if (!args.out_circuit_file_path.empty()) {
                    add_step<CircuitWriteStep>(circuit_maker, args.out_circuit_file_path);
                }

                // fill assignment table
                auto& assigner = add_step<Assigner>(
                    circuit_maker, circuit_maker,
                    args.circuit_name, args.in_trace_file_path,
                    AssignerOptions(false, args.circuit_limits)
                );

                // write assignment table to file if needed
                if (!args.out_assignment_table_file_path.empty()) {
                    add_step<AssignmentTableBinaryWriter>(assigner, assigner, args.out_assignment_table_file_path);
                }

                // write assignment description to file if needed
                if (!args.out_assignment_description_file_path.empty()) {
                    add_step<AssignmentTableDescriptionWriter>(assigner, args.out_assignment_description_file_path);
                }

                // print debug assignment table if needed
                if (!args.output_artifacts.empty()) {
                    add_step<AssignmentTableDebugPrinter>(assigner, assigner, args.output_artifacts);
                }
            }
        };

    } // namespace proof_producer
} // namespace nil
