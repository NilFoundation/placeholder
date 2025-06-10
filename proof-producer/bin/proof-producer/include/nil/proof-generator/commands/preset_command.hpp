#pragma once

#include <memory>
#include <boost/log/trivial.hpp>
#include <boost/filesystem.hpp>

#include <nil/crypto3/bench/scoped_profiler.hpp>

#include <nil/proof-generator/command_step.hpp>
#include <nil/proof-generator/cli_arg_utils.hpp>
#include <nil/proof-generator/types/type_system.hpp>
#include <nil/proof-generator/resources.hpp>
#include <nil/proof-generator/marshalling_utils.hpp>
#include <nil/proof-generator/commands/detail/io/circuit_io.hpp>
#include <nil/proof-generator/commands/detail/io/assignment_table_io.hpp>

#include <nil/proof-generator/preset/preset.hpp>
#include <nil/proof-generator/output_artifacts/circuit_writer.hpp>
#include <nil/proof-generator/output_artifacts/output_artifacts.hpp>
#include <nil/proof-generator/preset/limits.hpp>

namespace nil {
    namespace proof_producer {

        template<typename CurveType, typename HashType>
        struct PresetStep {
            using Types                  = TypeSystem<CurveType, HashType>;
            using BlueprintField         = typename Types::BlueprintField;
            using ConstraintSystem       = typename Types::ConstraintSystem;
            using AssignmentTable        = typename Types::AssignmentTable;
            using TableDescription       = typename Types::TableDescription;

            struct Executor:
                public command_step,
                public resources::resources_provider<ConstraintSystem, AssignmentTable, TableDescription>
            {

                Executor(const std::string& circuit_name, const CircuitsLimits& circuit_limits):
                    circuit_name_(circuit_name),
                    circuit_limits_(circuit_limits)
                {}

                CommandResult execute() override
                {
                    using resources::notify;

                    std::shared_ptr<ConstraintSystem> circuit;
                    std::shared_ptr<AssignmentTable> assignment_table;
                    std::shared_ptr<TableDescription> table_description;

                    PROFILE_SCOPE("Preset");
                    const auto err = CircuitFactory<BlueprintField>::initialize_circuit(
                            circuit_name_,
                            circuit,
                            assignment_table,
                            table_description,
                            circuit_limits_
                    );
                    PROFILE_SCOPE_END();

                    if (err) {
                        return CommandResult::Error(ResultCode::InvalidInput, "Can't initialize circuit '{}', err: {}" , circuit_name_, err.value());
                    }

                    notify<ConstraintSystem>(*this, circuit);
                    notify<AssignmentTable> (*this, assignment_table);
                    notify<TableDescription>(*this, table_description);

                    return CommandResult::Ok();
                }

            private:
                const std::string circuit_name_;
                const CircuitsLimits circuit_limits_;
            };
        };


        template <typename CurveType, typename HashType>
        class PresetCommand: public command_chain {
        public:
            struct Args {
                std::string circuit_name;
                boost::filesystem::path out_circuit_file_path;
                boost::filesystem::path out_assignment_table_file_path;
                nil::proof_producer::OutputArtifacts output_artifacts;
                nil::proof_producer::CircuitsLimits circuit_limits;

                Args(boost::program_options::options_description& config) {
                    namespace po = boost::program_options;

                    config.add_options()
                        ("circuit-name", po::value(&circuit_name)->required(), "Target circuit name")
                        ("circuit", po::value(&out_circuit_file_path), "Circuit output file")
                        ("assignment-table,t", po::value(&out_assignment_table_file_path), "Assignment table (empty) output file");

                    register_output_artifacts_cli_args(output_artifacts, config);
                    register_circuits_limits_cli_args(circuit_limits, config);
                }
            };

            PresetCommand(const Args& args) {

                using PresetStep                  = typename PresetStep<CurveType, HashType>::Executor;
                using CircuitWriter               = typename CircuitIO<CurveType, HashType>::Writer;
                using AssignmentTableBinaryWriter = typename AssignmentTableIO<CurveType, HashType>::BinaryWriter;
                using AssignmentTableDebugPrinter = typename AssignmentTableIO<CurveType, HashType>::DebugPrinter;

                auto& circuit_maker = add_step<PresetStep>(args.circuit_name, args.circuit_limits); // init circuit for the given name

                if (!args.out_circuit_file_path.empty()) {
                    add_step<CircuitWriter>(circuit_maker, args.out_circuit_file_path); // write circuit to file
                }

                // prints empty table to check if it's working
                if (!args.out_assignment_table_file_path.empty()) {
                    add_step<AssignmentTableBinaryWriter>(circuit_maker, circuit_maker, args.out_assignment_table_file_path);
                }

                // prints empty table to check if it's working
                if (!args.output_artifacts.empty()) {
                    add_step<AssignmentTableDebugPrinter>(circuit_maker, circuit_maker, args.output_artifacts);
                }
            }
        };

    } // namespace proof_producer
} // namespace nil
