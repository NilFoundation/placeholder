#ifndef PROOF_GENERATOR_ASSIGNER_PRESET_COMMAND_HPP
#define PROOF_GENERATOR_ASSIGNER_PRESET_COMMAND_HPP

#include <memory>
#include <boost/log/trivial.hpp>
#include <boost/filesystem.hpp>

#include <nil/crypto3/bench/scoped_profiler.hpp>

#include <nil/proof-generator/command_step.hpp>
#include <nil/proof-generator/types/type_system.hpp>
#include <nil/proof-generator/resources.hpp>
#include <nil/proof-generator/marshalling_utils.hpp>
#include <nil/proof-generator/commands/detail/io/circuit_io.hpp>
#include <nil/proof-generator/commands/detail/io/assignment_table_io.hpp>

#include <nil/proof-generator/preset/preset.hpp>
#include <nil/proof-generator/output_artifacts/circuit_writer.hpp>
#include <nil/proof-generator/output_artifacts/output_artifacts.hpp>
#include "nil/crypto3/bench/scoped_profiler.hpp"

namespace nil {
    namespace proof_generator {

        template<typename CurveType, typename HashType>
        struct PresetStep {
            using Types            = TypeSystem<CurveType, HashType>;
            using BlueprintField   = typename Types::BlueprintField;
            using ConstraintSystem = typename Types::ConstraintSystem;
            using AssignmentTable  = typename Types::AssignmentTable;
            using TableDescription = typename Types::TableDescription;

            struct Executor: 
                public command_step, 
                public resources::resources_provider<ConstraintSystem, AssignmentTable, TableDescription>
            {

                Executor(const std::string& circuit_name): circuit_name_(circuit_name) {}

                CommandResult execute() override 
                {
                    using resources::notify;

                    std::shared_ptr<ConstraintSystem> circuit;
                    std::shared_ptr<AssignmentTable> assignment_table;
                    std::shared_ptr<TableDescription> table_description;

                    TIME_LOG_START("Preset")
                    const auto err = CircuitFactory<BlueprintField>::initialize_circuit(
                            circuit_name_, 
                            circuit, 
                            assignment_table, 
                            table_description
                    );
                    TIME_LOG_END("Preset")

                    if (err) {
                        return CommandResult::UnknownError("Can't initialize circuit '{}', err: {}" , circuit_name_, err.value());
                    }

                    notify<ConstraintSystem>(*this, circuit);
                    notify<AssignmentTable> (*this, assignment_table);
                    notify<TableDescription>(*this, table_description);

                    return CommandResult::Ok();
                }

            private:
                const std::string circuit_name_;
            };
        };


        template <typename CurveType, typename HashType>
        class PresetCommand: public command_chain {
        public:
            struct Args { // TODO fill from boost program options and print as help
                std::string circuit_name;
                boost::filesystem::path circuit_file_path;
                boost::filesystem::path assignment_table_file_path;
                nil::proof_generator::OutputArtifacts output_artifacts;                
            };

            PresetCommand(const Args& args) {

                using PresetStep                  = typename PresetStep<CurveType, HashType>::Executor;
                using CircuitWriter               = typename CircuitIO<CurveType, HashType>::Writer;
                using AssignmentTableBinaryWriter = typename AssignmentTableIO<CurveType, HashType>::BinaryWriter;
                using AssignmentTableDebugPrinter = typename AssignmentTableIO<CurveType, HashType>::DebugPrinter;

                auto& circuit_maker = add_step<PresetStep>(args.circuit_name); // init circuit for the given name

                if (!args.circuit_file_path.empty()) {
                    add_step<CircuitWriter>(circuit_maker, args.circuit_file_path); // write circuit to file
                }

                // prints empty table to check if it's working
                if (!args.assignment_table_file_path.empty()) {
                    add_step<AssignmentTableBinaryWriter>(circuit_maker, circuit_maker, args.assignment_table_file_path);
                }

                // prints empty table to check if it's working
                if (!args.output_artifacts.empty()) {
                    add_step<AssignmentTableDebugPrinter>(circuit_maker, circuit_maker, args.output_artifacts);
                }
            }
        };

    } // namespace proof_generator
} // namespace nil

#endif // PROOF_GENERATOR_ASSIGNER_PRESET_COMMAND_HPP
