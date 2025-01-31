#ifndef PROOF_GENERATOR_LIBS_PRESET_PRESET_HPP_
#define PROOF_GENERATOR_LIBS_PRESET_PRESET_HPP_

#include <boost/log/core.hpp>
#include <boost/log/expressions.hpp>
#include <boost/log/trivial.hpp>

#include <nil/proof-generator/types/type_system.hpp>
#include <nil/proof-generator/preset/bytecode.hpp>
#include <nil/proof-generator/preset/rw.hpp>
#include <nil/proof-generator/preset/zkevm.hpp>
#include <nil/proof-generator/preset/copy.hpp>
#include <nil/proof-generator/preset/exp.hpp>

#include <functional>
#include <optional>
#include <string>

namespace nil {
    namespace proof_generator {
        namespace circuits {
            using Name = std::string;

            const Name BYTECODE = "bytecode";
            const Name RW = "rw";
            const Name ZKEVM = "zkevm";
            const Name COPY = "copy";
            const Name EXP = "exp";

        } // namespace circuits

        template<typename BlueprintFieldType>
        class CircuitFactory {
            using Circuit          = typename PresetTypes<BlueprintFieldType>::ConstraintSystem;
            using AssignmentTable  = typename PresetTypes<BlueprintFieldType>::AssignmentTable;
            using TableDescription = typename PresetTypes<BlueprintFieldType>::TableDescription;

            using CircuitInitializer = std::function<std::optional<std::string>(
                std::shared_ptr<Circuit>& circuit,
                std::shared_ptr<AssignmentTable>& assignment_table,
                const CircuitsLimits& circuits_limits)
            >;

            static const std::map<const circuits::Name, CircuitInitializer> circuit_selector;

        public:
            static std::optional<std::string> initialize_circuit(const std::string& circuit_name,
                std::shared_ptr<Circuit>& circuit,
                std::shared_ptr<AssignmentTable>& assignment_table,
                std::shared_ptr<TableDescription>& desc,
                const CircuitsLimits& circuits_limits
            ) {

                auto find_it = circuit_selector.find(circuit_name);
                if (find_it == circuit_selector.end()) {
                    return "Unknown circuit name " + circuit_name;
                }
                const auto err = find_it->second(circuit, assignment_table, circuits_limits);
                if (err) {
                    return err;
                }
                if (!assignment_table) {
                    return "Assignment table was not initialized";
                }
                desc = std::make_shared<TableDescription>(
                    assignment_table->witnesses_amount(), assignment_table->public_inputs_amount(), assignment_table->constants_amount(), assignment_table->selectors_amount()
                );
                return {};
            }
        };

        template<typename BlueprintFieldType>
        const std::map<const circuits::Name, typename CircuitFactory<BlueprintFieldType>::CircuitInitializer>
            CircuitFactory<BlueprintFieldType>::circuit_selector = {
                {circuits::BYTECODE, initialize_bytecode_circuit<BlueprintFieldType>},
                {circuits::RW, initialize_rw_circuit<BlueprintFieldType>},
                {circuits::ZKEVM, initialize_zkevm_circuit<BlueprintFieldType>},
                {circuits::COPY, initialize_copy_circuit<BlueprintFieldType>},
                {circuits::EXP, initialize_exp_circuit<BlueprintFieldType>},
        };
    } // proof_generator
} // nil
#endif  // PROOF_GENERATOR_LIBS_PRESET_PRESET_HPP_
