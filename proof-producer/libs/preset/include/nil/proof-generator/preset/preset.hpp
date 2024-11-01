#ifndef PROOF_GENERATOR_LIBS_PRESET_PRESET_HPP_
#define PROOF_GENERATOR_LIBS_PRESET_PRESET_HPP_

#include <boost/log/core.hpp>
#include <boost/log/expressions.hpp>
#include <boost/log/trivial.hpp>
#include <istream>

#include "nil/proof-generator/preset/bytecode.hpp"

#include <optional>
#include <string>
#include <unordered_map>

namespace nil {
    namespace proof_generator {
        template<typename BlueprintFieldType>
        class CircuitFactory {
            static std::map<const std::string, std::function<std::optional<std::string>(
                    std::optional<nil::crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>>& circuit,
                    std::optional<nil::crypto3::zk::snark::plonk_assignment_table<BlueprintFieldType>>& assignment_table)>> circuit_selector;
        public:
            static std::optional<std::string> initialize_circuit(const std::string& circuit_name,
                std::optional<nil::crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>>& circuit,
                std::optional<nil::crypto3::zk::snark::plonk_assignment_table<BlueprintFieldType>>& assignment_table,
                std::optional<nil::crypto3::zk::snark::plonk_table_description<BlueprintFieldType>>& desc) {
                auto find_it = circuit_selector.find(circuit_name);
                if (find_it == circuit_selector.end()) {
                    return "Unknown circuit name " + circuit_name;
                }
                const auto err = find_it->second(circuit, assignment_table);
                if (err) {
                    return err;
                }
                if (!assignment_table) {
                    return "Assignment table was not initialized";
                }
                desc.emplace(assignment_table->witnesses_amount(), assignment_table->public_inputs_amount(), assignment_table->constants_amount(), assignment_table->selectors_amount());
                return {};
            }
        };

        template<typename BlueprintFieldType>
        std::map<const std::string, std::function<std::optional<std::string>(
                    std::optional<nil::crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>>& circuit,
                    std::optional<nil::crypto3::zk::snark::plonk_assignment_table<BlueprintFieldType>>& assignment_table)>> CircuitFactory<BlueprintFieldType>::circuit_selector = {
                {"bytecode", initialize_bytecode_circuit<BlueprintFieldType>}
        };
    } // proof_generator
} // nil
#endif  // PROOF_GENERATOR_LIBS_PRESET_PRESET_HPP_
