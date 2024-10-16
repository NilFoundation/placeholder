#ifndef PROOF_GENERATOR_LIBS_PRESET_PRESET_HPP_
#define PROOF_GENERATOR_LIBS_PRESET_PRESET_HPP_

#include <boost/log/core.hpp>
#include <boost/log/expressions.hpp>
#include <boost/log/trivial.hpp>
#include <istream>

#include "nil/proof-generator/preset/bytecode.hpp"
#include "nil/proof-generator/preset/add.hpp"

#include <optional>
#include <string>
#include <unordered_map>

namespace nil {
    namespace proof_generator {
        template<typename BlueprintFieldType>
        class CircuitFactory {
            static std::map<const std::string, std::function<std::optional<std::string>(
                    std::optional<nil::crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>>& circuit,
                    std::optional<nil::crypto3::zk::snark::plonk_table<BlueprintFieldType, nil::crypto3::zk::snark::plonk_column<BlueprintFieldType>>>& assignments)>> circuit_selector;
        public:
            static std::optional<std::string> initialize_circuit(const std::string& circuit_name,
                std::optional<nil::crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>>& circuit,
                std::optional<nil::crypto3::zk::snark::plonk_table<BlueprintFieldType, nil::crypto3::zk::snark::plonk_column<BlueprintFieldType>>>& assignments) {
                auto find_it = circuit_selector.find(circuit_name);
                if (find_it == circuit_selector.end()) {
                    return "Unknown circuit name " + circuit_name;
                }
                return find_it->second(circuit, assignments);
            }
        };

        template<typename BlueprintFieldType>
        std::map<const std::string, std::function<std::optional<std::string>(
                    std::optional<nil::crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>>& circuit,
                    std::optional<nil::crypto3::zk::snark::plonk_table<BlueprintFieldType, nil::crypto3::zk::snark::plonk_column<BlueprintFieldType>>>& assignments)>> CircuitFactory<BlueprintFieldType>::circuit_selector = {
                {"add", initialize_add_circuit<BlueprintFieldType>},
                {"bytecode", initialize_bytecode_circuit<BlueprintFieldType>}
        };
    } // proof_generator
} // nil
#endif  // PROOF_GENERATOR_LIBS_PRESET_PRESET_HPP_
