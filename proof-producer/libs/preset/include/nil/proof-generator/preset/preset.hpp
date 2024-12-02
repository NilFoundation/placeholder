#ifndef PROOF_GENERATOR_LIBS_PRESET_PRESET_HPP_
#define PROOF_GENERATOR_LIBS_PRESET_PRESET_HPP_

#include <boost/log/core.hpp>
#include <boost/log/expressions.hpp>
#include <boost/log/trivial.hpp>
#include <istream>

#include "nil/proof-generator/preset/bytecode.hpp"
#include "nil/proof-generator/preset/rw.hpp"
#include "nil/proof-generator/preset/zkevm.hpp"
#include "nil/proof-generator/preset/copy.hpp"

#include <optional>
#include <string>
#include <unordered_map>

namespace nil {
    namespace proof_generator {
        namespace circuits {
            using Name = std::string;

            const Name BYTECODE = "bytecode";
            const Name RW = "rw";
            const Name ZKEVM = "zkevm";
            const Name COPY = "copy";

        } // namespace circuits

        template<typename BlueprintFieldType>
        class CircuitFactory {
            static const std::map<const circuits::Name, std::function<std::optional<std::string>(
                    std::optional<blueprint::circuit<nil::crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>>>& circuit,
                    std::optional<nil::crypto3::zk::snark::plonk_assignment_table<BlueprintFieldType>>& assignment_table)>> circuit_selector;
        public:
            static std::optional<std::string> initialize_circuit(const std::string& circuit_name,
                std::optional<blueprint::circuit<nil::crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>>>& circuit,
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
        const std::map<const circuits::Name, std::function<std::optional<std::string>(
                    std::optional<blueprint::circuit<nil::crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>>>& circuit,
                    std::optional<nil::crypto3::zk::snark::plonk_assignment_table<BlueprintFieldType>>& assignment_table)>> CircuitFactory<BlueprintFieldType>::circuit_selector = {
                {circuits::BYTECODE, initialize_bytecode_circuit<BlueprintFieldType>},
                {circuits::RW, initialize_rw_circuit<BlueprintFieldType>},
                {circuits::ZKEVM, initialize_zkevm_circuit<BlueprintFieldType>},
                {circuits::COPY, initialize_copy_circuit<BlueprintFieldType>}
        };
    } // proof_generator
} // nil
#endif  // PROOF_GENERATOR_LIBS_PRESET_PRESET_HPP_
