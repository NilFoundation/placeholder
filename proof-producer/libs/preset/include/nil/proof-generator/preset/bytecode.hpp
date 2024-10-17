#ifndef PROOF_GENERATOR_LIBS_PRESET_BYTECODE_HPP_
#define PROOF_GENERATOR_LIBS_PRESET_BYTECODE_HPP_

#include <boost/log/core.hpp>
#include <boost/log/expressions.hpp>
#include <boost/log/trivial.hpp>
#include <nil/blueprint/blueprint/plonk/assignment.hpp>
#include <nil/blueprint/zkevm/bytecode.hpp>
#include <optional>
#include <string>

namespace nil {
    namespace proof_generator {
        template<typename BlueprintFieldType>
        std::optional<std::string> initialize_bytecode_circuit(
                nil::blueprint::circuit<nil::crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>>& bytecode_circuit,
                nil::blueprint::assignment<nil::crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>>& bytecode_table) {

            using ArithmetizationType =
                    nil::crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>;

            using CircuitType = nil::blueprint::components::zkevm_bytecode<ArithmetizationType, BlueprintFieldType>;

            // initialize assignment table
            nil::crypto3::zk::snark::plonk_table_description<BlueprintFieldType> desc(65,  // witness
                                                                                    1,   // public
                                                                                    5,   // constants
                                                                                    30   // selectors
            );
            BOOST_LOG_TRIVIAL(debug) << "bytecode table:\n"
                                    << "witnesses = " << desc.witness_columns
                                    << " public inputs = " << desc.public_input_columns
                                    << " constants = " << desc.constant_columns
                                    << " selectors = " << desc.selector_columns << "\n";

            // Prepare witness container to make an instance of the component
            typename CircuitType::manifest_type m = CircuitType::get_manifest();
            size_t witness_amount = *(m.witness_amount->begin());
            std::vector<std::uint32_t> witnesses(witness_amount);
            std::iota(witnesses.begin(), witnesses.end(), 0);  // fill 0, 1, ...

            constexpr size_t max_code_size = 24576;
            CircuitType component_instance = CircuitType(
                witnesses, std::array<std::uint32_t, 1>{0}, std::array<std::uint32_t, 1>{0}, max_code_size);

            auto lookup_tables = component_instance.component_lookup_tables();
            for (auto& [k, v] : lookup_tables) {
                bytecode_circuit.reserve_table(k);
            }

            // TODO: pass a proper public input here
            typename CircuitType::input_type input({}, {}, typename CircuitType::var());

            nil::blueprint::components::generate_circuit(component_instance, bytecode_circuit,
                                                        bytecode_table, input, 0);

            std::size_t cur_selector_id = 0;
            for (const auto& gate : bytecode_circuit.gates()) {
                cur_selector_id = std::max(cur_selector_id, gate.selector_index);
            }
            for (const auto& lookup_gate : bytecode_circuit.lookup_gates()) {
                cur_selector_id = std::max(cur_selector_id, lookup_gate.tag_index);
            }
            cur_selector_id++;
            nil::crypto3::zk::snark::pack_lookup_tables_horizontal(
                bytecode_circuit.get_reserved_indices(), bytecode_circuit.get_reserved_tables(),
                bytecode_circuit.get_reserved_dynamic_tables(), bytecode_circuit, bytecode_table,
                bytecode_table.rows_amount(), 500000);
            // TODO bytecode_table.rows_amount() = 0 here, it's correct?'
            return {};
        }
    } // proof_generator
} // nil
#endif  // PROOF_GENERATOR_LIBS_PRESET_BYTECODE_HPP_
