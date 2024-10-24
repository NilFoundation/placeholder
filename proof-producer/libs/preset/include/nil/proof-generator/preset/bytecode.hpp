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
                std::optional<nil::crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>>& bytecode_circuit,
                std::optional<nil::crypto3::zk::snark::plonk_table<BlueprintFieldType, nil::crypto3::zk::snark::plonk_column<BlueprintFieldType>>>& bytecode_table) {

            using ArithmetizationType =
                    nil::crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>;

            using ComponentType = nil::blueprint::components::zkevm_bytecode<ArithmetizationType, BlueprintFieldType>;

            // initialize assignment table
            nil::crypto3::zk::snark::plonk_table_description<BlueprintFieldType> desc(65,  // witness
                                                                                    1,   // public
                                                                                    5,   // constants
                                                                                    30   // selectors
            );
            bytecode_circuit.emplace();
            bytecode_table.emplace(desc.witness_columns, desc.public_input_columns, desc.constant_columns, desc.selector_columns);
            BOOST_LOG_TRIVIAL(debug) << "bytecode table:\n"
                                    << "witnesses = " << desc.witness_columns
                                    << " public inputs = " << desc.public_input_columns
                                    << " constants = " << desc.constant_columns
                                    << " selectors = " << desc.selector_columns << "\n";

            // Prepare witness container to make an instance of the component
            /*typename ComponentType::manifest_type m = ComponentType::get_manifest();
            size_t witness_amount = *(m.witness_amount->begin());
            std::vector<std::uint32_t> witnesses(witness_amount);
            std::iota(witnesses.begin(), witnesses.end(), 0);  // fill 0, 1, ...

            constexpr size_t max_code_size = 24576;
            ComponentType component_instance = ComponentType(
                witnesses, std::array<std::uint32_t, 1>{0}, std::array<std::uint32_t, 1>{0}, max_code_size);

            auto lookup_tables = component_instance.component_lookup_tables();
            for (auto& [k, v] : lookup_tables) {
                bytecode_circuit->reserve_table(k);
            }

            // TODO: pass a proper public input here
            typename ComponentType::input_type input({}, {}, typename ComponentType::var());

            nil::blueprint::components::generate_circuit(component_instance, *bytecode_circuit,
                                                        *bytecode_table, input, 0);

            nil::crypto3::zk::snark::pack_lookup_tables_horizontal(
                bytecode_circuit->get_reserved_indices(), bytecode_circuit->get_reserved_tables(),
                bytecode_circuit->get_reserved_dynamic_tables(), *bytecode_circuit, *bytecode_table,
                bytecode_table->rows_amount(), 500000);*/

            return {};
        }
    } // proof_generator
} // nil
#endif  // PROOF_GENERATOR_LIBS_PRESET_BYTECODE_HPP_
