#ifndef ZKEMV_FRAMEWORK_LIBS_PRESET_BYTECODE_HPP_
#define ZKEMV_FRAMEWORK_LIBS_PRESET_BYTECODE_HPP_

#include <assigner.hpp>
#include <boost/log/core.hpp>
#include <boost/log/expressions.hpp>
#include <boost/log/trivial.hpp>
#include <nil/blueprint/blueprint/plonk/assignment.hpp>
#include <nil/blueprint/zkevm/bytecode.hpp>
#include <optional>
#include <string>

template<typename BlueprintFieldType>
std::optional<std::string> initialize_bytecode_circuit(
    nil::blueprint::circuit<nil::crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>>&
        bytecode_circuit,
    std::unordered_map<nil::evm_assigner::zkevm_circuit,
                       nil::blueprint::assignment<
                           nil::crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>>>&
        assignments) {
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
    using ArithmetizationType =
        nil::crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>;

    auto insert_it = assignments.insert(std::pair<nil::evm_assigner::zkevm_circuit,
                                                  nil::blueprint::assignment<ArithmetizationType>>(
        nil::evm_assigner::zkevm_circuit::BYTECODE,
        nil::blueprint::assignment<ArithmetizationType>(desc)));
    auto& bytecode_table = insert_it.first->second;

    using component_type =
        nil::blueprint::components::zkevm_bytecode<ArithmetizationType, BlueprintFieldType>;

    // Prepare witness container to make an instance of the component
    typename component_type::manifest_type m = component_type::get_manifest();
    size_t witness_amount = *(m.witness_amount->begin());
    std::vector<std::uint32_t> witnesses(witness_amount);
    std::iota(witnesses.begin(), witnesses.end(), 0);  // fill 0, 1, ...

    constexpr size_t max_code_size = 24576;
    component_type component_instance = component_type(
        witnesses, std::array<std::uint32_t, 1>{0}, std::array<std::uint32_t, 1>{0}, max_code_size);

    auto lookup_tables = component_instance.component_lookup_tables();
    for (auto& [k, v] : lookup_tables) {
        bytecode_circuit.reserve_table(k);
    }

    // TODO: pass a proper public input here
    typename component_type::input_type input({}, {}, typename component_type::var());

    nil::blueprint::components::generate_circuit(component_instance, bytecode_circuit,
                                                 bytecode_table, input, 0);

    std::vector<size_t> lookup_columns_indices;
    for (std::size_t i = 1; i < bytecode_table.constants_amount(); i++) {
        lookup_columns_indices.push_back(i);
    }

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
        lookup_columns_indices, cur_selector_id, bytecode_table.rows_amount(), 500000);
    // TODO bytecode_table.rows_amount() = 0 here, it's correct?'
    return {};
}

#endif  // ZKEMV_FRAMEWORK_LIBS_PRESET_BYTECODE_HPP_
