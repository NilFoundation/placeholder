#pragma once

#include <assigner.hpp>
#include <boost/log/core.hpp>
#include <boost/log/expressions.hpp>
#include <boost/log/trivial.hpp>
#include <cstddef>
#include <nil/blueprint/blueprint/plonk/assignment.hpp>
#include <nil/blueprint/zkevm_bbf/l1_wrapper.hpp>
#include <nil/blueprint/zkevm_bbf/rw.hpp>
#include <optional>
#include <string>

template<typename BlueprintFieldType>
std::optional<std::string> initialize_rw_circuit(
    nil::blueprint::circuit<nil::crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>>&
        rw_circuit,
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
    BOOST_LOG_TRIVIAL(debug) << "rw table:\n"
                             << "witnesses = " << desc.witness_columns
                             << " public inputs = " << desc.public_input_columns
                             << " constants = " << desc.constant_columns
                             << " selectors = " << desc.selector_columns << "\n";
    using ArithmetizationType =
        nil::crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>;

    std::size_t start_row = 0;

    std::vector<std::size_t> witnesses;
    for( std::size_t i = 0; i < desc.witness_columns; i++) witnesses.push_back(i);
    std::vector<std::size_t> public_inputs = {0};
    for( std::size_t i = 0; i < desc.public_input_columns; i++) public_inputs.push_back(i);
    std::vector<std::size_t> constants;
    for( std::size_t i = 0; i < desc.constant_columns; i++) constants.push_back(i);

    using BBFType = nil::blueprint::bbf::rw;
    using component_type = components::plonk_l1_wrapper<BlueprintFieldType, BBFType, size_t, size_t>;
    component_type component_instance(witnesses, public_inputs, constants);

    size_t max_rw_size = 500;
    nil::blueprint::components::generate_circuit<BlueprintFieldType, BBFType, , size_t, size_t>(
        component_instance, rw_circuit, assignments, constraint_input, start_row, max_rw_size, 0);
    zk::snark::pack_lookup_tables_horizontal(
        rw_circuit.get_reserved_indices(),
        rw_circuit.get_reserved_tables(),
        rw_circuit.get_reserved_dynamic_tables(),
        rw_circuit, assignment,
        assignments.rows_amount(),
        100000
    );
    return {};
}
