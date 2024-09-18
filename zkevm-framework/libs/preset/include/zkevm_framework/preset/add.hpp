#ifndef ZKEMV_FRAMEWORK_LIBS_PRESET_ADD_HPP_
#define ZKEMV_FRAMEWORK_LIBS_PRESET_ADD_HPP_

#include <assigner.hpp>
#include <boost/log/core.hpp>
#include <boost/log/expressions.hpp>
#include <boost/log/trivial.hpp>
#include <nil/blueprint/blueprint/plonk/assignment.hpp>
#include <nil/blueprint/basic_non_native_policy.hpp>
#include <nil/blueprint/components/algebra/fields/plonk/addition.hpp>
#include <optional>
#include <string>

template<typename BlueprintFieldType>
std::optional<std::string> initialize_add_circuit(
    nil::blueprint::circuit<nil::crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>>&
        add_circuit,
    std::unordered_map<nil::evm_assigner::zkevm_circuit,
                       nil::blueprint::assignment<
                           nil::crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>>>&
        assignments) {
    // initialize assignment table
    nil::crypto3::zk::snark::plonk_table_description<BlueprintFieldType> desc(65,  // witness
                                                                              1,   // public
                                                                              35,   // constants
                                                                              56   // selectors
    );
    BOOST_LOG_TRIVIAL(debug) << "add table:\n"
                             << "witnesses = " << desc.witness_columns
                             << " public inputs = " << desc.public_input_columns
                             << " constants = " << desc.constant_columns
                             << " selectors = " << desc.selector_columns << "\n";
    using ArithmetizationType =
        nil::crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>;

    auto insert_it = assignments.insert(std::pair<nil::evm_assigner::zkevm_circuit,
                                                  nil::blueprint::assignment<ArithmetizationType>>(
        nil::evm_assigner::zkevm_circuit::RW,// index = 0, just for experiment with add
        nil::blueprint::assignment<ArithmetizationType>(desc)));
    auto& add_table = insert_it.first->second;

    using component_type =
        nil::blueprint::components::addition<nil::crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>,
                                             BlueprintFieldType, nil::blueprint::basic_non_native_policy<BlueprintFieldType>>;

    // Prepare witness container to make an instance of the component
    typename component_type::manifest_type m = component_type::get_manifest();
    size_t witness_amount = *(m.witness_amount->begin());
    std::vector<std::uint32_t> witnesses(witness_amount);
    std::iota(witnesses.begin(), witnesses.end(), 0);  // fill 0, 1, ...

    component_type component_instance = component_type(
        witnesses, std::array<std::uint32_t, 1>{0}, std::array<std::uint32_t, 1>{0});

    const auto& row_idx = add_table.public_input_column_size(0);
    auto v0 = typename component_type::var(0, row_idx, false, component_type::var::column_type::public_input);
    auto v1 = typename component_type::var(0, row_idx + 1, false, component_type::var::column_type::public_input);
    typename component_type::input_type input = {v0, v1};

    nil::blueprint::components::generate_circuit(component_instance, add_circuit,
                                                 add_table, input, 0);

    BOOST_LOG_TRIVIAL(debug) << "rows amount = " << add_table.rows_amount() << "\n";
    return {};
}

#endif  // ZKEMV_FRAMEWORK_LIBS_PRESET_ADD_HPP_
