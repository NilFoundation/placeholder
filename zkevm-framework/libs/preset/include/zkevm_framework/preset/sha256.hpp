#ifndef ZKEMV_FRAMEWORK_LIBS_PRESET_SHA256_HPP_
#define ZKEMV_FRAMEWORK_LIBS_PRESET_SHA256_HPP_

#include <assigner.hpp>
#include <boost/log/core.hpp>
#include <boost/log/expressions.hpp>
#include <boost/log/trivial.hpp>
#include <nil/blueprint/blueprint/plonk/assignment.hpp>
#include <nil/blueprint/components/hashes/sha2/plonk/sha256.hpp>
#include <optional>
#include <string>

template<typename BlueprintFieldType>
std::optional<std::string> initialize_sha256_circuit(
    nil::blueprint::circuit<nil::crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>>&
        sha256_circuit,
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
    BOOST_LOG_TRIVIAL(debug) << "sha256 table:\n"
                             << "witnesses = " << desc.witness_columns
                             << " public inputs = " << desc.public_input_columns
                             << " constants = " << desc.constant_columns
                             << " selectors = " << desc.selector_columns << "\n";
    using ArithmetizationType =
        nil::crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>;

    auto insert_it = assignments.insert(std::pair<nil::evm_assigner::zkevm_circuit,
                                                  nil::blueprint::assignment<ArithmetizationType>>(
        nil::evm_assigner::zkevm_circuit::BYTECODE,// index = 0, just for experiment with sha256
        nil::blueprint::assignment<ArithmetizationType>(desc)));
    auto& sha256_table = insert_it.first->second;

    using component_type =
        nil::blueprint::components::sha256<nil::crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>>;

    // Prepare witness container to make an instance of the component
    typename component_type::manifest_type m = component_type::get_manifest();
    size_t witness_amount = *(m.witness_amount->begin());
    std::vector<std::uint32_t> witnesses(witness_amount);
    std::iota(witnesses.begin(), witnesses.end(), 0);  // fill 0, 1, ...

    component_type component_instance = component_type(
        witnesses, std::array<std::uint32_t, 1>{0}, std::array<std::uint32_t, 1>{0});

    auto lookup_tables = component_instance.component_lookup_tables();
    for (auto& [k, v] : lookup_tables) {
        sha256_circuit.reserve_table(k);
    }

    constexpr const std::int32_t block_size = 2;
    constexpr const std::int32_t input_blocks_amount = 2;

    const auto& row_idx = sha256_table.public_input_column_size(0);
    std::array<typename component_type::var, input_blocks_amount * block_size> input_block_vars = {
        typename component_type::var(0, row_idx, false, component_type::var::column_type::public_input),
        typename component_type::var(0, row_idx + 1, false, component_type::var::column_type::public_input),
        typename component_type::var(0, row_idx + 2, false, component_type::var::column_type::public_input),
        typename component_type::var(0, row_idx + 3, false, component_type::var::column_type::public_input)
    };
    typename component_type::input_type input = {input_block_vars};

    nil::blueprint::components::generate_circuit(component_instance, sha256_circuit,
                                                 sha256_table, input, 0);

    std::vector<size_t> lookup_columns_indices;
    for (std::size_t i = 1; i < sha256_table.constants_amount(); i++) {
        lookup_columns_indices.push_back(i);
    }

    std::size_t cur_selector_id = 0;
    for (const auto& gate : sha256_circuit.gates()) {
        cur_selector_id = std::max(cur_selector_id, gate.selector_index);
    }
    for (const auto& lookup_gate : sha256_circuit.lookup_gates()) {
        cur_selector_id = std::max(cur_selector_id, lookup_gate.tag_index);
    }
    cur_selector_id++;
    nil::crypto3::zk::snark::pack_lookup_tables_horizontal(
        sha256_circuit.get_reserved_indices(), sha256_circuit.get_reserved_tables(),
        sha256_circuit.get_reserved_dynamic_tables(), sha256_circuit, sha256_table,
        lookup_columns_indices, cur_selector_id, sha256_table.rows_amount(), 500000);
    BOOST_LOG_TRIVIAL(debug) << "rows amount = " << sha256_table.rows_amount() << "\n";
    return {};
}

#endif  // ZKEMV_FRAMEWORK_LIBS_PRESET_SHA256_HPP_
