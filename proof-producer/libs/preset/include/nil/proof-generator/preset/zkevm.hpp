#ifndef PROOF_GENERATOR_LIBS_PRESET_ZKEVM_HPP_
#define PROOF_GENERATOR_LIBS_PRESET_ZKEVM_HPP_

#include <boost/log/core.hpp>
#include <boost/log/expressions.hpp>
#include <boost/log/trivial.hpp>
#include <nil/blueprint/bbf/enums.hpp>
#include <nil/blueprint/blueprint/plonk/circuit.hpp>
#include <nil/crypto3/zk/snark/arithmetization/plonk/assignment.hpp>
#include <nil/proof-generator/preset/limits.hpp>
#include <nil/blueprint/zkevm_bbf/zkevm.hpp>
#include <nil/blueprint/bbf/l1_wrapper.hpp>
#include <optional>
#include <string>


namespace nil {
    namespace proof_generator {
        template<typename BlueprintFieldType>
        std::optional<std::string> initialize_zkevm_circuit(
                std::optional<blueprint::circuit<nil::crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>>>& zkevm_circuit,
                std::optional<nil::crypto3::zk::snark::plonk_assignment_table<BlueprintFieldType>>& zkevm_table) {

            using ComponentType = nil::blueprint::bbf::zkevm<BlueprintFieldType, nil::blueprint::bbf::GenerationStage::CONSTRAINTS>;

            // initialize assignment table
            const auto desc = ComponentType::get_table_description(limits::max_zkevm_rows, limits::max_copy, limits::max_rw_size, 
                limits::max_keccak_blocks, limits::max_bytecode_size);
            zkevm_table.emplace(desc.witness_columns, desc.public_input_columns, desc.constant_columns, desc.selector_columns);
            BOOST_LOG_TRIVIAL(debug) << "zkevm table:\n"
                                    << "witnesses = " << zkevm_table->witnesses_amount()
                                    << " public inputs = " << zkevm_table->public_inputs_amount()
                                    << " constants = " << zkevm_table->constants_amount()
                                    << " selectors = " << zkevm_table->selectors_amount() << "\n";

            std::size_t start_row = 0;
            std::vector<std::size_t> witnesses(desc.witness_columns);
            std::iota(witnesses.begin(), witnesses.end(), 0);  // fill 0, 1, ...
            std::vector<std::size_t> public_inputs(desc.public_input_columns);
            std::iota(public_inputs.begin(), public_inputs.end(), 0);  // fill 0, 1, ...
            std::vector<std::size_t> constants(desc.constant_columns);
            std::iota(constants.begin(), constants.end(), 0);  // fill 0, 1, ...

            using L1WrapperType = nil::blueprint::components::plonk_l1_wrapper<BlueprintFieldType,
                nil::blueprint::bbf::zkevm, std::size_t, std::size_t, std::size_t, std::size_t, std::size_t>;
            L1WrapperType wrapper(witnesses, public_inputs, constants);

            typename ComponentType::input_type input;

            nil::blueprint::circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>> circuit;

            nil::blueprint::components::generate_circuit<BlueprintFieldType, nil::blueprint::bbf::zkevm, std::size_t, std::size_t, std::size_t, std::size_t, std::size_t>(
                wrapper, circuit, *zkevm_table, input, start_row,
                 limits::max_zkevm_rows, limits::max_copy, limits::max_rw_size, limits::max_keccak_blocks, limits::max_bytecode_size);

            zk::snark::pack_lookup_tables_horizontal(
                circuit.get_reserved_indices(),
                circuit.get_reserved_tables(),
                circuit.get_reserved_dynamic_tables(),
                circuit, *zkevm_table,
                zkevm_table->rows_amount(),
                100000
            );

            zkevm_circuit.emplace(circuit);

            return {};
        }
    } // proof_generator
} // nil
#endif  // PROOF_GENERATOR_LIBS_PRESET_ZKEVM_HPP_
