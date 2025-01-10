#ifndef PROOF_GENERATOR_LIBS_PRESET_BYTECODE_HPP_
#define PROOF_GENERATOR_LIBS_PRESET_BYTECODE_HPP_

#include <boost/log/core.hpp>
#include <boost/log/expressions.hpp>
#include <boost/log/trivial.hpp>
#include <memory>
#include <nil/blueprint/bbf/enums.hpp>
#include <nil/blueprint/zkevm_bbf/bytecode.hpp>
#include <nil/blueprint/bbf/l1_wrapper.hpp>
#include <nil/proof-generator/preset/limits.hpp>
#include <nil/proof-generator/types/type_system.hpp>
#include <optional>
#include <string>

namespace nil {
    namespace proof_generator {
        template<typename BlueprintFieldType>
        std::optional<std::string> initialize_bytecode_circuit(
                std::shared_ptr<typename PresetTypes<BlueprintFieldType>::ConstraintSystem>& bytecode_circuit,
                std::shared_ptr<typename PresetTypes<BlueprintFieldType>::AssignmentTable>& bytecode_table) {

            using ComponentType = nil::blueprint::bbf::bytecode<BlueprintFieldType, nil::blueprint::bbf::GenerationStage::CONSTRAINTS>;
            using ConstraintSystem = typename PresetTypes<BlueprintFieldType>::ConstraintSystem;
            using AssignmentTable = typename PresetTypes<BlueprintFieldType>::AssignmentTable;

            // initialize assignment table
            const auto desc = ComponentType::get_table_description(limits::max_bytecode_size, limits::max_keccak_blocks);
            bytecode_table = std::make_shared<AssignmentTable>(desc.witness_columns, desc.public_input_columns, desc.constant_columns, desc.selector_columns);

            BOOST_LOG_TRIVIAL(debug) << "bytecode table:\n"
                                    << "witnesses = " << bytecode_table->witnesses_amount()
                                    << " public inputs = " << bytecode_table->public_inputs_amount()
                                    << " constants = " << bytecode_table->constants_amount()
                                    << " selectors = " << bytecode_table->selectors_amount() << "\n";

            std::size_t start_row = 0;
            std::vector<std::size_t> witnesses(desc.witness_columns);
            std::iota(witnesses.begin(), witnesses.end(), 0);  // fill 0, 1, ...
            std::vector<std::size_t> public_inputs(desc.public_input_columns);
            std::iota(public_inputs.begin(), public_inputs.end(), 0);  // fill 0, 1, ...
            std::vector<std::size_t> constants(desc.constant_columns);
            std::iota(constants.begin(), constants.end(), 0);  // fill 0, 1, ...

            using L1WrapperType = nil::blueprint::components::plonk_l1_wrapper<BlueprintFieldType, nil::blueprint::bbf::bytecode, std::size_t, std::size_t>;
            L1WrapperType wrapper(witnesses, public_inputs, constants);

            typename ComponentType::input_type input;

            typename PresetTypes<BlueprintFieldType>::ConstraintSystem circuit;

            nil::blueprint::components::generate_circuit<BlueprintFieldType, nil::blueprint::bbf::bytecode, std::size_t, std::size_t>(
                wrapper, circuit, *bytecode_table, input, start_row, limits::max_bytecode_size, limits::max_keccak_blocks);

            crypto3::zk::snark::pack_lookup_tables_horizontal(
                circuit.get_reserved_indices(),
                circuit.get_reserved_tables(),
                circuit.get_reserved_dynamic_tables(),
                circuit, *bytecode_table,
                bytecode_table->rows_amount(),
                100000
            );

            bytecode_circuit = std::make_shared<ConstraintSystem>(std::move(circuit));

            return {};
        }
    } // proof_generator
} // nil
#endif  // PROOF_GENERATOR_LIBS_PRESET_BYTECODE_HPP_
