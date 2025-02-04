#ifndef PROOF_GENERATOR_LIBS_PRESET_ZKEVM_HPP_
#define PROOF_GENERATOR_LIBS_PRESET_ZKEVM_HPP_

#include <boost/log/core.hpp>
#include <boost/log/expressions.hpp>
#include <boost/log/trivial.hpp>

#include <nil/blueprint/bbf/enums.hpp>
#include <nil/blueprint/bbf/l1_wrapper.hpp>

#include <nil/proof-generator/types/type_system.hpp>
#include <nil/proof-generator/preset/limits.hpp>
#include <nil/blueprint/zkevm_bbf/zkevm.hpp>

#include <optional>
#include <string>


namespace nil {
    namespace proof_producer {
        template<typename BlueprintFieldType>
        std::optional<std::string> initialize_zkevm_circuit(
                std::shared_ptr<typename PresetTypes<BlueprintFieldType>::ConstraintSystem>& zkevm_circuit,
                std::shared_ptr<typename PresetTypes<BlueprintFieldType>::AssignmentTable>& zkevm_table,
                const CircuitsLimits& circuits_limits) {

            using ComponentType = nil::blueprint::bbf::zkevm<BlueprintFieldType, nil::blueprint::bbf::GenerationStage::CONSTRAINTS>;
            using ConstraintSystem = typename PresetTypes<BlueprintFieldType>::ConstraintSystem;
            using AssignmentTable = typename PresetTypes<BlueprintFieldType>::AssignmentTable;

            // initialize assignment table

            const auto desc = ComponentType::get_table_description(circuits_limits.max_zkevm_rows, circuits_limits.max_copy, circuits_limits.max_rw_size,
                circuits_limits.max_keccak_blocks, circuits_limits.max_bytecode_size);
            zkevm_table = std::make_shared<AssignmentTable>(desc.witness_columns, desc.public_input_columns, desc.constant_columns, desc.selector_columns);

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
                 circuits_limits.max_zkevm_rows, circuits_limits.max_copy, circuits_limits.max_rw_size, circuits_limits.max_keccak_blocks, circuits_limits.max_bytecode_size);

            zk::snark::pack_lookup_tables_horizontal(
                circuit.get_reserved_indices(),
                circuit.get_reserved_tables(),
                circuit.get_reserved_dynamic_tables(),
                circuit, *zkevm_table,
                zkevm_table->rows_amount(),
                100000
            );

            zkevm_circuit = std::make_shared<ConstraintSystem>(std::move(circuit));

            return {};
        }
    } // proof_producer
} // nil
#endif  // PROOF_GENERATOR_LIBS_PRESET_ZKEVM_HPP_
