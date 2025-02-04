#pragma once

#include <optional>
#include <string>

#include <nil/proof-generator/types/type_system.hpp>
#include <nil/blueprint/zkevm_bbf/copy.hpp>
#include <nil/blueprint/bbf/l1_wrapper.hpp>
#include <nil/proof-generator/preset/limits.hpp>


namespace nil {
    namespace proof_producer {

        template<typename BlueprintFieldType>
        std::optional<std::string> initialize_copy_circuit(
            std::shared_ptr<typename PresetTypes<BlueprintFieldType>::ConstraintSystem>& copy_circuit,
            std::shared_ptr<typename PresetTypes<BlueprintFieldType>::AssignmentTable>& copy_table,
            const CircuitsLimits& circuits_limits) {

            namespace snark = crypto3::zk::snark;
            namespace bbf = nil::blueprint::bbf;

            using ComponentType = bbf::copy<BlueprintFieldType, bbf::GenerationStage::CONSTRAINTS>;
            using ConstraintSystem = typename PresetTypes<BlueprintFieldType>::ConstraintSystem;
            using AssignmentTable = typename PresetTypes<BlueprintFieldType>::AssignmentTable;


            // TODO move to common? BEGIN

            // initialize assignment table
            const auto desc = ComponentType::get_table_description(
                circuits_limits.max_copy, circuits_limits.max_rw_size, circuits_limits.max_keccak_blocks, circuits_limits.max_bytecode_size
            );
            copy_table = std::make_shared<AssignmentTable>(desc.witness_columns, desc.public_input_columns, desc.constant_columns, desc.selector_columns);

            BOOST_LOG_TRIVIAL(debug) << "copy table:\n"
                        << "witnesses = " << copy_table->witnesses_amount()
                        << " public inputs = " << copy_table->public_inputs_amount()
                        << " constants = " << copy_table->constants_amount()
                        << " selectors = " << copy_table->selectors_amount()
                        << " rows_amount = " << copy_table->rows_amount()
                        << "\n";

            std::size_t start_row = 0;
            std::vector<std::size_t> witnesses(desc.witness_columns);
            std::iota(witnesses.begin(), witnesses.end(), 0);  // fill 0, 1, ...
            std::vector<std::size_t> public_inputs(desc.public_input_columns);
            std::iota(public_inputs.begin(), public_inputs.end(), 0);  // fill 0, 1, ...
            std::vector<std::size_t> constants(desc.constant_columns);
            std::iota(constants.begin(), constants.end(), 0);  // fill 0, 1, ...

            // TODO move to common? END

            using L1WrapperType = blueprint::components::plonk_l1_wrapper<
                BlueprintFieldType,
                bbf::copy,
                std::size_t, std::size_t, std::size_t, std::size_t
            >;
            L1WrapperType wrapper(witnesses, public_inputs, constants);


            nil::blueprint::circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>> circuit;
            typename ComponentType::input_type input;
            input.rlc_challenge = circuits_limits.RLC_CHALLENGE;

            blueprint::components::generate_circuit(
                wrapper,
                circuit,
                *copy_table,
                input,
                start_row,
                circuits_limits.max_copy,
                circuits_limits.max_rw_size,
                circuits_limits.max_keccak_blocks,
                circuits_limits.max_bytecode_size
            );

            snark::pack_lookup_tables_horizontal(
                circuit.get_reserved_indices(),
                circuit.get_reserved_tables(),
                circuit.get_reserved_dynamic_tables(),
                circuit, *copy_table,
                copy_table->rows_amount(),
                100000
            );

            BOOST_LOG_TRIVIAL(debug) << "copy table preset end:\n"
                << "witnesses = " << copy_table->witnesses_amount()
                << " public inputs = " << copy_table->public_inputs_amount()
                << " constants = " << copy_table->constants_amount()
                << " selectors = " << copy_table->selectors_amount()
                << " rows_amount = " << copy_table->rows_amount()
                << "\n";

            copy_circuit = std::make_shared<ConstraintSystem>(std::move(circuit));

            return {};
        }

    } // namespace proof_producer
} // namespace nil
