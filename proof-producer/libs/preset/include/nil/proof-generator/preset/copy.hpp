#pragma once

#include <optional>
#include <string>

#include <nil/proof-generator/types/type_system.hpp>
#include <nil/blueprint/zkevm_bbf/copy.hpp>
#include <nil/blueprint/bbf/circuit_builder.hpp>
#include <nil/proof-generator/preset/limits.hpp>


namespace nil {
    namespace proof_producer {

        template<typename BlueprintFieldType>
        std::optional<std::string> initialize_copy_circuit(
                std::shared_ptr<typename PresetTypes<BlueprintFieldType>::ConstraintSystem>& copy_circuit,
                std::shared_ptr<typename PresetTypes<BlueprintFieldType>::AssignmentTable>& copy_table,
                const CircuitsLimits& circuits_limits) {

            using ConstraintSystem = typename PresetTypes<BlueprintFieldType>::ConstraintSystem;
            using AssignmentTable = typename PresetTypes<BlueprintFieldType>::AssignmentTable;

            blueprint::bbf::circuit_builder<
                BlueprintFieldType, nil::blueprint::bbf::copy,
                std::size_t, std::size_t, std::size_t, std::size_t, std::size_t
            > builder(circuits_limits.max_copy_rows, circuits_limits.max_rw_rows,
                      circuits_limits.max_keccak_blocks, circuits_limits.max_bytecode_rows,
                      circuits_limits.max_call_commits);

            copy_circuit = std::make_shared<ConstraintSystem>(builder.get_circuit());

            // initialize assignment table
            copy_table = std::make_shared<AssignmentTable>(builder.get_presets());
            BOOST_LOG_TRIVIAL(debug) << "copy table:\n"
                                     << "witnesses = " << copy_table->witnesses_amount()
                                     << " public inputs = " << copy_table->public_inputs_amount()
                                     << " constants = " << copy_table->constants_amount()
                                     << " selectors = " << copy_table->selectors_amount() << "\n";

            return {};
        }

    } // namespace proof_producer
} // namespace nil
