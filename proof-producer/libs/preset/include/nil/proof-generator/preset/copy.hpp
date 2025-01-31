#pragma once

#include <optional>
#include <string>

#include <nil/blueprint/blueprint/plonk/circuit.hpp>
#include <nil/crypto3/zk/snark/arithmetization/plonk/assignment.hpp>
#include <nil/blueprint/zkevm_bbf/copy.hpp>
#include <nil/blueprint/bbf/circuit_builder.hpp>
#include <nil/proof-generator/preset/limits.hpp>


namespace nil {
    namespace proof_generator {

        template<typename BlueprintFieldType>
        std::optional<std::string> initialize_copy_circuit(
                std::optional<blueprint::circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>>>& copy_circuit,
                std::optional<crypto3::zk::snark::plonk_assignment_table<BlueprintFieldType>>& copy_table, const CircuitsLimits& circuits_limits) {
            nil::blueprint::components::circuit_builder<
                BlueprintFieldType, nil::blueprint::bbf::copy,
                std::size_t, std::size_t, std::size_t, std::size_t
            > builder(circuits_limits.max_copy, circuits_limits.max_rw_size,
                      circuits_limits.max_keccak_blocks, circuits_limits.max_bytecode_size);

            auto circuit = builder.get_circuit();

            // initialize assignment table
            copy_table = builder.get_presets();
            BOOST_LOG_TRIVIAL(debug) << "copy table:\n"
                                     << "witnesses = " << copy_table->witnesses_amount()
                                     << " public inputs = " << copy_table->public_inputs_amount()
                                     << " constants = " << copy_table->constants_amount()
                                     << " selectors = " << copy_table->selectors_amount() << "\n";

            snark::pack_lookup_tables_horizontal(
                circuit.get_reserved_indices(),
                circuit.get_reserved_tables(),
                circuit.get_reserved_dynamic_tables(),
                circuit, *copy_table,
                copy_table->rows_amount(),
                100000
            );

            copy_circuit.emplace(circuit);

            return {};
        }

    } // namespace proof_generator
} // namespace nil
