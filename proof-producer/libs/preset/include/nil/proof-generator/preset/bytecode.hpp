#ifndef PROOF_GENERATOR_LIBS_PRESET_BYTECODE_HPP_
#define PROOF_GENERATOR_LIBS_PRESET_BYTECODE_HPP_

#include <boost/log/core.hpp>
#include <boost/log/expressions.hpp>
#include <boost/log/trivial.hpp>
#include <nil/blueprint/bbf/enums.hpp>
#include <nil/blueprint/blueprint/plonk/circuit.hpp>
#include <nil/crypto3/zk/snark/arithmetization/plonk/assignment.hpp>
#include <nil/blueprint/zkevm_bbf/bytecode.hpp>
#include <nil/blueprint/bbf/circuit_builder.hpp>
#include <nil/proof-generator/preset/limits.hpp>
#include <optional>
#include <string>

namespace nil {
    namespace proof_generator {
        template<typename BlueprintFieldType>
        std::optional<std::string> initialize_bytecode_circuit(
                std::optional<blueprint::circuit<nil::crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>>>& bytecode_circuit,
                std::optional<nil::crypto3::zk::snark::plonk_assignment_table<BlueprintFieldType>>& bytecode_table,
                const CircuitsLimits& circuits_limits) {
            nil::blueprint::components::circuit_builder<
                BlueprintFieldType, nil::blueprint::bbf::bytecode, std::size_t, std::size_t
            > builder(circuits_limits.max_bytecode_size, circuits_limits.max_keccak_blocks);

            auto circuit = builder.get_circuit();

            // initialize assignment table
            bytecode_table = builder.get_presets();
            BOOST_LOG_TRIVIAL(debug) << "bytecode table:\n"
                                     << "witnesses = " << bytecode_table->witnesses_amount()
                                     << " public inputs = " << bytecode_table->public_inputs_amount()
                                     << " constants = " << bytecode_table->constants_amount()
                                     << " selectors = " << bytecode_table->selectors_amount() << "\n";

            zk::snark::pack_lookup_tables_horizontal(
                circuit.get_reserved_indices(),
                circuit.get_reserved_tables(),
                circuit.get_reserved_dynamic_tables(),
                circuit, *bytecode_table,
                bytecode_table->rows_amount(),
                100000
            );

            bytecode_circuit.emplace(circuit);

            return {};
        }
    } // proof_generator
} // nil
#endif  // PROOF_GENERATOR_LIBS_PRESET_BYTECODE_HPP_
