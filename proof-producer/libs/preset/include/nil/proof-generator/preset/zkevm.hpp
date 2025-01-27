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
#include <nil/blueprint/bbf/circuit_builder.hpp>
#include <optional>
#include <string>


namespace nil {
    namespace proof_generator {
        template<typename BlueprintFieldType>
        std::optional<std::string> initialize_zkevm_circuit(
                std::optional<blueprint::circuit<nil::crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>>>& zkevm_circuit,
                std::optional<nil::crypto3::zk::snark::plonk_assignment_table<BlueprintFieldType>>& zkevm_table,
                const CircuitsLimits& circuits_limits) {

            nil::blueprint::components::circuit_builder<
                BlueprintFieldType, nil::blueprint::bbf::zkevm,
                std::size_t, std::size_t, std::size_t, std::size_t, std::size_t
            > builder(circuits_limits.max_zkevm_rows, circuits_limits.max_copy, circuits_limits.max_rw_size,
                      circuits_limits.max_keccak_blocks, circuits_limits.max_bytecode_size);

            // initialize assignment table
            zkevm_table = builder.get_presets();
            BOOST_LOG_TRIVIAL(debug) << "zkevm table:\n"
                                     << "witnesses = " << zkevm_table->witnesses_amount()
                                     << " public inputs = " << zkevm_table->public_inputs_amount()
                                     << " constants = " << zkevm_table->constants_amount()
                                     << " selectors = " << zkevm_table->selectors_amount() << "\n";

            auto circuit = builder.get_circuit();

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
