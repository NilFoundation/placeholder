#ifndef PROOF_GENERATOR_LIBS_PRESET_RW_HPP_
#define PROOF_GENERATOR_LIBS_PRESET_RW_HPP_

#include <boost/log/trivial.hpp>
#include <nil/blueprint/bbf/enums.hpp>
#include <nil/blueprint/blueprint/plonk/circuit.hpp>
#include <nil/crypto3/zk/snark/arithmetization/plonk/assignment.hpp>
#include <nil/proof-generator/preset/limits.hpp>
#include <nil/blueprint/zkevm_bbf/rw.hpp>
#include <nil/blueprint/bbf/circuit_builder.hpp>
#include <optional>
#include <string>

namespace nil {
    namespace proof_generator {
        template<typename BlueprintFieldType>
        std::optional<std::string> initialize_rw_circuit(
                std::optional<blueprint::circuit<nil::crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>>>& rw_circuit,
                std::optional<nil::crypto3::zk::snark::plonk_assignment_table<BlueprintFieldType>>& rw_table,
                const CircuitsLimits& circuits_limits) {
            nil::blueprint::components::circuit_builder<
                BlueprintFieldType, nil::blueprint::bbf::rw, std::size_t, std::size_t
            > builder(circuits_limits.max_rw_size, circuits_limits.max_mpt_size);

            auto circuit = builder.get_circuit();

            // initialize assignment table
            rw_table = builder.get_presets();
            BOOST_LOG_TRIVIAL(debug) << "rw table:\n"
                                     << "witnesses = " << rw_table->witnesses_amount()
                                     << " public inputs = " << rw_table->public_inputs_amount()
                                     << " constants = " << rw_table->constants_amount()
                                     << " selectors = " << rw_table->selectors_amount() << "\n";

            zk::snark::pack_lookup_tables_horizontal(
                circuit.get_reserved_indices(),
                circuit.get_reserved_tables(),
                circuit.get_reserved_dynamic_tables(),
                circuit, *rw_table,
                rw_table->rows_amount(),
                100000
            );

            rw_circuit.emplace(circuit);

            return {};
        }
    } // proof_generator
} // nil
#endif  // PROOF_GENERATOR_LIBS_PRESET_RW_HPP_
