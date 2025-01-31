#ifndef PROOF_GENERATOR_LIBS_PRESET_EXP_HPP_
#define PROOF_GENERATOR_LIBS_PRESET_EXP_HPP_

#include <boost/log/core.hpp>
#include <boost/log/expressions.hpp>
#include <boost/log/trivial.hpp>
#include <nil/blueprint/bbf/enums.hpp>
#include <nil/blueprint/blueprint/plonk/circuit.hpp>
#include <nil/crypto3/zk/snark/arithmetization/plonk/assignment.hpp>
#include <nil/proof-generator/preset/limits.hpp>
#include <nil/blueprint/zkevm_bbf/exp.hpp>
#include <nil/blueprint/bbf/circuit_builder.hpp>
#include <optional>
#include <string>


namespace nil {
    namespace proof_generator {
        template<typename BlueprintFieldType>
        std::optional<std::string> initialize_exp_circuit(
                std::optional<blueprint::circuit<nil::crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>>>& exp_circuit,
                std::optional<nil::crypto3::zk::snark::plonk_assignment_table<BlueprintFieldType>>& exp_table,
                const CircuitsLimits& circuits_limits) {
            nil::blueprint::components::circuit_builder<
                BlueprintFieldType, nil::blueprint::bbf::exponentiation, std::size_t, std::size_t
            > builder(circuits_limits.max_rows, circuits_limits.max_exp_rows);

            auto circuit = builder.get_circuit();

            // initialize assignment table
            exp_table = builder.get_presets();
            BOOST_LOG_TRIVIAL(debug) << "exp table:\n"
                                     << "witnesses = " << exp_table->witnesses_amount()
                                     << " public inputs = " << exp_table->public_inputs_amount()
                                     << " constants = " << exp_table->constants_amount()
                                     << " selectors = " << exp_table->selectors_amount() << "\n";

            zk::snark::pack_lookup_tables_horizontal(
                circuit.get_reserved_indices(),
                circuit.get_reserved_tables(),
                circuit.get_reserved_dynamic_tables(),
                circuit, *exp_table,
                exp_table->rows_amount(),
                100000
            );

            exp_circuit.emplace(circuit);

            return {};
        }
    } // proof_generator
} // nil
#endif  // PROOF_GENERATOR_LIBS_PRESET_EXP_HPP_
