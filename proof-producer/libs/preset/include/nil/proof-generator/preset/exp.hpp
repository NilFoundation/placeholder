#ifndef PROOF_GENERATOR_LIBS_PRESET_EXP_HPP_
#define PROOF_GENERATOR_LIBS_PRESET_EXP_HPP_

#include <boost/log/core.hpp>
#include <boost/log/expressions.hpp>
#include <boost/log/trivial.hpp>
#include <nil/blueprint/bbf/enums.hpp>
#include <nil/blueprint/blueprint/plonk/circuit.hpp>
#include <nil/crypto3/zk/snark/arithmetization/plonk/assignment.hpp>
#include <nil/proof-generator/types/type_system.hpp>
#include <nil/proof-generator/preset/limits.hpp>
#include <nil/blueprint/zkevm_bbf/big_field/circuits/exp.hpp>
#include <nil/blueprint/bbf/circuit_builder.hpp>
#include <optional>
#include <string>


namespace nil {
    namespace proof_producer {
        template<typename BlueprintFieldType>
        std::optional<std::string> initialize_exp_circuit(
                std::shared_ptr<typename PresetTypes<BlueprintFieldType>::ConstraintSystem>& exp_circuit,
                std::shared_ptr<typename PresetTypes<BlueprintFieldType>::AssignmentTable>&  exp_table,
                const CircuitsLimits& circuits_limits) {

            using ConstraintSystem = typename PresetTypes<BlueprintFieldType>::ConstraintSystem;
            using AssignmentTable = typename PresetTypes<BlueprintFieldType>::AssignmentTable;

            blueprint::bbf::circuit_builder<
                BlueprintFieldType, nil::blueprint::bbf::zkevm_big_field::exponentiation, std::size_t, std::size_t
            > builder(circuits_limits.max_exp_rows, circuits_limits.max_exp_ops);

            exp_circuit = std::make_shared<ConstraintSystem>(builder.get_circuit());

            // initialize assignment table
            exp_table = std::make_shared<AssignmentTable>(builder.get_presets());
            BOOST_LOG_TRIVIAL(debug) << "exp table:\n"
                                     << "witnesses = " << exp_table->witnesses_amount()
                                     << " public inputs = " << exp_table->public_inputs_amount()
                                     << " constants = " << exp_table->constants_amount()
                                     << " selectors = " << exp_table->selectors_amount() << "\n";

            return {};
        }
    } // proof_producer
} // nil
#endif  // PROOF_GENERATOR_LIBS_PRESET_EXP_HPP_
