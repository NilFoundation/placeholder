#ifndef PROOF_GENERATOR_LIBS_PRESET_ZKEVM_HPP_
#define PROOF_GENERATOR_LIBS_PRESET_ZKEVM_HPP_

#include <boost/log/core.hpp>
#include <boost/log/expressions.hpp>
#include <boost/log/trivial.hpp>

#include <nil/blueprint/bbf/enums.hpp>
#include <nil/blueprint/bbf/circuit_builder.hpp>
#include <nil/blueprint/zkevm_bbf/big_field/circuits/zkevm.hpp>

#include <nil/proof-generator/types/type_system.hpp>
#include <nil/proof-generator/preset/limits.hpp>

#include <optional>
#include <string>


namespace nil {
    namespace proof_producer {
        template<typename BlueprintFieldType>
        std::optional<std::string> initialize_zkevm_circuit(
                std::shared_ptr<typename PresetTypes<BlueprintFieldType>::ConstraintSystem>& zkevm_circuit,
                std::shared_ptr<typename PresetTypes<BlueprintFieldType>::AssignmentTable>& zkevm_table,
                const CircuitsLimits& circuits_limits) {

            using ConstraintSystem = typename PresetTypes<BlueprintFieldType>::ConstraintSystem;
            using AssignmentTable = typename PresetTypes<BlueprintFieldType>::AssignmentTable;

            blueprint::bbf::circuit_builder<
                BlueprintFieldType, nil::blueprint::bbf::zkevm_big_field::zkevm,
                std::size_t, std::size_t, std::size_t, std::size_t, std::size_t, std::size_t, std::size_t
            > builder(circuits_limits.max_zkevm_rows, circuits_limits.max_copy_rows, circuits_limits.max_rw_rows,
                      circuits_limits.max_keccak_blocks, circuits_limits.max_bytecode_rows, circuits_limits.max_state_rows, circuits_limits.max_filter_indices);

            zkevm_circuit = std::make_shared<ConstraintSystem>(builder.get_circuit());

            // initialize assignment table
            zkevm_table = std::make_shared<AssignmentTable>(builder.get_presets());
            BOOST_LOG_TRIVIAL(debug) << "zkevm table:\n"
                                     << "witnesses = " << zkevm_table->witnesses_amount()
                                     << " public inputs = " << zkevm_table->public_inputs_amount()
                                     << " constants = " << zkevm_table->constants_amount()
                                     << " selectors = " << zkevm_table->selectors_amount() << "\n";

            return {};
        }
    } // proof_producer
} // nil
#endif  // PROOF_GENERATOR_LIBS_PRESET_ZKEVM_HPP_
