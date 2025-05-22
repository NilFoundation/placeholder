#ifndef PROOF_GENERATOR_LIBS_PRESET_BYTECODE_HPP_
#define PROOF_GENERATOR_LIBS_PRESET_BYTECODE_HPP_

#include <boost/log/core.hpp>
#include <boost/log/expressions.hpp>
#include <boost/log/trivial.hpp>
#include <memory>
#include <nil/blueprint/bbf/enums.hpp>
#include <nil/blueprint/zkevm_bbf/big_field/circuits/bytecode.hpp>
#include <nil/blueprint/bbf/circuit_builder.hpp>
#include <nil/proof-generator/preset/limits.hpp>
#include <nil/proof-generator/types/type_system.hpp>
#include <optional>
#include <string>

namespace nil {
    namespace proof_producer {
        template<typename BlueprintFieldType>
        std::optional<std::string> initialize_bytecode_circuit(
                std::shared_ptr<typename PresetTypes<BlueprintFieldType>::ConstraintSystem>& bytecode_circuit,
                std::shared_ptr<typename PresetTypes<BlueprintFieldType>::AssignmentTable>& bytecode_table,
                const CircuitsLimits& circuits_limits) {

            using ConstraintSystem = typename PresetTypes<BlueprintFieldType>::ConstraintSystem;
            using AssignmentTable = typename PresetTypes<BlueprintFieldType>::AssignmentTable;

            blueprint::bbf::circuit_builder<
                BlueprintFieldType, nil::blueprint::bbf::zkevm_big_field::bytecode, std::size_t, std::size_t
            > builder(circuits_limits.max_bytecode_rows, circuits_limits.max_keccak_blocks);

            bytecode_circuit = std::make_shared<ConstraintSystem>(builder.get_circuit());

            // initialize assignment table
            bytecode_table = std::make_shared<AssignmentTable>(builder.get_presets());
            BOOST_LOG_TRIVIAL(debug) << "bytecode table:\n"
                                     << "witnesses = " << bytecode_table->witnesses_amount()
                                     << " public inputs = " << bytecode_table->public_inputs_amount()
                                     << " constants = " << bytecode_table->constants_amount()
                                     << " selectors = " << bytecode_table->selectors_amount() << "\n";

            return {};
        }
    } // proof_producer
} // nil
#endif  // PROOF_GENERATOR_LIBS_PRESET_BYTECODE_HPP_
