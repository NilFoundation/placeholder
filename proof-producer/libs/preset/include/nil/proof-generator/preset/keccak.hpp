#ifndef PROOF_GENERATOR_LIBS_PRESET_KECCAK_HPP_
#define PROOF_GENERATOR_LIBS_PRESET_KECCAK_HPP_

#include <boost/log/core.hpp>
#include <boost/log/expressions.hpp>
#include <boost/log/trivial.hpp>
#include <nil/blueprint/bbf/enums.hpp>
#include <nil/blueprint/blueprint/plonk/circuit.hpp>
#include <nil/crypto3/zk/snark/arithmetization/plonk/assignment.hpp>
#include <nil/proof-generator/types/type_system.hpp>
#include <nil/proof-generator/preset/limits.hpp>
#include <nil/blueprint/bbf/circuit_builder.hpp>
#include <nil/blueprint/zkevm_bbf/big_field/circuits/keccak.hpp>
#include <optional>
#include <string>


namespace nil {
    namespace proof_producer {
        template<typename BlueprintFieldType>
        std::optional<std::string> initialize_keccak_circuit(
                std::shared_ptr<typename PresetTypes<BlueprintFieldType>::ConstraintSystem>& keccak_circuit,
                std::shared_ptr<typename PresetTypes<BlueprintFieldType>::AssignmentTable>&  keccak_table,
                const CircuitsLimits& circuits_limits) {
            namespace bbf = nil::blueprint::bbf;

            using ConstraintSystem = typename PresetTypes<BlueprintFieldType>::ConstraintSystem;
            using AssignmentTable = typename PresetTypes<BlueprintFieldType>::AssignmentTable;

            bbf::circuit_builder<BlueprintFieldType, bbf::zkevm_big_field::zkevm_keccak, std::size_t> builder(circuits_limits.max_keccak_blocks);

            keccak_circuit = std::make_shared<ConstraintSystem>(builder.get_circuit());

            // initialize assignment table
            keccak_table = std::make_shared<AssignmentTable>(builder.get_presets());
            BOOST_LOG_TRIVIAL(debug) << "keccak table:\n"
                                     << "witnesses = " << keccak_table->witnesses_amount()
                                     << " public inputs = " << keccak_table->public_inputs_amount()
                                     << " constants = " << keccak_table->constants_amount()
                                     << " selectors = " << keccak_table->selectors_amount() << "\n";

            return {};
        }
    } // proof_producer
} // nil

#endif  // PROOF_GENERATOR_LIBS_PRESET_KECCAK_HPP_
