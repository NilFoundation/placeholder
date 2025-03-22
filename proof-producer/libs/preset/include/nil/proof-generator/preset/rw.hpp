#ifndef PROOF_GENERATOR_LIBS_PRESET_RW_HPP_
#define PROOF_GENERATOR_LIBS_PRESET_RW_HPP_

#include <boost/log/trivial.hpp>
#include <memory>
#include <nil/blueprint/bbf/enums.hpp>
#include <nil/proof-generator/types/type_system.hpp>
#include <nil/proof-generator/preset/limits.hpp>
#include <nil/blueprint/zkevm_bbf/rw.hpp>
#include <nil/blueprint/bbf/circuit_builder.hpp>
#include <optional>
#include <string>
#include <tuple>

namespace nil {
    namespace proof_producer {
        template<typename BlueprintFieldType>
        std::optional<std::string> initialize_rw_circuit(
                std::shared_ptr<typename PresetTypes<BlueprintFieldType>::ConstraintSystem>& rw_circuit,
                std::shared_ptr<typename PresetTypes<BlueprintFieldType>::AssignmentTable>& rw_table,
                const CircuitsLimits& circuits_limits) {

            using ConstraintSystem = typename PresetTypes<BlueprintFieldType>::ConstraintSystem;
            using AssignmentTable = typename PresetTypes<BlueprintFieldType>::AssignmentTable;

            blueprint::bbf::circuit_builder<
                BlueprintFieldType, nil::blueprint::bbf::rw, std::size_t, std::size_t, std::size_t
            > builder(circuits_limits.max_rw_rows, circuits_limits.max_mpt_rows,
                      circuits_limits.max_call_commits);

            rw_circuit = std::make_shared<ConstraintSystem>(builder.get_circuit());

            // initialize assignment table
            rw_table = std::make_shared<AssignmentTable>(builder.get_presets());
            BOOST_LOG_TRIVIAL(debug) << "rw table:\n"
                                     << "witnesses = " << rw_table->witnesses_amount()
                                     << " public inputs = " << rw_table->public_inputs_amount()
                                     << " constants = " << rw_table->constants_amount()
                                     << " selectors = " << rw_table->selectors_amount() << "\n";

            return {};
        }
    } // proof_producer
} // nil
#endif  // PROOF_GENERATOR_LIBS_PRESET_RW_HPP_
