#ifndef PROOF_GENERATOR_LIBS_PRESET_KECCAK_HPP_
#define PROOF_GENERATOR_LIBS_PRESET_KECCAK_HPP_

#include <boost/log/core.hpp>
#include <boost/log/expressions.hpp>
#include <boost/log/trivial.hpp>
#include <nil/blueprint/bbf/enums.hpp>
#include <nil/blueprint/blueprint/plonk/circuit.hpp>
#include <nil/crypto3/zk/snark/arithmetization/plonk/assignment.hpp>
#include <nil/proof-generator/preset/limits.hpp>
#include <nil/blueprint/zkevm_bbf/keccak.hpp>
#include <nil/blueprint/bbf/l1_wrapper.hpp>
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

            using ComponentType = bbf::keccak<BlueprintFieldType, bbf::GenerationStage::CONSTRAINTS>;
            using ConstraintSystem = typename PresetTypes<BlueprintFieldType>::ConstraintSystem;
            using AssignmentTable = typename PresetTypes<BlueprintFieldType>::AssignmentTable;


            // initialize assignment table
            const auto desc = ComponentType::get_table_description(); // TODO(oclaw): add circuits_limits.max_rows, circuits_limits.max_keccak_blocks?
            keccak_table = std::make_shared<AssignmentTable>(desc.witness_columns, desc.public_input_columns, desc.constant_columns, desc.selector_columns);

            BOOST_LOG_TRIVIAL(debug) << "keccak table:\n"
                                     << "witnesses = " << keccak_table->witnesses_amount()
                                     << " public inputs = " << keccak_table->public_inputs_amount()
                                     << " constants = " << keccak_table->constants_amount()
                                     << " selectors = " << keccak_table->selectors_amount() << "\n";

            std::size_t start_row = 0;
            std::vector<std::size_t> witnesses(desc.witness_columns);
            std::iota(witnesses.begin(), witnesses.end(), 0);  // fill 0, 1, ...
            std::vector<std::size_t> public_inputs(desc.public_input_columns);
            std::iota(public_inputs.begin(), public_inputs.end(), 0);  // fill 0, 1, ...
            std::vector<std::size_t> constants(desc.constant_columns);
            std::iota(constants.begin(), constants.end(), 0);  // fill 0, 1, ...

            using L1WrapperType = nil::blueprint::components::plonk_l1_wrapper<BlueprintFieldType, bbf::keccak>;
            L1WrapperType wrapper(witnesses, public_inputs, constants);

            typename ComponentType::input_type input;
            input.rlc_challenge = circuits_limits.RLC_CHALLENGE;

            nil::blueprint::circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>> circuit;

            nil::blueprint::components::generate_circuit<BlueprintFieldType, bbf::keccak>(
                wrapper, circuit, *keccak_table, input, start_row); // circuits_limits.max_rows, circuits_limits.max_keccak_blocks

            zk::snark::pack_lookup_tables_horizontal(
                circuit.get_reserved_indices(),
                circuit.get_reserved_tables(),
                circuit.get_reserved_dynamic_tables(),
                circuit, *keccak_table,
                keccak_table->rows_amount(),
                100000
            );

            keccak_circuit = std::make_shared<ConstraintSystem>(std::move(circuit));

            return {};
        }
    } // proof_producer
} // nil

#endif  // PROOF_GENERATOR_LIBS_PRESET_KECCAK_HPP_
