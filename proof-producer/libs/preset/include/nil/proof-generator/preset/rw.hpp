#ifndef PROOF_GENERATOR_LIBS_PRESET_RW_HPP_
#define PROOF_GENERATOR_LIBS_PRESET_RW_HPP_

#include <boost/log/trivial.hpp>
#include <nil/blueprint/bbf/enums.hpp>
#include <nil/blueprint/blueprint/plonk/circuit.hpp>
#include <nil/crypto3/zk/snark/arithmetization/plonk/assignment.hpp>
#include <nil/blueprint/zkevm_bbf/rw.hpp>
#include <nil/blueprint/zkevm_bbf/l1_wrapper.hpp>
#include <optional>
#include <string>

namespace nil {
    namespace proof_generator {
        template<typename BlueprintFieldType>
        std::optional<std::string> initialize_rw_circuit(
                std::optional<nil::crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>>& rw_circuit,
                std::optional<nil::crypto3::zk::snark::plonk_assignment_table<BlueprintFieldType>>& rw_table) {

            using ArithmetizationType =
                    nil::crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>;

            using ComponentType = nil::blueprint::bbf::rw<BlueprintFieldType, nil::blueprint::bbf::GenerationStage::CONSTRAINTS>;

            // initialize assignment table
            std::size_t max_rw_size = 1000;
            std::size_t max_mpt_size = 30;

            const auto desc = ComponentType::get_table_description(max_rw_size, max_mpt_size);
            rw_table.emplace(desc.witness_columns, desc.public_input_columns, desc.constant_columns, desc.selector_columns);
            BOOST_LOG_TRIVIAL(debug) << "rw table:\n"
                                    << "witnesses = " << rw_table->witnesses_amount()
                                    << " public inputs = " << rw_table->public_inputs_amount()
                                    << " constants = " << rw_table->constants_amount()
                                    << " selectors = " << rw_table->selectors_amount() << "\n";

            std::size_t start_row = 0;
            std::vector<std::size_t> witnesses(desc.witness_columns);
            std::iota(witnesses.begin(), witnesses.end(), 0);  // fill 0, 1, ...
            std::vector<std::size_t> public_inputs(desc.public_input_columns);
            std::iota(public_inputs.begin(), public_inputs.end(), 0);  // fill 0, 1, ...
            std::vector<std::size_t> constants(desc.constant_columns);
            std::iota(constants.begin(), constants.end(), 0);  // fill 0, 1, ...

            using L1WrapperType = nil::blueprint::components::plonk_l1_wrapper<BlueprintFieldType, nil::blueprint::bbf::rw, std::size_t, std::size_t>;
            L1WrapperType wrapper(witnesses, public_inputs, constants);

            typename ComponentType::input_type input;

            nil::blueprint::circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>> circuit;

            nil::blueprint::components::generate_circuit<BlueprintFieldType, nil::blueprint::bbf::rw, std::size_t, std::size_t>(
                wrapper, circuit, *rw_table, input, start_row, max_rw_size, max_mpt_size);

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
