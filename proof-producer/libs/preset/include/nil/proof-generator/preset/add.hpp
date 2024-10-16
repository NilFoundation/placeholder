#ifndef PROOF_GENERATOR_LIBS_PRESET_ADD_HPP_
#define PROOF_GENERATOR_LIBS_PRESET_ADD_HPP_

#include <boost/log/trivial.hpp>
#include <nil/blueprint/basic_non_native_policy.hpp>
#include <nil/blueprint/components/algebra/fields/plonk/addition.hpp>
#include <optional>
#include <string>

namespace nil {
    namespace proof_generator {
        template<typename BlueprintFieldType>
        std::optional<std::string> initialize_add_circuit(
                std::optional<nil::crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>>& add_circuit,
                std::optional<nil::crypto3::zk::snark::plonk_assignment_table<BlueprintFieldType>>& add_table) {

            using ArithmetizationType =
                    nil::crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>;

            using ComponentType = nil::blueprint::components::addition<nil::crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>,
                                                BlueprintFieldType, nil::blueprint::basic_non_native_policy<BlueprintFieldType>>;
            // initialize assignment table
            add_table.emplace(15,  // witness
                              1,   // public
                              35,   // constants
                              1   // selectors
            );
            BOOST_LOG_TRIVIAL(debug) << "add table:\n"
                                    << "witnesses = " << add_table->witnesses_amount()
                                    << " public inputs = " << add_table->public_inputs_amount()
                                    << " constants = " << add_table->constants_amount()
                                    << " selectors = " << add_table->selectors_amount() << "\n";

            // Prepare witness container to make an instance of the component
            typename ComponentType::manifest_type m = ComponentType::get_manifest();
            size_t witness_amount = *(m.witness_amount->begin());
            std::vector<std::uint32_t> witnesses(witness_amount);
            std::iota(witnesses.begin(), witnesses.end(), 0);  // fill 0, 1, ...

            ComponentType component_instance = ComponentType(
                witnesses, std::array<std::uint32_t, 1>{0}, std::array<std::uint32_t, 1>{0});

            const auto& row_idx = add_table->public_input_column_size(0);
            auto v0 = typename ComponentType::var(0, row_idx, false, ComponentType::var::column_type::public_input);
            auto v1 = typename ComponentType::var(0, row_idx + 1, false, ComponentType::var::column_type::public_input);
            typename ComponentType::input_type input = {v0, v1};

            nil::blueprint::circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>> circuit;
            nil::blueprint::components::generate_circuit_(component_instance, circuit, *add_table, input, 0);
            add_circuit.emplace(circuit);
            return {};
        }
    } // proof_generator
} // nil
#endif  // PROOF_GENERATOR_LIBS_PRESET_ADD_HPP_
