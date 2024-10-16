#ifndef PROOF_GENERATOR_LIBS_PRESET_ADD_HPP_
#define PROOF_GENERATOR_LIBS_PRESET_ADD_HPP_

#include <boost/log/core.hpp>
#include <boost/log/expressions.hpp>
#include <boost/log/trivial.hpp>
#include <nil/blueprint/blueprint/plonk/assignment.hpp>
#include <nil/blueprint/basic_non_native_policy.hpp>
#include <nil/blueprint/components/algebra/fields/plonk/addition.hpp>
#include <optional>
#include <string>

namespace nil {
    namespace proof_generator {
        template<typename BlueprintFieldType>
        std::optional<std::string> initialize_add_circuit(
                nil::blueprint::circuit<nil::crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>>& add_circuit,
                nil::blueprint::assignment<nil::crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>>& add_table) {

            using ArithmetizationType =
                    nil::crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>;

            using CircuitType = nil::blueprint::components::addition<nil::crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>,
                                                BlueprintFieldType, nil::blueprint::basic_non_native_policy<BlueprintFieldType>>;
            // initialize assignment table
            nil::crypto3::zk::snark::plonk_table_description<BlueprintFieldType> desc(15,  // witness
                                                                                    1,   // public
                                                                                    35,   // constants
                                                                                    1   // selectors
            );
            BOOST_LOG_TRIVIAL(debug) << "add table:\n"
                                    << "witnesses = " << desc.witness_columns
                                    << " public inputs = " << desc.public_input_columns
                                    << " constants = " << desc.constant_columns
                                    << " selectors = " << desc.selector_columns << "\n";

            // Prepare witness container to make an instance of the component
            typename CircuitType::manifest_type m = CircuitType::get_manifest();
            size_t witness_amount = *(m.witness_amount->begin());
            std::vector<std::uint32_t> witnesses(witness_amount);
            std::iota(witnesses.begin(), witnesses.end(), 0);  // fill 0, 1, ...

            CircuitType component_instance = CircuitType(
                witnesses, std::array<std::uint32_t, 1>{0}, std::array<std::uint32_t, 1>{0});

            const auto& row_idx = add_table.public_input_column_size(0);
            auto v0 = typename CircuitType::var(0, row_idx, false, CircuitType::var::column_type::public_input);
            auto v1 = typename CircuitType::var(0, row_idx + 1, false, CircuitType::var::column_type::public_input);
            typename CircuitType::input_type input = {v0, v1};

            nil::blueprint::components::generate_circuit(component_instance, add_circuit,
                                                        add_table, input, 0);

            return {};
        }
    } // proof_generator
} // nil
#endif  // PROOF_GENERATOR_LIBS_PRESET_ADD_HPP_
