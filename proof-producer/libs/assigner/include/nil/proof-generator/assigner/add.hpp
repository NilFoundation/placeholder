#ifndef PROOF_GENERATOR_LIBS_ASSIGNER_ADD_HPP_
#define PROOF_GENERATOR_LIBS_ASSIGNER_ADD_HPP_

#include <boost/log/trivial.hpp>

#include <nil/crypto3/zk/snark/arithmetization/plonk/assignment.hpp>
#include <nil/blueprint/components/algebra/fields/plonk/addition.hpp>
#include <nil/proof-generator/assigner/trace_parser.hpp>

namespace nil {
    namespace proof_generator {

        /// @brief Fill assignment table
        template<typename BlueprintFieldType>
        std::optional<std::string> fill_add_assignment_table(nil::crypto3::zk::snark::plonk_assignment_table<BlueprintFieldType>& assignment_table,
                                                             const boost::filesystem::path& trace_file_path) {
            BOOST_LOG_TRIVIAL(debug) << "fill add table from " << trace_file_path << "\n";

            using component_type =
                nil::blueprint::components::addition<nil::crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>,
                                                    BlueprintFieldType, nil::blueprint::basic_non_native_policy<BlueprintFieldType>>;

            // Prepare witness container to make an instance of the component
            typename component_type::manifest_type m = component_type::get_manifest();
            size_t witness_amount = *(m.witness_amount->begin());
            std::vector<std::uint32_t> witnesses(witness_amount);
            std::iota(witnesses.begin(), witnesses.end(), 0);  // fill 0, 1, ...

            component_type component_instance = component_type(
                witnesses, std::array<std::uint32_t, 1>{0}, std::array<std::uint32_t, 1>{0});

            const auto& row_idx = assignment_table.public_input_column_size(0);
            auto v0 = typename component_type::var(0, row_idx, false, component_type::var::column_type::public_input);
            auto v1 = typename component_type::var(0, row_idx + 1, false, component_type::var::column_type::public_input);
            typename component_type::input_type component_input = {v0, v1};
            //set input values
            std::vector<std::string> input = {"326522724692461750427768532537390503835", "89059515727727869117346995944635890507"};
            assignment_table.public_input(0, row_idx) = typename BlueprintFieldType::integral_type(input[0].c_str());
            assignment_table.public_input(0, row_idx + 1) = typename BlueprintFieldType::integral_type(input[1].c_str());

            nil::blueprint::components::generate_assignments_(component_instance, assignment_table, component_input, 0);
            return {};
        }
    } // proof_generator
} // nil

#endif  // PROOF_GENERATOR_LIBS_ASSIGNER__ADD_HPP_
