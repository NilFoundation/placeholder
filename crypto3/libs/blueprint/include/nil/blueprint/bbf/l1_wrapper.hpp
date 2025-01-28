//---------------------------------------------------------------------------//
// Copyright (c) 2024 Elena Tatuzova <e.tatuzova@nil.foundation>
//
// MIT License
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.
//---------------------------------------------------------------------------//

#pragma once

#include <functional>

#include <nil/crypto3/zk/snark/arithmetization/plonk/constraint_system.hpp>

#include <nil/blueprint/blueprint/plonk/assignment.hpp>
#include <nil/blueprint/blueprint/plonk/circuit.hpp>
#include <nil/blueprint/component.hpp>
#include <nil/blueprint/manifest.hpp>

#include <nil/blueprint/bbf/generic.hpp> // also included by any subcomponent
#include <nil/crypto3/zk/snark/arithmetization/plonk/lookup_table_definition.hpp>


namespace nil {
    namespace blueprint {
        namespace components {
            template<
                typename ArithmetizationType,
                typename FieldType,
                template<typename, nil::blueprint::bbf::GenerationStage> typename BBFType,
                typename... ComponentStaticInfoArgs
            >
            class l1_wrapper;

            template<
                typename BlueprintFieldType,
                template<typename, nil::blueprint::bbf::GenerationStage> typename BBFType,
                typename... ComponentStaticInfoArgs
            >
            class l1_wrapper<
                crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>,
                BlueprintFieldType,
                BBFType,
                ComponentStaticInfoArgs...>
                : public plonk_component<BlueprintFieldType>
            {
            public:
                using component_type = plonk_component<BlueprintFieldType>;
                using bbf_assignment_type = BBFType<BlueprintFieldType,nil::blueprint::bbf::GenerationStage::ASSIGNMENT>;
                using bbf_constraints_type = BBFType<BlueprintFieldType,nil::blueprint::bbf::GenerationStage::CONSTRAINTS>;

                using var = typename component_type::var;
                using manifest_type = plonk_component_manifest;

                class gate_manifest_type : public component_gate_manifest {
                public:
                    std::uint32_t gates_amount() const override {
                        return l1_wrapper::gates_amount;
                    }
                };

                static gate_manifest get_gate_manifest(std::size_t witness_amount) {
                    static gate_manifest manifest = gate_manifest(gate_manifest_type());
                    return manifest;
                }

                static manifest_type get_manifest() {
                    static manifest_type manifest = manifest_type(
                        std::shared_ptr<manifest_param>(new manifest_single_value_param(3)), // TODO: this has nothing to do with reality,
                        false                                                                // to be dropped eventually
                    );
                    return manifest;
                }

                static nil::crypto3::zk::snark::plonk_table_description<BlueprintFieldType> get_table_description(
                    ComponentStaticInfoArgs... component_static_info_args
                ){
                    return bbf_constraints_type::get_table_description(component_static_info_args...);
                }

                static std::size_t get_rows_amount(
                    ComponentStaticInfoArgs... component_static_info_args
                ){
                    auto desc = bbf_constraints_type::get_table_description(component_static_info_args...);
                    return desc.usable_rows_amount;
                }
                static std::size_t get_empty_rows_amount(
                    ComponentStaticInfoArgs... component_static_info_args
                ){
                    return get_rows_amount(component_static_info_args...);
                }

                constexpr static const std::size_t gates_amount = 0; // TODO: this is very unoptimized!
                const std::string component_name = "wrapper of BBF-components";

                struct input_type {
                };

                struct result_type {
                    result_type() { }

                    std::vector<std::reference_wrapper<var>> all_vars() {
                        return {};
                    }
                };

                template<typename ContainerType>
                explicit l1_wrapper(ContainerType witness) : component_type(witness, {}, {}, get_manifest()) {};

                template<typename WitnessContainerType, typename ConstantContainerType,
                         typename PublicInputContainerType>
                l1_wrapper(WitnessContainerType witness, ConstantContainerType constant,
                         PublicInputContainerType public_input) :
                    component_type(witness, constant, public_input, get_manifest()) {};

                l1_wrapper(std::initializer_list<typename component_type::witness_container_type::value_type> witnesses,
                         std::initializer_list<typename component_type::constant_container_type::value_type>
                             constants,
                         std::initializer_list<typename component_type::public_input_container_type::value_type>
                             public_inputs) :
                    component_type(witnesses, constants, public_inputs, get_manifest()) {};

                std::map<std::string, std::size_t> component_lookup_tables() const{
                    std::map<std::string, std::size_t> lookup_tables;
                    return lookup_tables;
                }
            };

            template<typename BlueprintFieldType, template<typename, nil::blueprint::bbf::GenerationStage> typename BBFType, typename... ComponentStaticInfoArgs>
            using plonk_l1_wrapper = l1_wrapper<
                crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>,
                BlueprintFieldType,
                BBFType,
                ComponentStaticInfoArgs...
            >;

            template<
                typename BlueprintFieldType,
                template<typename, nil::blueprint::bbf::GenerationStage> typename BBFType,
                typename... ComponentStaticInfoArgs
            >
            typename plonk_l1_wrapper<BlueprintFieldType, BBFType, ComponentStaticInfoArgs...>::result_type
            generate_assignments(
                const plonk_l1_wrapper<BlueprintFieldType, BBFType, ComponentStaticInfoArgs...>  &component,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>>  &assignment,
                const typename BBFType<BlueprintFieldType, nil::blueprint::bbf::GenerationStage::ASSIGNMENT>::input_type  &instance_input,
                const std::uint32_t  start_row_index,
                ComponentStaticInfoArgs... component_static_info_args
            ) {
                using component_type = plonk_l1_wrapper<BlueprintFieldType, BBFType, ComponentStaticInfoArgs...>;
                using val = typename BlueprintFieldType::value_type;
                using context_type = typename nil::blueprint::bbf::context<BlueprintFieldType,
                                              nil::blueprint::bbf::GenerationStage::ASSIGNMENT>;
                using BBF = BBFType<BlueprintFieldType, nil::blueprint::bbf::GenerationStage::ASSIGNMENT>;
                auto desc = component_type::get_table_description(component_static_info_args...);

                context_type ct = context_type(assignment, desc.usable_rows_amount, start_row_index);
                BBF bbf_instance(ct, instance_input, component_static_info_args...);
                return typename plonk_l1_wrapper<BlueprintFieldType, BBFType, ComponentStaticInfoArgs...>::result_type();
            }

            template<
                typename BlueprintFieldType,
                template<typename, nil::blueprint::bbf::GenerationStage> typename BBFType,
                typename... ComponentStaticInfoArgs
            >
            typename plonk_l1_wrapper<BlueprintFieldType, BBFType, ComponentStaticInfoArgs...>::result_type generate_circuit(
                const plonk_l1_wrapper<BlueprintFieldType, BBFType, ComponentStaticInfoArgs...>  &component,
                circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>>  &bp,
                nil::crypto3::zk::snark::plonk_assignment_table<BlueprintFieldType> &assignment,
                const typename BBFType<BlueprintFieldType, nil::blueprint::bbf::GenerationStage::CONSTRAINTS>::input_type  &instance_input,
                const std::size_t start_row_index,
                ComponentStaticInfoArgs... component_static_info_args
            ) {
                using constraint_type = crypto3::zk::snark::plonk_constraint<BlueprintFieldType>;
                using plonk_copy_constraint = crypto3::zk::snark::plonk_copy_constraint<BlueprintFieldType>;
                using lookup_constraint_type = crypto3::zk::snark::plonk_lookup_constraint<BlueprintFieldType>;

                using component_type = const plonk_l1_wrapper<BlueprintFieldType, BBFType, ComponentStaticInfoArgs...>;
                using var = typename component_type::var;
                using context_type = typename nil::blueprint::bbf::context<BlueprintFieldType, nil::blueprint::bbf::GenerationStage::CONSTRAINTS>;
                using BBF = BBFType<BlueprintFieldType, nil::blueprint::bbf::GenerationStage::CONSTRAINTS>;
                using nil::blueprint::bbf::row_selector;
                using TYPE = typename context_type::TYPE;

                context_type ct = context_type(
                    component_type::get_table_description(component_static_info_args...),
                    component_type::get_table_description(component_static_info_args...).usable_rows_amount,
                    start_row_index
                );
                BBF bbf_instance(ct, instance_input, component_static_info_args...);


//                ct.optimize_gates();

                // compatibility layer: constraint list => gates & selectors
                std::unordered_map<row_selector<>, std::vector<std::pair<TYPE, std::string>>> constraint_list =
                    ct.get_constraints();

                for(const auto& [row_list, data] : constraint_list) {
                    /*
                    std::cout << "GATE:\n";
                    for(const auto& c : constraints) {
                        std::cout << c << "\n";
                    }
                    std::cout << "Rows: ";
                    */
                    std::vector<TYPE> constraints;
                    for(auto const& d : data){
                        constraints.push_back(d.first);
                    }
                    std::size_t selector_index = bp.add_gate(constraints);
                    for(const std::size_t& row_index : row_list) {
                        // std::cout << row_index << " ";
                        assignment.enable_selector(selector_index, row_index);
                    }
                    //std::cout << "\n";
                }

                // compatibility layer: copy constraint list
                std::vector<plonk_copy_constraint> copy_constraints = ct.get_copy_constraints();
                for(const auto& cc : copy_constraints) {
                    bp.add_copy_constraint(cc);
                }

                // compatibility layer: dynamic lookup tables
                std::map<std::string,std::pair<std::vector<std::size_t>,row_selector<>>>
                    dynamic_lookup_tables = ct.get_dynamic_lookup_tables();

                // compatibility layer: lookup constraint list
                auto lookup_constraints = ct.get_lookup_constraints();
                std::set<std::string> lookup_tables;
                for(const auto& [row_list, lookup_list] : lookup_constraints) {
                    std::vector<lookup_constraint_type> lookup_gate;
                    for(const auto& single_lookup_constraint : lookup_list) {
                        std::string table_name = single_lookup_constraint.first;
                        if (lookup_tables.find(table_name) == lookup_tables.end()) {
                            if (dynamic_lookup_tables.find(table_name) != dynamic_lookup_tables.end()) {
                                bp.reserve_dynamic_table(table_name);
                            } else {
                                bp.reserve_table(table_name);
                            }
                            lookup_tables.insert(table_name);
                        }
                        std::size_t table_index = bp.get_reserved_indices().at(table_name);
                        lookup_gate.push_back({table_index,single_lookup_constraint.second});
                    }
                    std::size_t selector_index = bp.add_lookup_gate(lookup_gate);
                    for(std::size_t row_index : row_list) {
                        assignment.enable_selector(selector_index, row_index);
                    }
                }

                // compatibility layer: dynamic lookup tables - continued
                for(const auto& [name, area] : dynamic_lookup_tables) {
                    bp.register_dynamic_table(name);
                    std::size_t selector_index = bp.get_dynamic_lookup_table_selector();
                    for(std::size_t row_index : area.second) {
                        assignment.enable_selector(selector_index,row_index);
                    }
                    crypto3::zk::snark::plonk_lookup_table<BlueprintFieldType> table_specs;
                    table_specs.tag_index = selector_index;
                    table_specs.columns_number = area.first.size();
                    std::vector<var> dynamic_lookup_cols;
                    for(const auto& c : area.first) {
                        dynamic_lookup_cols.push_back(var(c, 0, false, var::column_type::witness)); // TODO: does this make sense?!
                    }
                    table_specs.lookup_options = {dynamic_lookup_cols};
                    bp.define_dynamic_table(name,table_specs);
                }

                // compatibility layer: constants
                auto c_list = ct.get_constants();
                // std::cout << "const list size = " << c_list.size() << "\n";
                for(std::size_t i = 0; i < c_list.size(); i++) { // columns
                    // std::cout << "column size = " << c_list[i].size() << "\n";
                    for(std::size_t j = 0; j < c_list[i].size(); j++) { // rows
                        // std::cout << i << ", " << j << ": " << c_list[i][j] << "\n";
                        assignment.constant(component.C(i), j) = c_list[i][j];
                    }
                }

                // std::cout << "Gates amount = " << bp.num_gates() << "\n";
                // std::cout << "Lookup gates amount = " << bp.num_lookup_gates() << "\n";
                return typename plonk_l1_wrapper<BlueprintFieldType, BBFType, ComponentStaticInfoArgs...>::result_type();
            }
        }
    }
}
