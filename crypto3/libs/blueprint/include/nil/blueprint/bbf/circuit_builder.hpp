//---------------------------------------------------------------------------//
// Copyright (c) 2024 Alexey Yashunsky <a.yashunsky@nil.foundation>
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
// @file Declaration of interfaces for BBF-components' circuit builder class
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_BLUEPRINT_PLONK_BBF_CIRCUIT_BUILDER_HPP
#define CRYPTO3_BLUEPRINT_PLONK_BBF_CIRCUIT_BUILDER_HPP

#include <functional>

#include <nil/crypto3/zk/snark/arithmetization/plonk/constraint_system.hpp>

#include <nil/blueprint/blueprint/plonk/assignment.hpp>
#include <nil/blueprint/blueprint/plonk/circuit.hpp>
#include <nil/blueprint/component.hpp>
#include <nil/blueprint/manifest.hpp>

#include <nil/blueprint/bbf/generic.hpp>

#include <nil/crypto3/zk/snark/arithmetization/plonk/lookup_table_definition.hpp>

namespace nil {
    namespace blueprint {
        namespace bbf {

            template<typename FieldType, template<typename, GenerationStage stage> class Component, typename... ComponentStaticInfoArgs>
            class circuit_builder {
//                using static_info_args_storage_type = typename std::conditional<sizeof...(ComponentStaticInfoArgs) == 0,
//                    std::tuple<>, std::tuple<ComponentStaticInfoArgs...>>::type;
                using static_info_args_storage_type = std::tuple<ComponentStaticInfoArgs...>;
                public:

                circuit_builder(std::size_t witnesses, std::size_t public_inputs, std::size_t user_constants, std::size_t rows,
                    ComponentStaticInfoArgs... component_static_info_args) {

                    prepare_circuit_parameters(witnesses,public_inputs,user_constants,rows);
       std::cout << std::tuple_size<static_info_args_storage_type>{} << std::endl;
       std::cout << sizeof...(component_static_info_args) << std::endl;
//                    static_info_args_storage = {component_static_info_args...};
                }

                // typical setup: 1 PI column, 0 constant columns, witnesses × rows
                circuit_builder(std::size_t witnesses, std::size_t rows, ComponentStaticInfoArgs... component_static_info_args) {
                    prepare_circuit_parameters(witnesses,1,0,rows);
        std::cout << std::tuple_size<static_info_args_storage_type>{} << std::endl;
       std::cout << sizeof...(component_static_info_args) << std::endl;
//                    static_info_args_storage = {component_static_info_args...};
                }

                // query component for minimal requirements
                circuit_builder(ComponentStaticInfoArgs... component_static_info_args) {
                    using generator = Component<FieldType,GenerationStage::CONSTRAINTS>;
                    typename generator::table_params min_params = generator::get_minimal_requirements();
                    prepare_circuit_parameters(min_params.witnesses,min_params.public_inputs,min_params.constants,min_params.rows);
        std::cout << std::tuple_size<static_info_args_storage_type>{} << std::endl;
       std::cout << sizeof...(component_static_info_args) << std::endl;
//                    static_info_args_storage = {component_static_info_args...};
                }

                private:
//                static_info_args_storage_type static_info_args_storage;

                void prepare_circuit_parameters(std::size_t witnesses, std::size_t public_inputs,
                                                std::size_t user_constants, std::size_t rows) {
                    using generator = Component<FieldType,GenerationStage::CONSTRAINTS>;

                    typename generator::table_params min_params = generator::get_minimal_requirements();
                    if (witnesses < min_params.witnesses) {
                        std::stringstream error;
                        error << "Number of witnesses = " << witnesses
                            << " is below the minimal number of witnesses (" << min_params.witnesses << ") for the component.";
                        throw std::out_of_range(error.str());
                    }
                    if (public_inputs < min_params.public_inputs) {
                        std::stringstream error;
                        error << "Number of public inputs = " << public_inputs
                            << " is below the minimal number of public inputs (" << min_params.public_inputs << ") for the component.";
                        throw std::out_of_range(error.str());
                    }
                    if (user_constants < min_params.constants) {
                        std::stringstream error;
                        error << "Number of constants = " << user_constants
                            << " is below the minimal number of constants (" << min_params.constants << ") for the component.";
                        throw std::out_of_range(error.str());
                    }
                    if (rows < min_params.rows) {
                        std::stringstream error;
                        error << "Number of rows = " << rows
                            << " is below the minimal number of rows (" << min_params.rows << ") for the component.";
                        throw std::out_of_range(error.str());
                    }
                    // initialize params according to arguments
                    witnesses_amount = witnesses;
                    public_inputs_amount = public_inputs;
		    constants_amount = user_constants;
                    rows_amount = rows;
                }

                public:
                void generate_constraints() {
                    using generator = Component<FieldType,GenerationStage::CONSTRAINTS>;
                    using context_type = typename nil::blueprint::bbf::context<FieldType, nil::blueprint::bbf::GenerationStage::CONSTRAINTS>;
                    using constraint_type = crypto3::zk::snark::plonk_constraint<FieldType>;
                    using copy_constraint_type = crypto3::zk::snark::plonk_copy_constraint<FieldType>;
                    using lookup_constraint_type = crypto3::zk::snark::plonk_lookup_constraint<FieldType>;
                    using value_type = typename FieldType::value_type;
                    using var = crypto3::zk::snark::plonk_variable<value_type>;
                    using TYPE = typename generator::TYPE;
                    using raw_input_type = typename generator::raw_input_type;

                    context_type ct = context_type(
                        crypto3::zk::snark::plonk_table_description<FieldType>(
                            witnesses_amount, public_inputs_amount, constants_amount, 0, rows_amount,
                            std::pow(2, std::ceil(std::log2(rows_amount)))),
                            rows_amount, 0 // use all rows, start from 0
                        );

                    raw_input_type raw_input = {};
                    auto v = std::tuple_cat(std::make_tuple(ct), generator::form_input(ct,raw_input));
                    std::make_from_tuple<generator>(v);

                    // for the moment, does nothing
                    ct.optimize_gates();

                    // constraint list => gates & selectors. TODO: super-selector + constant columns + contraints
                    std::unordered_map<row_selector<>, std::vector<TYPE>> constraint_list = ct.get_constraints();

                    for(const auto& [row_list, constraints] : constraint_list) {
                        std::size_t selector_index = bp.add_gate(constraints);
                        for(std::size_t row_index : row_list) {
                            // TODO: replace with preset generation
                            // assignment.enable_selector(selector_index, row_index);
                        }
                    }

                    // copy constraint list
                    std::vector<copy_constraint_type> copy_constraints = ct.get_copy_constraints();
                    for(const auto& cc : copy_constraints) {
                        bp.add_copy_constraint(cc);
                    }

                    // dynamic lookup tables
                    std::map<std::string,std::pair<std::vector<std::size_t>,row_selector<>>>
                        dynamic_lookup_tables = ct.get_dynamic_lookup_tables();

                    // lookup constraint list
                    std::unordered_map<row_selector<>, std::vector<std::pair<std::string, std::vector<constraint_type>>>>
                        lookup_constraints = ct.get_lookup_constraints();
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
                            // TODO: replace with preset generation
                            // assignment.enable_selector(selector_index, row_index);
                        }
                    }

                    // dynamic lookup tables - continued
                    for(const auto& [name, area] : dynamic_lookup_tables) {
                        bp.register_dynamic_table(name);
                        std::size_t selector_index = bp.get_dynamic_lookup_table_selector();
                        for(std::size_t row_index : area.second) {
                            // TODO: replace with preset generation
                            // assignment.enable_selector(selector_index,row_index);
                        }
                        crypto3::zk::snark::plonk_lookup_table<FieldType> table_specs;
                        table_specs.tag_index = selector_index;
                        table_specs.columns_number = area.first.size();
                        std::vector<var> dynamic_lookup_cols;
                        for(const auto& c : area.first) {
                            dynamic_lookup_cols.push_back(var(c, 0, false, var::column_type::witness)); // TODO: does this make sense?!
                        }
                        table_specs.lookup_options = {dynamic_lookup_cols};
                        bp.define_dynamic_table(name,table_specs);
                    }

                    // constants
                    auto c_list = ct.get_constants();
                    // std::cout << "const list size = " << c_list.size() << "\n";
                    for(std::size_t i = 0; i < c_list.size(); i++) { // columns
                        // std::cout << "column size = " << c_list[i].size() << "\n";
                        for(std::size_t j = 0; j < c_list[i].size(); j++) { // rows
                            // TODO: replace with preset generation
                            // assignment.constant(component.C(i), j) = c_list[i][j];
                        }
                    }

                    // std::cout << "Gates amount = " << bp.num_gates() << "\n";
                    // std::cout << "Lookup gates amount = " << bp.num_lookup_gates() << "\n";
                }

                void load_presets() { // TODO: arg = source
                }

                // template<typename... RawInputTypes>
                void generate_assignment(typename Component<FieldType, GenerationStage::ASSIGNMENT>::raw_input_type raw_input) {
                    using generator = Component<FieldType,GenerationStage::ASSIGNMENT>;
                    // using raw_input_type = typename generator::raw_input_type;
                    using assignment_type = assignment<crypto3::zk::snark::plonk_constraint_system<FieldType>>;
                    using context_type = typename nil::blueprint::bbf::context<FieldType, nil::blueprint::bbf::GenerationStage::ASSIGNMENT>;

                    assignment_type at = assignment_type(crypto3::zk::snark::plonk_table_description<FieldType>(
                            witnesses_amount, public_inputs_amount, constants_amount, 0, rows_amount,
                            std::pow(2, std::ceil(std::log2(rows_amount)))));

                    context_type ct = context_type(at, rows_amount, 0); // use all rows, start from 0

                    auto v = std::tuple_cat(std::make_tuple(ct), generator::form_input(ct,raw_input));
                    std::make_from_tuple<generator>(v);
                }

                private:
                    std::size_t witnesses_amount;
                    std::size_t public_inputs_amount;
                    std::size_t constants_amount;
                    std::size_t rows_amount;

                    circuit<crypto3::zk::snark::plonk_constraint_system<FieldType>> bp;
                    crypto3::zk::snark::plonk_assignment_table<FieldType> presets =
                        crypto3::zk::snark::plonk_assignment_table<FieldType>(0,0,constants_amount,0); // intended extensible
            };

        }  // namespace bbf
    }   // namespace blueprint
}    // namespace nil
#endif    // CRYPTO3_BLUEPRINT_PLONK_BBF_WRAPPER_HPP
