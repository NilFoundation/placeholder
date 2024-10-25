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

            template<typename FieldType, template<typename, GenerationStage stage> class Component>
            class circuit_builder {
                public:
                circuit_builder(std::size_t witnesses, std::size_t public_inputs, std::size_t user_constants, std::size_t rows) {
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
                    witnesses_amount =  witnesses;
                    public_inputs_amount = public_inputs;
		    constants_amount = user_constants;
                    rows_amount = rows;
                }

                // typical setup: 1 PI column, 0 constant columns, witnesses × rows
                circuit_builder(std::size_t witnesses, std::size_t rows) {
                    circuit_builder(witnesses,1,0,rows);
                }

                // query component for minimal requirements
                circuit_builder() {
                    using generator = Component<FieldType,GenerationStage::CONSTRAINTS>;
                    typename generator::table_params min_params = generator::get_minimal_requirements();
                    circuit_builder(min_params.witnesses,min_params.public_inputs,min_params.constants,min_params.rows);
                }

                void generate_constraints() {
                    using generator = Component<FieldType,GenerationStage::CONSTRAINTS>;
                    using context_type = typename nil::blueprint::bbf::context<FieldType, nil::blueprint::bbf::GenerationStage::CONSTRAINTS>;
                    using constraint_type = crypto3::zk::snark::plonk_constraint<FieldType>;
                    using copy_constraint_type = crypto3::zk::snark::plonk_copy_constraint<FieldType>;
                    using lookup_constraint_type = crypto3::zk::snark::plonk_lookup_constraint<FieldType>;

                    context_type ct = context_type(
                        crypto3::zk::snark::plonk_table_description<FieldType>(
                            witnesses_amount, public_inputs_amount, constants_amount, 0, rows_amount,
                            std::pow(2, std::ceil(std::log2(rows_amount())))),
                            rows_amount, 0 // use all rows, start from 0
                        );

                    std::make_from_tuple<generator>(std::tuple_cat(std::make_tuple(ct),generator::emplace_PI(generator::PI())));

                    // for the moment, does nothing
                    ct.optimize_gates();

                    // constraint list => gates & selectors. TODO: super-selector + constant columns + contraints
                    std::vector<std::pair<std::vector<constraint_type>, std::set<std::size_t>>> constraint_list = ct.get_constraints();

                    for(const auto& [constraints, row_list] : constraint_list) {
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
                    std::map<std::string,std::pair<std::vector<std::size_t>,std::set<std::size_t>>>
                        dynamic_lookup_tables = ct.get_dynamic_lookup_tables();

                    // lookup constraint list
                    std::vector<std::pair<std::vector<std::pair<std::string,std::vector<constraint_type>>>, std::set<std::size_t>>>
                    lookup_constraints = ct.get_lookup_constraints();
                    std::set<std::string> lookup_tables;
                    for(const auto& [lookup_list, row_list] : lookup_constraints) {
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

                void generate_assignment() {
                    using generator = Component<FieldType,GenerationStage::ASSIGNMENT>;

                }

                private:
                    std::size_t witnesses_amount;
                    std::size_t public_inputs_amount;
                    std::size_t constants_amount;
                    std::size_t rows_amount;

                    circuit<crypto3::zk::snark::plonk_constraint_system<FieldType>> bp;
                    crypto3::zk::snark::plonk_assignment_table<FieldType> presets(0,0,constants_amount,0); // intended extensible
            };

        }  // namespace bbf
    }   // namespace blueprint
}    // namespace nil
#endif    // CRYPTO3_BLUEPRINT_PLONK_BBF_WRAPPER_HPP
