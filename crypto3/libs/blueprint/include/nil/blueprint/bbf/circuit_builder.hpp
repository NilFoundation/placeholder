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
                using static_info_args_storage_type = std::tuple<ComponentStaticInfoArgs...>;
                public:

                circuit_builder(std::size_t witnesses, std::size_t public_inputs, std::size_t user_constants, std::size_t rows,
                    ComponentStaticInfoArgs... component_static_info_args) {

                    prepare_circuit_parameters(witnesses,public_inputs,user_constants,rows);
                    static_info_args_storage = {component_static_info_args...};
                }

                // typical setup: 1 PI column, 0 constant columns, witnesses × rows
                circuit_builder(std::size_t witnesses, std::size_t rows, ComponentStaticInfoArgs... component_static_info_args) {
                    prepare_circuit_parameters(witnesses,1,0,rows);
                    static_info_args_storage = {component_static_info_args...};
                }

                // query component for minimal requirements
                circuit_builder(ComponentStaticInfoArgs... component_static_info_args) {
                    using generator = Component<FieldType,GenerationStage::CONSTRAINTS>;
                    typename generator::table_params min_params = generator::get_minimal_requirements();
                    prepare_circuit_parameters(min_params.witnesses,
                                               std::max(min_params.public_inputs,std::size_t(1)), // assure at least 1 PI column is present
                                               min_params.constants,
                                               min_params.rows);
                    static_info_args_storage = {component_static_info_args...};
                }

                private:
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
                    presets = crypto3::zk::snark::plonk_assignment_table<FieldType>(0,0,constants_amount,0); // intended extensible
                    generate_constraints();
                }

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
                    auto v = std::tuple_cat(std::make_tuple(ct), generator::form_input(ct,raw_input), static_info_args_storage);
                    std::make_from_tuple<generator>(v);

                    // constraint list => gates & selectors. TODO: super-selector + constant columns + contraints
                    std::unordered_map<row_selector<>, std::vector<TYPE>> constraint_list = ct.get_constraints();

                    for(const auto& [row_list, constraints] : constraint_list) {
                        std::size_t selector_index = bp.add_gate(constraints);
                        if (presets.selectors_amount() <= selector_index) {
                            presets.resize_selectors(selector_index + 1);
                        }
                        for(std::size_t row_index : row_list) {
                            presets.enable_selector(selector_index, row_index);
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
                    std::unordered_map<row_selector<>, std::vector<typename context_type::lookup_constraint_type>>
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
                        if (presets.selectors_amount() <= selector_index) {
                            presets.resize_selectors(selector_index + 1);
                        }
                        for(std::size_t row_index : row_list) {
                            presets.enable_selector(selector_index, row_index);
                        }
                    }

                    // dynamic lookup tables - continued
                    for(const auto& [name, area] : dynamic_lookup_tables) {
                        bp.register_dynamic_table(name);
                        std::size_t selector_index = bp.get_dynamic_lookup_table_selector();
                        if (presets.selectors_amount() <= selector_index) {
                            presets.resize_selectors(selector_index + 1);
                        }
                        for(std::size_t row_index : area.second) {
                            presets.enable_selector(selector_index,row_index);
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
                            presets.constant(i,j) = c_list[i][j];
                        }
                    }

                    // std::cout << "Gates amount = " << bp.num_gates() << "\n";
                    // std::cout << "Lookup gates amount = " << bp.num_lookup_gates() << "\n";
                }

                std::set<std::vector<typename FieldType::value_type>>
                load_dynamic_lookup(const crypto3::zk::snark::plonk_assignment_table<FieldType> &assignments, std::size_t table_id) {
                    std::set<std::vector<typename FieldType::value_type>> result;
                    auto &table = bp.lookup_tables()[table_id-1];

                    crypto3::zk::snark::plonk_column<FieldType> selector = assignments.selector(table.tag_index);

                    for( std::size_t selector_row = 0; selector_row < rows_amount; selector_row++ ){
                        if( selector_row < selector.size() && !selector[selector_row].is_zero() ){
                            for( std::size_t op = 0; op < table.lookup_options.size(); op++){
                                std::vector<typename FieldType::value_type> item(table.lookup_options[op].size());
                                for( std::size_t i = 0; i < table.lookup_options[op].size(); i++){
                                    crypto3::zk::snark::plonk_constraint<FieldType> expr = table.lookup_options[op][i];;
                                    item[i] = expr.evaluate(selector_row, assignments);
                                }
                                result.insert(item);
                            }
                        }
                    }
                    return result;
                }

                public:
                std::pair<crypto3::zk::snark::plonk_assignment_table<FieldType>, Component<FieldType, GenerationStage::ASSIGNMENT>>
                assign(typename Component<FieldType, GenerationStage::ASSIGNMENT>::raw_input_type raw_input) {
                    using generator = Component<FieldType,GenerationStage::ASSIGNMENT>;
                    using assignment_type = crypto3::zk::snark::plonk_assignment_table<FieldType>;
                    using context_type = typename nil::blueprint::bbf::context<FieldType, nil::blueprint::bbf::GenerationStage::ASSIGNMENT>;

                    // actually we should use presets to chose the right size and partly fill it
                    assignment_type at = assignment_type(witnesses_amount, public_inputs_amount,
                        presets.constants_amount(), presets.selectors_amount());

                    // copy preset constants
                    for(std::size_t i = 0; i < presets.constants_amount(); i++) {
                        at.fill_constant(i, presets.constant(i));
                    }
                    // copy preset selectors
                    for(std::size_t i = 0; i < presets.selectors_amount(); i++) {
                        at.fill_selector(i, presets.selector(i));
                    }

                    context_type ct = context_type(at, rows_amount, 0); // use all rows, start from 0

                    auto v = std::tuple_cat(std::make_tuple(ct), generator::form_input(ct,raw_input), static_info_args_storage);
                    return std::make_pair(at,std::make_from_tuple<generator>(v));
                }

                bool is_satisfied(const crypto3::zk::snark::plonk_assignment_table<FieldType> &assignments) {
                    std::set<uint32_t> used_gates;
                    for (std::uint32_t i = 0; i < bp.gates().size(); i++) {
                         used_gates.insert(i);
                    }

                    std::set<uint32_t> used_lookup_gates;
                    for (std::uint32_t i = 0; i < bp.lookup_gates().size(); i++) {
                         used_lookup_gates.insert(i);
                    }

                    std::set<uint32_t> used_copy_constraints;
                    for (std::uint32_t i = 0; i < bp.copy_constraints().size(); i++) {
                         used_copy_constraints.insert(i);
                    }

                    std::set<uint32_t> selector_rows;
                    for (std::uint32_t i = 0; i < rows_amount; i++) {
                         selector_rows.insert(i);
                    }

                    const auto &gates = bp.gates();
                    const auto &copy_constraints = bp.copy_constraints();
                    const auto &lookup_gates = bp.lookup_gates();

                    std::map<std::string, std::set<std::vector<typename FieldType::value_type>>> used_dynamic_tables;

                    for (const auto& i : used_gates) {
                        crypto3::zk::snark::plonk_column<FieldType> selector = assignments.selector(gates[i].selector_index);

                        for (const auto& selector_row : selector_rows) {
                            if (selector_row < selector.size() && !selector[selector_row].is_zero()) {
                                for (std::size_t j = 0; j < gates[i].constraints.size(); j++) {

                                    typename FieldType::value_type constraint_result =
                                        gates[i].constraints[j].evaluate(selector_row, assignments);

                                    if (!constraint_result.is_zero()) {
                                        std::cout << "Constraint " << j << " from gate " << i << " on row " << selector_row
                                            << " is not satisfied." << std::endl;
                                        std::cout << "Constraint result: " << constraint_result << std::endl;
                                        std::cout << "Offending contraint: " << gates[i].constraints[j] << std::endl;
                                        return false;
                                    }
                                }
                            }
                        }
                    }

                    for (const auto& i : used_lookup_gates) {
                        crypto3::zk::snark::plonk_column<FieldType> selector = assignments.selector(lookup_gates[i].tag_index);

                        for (const auto& selector_row : selector_rows) {
                            if (selector_row < selector.size() && !selector[selector_row].is_zero()) {
                                for (std::size_t j = 0; j < lookup_gates[i].constraints.size(); j++) {
                                    std::vector<typename FieldType::value_type> input_values;
                                    input_values.reserve(lookup_gates[i].constraints[j].lookup_input.size());
                                    for (std::size_t k = 0; k < lookup_gates[i].constraints[j].lookup_input.size(); k++) {
                                        input_values.emplace_back(lookup_gates[i].constraints[j].lookup_input[k].evaluate(
                                            selector_row, assignments));
                                    }
                                    const auto table_name =
                                        bp.get_reserved_indices_right().at(lookup_gates[i].constraints[j].table_id);
                                    try {
                                        if( bp.get_reserved_dynamic_tables().find(table_name) != bp.get_reserved_dynamic_tables().end() ) {
                                            if( used_dynamic_tables.find(table_name) == used_dynamic_tables.end()) {
                                                used_dynamic_tables[table_name] =
                                                    load_dynamic_lookup(assignments, lookup_gates[i].constraints[j].table_id);
                                            }
                                            if(used_dynamic_tables[table_name].find(input_values) == used_dynamic_tables[table_name].end()) {
                                                for (std::size_t k = 0; k < input_values.size(); k++) {
                                                    std::cout << input_values[k] << " ";
                                                }
                                                std::cout << std::endl;
                                                std::cout << "Constraint " << j << " from lookup gate " << i << " from table "
                                                    << table_name << " on row " << selector_row << " is not satisfied."
                                                    << std::endl;
                                                std::cout << "Offending Lookup Gate: " << std::endl;
                                                for (const auto &constraint : lookup_gates[i].constraints) {
                                                    std::cout << "Table id: " << constraint.table_id << std::endl;
                                                    for (auto &lookup_input : constraint.lookup_input) {
                                                        std::cout << lookup_input << std::endl;
                                                    }
                                                }
                                                return false;
                                            }
                                            continue;
                                        }
                                        std::string main_table_name = table_name.substr(0, table_name.find("/"));
                                        std::string subtable_name = table_name.substr(table_name.find("/") + 1, table_name.size() - 1);

                                        const auto &table = bp.get_reserved_tables().at(main_table_name)->get_table();
                                        const auto &subtable = bp.get_reserved_tables().at(main_table_name)->subtables.at(subtable_name);

                                        std::size_t columns_number = subtable.column_indices.size();

                                        // Search the table for the input values
                                        // We can cache it with sorting, or use KMP, but I need a simple solution first
                                        bool found = false;
                                        BOOST_ASSERT(columns_number == input_values.size());
                                        for (std::size_t k = 0; k < table[0].size(); k++) {
                                            bool match = true;
                                            for (std::size_t l = 0; l < columns_number; l++) {
                                                if (table[subtable.column_indices[l]][k] != input_values[l]) {
                                                    match = false;
                                                    break;
                                                }
                                            }
                                            if (match) {
                                                found = true;
                                                break;
                                            }
                                        }
                                        if (!found) {
                                            std::cout << "Input values:";
                                            for (std::size_t k = 0; k < input_values.size(); k++) {
                                                std::cout << input_values[k] << " ";
                                            }
                                            std::cout << std::endl;
                                            std::cout << "Constraint " << j << " from lookup gate " << i << " from table "
                                                << table_name << " on row " << selector_row << " is not satisfied."
                                                << std::endl;
                                            std::cout << "Offending Lookup Gate: " << std::endl;
                                            for (const auto &constraint : lookup_gates[i].constraints) {
                                                std::cout << "Table id: " << constraint.table_id << std::endl;
                                                for (auto &lookup_input : constraint.lookup_input) {
                                                    std::cout << lookup_input << std::endl;
                                                }
                                            }
                                            return false;
                                        }
                                    } catch (std::out_of_range &e) {
                                        std::cout << "Lookup table " << table_name << " not found." << std::endl;
                                        std::cout << "Table_id = " << lookup_gates[i].constraints[j].table_id << " table_name "
                                                  << table_name << std::endl;
                                        return false;
                                    }
                                }
                            }
                        }
                    }

                    for (const auto& i : used_copy_constraints) {
                        if (var_value(assignments, copy_constraints[i].first) !=
                            var_value(assignments, copy_constraints[i].second)) {
                            std::cout << "Copy constraint number " << i << " is not satisfied."
                                      << " First variable: " << copy_constraints[i].first
                                      << " second variable: " << copy_constraints[i].second << std::endl;
                            std::cout << var_value(assignments, copy_constraints[i].first) << " != "
                                      << var_value(assignments, copy_constraints[i].second) << std::endl;
                            return false;
                        }
                    }
                    return true;
                }

                private:
                    std::size_t witnesses_amount;
                    std::size_t public_inputs_amount;
                    std::size_t constants_amount;
                    std::size_t rows_amount;

                    static_info_args_storage_type static_info_args_storage;

                    circuit<crypto3::zk::snark::plonk_constraint_system<FieldType>> bp;
                    crypto3::zk::snark::plonk_assignment_table<FieldType> presets;
            };

        }  // namespace bbf
    }   // namespace blueprint
}    // namespace nil
#endif    // CRYPTO3_BLUEPRINT_PLONK_BBF_CIRCUIT_BUILDER_HPP
