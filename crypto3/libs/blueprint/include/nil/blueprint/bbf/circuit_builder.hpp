//---------------------------------------------------------------------------//
// Copyright (c) 2024 Alexey Yashunsky <a.yashunsky@nil.foundation>
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
// @file Declaration of interfaces for BBF-components' circuit builder class
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_BLUEPRINT_PLONK_BBF_CIRCUIT_BUILDER_HPP
#define CRYPTO3_BLUEPRINT_PLONK_BBF_CIRCUIT_BUILDER_HPP

#include <functional>
#include <algorithm>

#include <nil/crypto3/zk/snark/arithmetization/plonk/constraint_system.hpp>

#include <nil/blueprint/blueprint/plonk/assignment.hpp>
#include <nil/blueprint/blueprint/plonk/circuit.hpp>
#include <nil/blueprint/component.hpp>

#include <nil/blueprint/bbf/gate_optimizer.hpp>
#include <nil/blueprint/bbf/generic.hpp>

#include <nil/crypto3/zk/snark/arithmetization/plonk/lookup_table_definition.hpp>
#include <nil/crypto3/zk/snark/arithmetization/plonk/lookup_constraint.hpp>

#include <nil/crypto3/hash/algorithm/hash.hpp>
#include <nil/crypto3/hash/sha2.hpp>
#include <nil/crypto3/hash/keccak.hpp>

#include <nil/crypto3/zk/snark/arithmetization/plonk/params.hpp>

namespace nil {
    namespace blueprint {
        namespace bbf {

            template<typename FieldType, template<typename, GenerationStage stage> class Component, typename... ComponentStaticInfoArgs>
            class circuit_builder {
                using static_info_args_storage_type = std::tuple<ComponentStaticInfoArgs...>;
                public:

                circuit_builder(std::size_t witnesses, std::size_t public_inputs, std::size_t user_constants, std::size_t rows,
                    ComponentStaticInfoArgs... component_static_info_args) {

                    static_info_args_storage = {component_static_info_args...};
                    prepare_circuit_parameters(witnesses,public_inputs,user_constants,rows);
                }

                // typical setup: 1 PI column, 0 constant columns, witnesses × rows
                circuit_builder(std::size_t witnesses, std::size_t rows, ComponentStaticInfoArgs... component_static_info_args) {
                    static_info_args_storage = {component_static_info_args...};
                    prepare_circuit_parameters(witnesses,1,0,rows);
                }

                // query component for minimal requirements
                circuit_builder(ComponentStaticInfoArgs... component_static_info_args) {
                    using generator = Component<FieldType,GenerationStage::CONSTRAINTS>;
                    static_info_args_storage = {component_static_info_args...};
                    typename generator::table_params min_params = std::apply(generator::get_minimal_requirements, static_info_args_storage);
                    prepare_circuit_parameters(min_params.witnesses,
                                               std::max(min_params.public_inputs,std::size_t(1)), // assure at least 1 PI column is present
                                               min_params.constants,
                                               min_params.rows);
                }

                private:
                void prepare_circuit_parameters(std::size_t witnesses, std::size_t public_inputs,
                                                std::size_t user_constants, std::size_t rows) {
                    using generator = Component<FieldType,GenerationStage::CONSTRAINTS>;

                    typename generator::table_params min_params = std::apply(generator::get_minimal_requirements, static_info_args_storage);
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

                size_t create_table(const std::string& table_name, std::set<std::string>& lookup_table_names,
                                    const optimized_gates<FieldType>& gates) {
                    if (lookup_table_names.find(table_name) == lookup_table_names.end()) {
                        if (gates.dynamic_lookup_tables.find(table_name) != gates.dynamic_lookup_tables.end()) {
                            bp.reserve_dynamic_table(table_name);
                        } else {
                            bp.reserve_table(table_name);
                        }
                        lookup_table_names.insert(table_name);
                    }
                    size_t table_index = bp.get_reserved_indices().at(table_name);
                    return table_index;
                }

                void generate_constraints() {
                    using generator = Component<FieldType,GenerationStage::CONSTRAINTS>;
                    using context_type = typename nil::blueprint::bbf::context<FieldType, nil::blueprint::bbf::GenerationStage::CONSTRAINTS>;
                    using constraint_type = crypto3::zk::snark::plonk_constraint<FieldType>;
                    using expression_type = typename constraint_type::base_type;

                    using copy_constraint_type = crypto3::zk::snark::plonk_copy_constraint<FieldType>;
                    using lookup_constraint_type = crypto3::zk::snark::plonk_lookup_constraint<FieldType>;
                    using lookup_input_constraints_type = crypto3::zk::snark::lookup_input_constraints<FieldType>;
                    using value_type = typename FieldType::value_type;
                    using var = crypto3::zk::snark::plonk_variable<value_type>;
                    using TYPE = typename generator::TYPE;
                    using raw_input_type = typename generator::raw_input_type;

                    using plonk_lookup_table = nil::crypto3::zk::snark::plonk_lookup_table<FieldType>;

                    context_type ct = context_type(
                        crypto3::zk::snark::plonk_table_description<FieldType>(
                            witnesses_amount, public_inputs_amount, constants_amount, 0, rows_amount,
                            std::pow(2, std::ceil(std::log2(rows_amount)))),
                            rows_amount, 0 // use all rows, start from 0
                        );

                    raw_input_type raw_input = {};
                    auto v = std::tuple_cat(std::make_tuple(ct), generator::form_input(ct,raw_input),
                        static_info_args_storage);
                    std::make_from_tuple<generator>(v);

                    // constants
                    auto c_list = ct.get_constants();
                    // std::cout << "const list size = " << c_list.size() << "\n";
                    for(std::size_t i = 0; i < c_list.size(); i++) { // columns
                        // std::cout << "column size = " << c_list[i].size() << "\n";
                        for(std::size_t j = 0; j < c_list[i].size(); j++) { // rows
                            presets.constant(i,j) = c_list[i][j];
                        }
                    }

                    // assure minimum inflation after padding
                    size_t usable_rows = std::pow(2, std::ceil(std::log2(rows_amount))) - 1; 

                    //////////////////////////  Don't use 'ct' below this line, we just moved it!!! /////////////////////////////
                    gates_optimizer<FieldType> optimizer(std::move(ct));
                    optimized_gates<FieldType> gates = optimizer.optimize_gates();

                    // TODO: replace with PLONK_SPECIAL_SELECTOR_ALL_USABLE_ROWS_SELECTED.
                    row_selector selector_column(usable_rows);
                    for (std::size_t i = 1; i < usable_rows; i++)
                        selector_column.set_row(i);
                    size_t full_selector_id = gates.add_selector(selector_column);

                    for(const auto& [selector_id, constraints] : gates.constraint_list) {
                        /*
                        std::cout << "GATE:\n";
                        for(const auto& c : constraints) {
                            std::cout << c << "\n";
                        }
                        std::cout << "Rows: ";
                        */
                        bp.add_gate(selector_id, constraints);

                        //std::cout << "\n";
                    }

                    // compatibility layer: copy constraint list
                    for(const auto& cc : gates.copy_constraints) {
                        bp.add_copy_constraint(cc);
                    }

                    std::set<std::string> lookup_table_names;
                    for (const auto& [selector_id, lookup_list] : gates.lookup_constraints) {
                        std::vector<lookup_constraint_type> lookup_gate;
                        for (const auto& single_lookup_constraint : lookup_list) {
                            std::string table_name = single_lookup_constraint.first;
                            size_t table_index = create_table(table_name, lookup_table_names, gates);
                            lookup_gate.push_back({table_index, single_lookup_constraint.second});
                        }

                        bp.add_lookup_gate(selector_id, lookup_gate);
                    }

                    for (const auto& [table_name, grouped_lookups] : gates.grouped_lookups) {
                        size_t table_index = create_table(table_name, lookup_table_names, gates);
                        for (const auto& [ group_id, lookups] : grouped_lookups) {
                            lookup_input_constraints_type lookup_gate;
                            for (const auto& [selector_id, lookup_inputs] : lookups) {
                                lookup_gate += lookup_inputs * expression_type(var(selector_id, 0, false, var::column_type::selector));
                            }
                            bp.add_lookup_gate(full_selector_id, (const std::vector<lookup_constraint_type>&)lookup_gate);
                        }
                    }

                    // compatibility layer: dynamic lookup tables - continued
                    for(const auto& [name, area] : gates.dynamic_lookup_tables) {
                        bp.register_dynamic_table(name);

                        std::size_t selector_index = area.second;

                        //crypto3::zk::snark::plonk_lookup_table<FieldType> table_specs;
                        plonk_lookup_table table_specs;
                        table_specs.tag_index = selector_index;
                        table_specs.columns_number = area.first.size();
                        std::vector<var> dynamic_lookup_cols;
                        for(const auto& c : area.first) {
                            // TODO: does this make sense?!
                            dynamic_lookup_cols.push_back(var(c, 0, false, var::column_type::witness));
                        }
                        table_specs.lookup_options = {dynamic_lookup_cols};
                        bp.define_dynamic_table(name,table_specs);
                    }

                    // this is where we pack lookup tables into constant columns and assign them selectors

                    const auto &lookup_table_ids = bp.get_reserved_indices();
                    const auto &lookup_tables = bp.get_reserved_tables();
                    const auto &dynamic_tables = bp.get_reserved_dynamic_tables();

                    std::vector<std::string> ordered_table_names =
                        nil::crypto3::zk::snark::get_tables_ordered_by_rows_number<FieldType>(lookup_tables);

                    std::size_t start_row = 1;
                    std::vector<plonk_lookup_table> bp_lookup_tables(lookup_table_ids.size());
                    std::size_t start_constant_column = presets.constants_amount();
                    std::size_t prev_columns_number = 0;

                    for(const auto &table_name : ordered_table_names) {
                        const auto &table = lookup_tables.at(table_name);

                        if (table->get_rows_number() > usable_rows) {
                            std::size_t options_number = table->get_rows_number() / usable_rows + 1;
                            start_constant_column += prev_columns_number;
                            std::size_t cur_constant_column = start_constant_column;
                            prev_columns_number = options_number * table->get_columns_number();

                            if (presets.constants_amount() < start_constant_column + prev_columns_number) {
                                presets.resize_constants(start_constant_column + prev_columns_number);
                            }
                            // assure all added columns have same amount of usable_rows and need no resizement later
                            for(std::size_t i = start_constant_column; i < start_constant_column + prev_columns_number; i++)
                                presets.constant(i, usable_rows - 1) = 0;

                            

                            if (table->get_rows_number() % usable_rows == 0) options_number--;
                            std::size_t cur = 0;
                            for(std::size_t i = 0; i < options_number; i++) {
                                for(std::size_t local_start_row = 1; local_start_row < usable_rows; local_start_row++, cur++) {
                                    for(std::size_t k = 0; k < table->get_columns_number(); k++) {
                                        if (cur < table->get_rows_number())
                                            presets.constant(cur_constant_column + k,local_start_row) = table->get_table()[k][cur];
                                        else
                                            presets.constant(cur_constant_column + k,local_start_row) =
                                                table->get_table()[k][table->get_rows_number()-1];
                                    }
                                }
                                cur_constant_column += table->get_columns_number();
                            }
                            for(const auto &[subtable_name, subtable] : table->subtables) {
                                if (subtable.begin != 0 || subtable.end != table->get_rows_number() -1)
                                    BOOST_ASSERT_MSG(false, "Only full big tables are supported now");
                                std::string full_table_name = table->table_name + "/" + subtable_name;
                                bp_lookup_tables[lookup_table_ids.at(full_table_name) - 1] =
                                    plonk_lookup_table(subtable.column_indices.size(), full_selector_id);

                                for(std::size_t i = 0; i < options_number; i++) {
                                    std::vector<nil::crypto3::zk::snark::plonk_variable<typename FieldType::value_type>> option;
                                    for(const auto &column_index : subtable.column_indices) {
                                        option.emplace_back(nil::crypto3::zk::snark::plonk_variable<typename FieldType::value_type>(
                                            start_constant_column + i * table->get_columns_number() + column_index, 0, false,
                                            nil::crypto3::zk::snark::plonk_variable<typename FieldType::value_type>::column_type::constant));
                                    }
                                    bp_lookup_tables[lookup_table_ids.at(full_table_name) - 1].append_option(option);
                                }
                            }
                            start_constant_column = cur_constant_column;
                            continue;
                        } else if (start_row + table->get_rows_number() < usable_rows) {
                            prev_columns_number = std::max(prev_columns_number,  table->get_columns_number());
                        } else if (table->get_rows_number() < usable_rows) {
                            start_row = 1;
                            start_constant_column += prev_columns_number;
                            prev_columns_number = table->get_columns_number();
                        }

                        // Place table into constant_columns.

                        // add constant columns if necessary
                        if (presets.constants_amount() < start_constant_column + table->get_table().size()) {
                            presets.resize_constants(start_constant_column + table->get_table().size());
                        }
                        // assure all added columns have same amount of usable_rows and need no resizement later
                        for(std::size_t i = start_constant_column; i < start_constant_column + table->get_table().size(); i++)
                            presets.constant(i,usable_rows-1) = 0;

                        for(std::size_t i = 0; i < table->get_table().size(); i++) {
                            for(std::size_t j = 0; j < table->get_table()[i].size(); j++) {
                                presets.constant(start_constant_column + i,start_row + j) = table->get_table()[i][j];
                            }
                        }

                        std::map<std::pair<std::size_t, std::size_t>, std::size_t> selector_ids;
                        for(const auto &[subtable_name, subtable]:table->subtables) {
                            if( selector_ids.find(std::make_pair(subtable.begin, subtable.end)) != selector_ids.end() ){
                                // std::cout  << "selector for " << subtable_name << " from " << start_row + subtable.begin
                                //            << " to " << start_row + subtable.end << std::endl;
                                auto selector_id = selector_ids[std::make_pair(subtable.begin, subtable.end)];
                                std::string full_table_name = table->table_name + "/" + subtable_name;
                                bp_lookup_tables[lookup_table_ids.at(full_table_name) - 1] =
                                    plonk_lookup_table(subtable.column_indices.size(), selector_id);
                                std::vector<nil::crypto3::zk::snark::plonk_variable<typename FieldType::value_type>> option;
                                for( const auto &column_index : subtable.column_indices ){
                                    option.emplace_back( nil::crypto3::zk::snark::plonk_variable<typename FieldType::value_type>(
                                        column_index, 0, false,
                                        nil::crypto3::zk::snark::plonk_variable<typename FieldType::value_type>::column_type::constant
                                    ) );
                                }
                                bp_lookup_tables[lookup_table_ids.at(full_table_name) - 1].append_option(option);
                                continue;
                            }
                            // Create selector
                            row_selector selector_column(usable_rows);
                            // std::cout  << "selector for " << subtable_name << " from " << start_row + subtable.begin
                            //            << " to " << start_row + subtable.end << std::endl;
                            for(std::size_t k = subtable.begin; k <= subtable.end; k++){
                                selector_column.set_row(start_row + k);
                            }
                            std::size_t cur_selector_id = gates.add_selector(selector_column);

                            std::string full_table_name = table->table_name + "/" + subtable_name;
                            bp_lookup_tables[lookup_table_ids.at(full_table_name) - 1] =
                                plonk_lookup_table(subtable.column_indices.size(), cur_selector_id);

                            std::vector<nil::crypto3::zk::snark::plonk_variable<typename FieldType::value_type>> option;
                            for(const auto &column_index : subtable.column_indices) {
                                option.emplace_back(nil::crypto3::zk::snark::plonk_variable<typename FieldType::value_type>(
                                    start_constant_column + column_index, 0, false,
                                    nil::crypto3::zk::snark::plonk_variable<typename FieldType::value_type>::column_type::constant
                                ) );
                            }
                            bp_lookup_tables[lookup_table_ids.at(full_table_name) - 1].append_option(option);
                            selector_ids[std::make_pair(subtable.begin, subtable.end)] = cur_selector_id;
                        }
                        start_row += table->get_rows_number();
                    }
                    for(const auto&[k, table]:dynamic_tables) {
                        BOOST_ASSERT(table->is_defined());
                        bp_lookup_tables[lookup_table_ids.at(k) - 1] = table->lookup_table;
                    }
                    for(std::size_t i = 0; i < bp_lookup_tables.size(); i++) {
                        bp.add_lookup_table(std::move(bp_lookup_tables[i]));
                    }

                    // Emplace all the selectors.
                    for(const auto& [row_list, selector_id]: gates.selectors_) {
//std::cout << "Selector id " << selector_id << " has row_list " << row_list << " after processing " << std::endl;
                        for(std::size_t row_index : row_list) {
                            if (presets.selectors_amount() <= selector_id) {
                                presets.resize_selectors(selector_id + 1);
                            }
//std::cout << "Enabling selector " << selector_id << " on row " << row_index << std::endl;
                            presets.enable_selector(selector_id, row_index);
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
                std::tuple<
                    crypto3::zk::snark::plonk_assignment_table<FieldType>,
                    Component<FieldType, GenerationStage::ASSIGNMENT>,
                    crypto3::zk::snark::plonk_table_description<FieldType>
                >
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
                    auto o = std::make_from_tuple<generator>(v);

                    crypto3::zk::snark::plonk_table_description<FieldType> desc = at.get_description();
                    std::cout << "Rows amount = " << at.rows_amount() << std::endl;
                    desc.usable_rows_amount = at.rows_amount();
                    nil::crypto3::zk::snark::basic_padding(at);
                    std::cout << "Rows amount after padding = " << at.rows_amount() << std::endl;
                    desc.rows_amount = at.rows_amount();

                    return std::make_tuple(at,o,desc);
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

                circuit<crypto3::zk::snark::plonk_constraint_system<FieldType>>& get_circuit() {
                    return bp;
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
