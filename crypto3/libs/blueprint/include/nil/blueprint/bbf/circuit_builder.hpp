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

#include <cstddef>
#include <functional>
#include <algorithm>

#include <nil/crypto3/zk/snark/arithmetization/plonk/constraint_system.hpp>

#include <nil/blueprint/blueprint/plonk/assignment.hpp>
#include <nil/blueprint/blueprint/plonk/circuit.hpp>
#include <nil/blueprint/component.hpp>
#include <nil/blueprint/utils/satisfiability_check.hpp>

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

                    using plonk_lookup_table = nil::crypto3::zk::snark::plonk_lookup_table<FieldType>;

                    context_type ctx{
                        crypto3::zk::snark::plonk_table_description<FieldType>(
                                witnesses_amount, public_inputs_amount, constants_amount, 0, rows_amount,
                                std::pow(2, std::ceil(std::log2(rows_amount)))),
                        rows_amount, 0 // use all rows, start from 0
                    };

                    typename generator::input_type input;
                    std::apply(generator::allocate_public_inputs, std::tuple_cat(
                            std::make_tuple(std::ref(ctx), std::ref(input)), static_info_args_storage));
                    std::make_from_tuple<generator>(std::tuple_cat(
                            std::make_tuple(std::ref(ctx), std::cref(input)), static_info_args_storage));

                    // constants
                    auto c_list = ctx.get_constants();
                    // std::cout << "const list size = " << c_list.size() << "\n";
                    for(std::size_t i = 0; i < c_list.size(); i++) { // columns
                        // std::cout << "column size = " << c_list[i].size() << "\n";
                        for(std::size_t j = 0; j < c_list[i].size(); j++) { // rows
                            presets.constant(i,j) = c_list[i][j];
                        }
                    }

                    // assure minimum inflation after padding
                    size_t usable_rows = std::pow(2, std::ceil(std::log2(rows_amount))) - 1;

                    //////////////////////////  Don't use 'ctx' below this line, we just moved it!!! /////////////////////////////
                    gates_optimizer<FieldType> optimizer(std::move(ctx));
                    optimized_gates<FieldType> gates = optimizer.optimize_gates();

                    // TODO: replace with PLONK_SPECIAL_SELECTOR_ALL_USABLE_ROWS_SELECTED.
                    row_selector selector_column(usable_rows);
                    for (std::size_t i = 1; i < usable_rows; i++)
                        selector_column.set_row(i);
                    size_t full_selector_id = gates.add_selector(selector_column);

                    for(const auto& [selector_id, data] : gates.constraint_list) {
                        /*
                        std::cout << "GATE:\n";
                        for(const auto& c : constraints) {
                            std::cout << c << "\n";
                        }
                        std::cout << "Rows: ";
                        */
                        std::vector<constraint_type> constraints;
                        std::vector<std::string> names;
                        for(const auto &d : data){
                            constraints.push_back(d.first);
                            names.push_back(d.second);
                        }
                        bp.add_gate(selector_id, constraints);
                        constraint_names.insert({selector_id, std::move(names)});
                        //std::cout << "\n";
                    }

                    // compatibility layer: copy constraint list
                    for(const auto& cc : gates.copy_constraints) {
                        bp.add_copy_constraint(cc);
                    }

                    std::set<std::string> lookup_table_names;

                    {
                        auto selector_id = crypto3::zk::snark::PLONK_SPECIAL_SELECTOR_ALL_ROWS_SELECTED;

                        // global polynomial constraints
                        std::vector<constraint_type> constraints;
                        std::vector<std::string> names;
                        for(const auto &[c, n] : gates.global_constraints) {
                            constraints.push_back(c);
                            names.push_back(n);
                        }

                        if (!constraints.empty()) {
                            bp.add_gate(selector_id, constraints);
                            constraint_names.insert({selector_id, std::move(names)});
                        }

                        // global lookup constraints if there are any
                        if (!gates.global_lookup_constraints.empty()) {
                            std::vector<lookup_constraint_type> lookup_gate;
                            for (const auto& single_lookup_constraint : gates.global_lookup_constraints) {
                                std::string table_name = single_lookup_constraint.first;
                                size_t table_index = create_table(table_name, lookup_table_names, gates);
                                lookup_gate.push_back({table_index, single_lookup_constraint.second});
                            }

                            bp.add_lookup_gate(selector_id, lookup_gate);
                        }
                    }

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
                        // Create table will only create it, if it does not already exist.
                        size_t table_index = create_table(table_name, lookup_table_names, gates);
                        for (const auto& [group_id, lookups] : grouped_lookups) {
                            std::vector<lookup_constraint_type> merged_lookup_gate;
                            lookup_input_constraints_type merged_lookup_input;
                            for (const auto& [selector_id, lookup_inputs] : lookups) {
                                merged_lookup_input += lookup_inputs *
                                    expression_type(var(selector_id, 0, false, var::column_type::selector));
                            }
                            std::cout << "Adding merged lookup input to table #" << table_index << " -> ";
                            for (const auto& li: merged_lookup_input)
                                std::cout << li << std::endl;

                            merged_lookup_gate.push_back({table_index, merged_lookup_input});
                            bp.add_lookup_gate(full_selector_id, merged_lookup_gate);
                        }
                    }

                    // compatibility layer: dynamic lookup tables - continued
                    for(const auto& [name, area] : gates.dynamic_lookup_tables) {
                        bp.register_dynamic_table(name);

                        std::size_t selector_index = area.second;

                        //crypto3::zk::snark::plonk_lookup_table<FieldType> table_specs;
                        plonk_lookup_table table_specs;
                        table_specs.tag_index = selector_index;

                        table_specs.columns_number = area.first[0].size();
                        for(const auto &cols : area.first) {
                            table_specs.lookup_options.emplace_back();
                            auto &option = table_specs.lookup_options.back();
                            for (auto c : cols)
                                option.push_back(var(c, 0, false, var::column_type::witness));
                        }

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

                        std::size_t table_rows_number = table->subtables.size() > 1 ? table->get_rows_number() :
                            (table->subtables.begin()->second.end - table->subtables.begin()->second.begin + 1);
                        std::size_t table_columns_number = table->subtables.size() > 1 ? table->get_columns_number() :
                            table->subtables.begin()->second.column_indices.size();
                        std::vector<std::size_t> column_map(table_columns_number);
                        if (table->subtables.size() == 1) {
                            column_map = table->subtables.begin()->second.column_indices;
                        } else {
                            for(std::size_t k = 0; k < table_columns_number; k++) {
                                column_map[k] = k;
                            }
                        }
                        std::size_t table_row_shift = table->subtables.size() > 1 ? 0 : table->subtables.begin()->second.begin;

                        if (table_rows_number > usable_rows) {
                            std::size_t options_number = table_rows_number / usable_rows + 1;
                            start_constant_column += prev_columns_number;
                            std::size_t cur_constant_column = start_constant_column;
                            prev_columns_number = options_number * table_columns_number;

                            if (presets.constants_amount() < start_constant_column + prev_columns_number) {
                                presets.resize_constants(start_constant_column + prev_columns_number);
                            }
                            // assure all added columns have same amount of usable_rows and need no resizement later
                            for(std::size_t i = start_constant_column; i < start_constant_column + prev_columns_number; i++)
                                presets.constant(i, usable_rows - 1) = 0;

                            // TODO: shouldn't we do it before we calculate prev_columns_number?
                            if (table_rows_number % usable_rows == 0) options_number--;

                            std::size_t cur = 0;
                            for(std::size_t i = 0; i < options_number; i++) {
                                for(std::size_t local_start_row = 1; local_start_row < usable_rows; local_start_row++, cur++) {
                                    for(std::size_t k = 0; k < table_columns_number; k++) {
                                        if (cur < table_rows_number)
                                            presets.constant(cur_constant_column + k,local_start_row) =
                                                table->get_table()[column_map[k]][table_row_shift + cur];
                                        else
                                            presets.constant(cur_constant_column + k,local_start_row) =
                                                table->get_table()[column_map[k]][table_row_shift + table_rows_number-1];
                                    }
                                }
                                cur_constant_column += table_columns_number;
                            }
                            for(const auto &[subtable_name, subtable] : table->subtables) {
                                if ((table->subtables.size() > 1) &&
                                    (subtable.begin != 0 || subtable.end != table->get_rows_number() -1))
                                    BOOST_ASSERT_MSG(false, "Only full big tables are supported now");
                                std::string full_table_name = table->table_name + "/" + subtable_name;
                                bp_lookup_tables[lookup_table_ids.at(full_table_name) - 1] =
                                    plonk_lookup_table(subtable.column_indices.size(), full_selector_id);

                                for(std::size_t i = 0; i < options_number; i++) {
                                    std::vector<nil::crypto3::zk::snark::plonk_variable<typename FieldType::value_type>> option;
                                    for(std::size_t k = 0; k < subtable.column_indices.size(); k++) {
                                        // if current subtable is the only one in the table, its columns are exatly
                                        // the columns present in the table
                                        std::size_t column_index = (table->subtables.size() > 1) ? subtable.column_indices[k] : k;
                                        option.emplace_back(nil::crypto3::zk::snark::plonk_variable<typename FieldType::value_type>(
                                            start_constant_column + i * table_columns_number + column_index, 0, false,
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
                            prev_columns_number = table_columns_number;
                        }

                        // Place table into constant_columns.

                        // add constant columns if necessary
                        if (presets.constants_amount() < start_constant_column + table_columns_number) {
                            presets.resize_constants(start_constant_column + table_columns_number);
                            }
                        // assure all added columns have same amount of usable_rows and need no resizement later
                        for(std::size_t i = start_constant_column; i < start_constant_column + table_columns_number; i++)
                            presets.constant(i,usable_rows - 1) = 0;

                        for(std::size_t i = 0; i < table_columns_number; i++) {
                            for(std::size_t j = table_row_shift; j < std::min(table_row_shift + table_rows_number,
                                                                table->get_table()[column_map[i]].size()); j++) {
                                presets.constant(start_constant_column + i,start_row + j - table_row_shift) =
                                    table->get_table()[column_map[i]][j];
                            }
                        }

                        std::map<std::pair<std::size_t, std::size_t>, std::size_t> selector_ids;
                        for(const auto &[subtable_name, subtable] : table->subtables) {
                            if( selector_ids.find(std::make_pair(subtable.begin, subtable.end)) != selector_ids.end() ){
                                // std::cout  << "selector for " << subtable_name << " from " << start_row + subtable.begin
                                //            << " to " << start_row + subtable.end << std::endl;
                                auto selector_id = selector_ids[std::make_pair(subtable.begin, subtable.end)];
                                std::string full_table_name = table->table_name + "/" + subtable_name;
                                bp_lookup_tables[lookup_table_ids.at(full_table_name) - 1] =
                                    plonk_lookup_table(subtable.column_indices.size(), selector_id);
                                std::vector<nil::crypto3::zk::snark::plonk_variable<typename FieldType::value_type>> option;
                                for(std::size_t k = 0; k < subtable.column_indices.size(); k++) {
                                    // if current subtable is the only one in the table, its columns are exatly
                                    // the columns present in the table
                                    std::size_t column_index = (table->subtables.size() > 1) ? subtable.column_indices[k] : k;
                                    option.emplace_back( nil::crypto3::zk::snark::plonk_variable<typename FieldType::value_type>(
                                        start_constant_column + column_index, 0, false,
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
                        start_row += table_rows_number;
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

                public:
                std::tuple<
                    crypto3::zk::snark::plonk_assignment_table<FieldType>,
                    Component<FieldType, GenerationStage::ASSIGNMENT>,
                    crypto3::zk::snark::plonk_table_description<FieldType>
                >
                assign(typename Component<FieldType, GenerationStage::ASSIGNMENT>::input_type input) {
                    using generator = Component<FieldType,GenerationStage::ASSIGNMENT>;
                    using context_type = typename nil::blueprint::bbf::context<FieldType, nil::blueprint::bbf::GenerationStage::ASSIGNMENT>;

                    auto at = get_presets();
                    context_type ctx = context_type(at, rows_amount, 0); // use all rows, start from 0

                    std::apply(generator::allocate_public_inputs, std::tuple_cat(
                            std::make_tuple(std::ref(ctx), std::ref(input)), static_info_args_storage));

                    auto component = std::make_from_tuple<generator>(std::tuple_cat(
                            std::make_tuple(std::ref(ctx), std::cref(input)), static_info_args_storage));

                    crypto3::zk::snark::plonk_table_description<FieldType> desc = at.get_description();
                    std::cout << "Rows amount = " << at.rows_amount() << std::endl;
                    desc.usable_rows_amount = at.rows_amount();
                    nil::crypto3::zk::snark::basic_padding(at);
                    std::cout << "Rows amount after padding = " << at.rows_amount() << std::endl;
                    desc.rows_amount = at.rows_amount();

                    return {at, component, desc};
                }

                bool is_satisfied(const crypto3::zk::snark::plonk_assignment_table<FieldType> &assignments,
                                  const satisfiability_check_options &options = {}) {

                    if (!constraint_names.empty() && !options.constraint_names) {
                        auto opts_copy = options;
                        opts_copy.constraint_names = &constraint_names;
                        return satisfiability_checker<FieldType>::is_satisfied(bp, assignments, opts_copy);
                    }
                    return satisfiability_checker<FieldType>::is_satisfied(bp, assignments, options);
                }

                const circuit<crypto3::zk::snark::plonk_constraint_system<FieldType>>& get_circuit() {
                    return bp;
                }

                crypto3::zk::snark::plonk_assignment_table<FieldType> get_presets() {
                    // actually we should use presets to chose the right size and partly fill it
                    crypto3::zk::snark::plonk_assignment_table<FieldType> at(
                        witnesses_amount, public_inputs_amount,
                        presets.constants_amount(), presets.selectors_amount());

                    for (std::size_t i = 0; i < presets.constants_amount(); ++i)
                        at.fill_constant(i, presets.constant(i));
                    for (std::size_t i = 0; i < presets.selectors_amount(); ++i)
                        at.fill_selector(i, presets.selector(i));

                    return at;
                }

                private:
                    std::size_t witnesses_amount;
                    std::size_t public_inputs_amount;
                    std::size_t constants_amount;
                    std::size_t rows_amount;

                    static_info_args_storage_type static_info_args_storage;

                    circuit<crypto3::zk::snark::plonk_constraint_system<FieldType>> bp;
                    crypto3::zk::snark::plonk_assignment_table<FieldType> presets;
                    std::map<uint32_t, std::vector<std::string>> constraint_names;
            };

        }  // namespace bbf
    }   // namespace blueprint
}    // namespace nil
#endif    // CRYPTO3_BLUEPRINT_PLONK_BBF_CIRCUIT_BUILDER_HPP
