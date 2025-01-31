//---------------------------------------------------------------------------//
// Copyright (c) 2024 Alexey Yashunsky <a.yashunsky@nil.foundation>
//               2024 Valeh Farzaliyev <estoniaa@nil.foundation>
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
// @file Declaration of interfaces for PLONK component wrapping the BBF-component interface
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_BLUEPRINT_PLONK_EXP_WRAPPER_HPP
#define CRYPTO3_BLUEPRINT_PLONK_EXP_WRAPPER_HPP

#include <functional>

#include <nil/crypto3/zk/snark/arithmetization/plonk/constraint_system.hpp>

#include <nil/blueprint/blueprint/plonk/assignment.hpp>
#include <nil/blueprint/blueprint/plonk/circuit.hpp>
#include <nil/blueprint/component.hpp>
#include <nil/blueprint/manifest.hpp>

#include <nil/blueprint/bbf/generic.hpp> 
#include <nil/blueprint/bbf/exp_table.hpp> // also included by exp.hpp below
#include <nil/blueprint/bbf/exp.hpp>


#include <nil/crypto3/zk/snark/arithmetization/plonk/lookup_table_definition.hpp>

namespace nil {
    namespace blueprint {
        namespace components {

            template<typename ArithmetizationType, typename FieldType>
            class exp_wrapper;

            template<typename BlueprintFieldType>
            class exp_wrapper<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>, BlueprintFieldType>
                : public plonk_component<BlueprintFieldType> {

            public:
                using component_type = plonk_component<BlueprintFieldType>;
                using word_type = zkevm_word_type;

                using var = typename component_type::var;
                using manifest_type = plonk_component_manifest;

                std::size_t max_rows;
                std::size_t max_exponentiations;

                class gate_manifest_type : public component_gate_manifest {
                public:
                    std::uint32_t gates_amount() const override {
                        return exp_wrapper::gates_amount;
                    }
                };

                static gate_manifest get_gate_manifest(std::size_t witness_amount, std::size_t max_rows, std::size_t max_exponentiations) {
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

                constexpr static std::size_t get_rows_amount(std::size_t witness_amount, std::size_t max_rows, std::size_t max_exponentiations) {
                    return max_rows;
                }
                constexpr static std::size_t get_empty_rows_amount(std::size_t witness_amount, std::size_t max_rows, std::size_t max_exponentiations) {
                    return max_rows;
                }

                constexpr static const std::size_t gates_amount = 6; // TODO: this is very unoptimized!
                const std::size_t rows_amount = get_rows_amount(this->witness_amount(),max_rows, max_exponentiations);
                const std::size_t empty_rows_amount = get_empty_rows_amount(this->witness_amount(),max_rows, max_exponentiations);
                const std::string component_name = "wrapper of exp BBF-component";

                class input_type : public bbf::exp_table_input_type {

                public:
                    std::vector<std::reference_wrapper<var>> all_vars() {

                        return {};
                    }
                };

                struct result_type {
                    result_type(const exp_wrapper &component, std::size_t start_row_index) { }

                    std::vector<std::reference_wrapper<var>> all_vars() {
                        return {};
                    }
                };


                exp_wrapper(
                    typename component_type::witness_container_type witnesses,
                    typename component_type::constant_container_type constants,
                    typename component_type::public_input_container_type public_inputs,
                    std::size_t _max_rows, 
                    std::size_t _max_exponentiations
                ) : component_type(witnesses, constants, public_inputs, get_manifest()),
                    max_rows(_max_rows), 
                    max_exponentiations(_max_exponentiations) 
                {};

                std::map<std::string, std::size_t> component_lookup_tables() const{
                    std::map<std::string, std::size_t> lookup_tables;
                    return lookup_tables;
                }
            };

            template<typename BlueprintFieldType>
            using plonk_exp_wrapper = exp_wrapper<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>, BlueprintFieldType>;

            template<typename BlueprintFieldType>
            typename plonk_exp_wrapper<BlueprintFieldType>::result_type
                generate_assignments(
                    const plonk_exp_wrapper<BlueprintFieldType>  &component,
                    assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>>  &assignment,
                    const typename plonk_exp_wrapper<BlueprintFieldType>::input_type  instance_input,
                    const std::uint32_t  start_row_index) {

                using value_type = typename BlueprintFieldType::value_type;
                using context_type = typename nil::blueprint::bbf::context<BlueprintFieldType,
                                                  nil::blueprint::bbf::GenerationStage::ASSIGNMENT>;
                using EXP_TABLE = typename nil::blueprint::bbf::exp_table<BlueprintFieldType,
                                                  nil::blueprint::bbf::GenerationStage::ASSIGNMENT>;
                using EXP_CIRCUIT = typename nil::blueprint::bbf::exp_circuit<BlueprintFieldType,
                                                  nil::blueprint::bbf::GenerationStage::ASSIGNMENT>;
                //using TYPE = typename Is_Zero::TYPE;
                using TYPE = typename context_type::TYPE;

                context_type ct = context_type(assignment, component.max_rows, start_row_index); 

                std::vector<std::size_t> table_lookup_area = {0,1,2,3,4,5};
                std::vector<std::size_t> circuit_area;
                for(std::size_t i = 6; i < component.witness_amount(); i++){
                    circuit_area.push_back(i);
                }
                context_type ct1 = ct.subcontext(table_lookup_area, 0, component.max_exponentiations + 1);
                context_type ct2 = ct.subcontext(circuit_area, 0, component.max_rows);

                
                EXP_TABLE   exp_table     = EXP_TABLE(ct1, instance_input, component.max_exponentiations +1);
                EXP_CIRCUIT exp_component = EXP_CIRCUIT(ct2, instance_input, component.max_rows, component.max_exponentiations);
       
                return typename plonk_exp_wrapper<BlueprintFieldType>::result_type(component, start_row_index);
            }

            template<typename BlueprintFieldType>
            typename plonk_exp_wrapper<BlueprintFieldType>::result_type generate_circuit(
                const plonk_exp_wrapper<BlueprintFieldType>  &component,
                circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>>  &bp,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>>  &assignment,
                const typename plonk_exp_wrapper<BlueprintFieldType>::input_type  &instance_input,
                const std::size_t start_row_index) {

                using context_type = typename nil::blueprint::bbf::context<BlueprintFieldType,
                                                  nil::blueprint::bbf::GenerationStage::CONSTRAINTS>;
                using EXP_TABLE = typename nil::blueprint::bbf::exp_table<BlueprintFieldType,
                                                  nil::blueprint::bbf::GenerationStage::CONSTRAINTS>;
                using EXP_CIRCUIT = typename nil::blueprint::bbf::exp_circuit<BlueprintFieldType,
                                                  nil::blueprint::bbf::GenerationStage::CONSTRAINTS>;
                using constraint_type = crypto3::zk::snark::plonk_constraint<BlueprintFieldType>;
                using plonk_copy_constraint = crypto3::zk::snark::plonk_copy_constraint<BlueprintFieldType>;
                using lookup_constraint_type = crypto3::zk::snark::plonk_lookup_constraint<BlueprintFieldType>;
                using TYPE = typename context_type::TYPE;

                using component_type = plonk_exp_wrapper<BlueprintFieldType>;
                using var = typename component_type::var;
                using nil::blueprint::bbf::row_selector;

                context_type ct = context_type(assignment.get_description(), component.max_rows, start_row_index); 

                std::vector<std::size_t> table_lookup_area = {0,1,2,3,4,5};
                std::vector<std::size_t> circuit_area;
                for(std::size_t i = 6; i < component.witness_amount(); i++){
                    circuit_area.push_back(i);
                }
                context_type ct1 = ct.subcontext(table_lookup_area, 0, component.max_exponentiations + 1);
                context_type ct2 = ct.subcontext(circuit_area, 0, component.max_rows);

                EXP_TABLE   exp_table     = EXP_TABLE(ct1, instance_input, component.max_exponentiations + 1);
                EXP_CIRCUIT exp_component = EXP_CIRCUIT(ct2, instance_input, component.max_rows, component.max_exponentiations);

                ct.optimize_gates();

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

                return typename plonk_exp_wrapper<BlueprintFieldType>::result_type(component, start_row_index);
            }
        }    // namespace components
    }        // namespace blueprint
}    // namespace nil

#endif    // CRYPTO3_BLUEPRINT_PLONK_EXP_WRAPPER_HPP