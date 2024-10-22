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
// @file Declaration of interfaces for PLONK component wrapping the BBF-component interface
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_BLUEPRINT_PLONK_BBF_BYTECODE_WRAPPER_HPP
#define CRYPTO3_BLUEPRINT_PLONK_BBF_BYTECODE_WRAPPER_HPP

#include <functional>

#include <nil/crypto3/zk/snark/arithmetization/plonk/constraint_system.hpp>

#include <nil/blueprint/blueprint/plonk/assignment.hpp>
#include <nil/blueprint/blueprint/plonk/circuit.hpp>
#include <nil/blueprint/component.hpp>
#include <nil/blueprint/manifest.hpp>

#include <nil/blueprint/bbf/generic.hpp> // also included by is_zero.hpp below
#include <nil/blueprint/zkevm-bbf/bytecode.hpp>

#include <nil/crypto3/zk/snark/arithmetization/plonk/lookup_table_definition.hpp>

namespace nil {
    namespace blueprint {
        namespace components {

            template<typename ArithmetizationType, typename FieldType>
            class zkevm_bytecode_wrapper;

            template<typename BlueprintFieldType>
            class zkevm_bytecode_wrapper<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>, BlueprintFieldType>
                : public plonk_component<BlueprintFieldType> {

            public:
                using component_type = plonk_component<BlueprintFieldType>;

                using var = typename component_type::var;
                using manifest_type = plonk_component_manifest;

                std::size_t max_bytecode_size;
                std::size_t max_keccak_blocks;

                class gate_manifest_type : public component_gate_manifest {
                public:
                    std::uint32_t gates_amount() const override {
                        return zkevm_bytecode_wrapper::gates_amount;
                    }
                };

                static gate_manifest get_gate_manifest(std::size_t witness_amount) {
                    static gate_manifest manifest = gate_manifest(gate_manifest_type());
                    return manifest;
                }

                static manifest_type get_manifest() {
                    static manifest_type manifest = manifest_type(
                        std::shared_ptr<manifest_param>(new manifest_single_value_param(10)),
                        false
                    );
                    return manifest;
                }

                constexpr static std::size_t get_rows_amount(std::size_t witness_amount, std::size_t max_bytecode_size, std::size_t max_keccak_blocks) {
                    return max_bytecode_size + max_keccak_blocks + 1;
                }
                constexpr static std::size_t get_empty_rows_amount(std::size_t max_bytecode_size, std::size_t max_keccak_blocks) {
                    return max_bytecode_size + max_keccak_blocks + 1;
                }

                constexpr static const std::size_t gates_amount = 5;
                const std::size_t rows_amount = get_rows_amount(this->witness_amount(),max_bytecode_size,max_keccak_blocks);
                const std::size_t empty_rows_amount = get_empty_rows_amount(max_bytecode_size,max_keccak_blocks);
                const std::string component_name = "wrapper of BBF version of zkevm bytecode component";

                class input_type : public bbf::bytecode_input_type<BlueprintFieldType> {
                    public:
                    var rlc_challenge;
                    input_type(var _rlc_challenge ) :rlc_challenge(_rlc_challenge) {}

                    std::vector<std::reference_wrapper<var>> all_vars() {
                        return {rlc_challenge};
                    }
                };

                struct result_type {
                    result_type(const zkevm_bytecode_wrapper &component, std::size_t start_row_index) { }

                    std::vector<std::reference_wrapper<var>> all_vars() {
                        return {};
                    }
                };

                zkevm_bytecode_wrapper(
                    typename component_type::witness_container_type witnesses,
                    typename component_type::constant_container_type constants,
                    typename component_type::public_input_container_type public_inputs,
                    std::size_t _max_bytecode_size,
                    std::size_t _max_keccak_blocks
                ) : component_type(witnesses, constants, public_inputs, get_manifest()),
                    max_bytecode_size(_max_bytecode_size),
                    max_keccak_blocks(_max_keccak_blocks)
                {};

                std::map<std::string, std::size_t> component_lookup_tables() const{
                    std::map<std::string, std::size_t> lookup_tables;
                    return lookup_tables;
                }
            };

            template<typename BlueprintFieldType>
            using plonk_zkevm_bytecode_wrapper =
                zkevm_bytecode_wrapper<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>, BlueprintFieldType>;

            template<typename BlueprintFieldType>
            typename plonk_zkevm_bytecode_wrapper<BlueprintFieldType>::result_type
                generate_assignments(
                    const plonk_zkevm_bytecode_wrapper<BlueprintFieldType>  &component,
                    assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>>  &assignment,
                    const typename plonk_zkevm_bytecode_wrapper<BlueprintFieldType>::input_type &instance_input,
                    const std::uint32_t  start_row_index) {

                using value_type = typename BlueprintFieldType::value_type;
                using context_type = typename nil::blueprint::bbf::context<BlueprintFieldType,
                                                  nil::blueprint::bbf::GenerationStage::ASSIGNMENT>;
                using zkEVM_Bytecode = typename nil::blueprint::bbf::zkevm_bytecode<BlueprintFieldType,
                                                  nil::blueprint::bbf::GenerationStage::ASSIGNMENT>;
                using TYPE = typename context_type::TYPE;

                context_type ct = context_type(assignment, component.max_bytecode_size + component.max_keccak_blocks + 1, start_row_index);

                zkEVM_Bytecode(ct,
                               var_value(assignment, instance_input.rlc_challenge),
                               component.max_bytecode_size,
                               component.max_keccak_blocks,
                               instance_input);

                return typename plonk_zkevm_bytecode_wrapper<BlueprintFieldType>::result_type(component, start_row_index);
            }

            template<typename BlueprintFieldType>
            typename plonk_zkevm_bytecode_wrapper<BlueprintFieldType>::result_type generate_circuit(
                const plonk_zkevm_bytecode_wrapper<BlueprintFieldType>  &component,
                circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>>  &bp,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>>  &assignment,
                const typename plonk_zkevm_bytecode_wrapper<BlueprintFieldType>::input_type  &instance_input,
                const std::size_t start_row_index) {

                using context_type = typename nil::blueprint::bbf::context<BlueprintFieldType,
                                                  nil::blueprint::bbf::GenerationStage::CONSTRAINTS>;
                using zkEVM_Bytecode = typename nil::blueprint::bbf::zkevm_bytecode<BlueprintFieldType,
                                                  nil::blueprint::bbf::GenerationStage::CONSTRAINTS>;
                using constraint_type = crypto3::zk::snark::plonk_constraint<BlueprintFieldType>;
                using plonk_copy_constraint = crypto3::zk::snark::plonk_copy_constraint<BlueprintFieldType>;
                using lookup_constraint_type = crypto3::zk::snark::plonk_lookup_constraint<BlueprintFieldType>;
                using TYPE = typename context_type::TYPE;

                using component_type = plonk_zkevm_bytecode_wrapper<BlueprintFieldType>;
                using var = typename component_type::var;

                context_type ct = context_type(assignment.get_description(),
                    component.max_bytecode_size + component.max_keccak_blocks + 1, start_row_index);

                zkEVM_Bytecode(ct,
                               instance_input.rlc_challenge,
                               component.max_bytecode_size,
                               component.max_keccak_blocks,
                               instance_input);

                ct.optimize_gates();

                // compatibility layer: constraint list => gates & selectors
                std::vector<std::pair<std::vector<constraint_type>, std::set<std::size_t>>> constraint_list = ct.get_constraints();

                for(const auto& [constraints, row_list] : constraint_list) {
                    /*
                    std::cout << "GATE:\n";
                    for(const auto& c : constraints) {
                        std::cout << c << "\n";
                    }
                    std::cout << "Rows: ";
                    */
                    std::size_t selector_index = bp.add_gate(constraints);
                    for(std::size_t row_index : row_list) {
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
                std::map<std::string,std::pair<std::vector<std::size_t>,std::set<std::size_t>>>
                    dynamic_lookup_tables = ct.get_dynamic_lookup_tables();

                // compatibility layer: lookup constraint list
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

                return typename plonk_zkevm_bytecode_wrapper<BlueprintFieldType>::result_type(component, start_row_index);
            }
        }    // namespace components
    }        // namespace blueprint
}    // namespace nil

#endif    // CRYPTO3_BLUEPRINT_PLONK_BBF_WRAPPER_HPP
