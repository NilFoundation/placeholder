//---------------------------------------------------------------------------//
// Copyright (c) 2024 Alexey Yashunsky <a.yashunsky@nil.foundation>
// Copyright (c) 2024 Valeh Farzaliyev <estoniaa@nil.foundation>
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

#ifndef CRYPTO3_BLUEPRINT_PLONK_KECCAK_ROUND_keccak_round_bbf_wrapper_HPP
#define CRYPTO3_BLUEPRINT_PLONK_KECCAK_ROUND_keccak_round_bbf_wrapper_HPP

#include <functional>
#include <nil/crypto3/zk/snark/arithmetization/plonk/constraint_system.hpp>
#include <nil/blueprint/blueprint/plonk/assignment.hpp>
#include <nil/blueprint/blueprint/plonk/circuit.hpp>
#include <nil/blueprint/component.hpp>
#include <nil/blueprint/manifest.hpp>

#include <nil/blueprint/bbf/hashes/keccak/keccak_round.hpp>
#include <nil/blueprint/bbf/generic.hpp> 
#include <nil/blueprint/bbf/enums.hpp>
#include <nil/blueprint/bbf/gate_optimizer.hpp>
#include <nil/crypto3/zk/snark/arithmetization/plonk/lookup_table_definition.hpp>

namespace nil {
    namespace blueprint {
        namespace components {

            template<typename ArithmetizationType, typename FieldType>
            class keccak_round_bbf_wrapper;

            template<typename BlueprintFieldType>
            class keccak_round_bbf_wrapper<
                crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>, BlueprintFieldType>
                : public plonk_component<BlueprintFieldType> {
              public:
                using component_type = plonk_component<BlueprintFieldType>;

                using var = typename component_type::var;
                using manifest_type = plonk_component_manifest;

                class gate_manifest_type : public component_gate_manifest {
                  public:
                    std::size_t witness_amount;
                    bool xor_with_mes;

                    static constexpr const std::size_t clamp = 15;

                    gate_manifest_type(std::size_t witness_amount_, bool xor_with_mes_)
                        : witness_amount(std::min(witness_amount_, clamp)),
                          xor_with_mes(xor_with_mes_) {}

                    std::uint32_t gates_amount() const override {
                        return keccak_round_bbf_wrapper::get_gates_amount(
                            witness_amount, xor_with_mes);
                    }
                };

                static gate_manifest get_gate_manifest(std::size_t witness_amount,
                                                       bool xor_with_mes) {
                    gate_manifest manifest = gate_manifest(
                        gate_manifest_type(witness_amount, xor_with_mes));
                    return manifest;
                }

                static manifest_type get_manifest() {
                    static manifest_type manifest = manifest_type(
                        std::shared_ptr<manifest_param>(new manifest_single_value_param(
                            15)),  // TODO: this has nothing to do with reality,
                        true       // to be dropped eventually
                    );
                    return manifest;
                }

                static nil::crypto3::zk::snark::plonk_table_description<BlueprintFieldType>
                get_table_description(const bool xor_with_mes) {
                    nil::crypto3::zk::snark::plonk_table_description<BlueprintFieldType> desc(
                        15, 1, 30, 50);
                    desc.usable_rows_amount = (xor_with_mes) ? 291 : 257;

                    return desc;
                }

                constexpr static std::size_t get_gates_amount(std::size_t witness_amount,
                                                              bool xor_with_mes) {
                    return 13;
                }
                constexpr static std::size_t get_rows_amount(std::size_t witness_amount,
                                                             bool xor_with_mes) {
                    return (xor_with_mes) ? 291 : 257;
                }
                constexpr static std::size_t get_empty_rows_amount() { return 0; }

                const bool xor_with_mes;
                const std::size_t rows_amount =
                    get_rows_amount(this->witness_amount(), xor_with_mes);
                const std::size_t gates_amount =
                    get_gates_amount(this->witness_amount(), xor_with_mes);
                const std::size_t empty_rows_amount = get_empty_rows_amount();
                const std::string component_name = "wrapper of keccak round BBF-component";

                struct input_type {
                    std::array<var, 25> inner_state;
                    std::array<var, 17> padded_message_chunk;
                    var round_constant;

                    std::vector<std::reference_wrapper<var>> all_vars() {
                        std::vector<std::reference_wrapper<var>> result;
                        result.insert(result.end(), inner_state.begin(), inner_state.end());
                        result.insert(result.end(), padded_message_chunk.begin(),
                                      padded_message_chunk.end());
                        result.push_back(round_constant);
                        return result;
                    }
                };

                struct result_type {
                    std::array<typename BlueprintFieldType::value_type, 25> inner_state;

                    result_type() {}

                    result_type(const keccak_round_bbf_wrapper &component,
                                std::size_t start_row_index) {}

                    result_type(
                        const std::array<typename BlueprintFieldType::value_type, 25> &result) {
                        for (std::size_t i = 0; i < 25; i++) inner_state[i] = result[i];
                    }

                    std::vector<std::reference_wrapper<var>> all_vars() {
                        std::vector<std::reference_wrapper<var>> result;
                        // result.insert(result.end(), inner_state.begin(), inner_state.end());
                        return result;
                    }
                };

                template<typename ContainerType>
                explicit keccak_round_bbf_wrapper(ContainerType witness, bool xor_with_mes_ = false)
                    : component_type(witness, {}, {}, get_manifest()),
                      xor_with_mes(xor_with_mes_){};

                template<typename WitnessContainerType, typename ConstantContainerType,
                         typename PublicInputContainerType>
                keccak_round_bbf_wrapper(WitnessContainerType witness,
                                         ConstantContainerType constant,
                                         PublicInputContainerType public_input,
                                         bool xor_with_mes_ = false)
                    : component_type(witness, constant, public_input, get_manifest()),
                      xor_with_mes(xor_with_mes_) {};

                keccak_round_bbf_wrapper(
                    std::initializer_list<
                        typename component_type::witness_container_type::value_type>
                        witnesses,
                    std::initializer_list<
                        typename component_type::constant_container_type::value_type>
                        constants,
                    std::initializer_list<
                        typename component_type::public_input_container_type::value_type>
                        public_inputs,
                    bool xor_with_mes_ = false)
                    : component_type(witnesses, constants, public_inputs, get_manifest()),
                      xor_with_mes(xor_with_mes_) {};

                std::map<std::string, std::size_t> component_lookup_tables() const {
                    std::map<std::string, std::size_t> lookup_tables;
                    // lookup_tables["keccak_normalize3_table/full"] = 0;            //
                    // REQUIRED_TABLE lookup_tables["keccak_normalize4_table/full"] = 0; //
                    // REQUIRED_TABLE lookup_tables["keccak_normalize6_table/full"] = 0; //
                    // REQUIRED_TABLE lookup_tables["keccak_chi_table/full"] = 0; // REQUIRED_TABLE
                    // lookup_tables["keccak_pack_table/range_check_sparse"] = 0;    //
                    // REQUIRED_TABLE
                    return lookup_tables;
                }
            };

            template<typename BlueprintFieldType>
            using plonk_keccak_round_bbf_wrapper = keccak_round_bbf_wrapper<
                crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>,
                BlueprintFieldType>;

            template<typename BlueprintFieldType>
            typename plonk_keccak_round_bbf_wrapper<BlueprintFieldType>::result_type
            generate_assignments(
                const plonk_keccak_round_bbf_wrapper<BlueprintFieldType> &component,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>>
                    &assignment,
                const typename plonk_keccak_round_bbf_wrapper<BlueprintFieldType>::input_type
                    instance_input,
                const std::uint32_t start_row_index) {
                using value_type = typename BlueprintFieldType::value_type;
                using context_type = typename nil::blueprint::bbf::context<
                    BlueprintFieldType, nil::blueprint::bbf::GenerationStage::ASSIGNMENT>;
                using KECCAK_ROUND = typename nil::blueprint::bbf::keccak_round<
                    BlueprintFieldType, nil::blueprint::bbf::GenerationStage::ASSIGNMENT>;
                // using TYPE = typename Is_Zero::TYPE;
                using TYPE = typename context_type::TYPE;

                context_type ct = context_type(assignment, component.rows_amount, start_row_index);
                //ct.print_witness_allocation_log(bbf::column_type::constant);

                typename KECCAK_ROUND::input_type input;
                input.round_constant = var_value(assignment, instance_input.round_constant);
                for (std::size_t i = 0; i < 17; i++) {
                    input.padded_message_chunk[i] =
                        var_value(assignment, instance_input.padded_message_chunk[i]);
                }
                for (std::size_t i = 0; i < 25; i++) {
                    input.inner_state[i] = var_value(assignment, instance_input.inner_state[i]);
                }

                auto keccak_round =
                    KECCAK_ROUND(ct, input, component.xor_with_mes);
                std::array<value_type, 25> result;
                for (std::size_t i = 0; i < 25; i++) {
                    result[i] = keccak_round.inner_state[i];
                }
                return typename plonk_keccak_round_bbf_wrapper<BlueprintFieldType>::result_type(
                    result);
            }

            template<typename BlueprintFieldType>
            typename plonk_keccak_round_bbf_wrapper<BlueprintFieldType>::result_type
            generate_circuit(
                const plonk_keccak_round_bbf_wrapper<BlueprintFieldType> &component,
                circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>> &bp,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>>
                    &assignment,
                const typename plonk_keccak_round_bbf_wrapper<BlueprintFieldType>::input_type
                    &instance_input,
                const std::size_t start_row_index) {
                using context_type = typename nil::blueprint::bbf::context<
                    BlueprintFieldType, nil::blueprint::bbf::GenerationStage::CONSTRAINTS>;
                using KECCAK_ROUND = typename nil::blueprint::bbf::keccak_round<
                    BlueprintFieldType, nil::blueprint::bbf::GenerationStage::CONSTRAINTS>;
                using constraint_type = crypto3::zk::snark::plonk_constraint<BlueprintFieldType>;
                using plonk_copy_constraint =
                    crypto3::zk::snark::plonk_copy_constraint<BlueprintFieldType>;
                using lookup_constraint_type =
                    crypto3::zk::snark::plonk_lookup_constraint<BlueprintFieldType>;
                using TYPE = typename context_type::TYPE;

                using component_type = plonk_keccak_round_bbf_wrapper<BlueprintFieldType>;
                using var = typename component_type::var;
                using nil::blueprint::bbf::row_selector;

                context_type ct = context_type(assignment.get_description(), component.rows_amount,
                                               start_row_index);

                typename KECCAK_ROUND::input_type input;
                input.round_constant = instance_input.round_constant;
                for (std::size_t i = 0; i < 17; i++) {
                    input.padded_message_chunk[i] = instance_input.padded_message_chunk[i];
                }
                for (std::size_t i = 0; i < 25; i++) {
                    input.inner_state[i] = instance_input.inner_state[i];
                }
                auto result = KECCAK_ROUND(ct, input, component.xor_with_mes);
                for (std::size_t i = 0; i < 25; i++) {
                    // std::cout << result[i] << std::endl;
                }
                
                auto c_list = ct.get_constants();
                // std::cout << "const list size = " << c_list.size() << "\n";
                for(std::size_t i = 0; i < c_list.size(); i++) { // columns
                    // std::cout << "column size = " << c_list[i].size() << "\n";
                    for(std::size_t j = 0; j < c_list[i].size(); j++) { // rows
                        // std::cout << i << ", " << j << ": " << c_list[i][j] << "\n";
                        assignment.constant(component.C(i), j) = c_list[i][j];
                    }
                }

                //////////////////////////  Don't use 'ct' below this line, we just moved it!!! /////////////////////////////
                nil::blueprint::bbf::gates_optimizer<BlueprintFieldType> optimizer(std::move(ct));
                nil::blueprint::bbf::optimized_gates<BlueprintFieldType> gates = optimizer.optimize_gates();

                // Register all the selectors.
                for (const auto& [row_list, selector_id]: gates.selectors_) {
                    for(std::size_t row_index : row_list) {
                        assignment.enable_selector(selector_id, row_index);
                    }
                }

                for (const auto& [selector_id, constraints] : gates.constraint_list) {
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

                std::set<std::string> lookup_tables;
                for(const auto& [selector_id, lookup_list] : gates.lookup_constraints) {
                    std::vector<lookup_constraint_type> lookup_gate;
                    for(const auto& single_lookup_constraint : lookup_list) {
                        std::string table_name = single_lookup_constraint.first;
                        if (lookup_tables.find(table_name) == lookup_tables.end()) {
                            if (gates.dynamic_lookup_tables.find(table_name) != gates.dynamic_lookup_tables.end()) {
                                bp.reserve_dynamic_table(table_name);
                            } else {
                                bp.reserve_table(table_name);
                            }
                            lookup_tables.insert(table_name);
                        }
                        std::size_t table_index = bp.get_reserved_indices().at(table_name);
                        lookup_gate.push_back({table_index, single_lookup_constraint.second});
                    }

                    bp.add_lookup_gate(selector_id, lookup_gate);
                }

                // compatibility layer: dynamic lookup tables - continued
                for(const auto& [name, area] : gates.dynamic_lookup_tables) {
                    bp.register_dynamic_table(name);

                    std::size_t selector_index = area.second;
                    
                    crypto3::zk::snark::plonk_lookup_table<BlueprintFieldType> table_specs;
                    table_specs.tag_index = selector_index;
                    table_specs.columns_number = area.first.size();
                    std::vector<var> dynamic_lookup_cols;
                    for(const auto& c : area.first) {
                        // TODO: does this make sense?!
                        dynamic_lookup_cols.push_back(
                            var(c, 0, false, var::column_type::witness));
                    }
                    table_specs.lookup_options = {dynamic_lookup_cols};
                    bp.define_dynamic_table(name,table_specs);
                }

                std::cout << "Gates amount = " << bp.num_gates() << "\n";
                std::cout << "Lookup gates amount = " << bp.num_lookup_gates() << "\n";

                return typename plonk_keccak_round_bbf_wrapper<BlueprintFieldType>::result_type(
                    component, start_row_index);
            }
        }  // namespace components
    }  // namespace blueprint
}  // namespace nil

#endif  // CRYPTO3_BLUEPRINT_PLONK_KECCAK_ROUND_keccak_round_bbf_wrapper_HPP
