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

#ifndef CRYPTO3_BLUEPRINT_PLONK_KECCAK_DYNAMIC_keccak_dynamic_bbf_wrapper_HPP
#define CRYPTO3_BLUEPRINT_PLONK_KECCAK_DYNAMIC_keccak_dynamic_bbf_wrapper_HPP

#include <functional>
#include <nil/blueprint/bbf/hashes/keccak/keccak_dynamic.hpp>
#include <nil/blueprint/blueprint/plonk/assignment.hpp>
#include <nil/blueprint/blueprint/plonk/circuit.hpp>
#include <nil/blueprint/component.hpp>
#include <nil/blueprint/manifest.hpp>
#include <nil/crypto3/zk/snark/arithmetization/plonk/constraint_system.hpp>

#include <nil/blueprint/bbf/gate_optimizer.hpp>
#include <nil/blueprint/bbf/enums.hpp>
#include <nil/crypto3/zk/snark/arithmetization/plonk/lookup_table_definition.hpp>

namespace nil {
    namespace blueprint {
        namespace components {

            template<typename ArithmetizationType, typename FieldType>
            class keccak_dynamic_bbf_wrapper;

            template<typename BlueprintFieldType>
            class keccak_dynamic_bbf_wrapper<
                crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>, BlueprintFieldType>
                : public plonk_component<BlueprintFieldType> {
              public:
                using component_type = plonk_component<BlueprintFieldType>;

                using var = typename component_type::var;
                using manifest_type = plonk_component_manifest;

                class gate_manifest_type : public component_gate_manifest {
                  public:
                    std::size_t witness_amount;
                    std::size_t max_blocks;

                    static constexpr const std::size_t clamp = 15;

                    gate_manifest_type(std::size_t witness_amount_, std::size_t max_blocks_)
                        : witness_amount(std::min(witness_amount_, clamp)), max_blocks(max_blocks_) {}

                    std::uint32_t gates_amount() const override {
                        return keccak_dynamic_bbf_wrapper::get_gates_amount(witness_amount, max_blocks);
                    }
                };

                static gate_manifest get_gate_manifest(std::size_t witness_amount, std::size_t max_blocks) {
                    gate_manifest manifest = gate_manifest(
                        gate_manifest_type(witness_amount, max_blocks));
                    return manifest;
                }

                static manifest_type get_manifest() {
                    static manifest_type manifest = manifest_type(
                        std::shared_ptr<manifest_param>(new manifest_single_value_param(15)),  // TODO: this has nothing to do with reality,
                        true       // to be dropped eventually
                    );
                    return manifest;
                }

                static nil::crypto3::zk::snark::plonk_table_description<BlueprintFieldType>
                get_table_description(const bool max_blocks) {
                    nil::crypto3::zk::snark::plonk_table_description<BlueprintFieldType> desc(
                        15, 1, 30, 50);
                    desc.usable_rows_amount = 6247*max_blocks;

                    return desc;
                }

                constexpr static std::size_t get_gates_amount(std::size_t witness_amount, std::size_t max_blocks) {
                    return 13 + ((max_blocks > 1) ? 1 : 0) + 1;
                }
                constexpr static std::size_t get_rows_amount(std::size_t witness_amount, std::size_t max_blocks) {
                    return 6247*max_blocks;
                }
                constexpr static std::size_t get_empty_rows_amount() { return 0; }

                const std::size_t max_blocks;
                const std::size_t rows_amount =
                    get_rows_amount(this->witness_amount(), max_blocks);
                const std::size_t gates_amount =
                    get_gates_amount(this->witness_amount(), max_blocks);
                const std::size_t empty_rows_amount = get_empty_rows_amount();
                const std::string component_name = "wrapper of keccak dynamic BBF-component";

                struct input_type {
                    var rlc_challenge;
                    std::vector<std::tuple<
                        std::vector<std::uint8_t>,
                        std::pair<typename BlueprintFieldType::value_type, typename BlueprintFieldType::value_type>
                    >> input;

                    std::vector<std::reference_wrapper<var>> all_vars() {
                        std::vector<std::reference_wrapper<var>> res;
                        res.push_back(rlc_challenge);
                        return res;
                    }
                };

                struct result_type {
                    result_type() {
                    }
                    std::vector<std::reference_wrapper<var>> all_vars() {
                        return {};
                    }
                };

                template<typename ContainerType>
                explicit keccak_dynamic_bbf_wrapper(ContainerType witness, std::size_t max_blocks_)
                    : component_type(witness, {}, {}, get_manifest()),
                       max_blocks(max_blocks_){};

                template<typename WitnessContainerType, typename ConstantContainerType,
                         typename PublicInputContainerType>
                keccak_dynamic_bbf_wrapper(WitnessContainerType witness,
                                         ConstantContainerType constant,
                                         PublicInputContainerType public_input,
                                         std::size_t max_blocks_)
                    : component_type(witness, constant, public_input, get_manifest()),
                       max_blocks(max_blocks_){};

                keccak_dynamic_bbf_wrapper(
                    std::initializer_list<
                        typename component_type::witness_container_type::value_type>
                        witnesses,
                    std::initializer_list<
                        typename component_type::constant_container_type::value_type>
                        constants,
                    std::initializer_list<
                        typename component_type::public_input_container_type::value_type>
                        public_inputs,
                    std::size_t max_blocks_)
                    : component_type(witnesses, constants, public_inputs, get_manifest()),
                      max_blocks(max_blocks_) {};

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
            using plonk_keccak_dynamic_bbf_wrapper = keccak_dynamic_bbf_wrapper<
                crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>,
                BlueprintFieldType>;

            template<typename BlueprintFieldType>
            typename plonk_keccak_dynamic_bbf_wrapper<BlueprintFieldType>::result_type
            generate_assignments(
                const plonk_keccak_dynamic_bbf_wrapper<BlueprintFieldType> &component,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>>
                    &assignment,
                const typename plonk_keccak_dynamic_bbf_wrapper<BlueprintFieldType>::input_type
                    instance_input,
                const std::uint32_t start_row_index) {
                using value_type = typename BlueprintFieldType::value_type;
                using context_type = typename nil::blueprint::bbf::context<
                    BlueprintFieldType, nil::blueprint::bbf::GenerationStage::ASSIGNMENT>;
                using KECCAK_DYNAMIC = typename nil::blueprint::bbf::keccak_dynamic<
                    BlueprintFieldType, nil::blueprint::bbf::GenerationStage::ASSIGNMENT>;
                using TYPE = typename context_type::TYPE;

                context_type ct = context_type(assignment, component.rows_amount, start_row_index);

                typename KECCAK_DYNAMIC::input_type input;
                input.rlc_challenge = var_value(assignment, instance_input.rlc_challenge);
                input.input = instance_input.input;

                auto keccak_round = KECCAK_DYNAMIC(ct, input, component.max_blocks);

                return typename plonk_keccak_dynamic_bbf_wrapper<BlueprintFieldType>::result_type();
            }

            template<typename BlueprintFieldType>
            typename plonk_keccak_dynamic_bbf_wrapper<BlueprintFieldType>::result_type
            generate_circuit(
                const plonk_keccak_dynamic_bbf_wrapper<BlueprintFieldType> &component,
                circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>> &bp,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>>
                    &assignment,
                const typename plonk_keccak_dynamic_bbf_wrapper<BlueprintFieldType>::input_type
                    &instance_input,
                const std::size_t start_row_index) {
                using context_type = typename nil::blueprint::bbf::context<
                    BlueprintFieldType, nil::blueprint::bbf::GenerationStage::CONSTRAINTS>;
                using KECCAK_DYNAMIC = typename nil::blueprint::bbf::keccak_dynamic<
                    BlueprintFieldType, nil::blueprint::bbf::GenerationStage::CONSTRAINTS>;
                using constraint_type = crypto3::zk::snark::plonk_constraint<BlueprintFieldType>;
                using plonk_copy_constraint = crypto3::zk::snark::plonk_copy_constraint<BlueprintFieldType>;
                using lookup_constraint_type = crypto3::zk::snark::plonk_lookup_constraint<BlueprintFieldType>;
                using TYPE = typename context_type::TYPE;

                using component_type = plonk_keccak_dynamic_bbf_wrapper<BlueprintFieldType>;
                using var = typename component_type::var;
                using nil::blueprint::bbf::row_selector;

                context_type ct = context_type(assignment.get_description(), component.rows_amount,
                                               start_row_index);

                typename KECCAK_DYNAMIC::input_type input;
                input.rlc_challenge = instance_input.rlc_challenge;
                input.input = instance_input.input;
                
                auto result = KECCAK_DYNAMIC(ct, input, component.max_blocks);
                // ct.print_witness_allocation_log(bbf::column_type::constant);
                
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
                
                return typename plonk_keccak_dynamic_bbf_wrapper<BlueprintFieldType>::result_type();
            }
        }  // namespace components
    }  // namespace blueprint
}  // namespace nil

#endif  // CRYPTO3_BLUEPRINT_PLONK_KECCAK_DYNAMIC_keccak_dynamic_bbf_wrapper_HPP
