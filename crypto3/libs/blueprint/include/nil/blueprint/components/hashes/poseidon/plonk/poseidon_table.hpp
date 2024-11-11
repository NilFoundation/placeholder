//---------------------------------------------------------------------------//
// Copyright (c) 2024 Georgios Fotiadis   <gfotiadis@nil.foundation>
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

#ifndef CRYPTO3_BLUEPRINT_COMPONENTS_POSEIDON_TABLE_HPP
#define CRYPTO3_BLUEPRINT_COMPONENTS_POSEIDON_TABLE_HPP

#include <nil/crypto3/zk/snark/arithmetization/plonk/constraint_system.hpp>

#include <nil/blueprint/blueprint/plonk/circuit.hpp>
#include <nil/blueprint/blueprint/plonk/assignment.hpp>
#include <nil/blueprint/component.hpp>
#include <nil/blueprint/manifest.hpp>
#include <nil/blueprint/lookup_library.hpp>

#include <nil/blueprint/components/hashes/sha2/plonk/detail/split_functions.hpp>

#include <nil/blueprint/components/hashes/poseidon/plonk/poseidon.hpp>
#include <nil/blueprint/components/hashes/poseidon/plonk/poseidon_constants.hpp>

#include <nil/crypto3/hash/type_traits.hpp>
#include <nil/crypto3/hash/algorithm/hash.hpp>

namespace nil {
    namespace blueprint {
        namespace components {
 
            template<typename ArithmetizationType>
            class poseidon_table;

            template<typename BlueprintFieldType>
            class poseidon_table<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>>
                : public plonk_component<BlueprintFieldType>
            {
            public:
                using component_type = plonk_component<BlueprintFieldType>;
                using var = typename component_type::var;
                using manifest_type = plonk_component_manifest;
                using value_type = typename BlueprintFieldType::value_type;

                std::size_t account_trie_length;

                struct poseidon_table_map {
                    var hash_value;
                    var l_msg;
                    var r_msg;

                    poseidon_table_map(const std::vector<std::uint32_t> witnesses){
                        hash_value = var(witnesses[0], 0);
                        l_msg = var(witnesses[1], 0);
                        r_msg = var(witnesses[2], 0);
                    }

                    poseidon_table_map(const poseidon_table &component){
                        hash_value = var(component.W(0), 0);
                        l_msg = var(component.W(1), 0);
                        r_msg = var(component.W(2), 0);
                    }

                    std::vector<std::uint32_t> witnesses(){
                        return {
                            std::uint32_t(hash_value.index),
                            std::uint32_t(l_msg.index),
                            std::uint32_t(r_msg.index)
                        };
                    }

                    std::size_t witness_amount() const {
                        return 3;
                    }
                };

                class gate_manifest_type : public component_gate_manifest {
                public:
                    std::uint32_t gates_amount() const override {
                        return 0;
                    }
                };

                static gate_manifest get_gate_manifest(std::size_t witness_amount, std::size_t account_trie_length) {
                    gate_manifest manifest = gate_manifest(gate_manifest_type());
                    return manifest;
                }

                static manifest_type get_manifest() {
                    static manifest_type manifest = manifest_type(
                        std::shared_ptr<manifest_param>(new manifest_single_value_param(3)),
                        false
                    );
                    return manifest;
                }

                constexpr static std::size_t get_rows_amount(std::size_t witness_amount, std::size_t account_trie_length) {
                    return (2*account_trie_length - 2 + 8);
                }

                constexpr static const std::size_t gates_amount = 0;
                constexpr static const std::size_t lookup_gates_amount = 0;
                std::size_t rows_amount = (2*account_trie_length - 2 + 8);

                struct input_type {
                    using data_item = std::pair<std::pair<typename BlueprintFieldType::value_type, typename BlueprintFieldType::value_type>, typename BlueprintFieldType::value_type>;
                    using data_type = std::vector<data_item>;

                    void fill_data(const data_type& _input){
                        input = _input;
                    }

                    data_type input;
                };

                struct result_type {
                    result_type(const poseidon_table &component, std::size_t start_row_index) {
                    }

                    std::vector<std::reference_wrapper<var>> all_vars() {
                        std::vector<std::reference_wrapper<var>> result;
                        return result;
                    }
                };

                template<typename ContainerType>
                explicit poseidon_table(ContainerType witness, std::size_t _account_trie_length) :
                    component_type(witness, {}, {}, get_manifest()), account_trie_length(_account_trie_length)
                    {};

                template<typename WitnessContainerType, typename ConstantContainerType,
                         typename PublicInputContainerType>
                poseidon_table(WitnessContainerType witness, ConstantContainerType constant,
                    PublicInputContainerType public_input,
                    std::size_t _account_trie_length
                ) : component_type(witness, constant, public_input, get_manifest()), account_trie_length(_account_trie_length) {};

                poseidon_table(
                    std::initializer_list<typename component_type::witness_container_type::value_type> witnesses,
                    std::initializer_list<typename component_type::constant_container_type::value_type>
                        constants,
                    std::initializer_list<typename component_type::public_input_container_type::value_type>
                        public_inputs,
                    std::size_t _account_trie_length
                ) : component_type(witnesses, constants, public_inputs, get_manifest()), account_trie_length(_account_trie_length){};
            };

            template<typename BlueprintFieldType>
            using plonk_poseidon_table =
                poseidon_table<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>>;

            template<typename BlueprintFieldType>
            typename plonk_poseidon_table<BlueprintFieldType>::result_type generate_assignments(
                const plonk_poseidon_table<BlueprintFieldType> &component,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>>
                    &assignment,
                const typename plonk_poseidon_table<BlueprintFieldType>::input_type
                    &instance_input,
                const std::uint32_t start_row_index
            ) {
                using component_type = plonk_poseidon_table<BlueprintFieldType>;
                using value_type = typename BlueprintFieldType::value_type;

                // value_type theta = var_value(assignment, instance_input.rlc_challenge);
                std::size_t input_idx = 0;
                // std::size_t block_counter = 0;
                std::pair<value_type, value_type> msg;
                value_type hash;

                typename component_type::poseidon_table_map t(component);

                for (std::size_t i = 0; i < (2*component.account_trie_length - 2 + 8); i++) {
                    msg = std::get<0>(instance_input.input[i]);
                    hash = std::get<1>(instance_input.input[i]);

                    // std::cout << "....hash[" << i << "] = " << hash << std::endl;
                    // std::cout << "....msg[" << i << "].first = " << msg.first << std::endl;
                    // std::cout << "....msg[" << i << "].second = " << msg.second << std::endl;

                    assignment.witness(t.hash_value.index, start_row_index + i) = hash;
                    assignment.witness(t.l_msg.index, start_row_index + i) = msg.first;
                    assignment.witness(t.r_msg.index, start_row_index + i) = msg.second;
                }

                return typename component_type::result_type(component, start_row_index);
	        }

            template<typename BlueprintFieldType>
            typename plonk_poseidon_table<BlueprintFieldType>::result_type generate_circuit(
                const plonk_poseidon_table<BlueprintFieldType> &component,
                circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>> &bp,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>>
                    &assignment,
                const typename plonk_poseidon_table<BlueprintFieldType>::input_type
                    &instance_input,
                const std::size_t start_row_index
            ) {
                using component_type = plonk_poseidon_table<BlueprintFieldType>;
                using var = typename component_type::var;

                bp.register_dynamic_table("poseidon_table");
                std::size_t selector_index = bp.get_dynamic_lookup_table_selector();
                assignment.enable_selector(selector_index, start_row_index, start_row_index + component.rows_amount - 1);

                crypto3::zk::snark::plonk_lookup_table<BlueprintFieldType> poseidon_table;
                typename component_type::poseidon_table_map t(component);

                poseidon_table.tag_index = selector_index;
                poseidon_table.columns_number =  3;//
                poseidon_table.lookup_options = {{
                    t.hash_value,
                    t.l_msg,
                    t.r_msg
                }};
                bp.define_dynamic_table("poseidon_table", poseidon_table);

                return typename component_type::result_type(component, start_row_index);
            }
        }
    }
}
#endif