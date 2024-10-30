//---------------------------------------------------------------------------//
// Copyright (c) 2024 Georgios Fotiadis <gfotiadis@nil.foundation>
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
// @file Declaration of interfaces for choice function on k-chunked values.
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_BLUEPRINT_COMPONENTS_PLONK_MPT_NONCE_CHANGED_HPP
#define CRYPTO3_BLUEPRINT_COMPONENTS_PLONK_MPT_NONCE_CHANGED_HPP

#include <nil/crypto3/zk/snark/arithmetization/plonk/constraint_system.hpp>

#include <nil/blueprint/blueprint/plonk/assignment.hpp>
#include <nil/blueprint/blueprint/plonk/circuit.hpp>
#include <nil/blueprint/component.hpp>
#include <nil/blueprint/manifest.hpp>

#include <nil/blueprint/detail/range_check_multi.hpp>

#include <nil/crypto3/hash/detail/poseidon/poseidon_permutation.hpp>
#include <nil/crypto3/hash/poseidon.hpp>
#include <nil/crypto3/random/algebraic_engine.hpp>

using namespace nil;
using namespace nil::crypto3::hashes::detail;

namespace nil {
    namespace blueprint {
        namespace components {
            template<typename ArithmetizationType, typename BlueprintFieldType, std::size_t num_chunks, std::size_t bit_size_chunk, std::size_t account_trie_length>
            class mpt_nonce_changed;

            template<typename BlueprintFieldType, std::size_t num_chunks, std::size_t bit_size_chunk, std::size_t account_trie_length>
            class mpt_nonce_changed<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>, BlueprintFieldType, num_chunks, bit_size_chunk, account_trie_length>
                : public plonk_component<BlueprintFieldType> {

            public:
                using component_type = plonk_component<BlueprintFieldType>;

                using var = typename component_type::var;
                using manifest_type = plonk_component_manifest;

                using range_check_component = range_check_multi<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>, BlueprintFieldType, num_chunks, bit_size_chunk>;

                class gate_manifest_type : public component_gate_manifest {
                public:
                    std::uint32_t gates_amount() const override {
                        return mpt_nonce_changed::gates_amount;
                    }
                };

                static gate_manifest get_gate_manifest(std::size_t witness_amount) {
                    static gate_manifest manifest = gate_manifest(gate_manifest_type());
                    return manifest;
                }

                static manifest_type get_manifest() {
                    static manifest_type manifest = manifest_type(
                        // ready to use any number of columns that fit 3*num_chunks+1 cells into less than 3 rows
                        std::shared_ptr<manifest_param>(new manifest_single_value_param(0)),
                        false // constant column not needed
                    );
                    return manifest;
                }

                constexpr static std::size_t get_rows_amount(std::size_t witness_amount) {
                    size_t assignment_table_rows = account_trie_length;
                    size_t rows = assignment_table_rows;
                    return (rows);
                }

                constexpr static const std::size_t gates_amount = 1; // <---- was gates_amount = 1 before....
                const std::size_t rows_amount = get_rows_amount(this->witness_amount());
                const std::string component_name = "multichunk binary carry on addition";

                 struct input_type {
                    var eth_address;

                    std::vector<std::reference_wrapper<var>> all_vars() {
                        std::vector<std::reference_wrapper<var>> res = {};
                        res.push_back(eth_address);
                        return res;
                    }
                };

                struct result_type {
		            // var z[num_chunks], ck;

                    result_type(const mpt_nonce_changed &component, std::uint32_t start_row_index) {
                    }

                    std::vector<std::reference_wrapper<var>> all_vars() {
                        std::vector<std::reference_wrapper<var>> res;
                        return res;
                    }
                };

                template<typename ContainerType>
                explicit mpt_nonce_changed(ContainerType witness) : component_type(witness, {}, {}, get_manifest()) {};

                template<typename WitnessContainerType, typename ConstantContainerType, typename PublicInputContainerType>
                mpt_nonce_changed(WitnessContainerType witness, ConstantContainerType constant, PublicInputContainerType public_input) :
                    component_type(witness, constant, public_input, get_manifest()) {};

                mpt_nonce_changed(
                    std::initializer_list<typename component_type::witness_container_type::value_type> witnesses,
                    std::initializer_list<typename component_type::constant_container_type::value_type> constants,
                    std::initializer_list<typename component_type::public_input_container_type::value_type> public_inputs) :
                    component_type(witnesses, constants, public_inputs, get_manifest()) {};
            };

            template<typename BlueprintFieldType, std::size_t num_chunks, std::size_t bit_size_chunk, std::size_t account_trie_length>
            using plonk_mpt_nonce_changed =
                mpt_nonce_changed<
                    crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>,
                    BlueprintFieldType,
                    num_chunks,
                    bit_size_chunk,
                    account_trie_length>;

            template<typename BlueprintFieldType, std::size_t num_chunks, std::size_t bit_size_chunk, std::size_t account_trie_length>
            typename plonk_mpt_nonce_changed<BlueprintFieldType,num_chunks,bit_size_chunk,account_trie_length>::result_type generate_assignments(
                const plonk_mpt_nonce_changed<BlueprintFieldType,num_chunks,bit_size_chunk,account_trie_length> &component,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>>
                    &assignment,
                const typename plonk_mpt_nonce_changed<BlueprintFieldType,num_chunks,bit_size_chunk,account_trie_length>::input_type
                    &instance_input,
                const std::uint32_t start_row_index) {

                using component_type = plonk_mpt_nonce_changed<BlueprintFieldType,num_chunks,bit_size_chunk,account_trie_length>;
                using range_check_type = typename component_type::range_check_component;

                using var = typename component_type::var;
                using value_type = typename BlueprintFieldType::value_type;
                using integral_type = typename BlueprintFieldType::integral_type; 

                const std::size_t WA = component.witness_amount();
                std::uint32_t rows = start_row_index;

                value_type eth_address;
                eth_address = var_value(assignment, instance_input.eth_address);

                std::cout << "...start_row_index = " << start_row_index << std::endl;

                // Fill in table W
                for(std::size_t i = 0; i < account_trie_length; i++) {
                    for (std::size_t j = 0; j < 2; j++) { // W[0][0] = old_root, W[1][0] = new_root
                        assignment.witness(component.W((j) % WA), start_row_index + i + (j)/WA) = eth_address;
                    }
                }
                rows += (account_trie_length);

                std::cout << "...start_row_index = " << start_row_index << std::endl;
                std::cout << "...assignment.rows_amount() = " << assignment.rows_amount() << std::endl;
                std::cout << "...rows = " << rows << std::endl;
                std::cout << "...component.rows_amount = " << component.rows_amount << std::endl;

                BOOST_ASSERT_MSG(rows - start_row_index == component.rows_amount, "!!!component rows not equal to actual component rows!!!");     

                return typename plonk_mpt_nonce_changed<BlueprintFieldType, num_chunks, bit_size_chunk, account_trie_length>::result_type(component, start_row_index);
	    }

            template<typename BlueprintFieldType, std::size_t num_chunks, std::size_t bit_size_chunk, std::size_t account_trie_length>
            std::size_t generate_gates(
                const plonk_mpt_nonce_changed<BlueprintFieldType,num_chunks,bit_size_chunk,account_trie_length> &component,
                circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>> &bp,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>> &assignment,
                const typename plonk_mpt_nonce_changed<BlueprintFieldType,num_chunks,bit_size_chunk,account_trie_length>::input_type
                    &instance_input) {

                using component_type = plonk_mpt_nonce_changed<BlueprintFieldType,num_chunks,bit_size_chunk,account_trie_length>;
                using range_check_type = typename component_type::range_check_component;

                using var = typename plonk_mpt_nonce_changed<BlueprintFieldType,num_chunks,bit_size_chunk,account_trie_length>::var;
                using constraint_type = crypto3::zk::snark::plonk_constraint<BlueprintFieldType>;
                using integral_type = typename BlueprintFieldType::integral_type;
                using val = typename BlueprintFieldType::value_type;

                const std::size_t WA = component.witness_amount();
                const std::size_t row_shift = -(4*num_chunks > 2*WA);
                const integral_type B = integral_type(1) << 64;

                size_t rows = account_trie_length;
                
                var val1, val2;

                std::vector<constraint_type> mpt_nonce_changed_constraints = {};

                for(std::size_t i = 0; i < account_trie_length; i++) {
                    val1 = var(component.W(0 % WA), i + 0/WA + row_shift, true);
                    val2 = var(component.W(0 % WA), i + 0/WA + row_shift, true);
                    mpt_nonce_changed_constraints.push_back(val1 - val2);
                }
                std::cout << "..rows = " << rows << std::endl;
                std::cout << "..component.rows_amount = " << component.rows_amount << std::endl;

                BOOST_ASSERT_MSG(rows == component.rows_amount, "!!!component rows not equal to actual component rows!!!");      

                return bp.add_gate(mpt_nonce_changed_constraints);
            }

            template<typename BlueprintFieldType, std::size_t num_chunks, std::size_t bit_size_chunk, std::size_t account_trie_length>
            void generate_copy_constraints(
                const plonk_mpt_nonce_changed<BlueprintFieldType, num_chunks, bit_size_chunk, account_trie_length> &component,
                circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>> &bp,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>>
                    &assignment,
                const typename plonk_mpt_nonce_changed<BlueprintFieldType,num_chunks,bit_size_chunk,account_trie_length>::input_type &instance_input,
                const std::size_t start_row_index) {

                std::cout << "\nConstruct copy constraints in the .hpp file" << std::endl;  
                std::cout << "-----------------------------------------------" << std::endl;  
                std::cout << "..start_row_index = " << start_row_index << std::endl;
                const std::size_t WA = component.witness_amount();

                using var = typename plonk_mpt_nonce_changed<BlueprintFieldType,num_chunks,bit_size_chunk,account_trie_length>::var;
                
                for(std::size_t i = 0; i < account_trie_length; i++) {
                    bp.add_copy_constraint({var(component.W(0 % WA), start_row_index + i + 0/WA,false), var(component.W(1 % WA), start_row_index + i + 1/WA,false)});
                }
            }

            template<typename BlueprintFieldType, std::size_t num_chunks, std::size_t bit_size_chunk, std::size_t account_trie_length>
            typename plonk_mpt_nonce_changed<BlueprintFieldType,num_chunks,bit_size_chunk,account_trie_length>::result_type generate_circuit(
                const plonk_mpt_nonce_changed<BlueprintFieldType,num_chunks,bit_size_chunk,account_trie_length> &component,
                circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>> &bp,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>>
                    &assignment,
                const typename plonk_mpt_nonce_changed<BlueprintFieldType,num_chunks,bit_size_chunk,account_trie_length>::input_type &instance_input,
                const std::size_t start_row_index) {

                using component_type = plonk_mpt_nonce_changed<BlueprintFieldType, num_chunks, bit_size_chunk, account_trie_length>;
                using range_check_type = typename component_type::range_check_component;

                const std::size_t WA = component.witness_amount();
                const std::size_t row_shift = 0;

                std::size_t selector_index = generate_gates(component, bp, assignment, instance_input);
                assignment.enable_selector(selector_index, start_row_index + row_shift);
                generate_copy_constraints(component, bp, assignment, instance_input, start_row_index);

                return typename plonk_mpt_nonce_changed<BlueprintFieldType,num_chunks,bit_size_chunk,account_trie_length>::result_type(component, start_row_index);
            }
        }    // namespace components
    }        // namespace blueprint
}    // namespace nil

#endif    // CRYPTO3_BLUEPRINT_COMPONENTS_PLONK_MPT_NONCE_CHANGED_HPP