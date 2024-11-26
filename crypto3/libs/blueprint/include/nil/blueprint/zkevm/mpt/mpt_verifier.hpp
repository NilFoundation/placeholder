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
#include <nil/blueprint/lookup_library.hpp>

#include <nil/blueprint/detail/range_check_multi.hpp>

#include <nil/blueprint/components/hashes/poseidon/plonk/poseidon_table.hpp>
#include <nil/crypto3/hash/poseidon.hpp>
#include <nil/crypto3/random/algebraic_engine.hpp>

#include <nil/blueprint/components/hashes/poseidon/plonk/poseidon.hpp>
#include <nil/blueprint/components/hashes/poseidon/plonk/poseidon_constants.hpp>

#include <nil/crypto3/hash/type_traits.hpp>
#include <nil/crypto3/hash/algorithm/hash.hpp>

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
                static constexpr std::size_t DEPTH = 24;

                using component_type = plonk_component<BlueprintFieldType>;
                using ArithmetizationType = crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>;

                using var = typename component_type::var;
                using manifest_type = plonk_component_manifest;

                using table_component_type = plonk_poseidon_table<BlueprintFieldType>;

                using range_check_component = range_check_multi<ArithmetizationType, BlueprintFieldType, num_chunks, bit_size_chunk>;

                table_component_type table_component;

                class gate_manifest_type : public component_gate_manifest {
                public:
                    std::uint32_t gates_amount() const override {
                        return mpt_nonce_changed::gates_amount;
                    }
                };

                static gate_manifest get_gate_manifest(std::size_t witness_amount) {
                    static gate_manifest manifest = gate_manifest(gate_manifest_type())
                    .merge_with(range_check_component::get_gate_manifest(witness_amount));
                    return manifest;
                }

                static manifest_type get_manifest() {
                    static manifest_type manifest = manifest_type(
                        // ready to use any number of columns that fit 3*num_chunks+1 cells into less than 3 rows
                        std::shared_ptr<manifest_param>(new manifest_single_value_param(24)),
                        // std::shared_ptr<manifest_param>(new manifest_range_param(10, 10*(account_trie_length + 5), 1)),
                        false // constant column not needed
                    )
                    .merge_with(range_check_component::get_manifest());
                    return manifest;
                }

                constexpr static std::size_t get_rows_amount(std::size_t witness_amount) {
                    size_t assignment_table_rows = account_trie_length + 5;
                    size_t rows = assignment_table_rows;
                    rows += range_check_component::get_rows_amount(witness_amount);
                    rows += range_check_component::get_rows_amount(witness_amount);
                    rows += range_check_component::get_rows_amount(witness_amount);
                    return (rows + 2*(account_trie_length - 1) + 8);
                }

                constexpr static const std::size_t gates_amount = 1; // <---- was gates_amount = 1 before....
                const std::size_t rows_amount = get_rows_amount(this->witness_amount());
                const std::string component_name = "MPT update verification";

                 struct input_type {
                    var eth_address, mpt_proof_type, storage, account_key;
                    std::pair<var, var> old_root, new_root, nonce;
                    std::vector<std::vector<var>> address_hash_traces, old_account_hash_traces, new_account_hash_traces, leafs;
                    std::vector<var> old_account, new_account;

                    std::vector<std::reference_wrapper<var>> all_vars() {
                        std::vector<std::reference_wrapper<var>> res = {};
                        res.push_back(eth_address);
                        res.push_back(mpt_proof_type);
                        res.push_back(old_root.first);
                        res.push_back(old_root.second);
                        res.push_back(new_root.first);
                        res.push_back(new_root.second);
                        res.push_back(nonce.first);
                        res.push_back(nonce.second);
                        for (std::size_t i = 0; i < account_trie_length; i++) {
                            for (std::size_t j = 0; j < 7; j++) {
                                res.push_back(address_hash_traces[i][j]);
                            }
                        } 
                        for (std::size_t i = 0; i < 2; i++) {
                            for (std::size_t j = 0; j < 3; j++) {
                                res.push_back(leafs[i][j]);
                            }
                        }
                        for (std::size_t i = 0; i < 7; i++) {
                            for (std::size_t j = 0; j < 3; j++) {
                                res.push_back(old_account_hash_traces[i][j]);
                            }
                        }   
                        for (std::size_t i = 0; i < 7; i++) {
                            for (std::size_t j = 0; j < 3; j++) {
                                res.push_back(new_account_hash_traces[i][j]);
                            }
                        } 
                        for (std::size_t i = 0; i < 6; i++) {
                            res.push_back(old_account[i]);
                        }    
                        for (std::size_t i = 0; i < 6; i++) {
                            res.push_back(new_account[i]);
                        }   
                        res.push_back(storage);
                        res.push_back(account_key);
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
                    component_type(witness, constant, public_input, get_manifest()), 
                    table_component(witness, constant, public_input, account_trie_length) {};

                mpt_nonce_changed(
                    std::initializer_list<typename component_type::witness_container_type::value_type> witnesses,
                    std::initializer_list<typename component_type::constant_container_type::value_type> constants,
                    std::initializer_list<typename component_type::public_input_container_type::value_type> public_inputs) :
                    component_type(witnesses, constants, public_inputs, get_manifest()),
                    table_component(witnesses, constants, public_inputs, account_trie_length) {};

                std::map<std::string, std::size_t> component_lookup_tables(){
                    std::map<std::string, std::size_t> lookup_tables;

                    lookup_tables["range_16bit/full"] = 0;
                    // lookup_tables["poseidon_table"] = 0; // DYNAMIC_TABLE

                    return lookup_tables;
                }
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
                using range_check_type = range_check_multi<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>,  BlueprintFieldType, num_chunks, bit_size_chunk>;

                range_check_type range_check_instance(component._W, component._C, component._PI);

                using var = typename component_type::var;
                using value_type = typename BlueprintFieldType::value_type;
                using integral_type = typename BlueprintFieldType::integral_type; 

                const std::size_t WA = component.witness_amount();
                std::uint32_t rows = start_row_index;

                // constructing the proof in .hpp file 
                // proof = [claim, address_hash_traces, leafs, old_account_hash_traces, new_account_hash_traces, old_account, new_account, storage, account_key
                //          storage_hash_traces, old_storage_key_hash_traces, new_storage_key_hash_traces]
                // where claim = (old_root, new_root, nonce, claim_kind) s.t. nonce = (old_nonce, new_nonce) and claim_kind = (eth_account, mpt_proof_type)
                // std::cout << "\nConstruct the proof in the .hpp file" << std::endl;  
                // std::cout << "------------------------------------" << std::endl;  

                value_type eth_address, mpt_proof_type;
                eth_address = var_value(assignment, instance_input.eth_address);
                mpt_proof_type = var_value(assignment, instance_input.mpt_proof_type); // mpt_proof_type = nonce_changed = 1  

                // old_root = (old_root_hi, old_root_lo)
                std::pair<typename BlueprintFieldType::value_type, typename BlueprintFieldType::value_type> old_root = {};
                old_root = {var_value(assignment, instance_input.old_root.first), var_value(assignment, instance_input.old_root.second)};

                // new_root = (new_root_hi, new_root_lo)
                std::pair<typename BlueprintFieldType::value_type, typename BlueprintFieldType::value_type> new_root = {};
                new_root = {var_value(assignment, instance_input.new_root.first), var_value(assignment, instance_input.new_root.second)};

                // nonce = (old_nonce, bew_nonce) we don't actually need this!!! 
                std::pair<typename BlueprintFieldType::value_type, typename BlueprintFieldType::value_type> nonce = {};
                nonce = {var_value(assignment, instance_input.nonce.first), var_value(assignment, instance_input.nonce.second)};

                // claim_kind = (eth_address, mpt_proof_type) 
                std::pair<typename BlueprintFieldType::value_type, typename BlueprintFieldType::value_type> claim_kind = {eth_address, mpt_proof_type};

                // claim = (old_root, new_root, nonce, claim_kind)
                std::vector<std::pair<typename BlueprintFieldType::value_type, typename BlueprintFieldType::value_type>> claim = {old_root, new_root, nonce, claim_kind};

                // address_hash_traces = (direction, domain, open_value, close_value, sibling, is_open_padding, is_close_padding)
                std::vector<std::vector<typename BlueprintFieldType::value_type>> address_hash_traces = {};
                for (std::size_t i = 0; i < instance_input.address_hash_traces.size(); i++) {
                    address_hash_traces.push_back({var_value(assignment, instance_input.address_hash_traces[i][0]),     // = direction[i]
                                                   var_value(assignment, instance_input.address_hash_traces[i][1]),     // = domain[i]
                                                   var_value(assignment, instance_input.address_hash_traces[i][2]),     // = open_value[i]
                                                   var_value(assignment, instance_input.address_hash_traces[i][3]),     // = close_value[i]
                                                   var_value(assignment, instance_input.address_hash_traces[i][4]),     // = sibling[i]
                                                   var_value(assignment, instance_input.address_hash_traces[i][5]),     // = is_open_padding[i]
                                                   var_value(assignment, instance_input.address_hash_traces[i][6])});   // = is_close_padding[i]
                }

                // leafs = [old_leaf, new_leaf] = [(old_leaf_value, sibling_value, node_type), (new_leaf_value, sibling_value, node_type)]
                std::vector<std::vector<typename BlueprintFieldType::value_type>> leafs = {};
                for (std::size_t i = 0; i < 2; i++) { // always two leafs
                    leafs.push_back({var_value(assignment, instance_input.leafs[i][0]), 
                                     var_value(assignment, instance_input.leafs[i][1]), 
                                     var_value(assignment, instance_input.leafs[i][2])});
                }

                // construct old/new_account_hash_traces, each of size 7
                std::vector<std::vector<typename BlueprintFieldType::value_type>> old_account_hash_traces = {};
                std::vector<std::vector<typename BlueprintFieldType::value_type>> new_account_hash_traces = {};
                for (std::size_t i = 0; i < instance_input.old_account_hash_traces.size(); i++) {
                    old_account_hash_traces.push_back({var_value(assignment, instance_input.old_account_hash_traces[i][0]), 
                                                       var_value(assignment, instance_input.old_account_hash_traces[i][1]),
                                                       var_value(assignment, instance_input.old_account_hash_traces[i][2])});
                    new_account_hash_traces.push_back({var_value(assignment, instance_input.new_account_hash_traces[i][0]), 
                                                       var_value(assignment, instance_input.new_account_hash_traces[i][1]),
                                                       var_value(assignment, instance_input.new_account_hash_traces[i][2])});
                }

                // old_account = [old_nonce, balance, keccak_code_hash_hi, keccak_code_hash_lo, poseidon_code_hash, code_size]
                // new_account = [new_nonce, balance, keccak_code_hash_hi, keccak_code_hash_lo, poseidon_code_hash, code_size]
                // where #old_account = #new_account = 6
                std::vector<typename BlueprintFieldType::value_type> old_account = {};
                std::vector<typename BlueprintFieldType::value_type> new_account = {};
                for (std::size_t i = 0; i < instance_input.old_account.size(); i++) {
                    old_account.push_back(var_value(assignment, instance_input.old_account[i]));
                    new_account.push_back(var_value(assignment, instance_input.new_account[i]));
                    if (i != 0){
                        // verify that all elements except for the nonces are the same in old_account and new_account
                        BOOST_ASSERT(old_account[i] == new_account[i]);
                    }
                }

                // storage and account_key
                value_type storage, account_key; 
                storage = var_value(assignment, instance_input.storage);
                // we don't actually need this, it is in old/new_account_hash_traces[4][1]
                account_key = var_value(assignment, instance_input.account_key); 

                // constructing the assignemnt table in .hpp file 
                // std::cout << "\nConstruct the assignemnt table in the .hpp file" << std::endl;  
                // std::cout << "-----------------------------------------------" << std::endl;  

                // construct key and other_key based on the bits of account_key
                std::vector<typename BlueprintFieldType::value_type> key, other_key;
                integral_type key_integral = integral_type(account_key.data);
                for (std::size_t i = 0; i < account_trie_length; i++) {
                    key.push_back(value_type(key_integral % 2));
                    key_integral = key_integral >> 1;
                }
                other_key = key; // this is because the old_path and new_path are the same

                size_t account_leaf_length, assignment_table_rows;
                if (mpt_proof_type == 1){
                    account_leaf_length = 4;
                }
                assignment_table_rows = account_trie_length + 1 + account_leaf_length;

                value_type segment_type[assignment_table_rows];
                for (std::size_t i = 0; i < account_trie_length + 1; i++) {
                    segment_type[i]  = (i == 0) ? 0 : 1; 
                }
                if (mpt_proof_type == 1){
                    segment_type[account_trie_length + 1]  = 2; 
                    segment_type[account_trie_length + 2]  = 3; 
                    segment_type[account_trie_length + 3]  = 4; 
                    segment_type[account_trie_length + 4]  = 5; 
                }
                
                // q_leaf0, q_leaf123 to be added as selector columns in assignment table
                // to choose between account_leaf rows
                value_type q_leaf0[assignment_table_rows], q_leaf123[assignment_table_rows];
                for (std::size_t i = 0; i < assignment_table_rows; i++) {
                    q_leaf0[i] = (segment_type[i] == 2) ? 1 : 0; 
                    q_leaf123[i] = (segment_type[i] == 3 || segment_type[i] == 4 || segment_type[i] == 5) ? 1 : 0; ;
                }

                // q_start, q_trie, q_leaf_0, q_leaf_1, q_leaf_2, q_leaf_3 to be added as selector columns in assignment table
                // to choose between different segment types
                value_type q_start[assignment_table_rows], q_trie[assignment_table_rows], q_leaf_0[assignment_table_rows];
                value_type q_leaf_1[assignment_table_rows], q_leaf_2[assignment_table_rows], q_leaf_3[assignment_table_rows];
                for (std::size_t i = 0; i < assignment_table_rows; i++) {
                    q_start[i]  = (segment_type[i] == 0) ? 1 : 0; 
                    q_trie[i]   = (segment_type[i] == 1) ? 1 : 0; 
                    q_leaf_0[i] = (segment_type[i] == 2) ? 1 : 0; 
                    q_leaf_1[i] = (segment_type[i] == 3) ? 1 : 0; 
                    q_leaf_2[i] = (segment_type[i] == 4) ? 1 : 0; 
                    q_leaf_3[i] = (segment_type[i] == 5) ? 1 : 0; 
                }

                // split old_nonce, new_nonce, code_size into 4 chunks each of 16-bits
                value_type old_nonce_chunks[num_chunks], new_nonce_chunks[num_chunks], code_size_chunks[num_chunks];
                integral_type B = integral_type(1) << bit_size_chunk;
                integral_type old_nonce_integral = integral_type(claim[2].first.data);
                integral_type new_nonce_integral = integral_type(claim[2].second.data);
                integral_type code_size_integral = integral_type(old_account[5].data);
                // std::cout << "..old_nonce_integral = " << old_nonce_integral << std::endl;
                // std::cout << "..new_nonce_integral = " << new_nonce_integral << std::endl;
                // std::cout << "..code_size_integral = " << code_size_integral << std::endl;

                for(std::size_t i = 0; i < num_chunks; i++) { 
                    old_nonce_chunks[i] = value_type(old_nonce_integral % B);
                    new_nonce_chunks[i] = value_type(new_nonce_integral % B);
                    code_size_chunks[i] = value_type(code_size_integral % B);
                    old_nonce_integral /= B;
                    new_nonce_integral /= B;
                    code_size_integral /= B;
                    // std::cout << "..old_nonce_chunks[" << i << "] = " << old_nonce_chunks[i] << std::endl;
                    // std::cout << "..new_nonce_chunks[" << i << "] = " << new_nonce_chunks[i] << std::endl;
                    // std::cout << "..code_size_chunks[" << i << "] = " << code_size_chunks[i] << std::endl;
                }

                // Fill in table W
                for(std::size_t i = 0; i < account_trie_length; i++) {
                    if (i == 0){
                        for (std::size_t j = 0; j < 2; j++) { // W[0][0] = old_root, W[1][0] = new_root
                            assignment.witness(component.W((j) % WA), start_row_index + i + (j)/WA) = claim[j].first + claim[j].second;
                        }
                        for (std::size_t j = 2; j < 5; j++) { // W[2][0] = open_value, W[3][0] = close_value, W[0][4] = sibling
                            assignment.witness(component.W(j % WA), start_row_index + i + j/WA) = address_hash_traces[i][j];
                        }
                        for (std::size_t j = 6; j < 8; j++) { // W[6][0] = depth, W[7][0] = direction
                            assignment.witness(component.W(j % WA), start_row_index + i + j/WA) = 0;
                        }
                        for (std::size_t j = 10; j < 13; j++) { // W[10][0] = key = 0, W[11][0] = other_key = 0, W[12][0] = path_type = start = 0 
                            assignment.witness(component.W(j % WA), start_row_index + i + j/WA) = 0;
                        }
                    }
                    else{
                        for (std::size_t j = 0; j < 2; j++) { // W[0][i] = old_value, W[1][i] = new_value
                            assignment.witness(component.W((j) % WA), start_row_index + i + (j)/WA) = address_hash_traces[i - 1][j + 2];
                        }
                        for (std::size_t j = 2; j < 5; j++) { // W[2][i] = old_child, W[3][i] = new_child, W[4][i] = sibling
                            assignment.witness(component.W(j % WA), start_row_index + i + j/WA) = address_hash_traces[i][j];
                        }
                        assignment.witness(component.W(6 % WA), start_row_index + i + 6/WA) = i; // W[6][i] = depth = i
                        assignment.witness(component.W(7 % WA), start_row_index + i + 7/WA) = address_hash_traces[i - 1][0]; // W[7][0] = direction[i]
                        assignment.witness(component.W(10 % WA), start_row_index + i + 10/WA) = key[i - 1]; // W[10][i] = key[i]
                        assignment.witness(component.W(11 % WA), start_row_index + i + 11/WA) = other_key[i - 1]; // W[11][i] = other_key[i]
                        assignment.witness(component.W(12 % WA), start_row_index + i + 12/WA) = 1; // W[12][0] = path_type = common = 1 
                    }
                    // assignment.witness(component.W(component_type::DEPTH), start_row_index + i) = 1;
                }

                // last row in account_trie
                assignment.witness(component.W((0) % WA), start_row_index + account_trie_length + (0)/WA) 
                                            = old_account_hash_traces[6][2]; // W[0][account_trie_size] = old_value
                assignment.witness(component.W((1) % WA), start_row_index + account_trie_length + (1)/WA) 
                                            = new_account_hash_traces[6][2]; // W[1][account_trie_size] = new_value               
                assignment.witness(component.W((2) % WA), start_row_index + account_trie_length + (2)/WA) 
                                            = old_account_hash_traces[6][1]; // W[2][account_trie_size] = old_child
                assignment.witness(component.W((3) % WA), start_row_index + account_trie_length + (3)/WA) 
                                            = new_account_hash_traces[6][1]; // W[3][account_trie_size] = new_child               
                assignment.witness(component.W((4) % WA), start_row_index + account_trie_length + (4)/WA) 
                                            = old_account_hash_traces[6][0]; // W[4][account_trie_size] = sibling               
                assignment.witness(component.W((6) % WA), start_row_index + account_trie_length + (6)/WA) 
                                            = account_trie_length; // W[6][account_trie_size] = depth = account_trie_size
                assignment.witness(component.W((7) % WA), start_row_index + account_trie_length + (7)/WA) 
                                            = address_hash_traces[account_trie_length - 1][0]; // W[7][account_trie_size] = direction[i]
                assignment.witness(component.W((10) % WA), start_row_index + account_trie_length + (10)/WA) 
                                            = key[account_trie_length - 1]; // W[10][account_trie_size] = key[i] 
                assignment.witness(component.W((11) % WA), start_row_index + account_trie_length + (11)/WA) 
                                            = other_key[account_trie_length - 1]; // W[11][account_trie_size] = other_key[i] 
                assignment.witness(component.W((12) % WA), start_row_index + account_trie_length + (12)/WA) 
                                            = 1; // W[12][account_trie_size] = path_type = common = 1 

                // rows += (account_trie_length + 1);
                // // std::cout << "..rows = " << rows << std::endl; 
                // // std::cout << "..start_row_index = " << start_row_index << std::endl; 

                assignment.witness(component.W((0) % WA), start_row_index + account_trie_length + 1 + (0)/WA) = old_account_hash_traces[5][2]; // W[0][account_trie_size + 1] = old_value
                assignment.witness(component.W((1) % WA), start_row_index + account_trie_length + 1 + (1)/WA) = new_account_hash_traces[5][2]; // W[1][account_trie_size + 1] = new_value                
                assignment.witness(component.W((2) % WA), start_row_index + account_trie_length + 1 + (2)/WA) = old_account_hash_traces[5][0]; // W[2][account_trie_size + 1] = old_child
                assignment.witness(component.W((3) % WA), start_row_index + account_trie_length + 1 + (3)/WA) = new_account_hash_traces[5][0]; // W[3][account_trie_size + 1] = new_child                        
                assignment.witness(component.W((4) % WA), start_row_index + account_trie_length + 1 + (4)/WA) = old_account_hash_traces[5][1]; // W[4][account_trie_size + 1] = sibling             
                assignment.witness(component.W((6) % WA), start_row_index + account_trie_length + 1 + (6)/WA) = 0; // W[6][account_trie_size + 1] = depth = 0
                assignment.witness(component.W((7) % WA), start_row_index + account_trie_length + 1 + (7)/WA) = 1; // W[7][account_trie_size + 1] = direction[i] = 1
                assignment.witness(component.W((12) % WA), start_row_index + account_trie_length + 1 + (12)/WA) = 1; // W[12][account_trie_size + 1] = path_type = common = 1

                assignment.witness(component.W((0) % WA), start_row_index + account_trie_length + 2 + (0)/WA) = old_account_hash_traces[3][2]; // W[0][account_trie_size + 2] = old_value
                assignment.witness(component.W((1) % WA), start_row_index + account_trie_length + 2 + (1)/WA) = new_account_hash_traces[3][2]; // W[1][account_trie_size + 2] = new_value                   
                assignment.witness(component.W((2) % WA), start_row_index + account_trie_length + 2 + (2)/WA) = old_account_hash_traces[3][0]; // W[2][account_trie_size + 2] = old_child
                assignment.witness(component.W((3) % WA), start_row_index + account_trie_length + 2 + (3)/WA) = new_account_hash_traces[3][0]; // W[3][account_trie_size + 2] = new_child                
                assignment.witness(component.W((4) % WA), start_row_index + account_trie_length + 2 + (4)/WA) = old_account_hash_traces[3][1]; // W[4][account_trie_size + 2] = sibling  
                assignment.witness(component.W((6) % WA), start_row_index + account_trie_length + 2 + (6)/WA) = 0; // W[6][account_trie_size + 2] = depth = 0
                assignment.witness(component.W((7) % WA), start_row_index + account_trie_length + 2 + (7)/WA) = 0; // W[7][account_trie_size + 2] = direction[i] = 0
                assignment.witness(component.W((12) % WA), start_row_index + account_trie_length + 2 + (12)/WA) = 1; // W[12][account_trie_size + 2] = path_type = common = 1

                assignment.witness(component.W((0) % WA), start_row_index + account_trie_length + 3 + (0)/WA) = old_account_hash_traces[2][2]; // W[0][account_trie_size + 3] = old_value
                assignment.witness(component.W((1) % WA), start_row_index + account_trie_length + 3 + (1)/WA) = new_account_hash_traces[2][2]; // W[1][account_trie_size + 3] = new_value                                  
                assignment.witness(component.W((2) % WA), start_row_index + account_trie_length + 3 + (2)/WA) = old_account_hash_traces[2][0]; // W[2][account_trie_size + 3] = old_child
                assignment.witness(component.W((3) % WA), start_row_index + account_trie_length + 3 + (3)/WA) = new_account_hash_traces[2][0]; // W[3][account_trie_size + 3] = new_child                              
                assignment.witness(component.W((4) % WA), start_row_index + account_trie_length + 3 + (4)/WA) = old_account_hash_traces[2][1]; // W[4][account_trie_size + 3] = sibling  
                assignment.witness(component.W((6) % WA), start_row_index + account_trie_length + 3 + (6)/WA) = 0; // W[6][account_trie_size + 3] = depth = 0
                assignment.witness(component.W((7) % WA), start_row_index + account_trie_length + 3 + (7)/WA) = 0; // W[7][account_trie_size + 3] = direction[i] = 0
                assignment.witness(component.W((12) % WA), start_row_index + account_trie_length + 3 + (12)/WA) = 1; // W[12][account_trie_size + 3] = path_type = common = 1

                // // std::cout << "..account_trie_size + 4 = " << account_trie_size + 4 << std::endl; 

                assignment.witness(component.W((0) % WA), start_row_index + account_trie_length + 4 + (0)/WA) 
                                            = old_account[0]*(integral_type(1) << 64) + old_account[5]; // W[0][assignment_table_rows] = old_nonce || code_size
                assignment.witness(component.W((1) % WA), start_row_index + account_trie_length + 4 + (1)/WA) 
                                            = new_account[0]*(integral_type(1) << 64) + new_account[5]; // W[1][assignment_table_rows] = new_nonce || code_size         
                assignment.witness(component.W((2) % WA), start_row_index + account_trie_length + 4 + (2)/WA) = old_account[0]; // W[2][assignment_table_rows] = old_nonce
                assignment.witness(component.W((3) % WA), start_row_index + account_trie_length + 4 + (3)/WA) = new_account[0]; // W[3][assignment_table_rows] = new_nonce         
                assignment.witness(component.W((4) % WA), start_row_index + account_trie_length + 4 + (4)/WA) = old_account[1]; // W[4][assignment_table_rows] = balance  
                assignment.witness(component.W((6) % WA), start_row_index + account_trie_length + 4 + (6)/WA) = 0; // W[6][assignment_table_rows] = depth = 0
                assignment.witness(component.W((7) % WA), start_row_index + account_trie_length + 4 + (7)/WA) = 0; // W[7][assignment_table_rows] = direction[i] = 0
                assignment.witness(component.W((12) % WA), start_row_index + account_trie_length + 4 + (12)/WA) = 1; // W[12][assignment_table_rows] = path_type = common = 1

                // fill in columns which do not depend on the segment_type
                for(std::size_t i = 0; i < assignment_table_rows; i++) {
                    assignment.witness(component.W(5 % WA), start_row_index + i + 5/WA) = segment_type[i]; // W[5][i] = segment_type[i]
                    assignment.witness(component.W(8 % WA), start_row_index + i + 8/WA) = claim[3].first; // W[8][i] = eth_address
                    assignment.witness(component.W(9 % WA), start_row_index + i + 9/WA) = claim[3].second; // W[9][i] = mpt_proof_type = 1
                    assignment.witness(component.W((16) % WA), start_row_index + i + (16)/WA) = q_leaf0[i]; 
                    // std::cout << "..q_leaf0[i] = " << q_leaf0[i] << std::endl;
                    assignment.witness(component.W((17) % WA), start_row_index + i + (17)/WA) = q_leaf123[i]; 
                    // std::cout << "..q_leaf123[i] = " << q_leaf123[i] << std::endl;                    
                    assignment.witness(component.W(18 % WA), start_row_index + i + 18/WA) = q_start[i]; 
                    // std::cout << "..q_start[i] = " << q_start[i] << std::endl;
                    assignment.witness(component.W(19 % WA), start_row_index + i + 19/WA) = q_trie[i];
                    // std::cout << "..q_trie[i] = " << q_trie[i] << std::endl;
                    assignment.witness(component.W(20 % WA), start_row_index + i + 20/WA) = q_leaf_0[i];
                    // std::cout << "..q_leaf_0[i] = " << q_leaf_0[i] << std::endl;
                    assignment.witness(component.W(21 % WA), start_row_index + i + 21/WA) = q_leaf_1[i];
                    // std::cout << "..q_leaf_1[i] = " << q_leaf_1[i] << std::endl;
                    assignment.witness(component.W(22 % WA), start_row_index + i + 22/WA) = q_leaf_2[i];
                    // std::cout << "..q_leaf_2[i] = " << q_leaf_2[i] << std::endl;
                    assignment.witness(component.W(23 % WA), start_row_index + i + 23/WA) = q_leaf_3[i];
                    // std::cout << "..q_leaf_3[i] = " << q_leaf_3[i] << std::endl;
                }
                rows += account_trie_length + 1 + account_leaf_length;

                 // we do not need key and other_key for account leaf rows
                for(std::size_t i = account_trie_length + 1; i < assignment_table_rows; i++) {
                    assignment.witness(component.W((10) % WA), start_row_index + i + (10)/WA) = 0; // W[10][i] = key[i] = 0
                    assignment.witness(component.W((11) % WA), start_row_index + i + (11)/WA) = 0; // W[11][i] = other_key[i] = 0               
                }

                for(std::size_t i = 0; i < num_chunks; i++) { 
                    // std::cout << "..old_nonce_chunks[i] = " << old_nonce_chunks[i] << std::endl;
                    assignment.witness(component.W((13) % WA), start_row_index + i + (13)/WA) = old_nonce_chunks[i]; 
                    // std::cout << "..new_nonce_chunks[i] = " << new_nonce_chunks[i] << std::endl;
                    assignment.witness(component.W((14) % WA), start_row_index + i + (14)/WA) = new_nonce_chunks[i]; 
                    // std::cout << "..code_size_chunks[i] = " << code_size_chunks[i] << std::endl;            
                    assignment.witness(component.W((15) % WA), start_row_index + i + (15)/WA) = code_size_chunks[i]; 
                }

                // Initializing range_check component
                typename range_check_type::input_type range_check_input_1;
                for(std::size_t i = 0; i < num_chunks; i++) {
                    range_check_input_1.x[i] = var(component.W((13) % WA), start_row_index + i + (13) / WA, false);
                }
                generate_assignments(range_check_instance, assignment, range_check_input_1, rows);
                rows += range_check_instance.rows_amount;

                // Initializing range_check component
                typename range_check_type::input_type range_check_input_2;
                for(std::size_t i = 0; i < num_chunks; i++) {
                    range_check_input_2.x[i] = var(component.W((14) % WA), start_row_index + i + (14) / WA, false);
                }
                generate_assignments(range_check_instance, assignment, range_check_input_2, rows);
                rows += range_check_instance.rows_amount;

                // Initializing range_check component
                typename range_check_type::input_type range_check_input_3;
                for(std::size_t i = 0; i < num_chunks; i++) {
                    range_check_input_3.x[i] = var(component.W((15) % WA), start_row_index + i + (15) / WA, false);
                }
                generate_assignments(range_check_instance, assignment, range_check_input_3, rows);
                rows += range_check_instance.rows_amount;

                typename component_type::table_component_type::input_type table_input;
                std::pair<typename BlueprintFieldType::value_type, typename BlueprintFieldType::value_type> old_msg, new_msg;
                value_type old_hash, new_hash; 
                std::vector<std::pair<std::pair<typename BlueprintFieldType::value_type, typename BlueprintFieldType::value_type>, typename BlueprintFieldType::value_type>> poseidon_tab_input;
                
                for(std::size_t i = 0; i < account_trie_length - 1; i++) {
                    old_msg = {address_hash_traces[i + 1][2], address_hash_traces[i + 1][4]};
                    old_hash = address_hash_traces[i][2];
                    poseidon_tab_input.push_back({old_msg, old_hash});
                    new_msg = {address_hash_traces[i + 1][3], address_hash_traces[i + 1][4]};
                    new_hash = address_hash_traces[i][3];
                    poseidon_tab_input.push_back({new_msg, new_hash});
                }
                old_msg = {old_account_hash_traces[6][1], old_account_hash_traces[6][0]};
                old_hash = old_account_hash_traces[6][2];
                poseidon_tab_input.push_back({old_msg, old_hash});
                new_msg = {new_account_hash_traces[6][1], new_account_hash_traces[6][0]};
                new_hash = new_account_hash_traces[6][2];
                poseidon_tab_input.push_back({new_msg, new_hash});

                old_msg = {old_account_hash_traces[5][0], old_account_hash_traces[5][1]};
                old_hash = old_account_hash_traces[5][2];
                poseidon_tab_input.push_back({old_msg, old_hash});
                new_msg = {new_account_hash_traces[5][0], new_account_hash_traces[5][1]};
                new_hash = new_account_hash_traces[5][2];
                poseidon_tab_input.push_back({new_msg, new_hash});

                old_msg = {old_account_hash_traces[3][0], old_account_hash_traces[3][1]};
                old_hash = old_account_hash_traces[3][2];
                poseidon_tab_input.push_back({old_msg, old_hash});
                new_msg = {new_account_hash_traces[3][0], new_account_hash_traces[3][1]};
                new_hash = new_account_hash_traces[3][2];
                poseidon_tab_input.push_back({new_msg, new_hash});

                old_msg = {old_account_hash_traces[2][0], old_account_hash_traces[2][1]};
                old_hash = old_account_hash_traces[2][2];
                poseidon_tab_input.push_back({old_msg, old_hash});
                new_msg = {new_account_hash_traces[2][0], new_account_hash_traces[2][1]};
                new_hash = new_account_hash_traces[2][2];
                poseidon_tab_input.push_back({new_msg, new_hash});

                table_input.input = poseidon_tab_input;
                generate_assignments(component.table_component, assignment, table_input, rows);
                rows += component.table_component.rows_amount;

                // std::cout << "..table_component_rows = " << component.table_component.rows_amount << std::endl;
                // std::cout << "..start_row_index = " << start_row_index << std::endl;
                // std::cout << "..assignment.rows_amount() = " << assignment.rows_amount() << std::endl;
                // std::cout << "..rows = " << rows << std::endl;
                // std::cout << "..component.rows_amount = " << component.rows_amount << std::endl;

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

                // range_check_type range_check_instance(component._W, component._C, component._PI);

                size_t assignment_table_rows = account_trie_length + 5;
                size_t rows = assignment_table_rows;
                
                var oldNonce, newNonce;
                var oldHash, newHash, oldValue, newValue, depthPrev, depthCurr, Depth;
                var oldHash_last, newHash_last, oldValue_last, newValue_last, Direction, Key, OtherKey;
                var qLeaf0, qLeaf123, qStart, qTrie, qLeaf_0, qLeaf_1, qLeaf_2, qLeaf_3, nextSegmentType;

                std::vector<constraint_type> mpt_nonce_changed_constraints = {};

                // 1. Shared Constraints
                // 1.1. for segment_type == account_trie = 1
                // std::cout << "\n1. Shared Constraints" << std::endl; 
                // std::cout << "\n1.1. For segment_type = account_trie" << std::endl; 
                for(std::size_t i = 0; i < account_trie_length; i++) {
                    Depth = var(component.W(6 % WA), i + 6/WA + row_shift, true);
                    Direction = var(component.W(7 % WA), i + 7/WA + row_shift, true);
                    Key = var(component.W(10 % WA), i + 10/WA + row_shift, true);
                    OtherKey = var(component.W(11 % WA), i + 11/WA + row_shift, true);
                    depthCurr = var(component.W(6 % WA), i + 1 + 6/WA + row_shift, true);
                    depthPrev = var(component.W(6 % WA), i + 6/WA + row_shift, true);
                    mpt_nonce_changed_constraints.push_back(Depth - i);
                    mpt_nonce_changed_constraints.push_back(Key - Direction);
                    mpt_nonce_changed_constraints.push_back(depthCurr - depthPrev - 1);
                    mpt_nonce_changed_constraints.push_back(OtherKey - Direction);
                }

                // 1.2. for segment_type != account_trie != 1
                // std::cout << "\n1.2. For segment_type != account_trie" << std::endl; 
                Depth = var(component.W(6 % WA), 0 + 6/WA + row_shift, true);
                Key = var(component.W(10 % WA), 0 + 10/WA + row_shift, true);
                mpt_nonce_changed_constraints.push_back(Key);
                mpt_nonce_changed_constraints.push_back(Depth);
                for(std::size_t i = account_trie_length + 1; i < assignment_table_rows; i++) {
                    Depth = var(component.W(6 % WA), i + 6/WA + row_shift, true);
                    Key = var(component.W(10 % WA), i + 10/WA + row_shift, true);
                    mpt_nonce_changed_constraints.push_back(Key);
                    mpt_nonce_changed_constraints.push_back(Depth);
                }

                // 1.3. range check for eth_address => verify it is 160-bits
                // std::cout << "\n1.3. Range check for eth_address => verify it is 160-bits" << std::endl; 
                // std::cout << "*** to be implemented in another circuit ***" << std::endl; 

                // 1.4. for segment_type = account_leaf0 = 2
                // std::cout << "\n1.4. For segment_type = account_leaf0" << std::endl; 
                // std::cout << "*** to be implemented ***" << std::endl; 

                // 3. Constraints for mpt_proof_type = nonce_changed = 1
                // 3.1. segment type transisions
                // std::cout << "\n3. Constraints for mpt_proof_type = nonce_changed = 1" << std::endl; 
                // std::cout << "\n3.1. Segment type transisions" << std::endl; 

                for(std::size_t i = 0; i < assignment_table_rows - 1; i++) {   
                    qStart = var(component.W(18 % WA), i + 18/WA + row_shift, true);
                    qTrie = var(component.W(19 % WA), i + 19/WA + row_shift, true);
                    qLeaf_0 = var(component.W(20 % WA), i + 20/WA + row_shift, true);
                    qLeaf_1 = var(component.W(21 % WA), i + 21/WA + row_shift, true);
                    qLeaf_2 = var(component.W(22 % WA), i + 22/WA + row_shift, true);
                    qLeaf_3 = var(component.W(23 % WA), i + 23/WA + row_shift, true);

                    nextSegmentType = var(component.W(5 % WA), i + 1 + 5/WA + row_shift, true);

                    mpt_nonce_changed_constraints.push_back(qStart*(1 - qStart));
                    mpt_nonce_changed_constraints.push_back(qStart*nextSegmentType*(nextSegmentType - 1)*(nextSegmentType - 2));

                    mpt_nonce_changed_constraints.push_back(qTrie*(1 - qTrie));
                    mpt_nonce_changed_constraints.push_back(qTrie*nextSegmentType*(nextSegmentType - 1)*(nextSegmentType - 2));

                    mpt_nonce_changed_constraints.push_back(qLeaf_0*(1 - qLeaf_0));
                    mpt_nonce_changed_constraints.push_back(qLeaf_0*nextSegmentType*(nextSegmentType - 3));

                    mpt_nonce_changed_constraints.push_back(qLeaf_1*(1 - qLeaf_1));
                    mpt_nonce_changed_constraints.push_back(qLeaf_1*(nextSegmentType - 4));

                    mpt_nonce_changed_constraints.push_back(qLeaf_2*(1 - qLeaf_2));
                    mpt_nonce_changed_constraints.push_back(qLeaf_2*(nextSegmentType - 5));                

                    mpt_nonce_changed_constraints.push_back(qLeaf_3*(1 - qLeaf_3));
                    mpt_nonce_changed_constraints.push_back(qLeaf_3*nextSegmentType);                
                }

                // // 3.2. constraints for segment types
                // // std::cout << "\n3.2. Constraints for account leaf segment types" << std::endl; 

                for(std::size_t i = account_trie_length + 1; i < assignment_table_rows; i++) {
                    Direction = var(component.W(7 % WA), i + 7/WA + row_shift, true);
                    qLeaf0 = var(component.W(16 % WA), i + 16/WA + row_shift, true);
                    qLeaf123 = var(component.W(17 % WA), i + 17/WA + row_shift, true);
                    mpt_nonce_changed_constraints.push_back(qLeaf0*(1 - qLeaf0));
                    mpt_nonce_changed_constraints.push_back(qLeaf0*(Direction - 1));
                    mpt_nonce_changed_constraints.push_back(qLeaf123*(1 - qLeaf123));
                    mpt_nonce_changed_constraints.push_back(qLeaf123*Direction);
                }

                // 3.3. constraints for old_nonce, new_nonce, code_size
                // - Range check components for old_nonce, new_nonce, code_size 
                // range_check_multi components added in the generate_circuit function

                // - verify that code_size in old_account and new_account are equal
                oldHash_last = var(component.W(0 % WA), assignment_table_rows - 1 + 0/WA + row_shift, true);
                oldNonce = var(component.W(2 % WA), assignment_table_rows - 1 + 0/WA + row_shift, true);
                newHash_last = var(component.W(1 % WA), assignment_table_rows - 1 + 1/WA + row_shift, true);
                newNonce = var(component.W(3 % WA), assignment_table_rows - 1 + 3/WA + row_shift, true);
                mpt_nonce_changed_constraints.push_back(oldHash_last - oldNonce*B - newHash_last + newNonce*B);

                // BOOST_ASSERT_MSG(rows == component.rows_amount, "!!!component rows not equal to actual component rows!!!");      

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

                // std::cout << "\nConstruct copy constraints in the .hpp file" << std::endl;  
                // std::cout << "-----------------------------------------------" << std::endl;  

                const std::size_t WA = component.witness_amount();

                using var = typename plonk_mpt_nonce_changed<BlueprintFieldType,num_chunks,bit_size_chunk,account_trie_length>::var;
                
                size_t assignment_table_rows = account_trie_length + 5;

                for(std::size_t i = 0; i < assignment_table_rows - 1; i++) {
                    bp.add_copy_constraint({var(component.W(2 % WA), start_row_index + i + 2/WA,false), var(component.W(0 % WA), start_row_index + i + 1 + 0/WA,false)});
                    bp.add_copy_constraint({var(component.W(3 % WA), start_row_index + i + 3/WA,false), var(component.W(1 % WA), start_row_index + i + 1 + 1/WA,false)});
                    bp.add_copy_constraint({var(component.W(8 % WA), start_row_index + i + 8/WA,false), var(component.W(8 % WA), start_row_index + i + 1 + 8/WA,false)});
                    bp.add_copy_constraint({var(component.W(9 % WA), start_row_index + i + 9/WA,false), var(component.W(9 % WA), start_row_index + i + 1 + 9/WA,false)});
                }
            }

            template<typename BlueprintFieldType, std::size_t num_chunks, std::size_t bit_size_chunk, std::size_t account_trie_length>
            typename plonk_mpt_nonce_changed<BlueprintFieldType,num_chunks,bit_size_chunk,account_trie_length>::result_type generate_circuit(
                const plonk_mpt_nonce_changed<BlueprintFieldType,num_chunks,bit_size_chunk,account_trie_length> &component,
                circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>> &bp,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>> &assignment,
                const typename plonk_mpt_nonce_changed<BlueprintFieldType,num_chunks,bit_size_chunk,account_trie_length>::input_type &instance_input,
                const std::size_t start_row_index) {

                using component_type = plonk_mpt_nonce_changed<BlueprintFieldType, num_chunks, bit_size_chunk, account_trie_length>;
                using range_check_type = typename component_type::range_check_component;
                using lookup_constraint_type = crypto3::zk::snark::plonk_lookup_constraint<BlueprintFieldType>;

                using var = typename component_type::var;
                using value_type = typename BlueprintFieldType::value_type;
                
                range_check_type range_check_instance(component._W, component._C, component._PI);

                const std::size_t WA = component.witness_amount();
                const std::size_t row_shift = (4*num_chunks > 2*WA);

                std::size_t selector_index = generate_gates(component, bp, assignment, instance_input);
                assignment.enable_selector(selector_index, start_row_index + row_shift);
                generate_copy_constraints(component, bp, assignment, instance_input, start_row_index);

                size_t rows = start_row_index + account_trie_length + 5;

                // 3.3. constraints for old_nonce, new_nonce, code_size
                // - Range check components for old_nonce, new_nonce, code_size 

                // Initializing range_check component for old_nonce
                typename range_check_type::input_type range_check_input_1;
                for(std::size_t i = 0; i < num_chunks; i++) {
                    range_check_input_1.x[i] = var(component.W((13) % WA), start_row_index + i + (13) / WA, false);
                }
                generate_circuit(range_check_instance, bp, assignment, range_check_input_1, rows);    
                rows += range_check_instance.rows_amount;    

                // Initializing range_check component for new_nonce
                typename range_check_type::input_type range_check_input_2;
                for(std::size_t i = 0; i < num_chunks; i++) {
                    range_check_input_2.x[i] = var(component.W((14) % WA), start_row_index + i + (14) / WA, false);
                }
                generate_circuit(range_check_instance, bp, assignment, range_check_input_2, rows);
                rows += range_check_instance.rows_amount;    

                // Initializing range_check component for code_size
                typename range_check_type::input_type range_check_input_3;
                for(std::size_t i = 0; i < num_chunks; i++) {
                    range_check_input_3.x[i] = var(component.W((15) % WA), start_row_index + i + (15) / WA, false);
                }
                generate_circuit(range_check_instance, bp, assignment, range_check_input_3, rows);
                rows += range_check_instance.rows_amount;  

                typename component_type::table_component_type::input_type table_input;
                std::pair<typename BlueprintFieldType::value_type, typename BlueprintFieldType::value_type> old_msg, new_msg;
                value_type old_hash, new_hash;
                std::vector<std::pair<std::pair<typename BlueprintFieldType::value_type, typename BlueprintFieldType::value_type>, typename BlueprintFieldType::value_type>> poseidon_tab_input;

                for(std::size_t i = 0; i < account_trie_length - 1; i++) {
                    old_msg = {var_value(assignment, instance_input.address_hash_traces[i + 1][2]), var_value(assignment, instance_input.address_hash_traces[i + 1][4])};
                    old_hash = var_value(assignment, instance_input.address_hash_traces[i][2]);
                    poseidon_tab_input.push_back({old_msg, old_hash});
                    new_msg = {var_value(assignment, instance_input.address_hash_traces[i + 1][3]), var_value(assignment, instance_input.address_hash_traces[i + 1][4])};
                    new_hash = var_value(assignment, instance_input.address_hash_traces[i][3]);
                    poseidon_tab_input.push_back({new_msg, new_hash});
                }

                old_msg = {var_value(assignment, instance_input.old_account_hash_traces[6][1]), var_value(assignment, instance_input.old_account_hash_traces[6][0])};
                old_hash = var_value(assignment, instance_input.old_account_hash_traces[6][2]);
                poseidon_tab_input.push_back({old_msg, old_hash});
                new_msg = {var_value(assignment, instance_input.new_account_hash_traces[6][1]), var_value(assignment, instance_input.new_account_hash_traces[6][0])};
                new_hash = var_value(assignment, instance_input.new_account_hash_traces[6][2]);
                poseidon_tab_input.push_back({new_msg, new_hash});

                old_msg = {var_value(assignment, instance_input.old_account_hash_traces[5][0]), var_value(assignment, instance_input.old_account_hash_traces[5][1])};
                old_hash = var_value(assignment, instance_input.old_account_hash_traces[5][2]);
                poseidon_tab_input.push_back({old_msg, old_hash});
                new_msg = {var_value(assignment, instance_input.new_account_hash_traces[5][0]), var_value(assignment, instance_input.new_account_hash_traces[5][1])};
                new_hash = var_value(assignment, instance_input.new_account_hash_traces[5][2]);
                poseidon_tab_input.push_back({new_msg, new_hash});

                old_msg = {var_value(assignment, instance_input.old_account_hash_traces[3][0]), var_value(assignment, instance_input.old_account_hash_traces[3][1])};
                old_hash = var_value(assignment, instance_input.old_account_hash_traces[3][2]);
                poseidon_tab_input.push_back({old_msg, old_hash});
                new_msg = {var_value(assignment, instance_input.new_account_hash_traces[3][0]), var_value(assignment, instance_input.new_account_hash_traces[3][1])};
                new_hash = var_value(assignment, instance_input.new_account_hash_traces[3][2]);
                poseidon_tab_input.push_back({new_msg, new_hash});

                old_msg = {var_value(assignment, instance_input.old_account_hash_traces[2][0]), var_value(assignment, instance_input.old_account_hash_traces[2][1])};
                old_hash = var_value(assignment, instance_input.old_account_hash_traces[2][2]);
                poseidon_tab_input.push_back({old_msg, old_hash});
                new_msg = {var_value(assignment, instance_input.new_account_hash_traces[2][0]), var_value(assignment, instance_input.new_account_hash_traces[2][1])};
                new_hash = var_value(assignment, instance_input.new_account_hash_traces[2][2]);
                poseidon_tab_input.push_back({new_msg, new_hash});

                table_input.input = poseidon_tab_input;
                generate_circuit(component.table_component, bp, assignment, table_input, rows);
                rows += component.table_component.rows_amount;  

                return typename plonk_mpt_nonce_changed<BlueprintFieldType,num_chunks,bit_size_chunk,account_trie_length>::result_type(component, start_row_index);
            }
        }    // namespace components
    }        // namespace blueprint
}    // namespace nil

#endif    // CRYPTO3_BLUEPRINT_COMPONENTS_PLONK_MPT_NONCE_CHANGED_HPP