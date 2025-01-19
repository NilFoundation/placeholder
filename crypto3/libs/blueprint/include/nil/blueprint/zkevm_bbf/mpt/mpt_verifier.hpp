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

#include <nil/blueprint/zkevm_bbf/subcomponents/poseidon_table.hpp>

namespace nil {
    namespace blueprint {
        namespace bbf {
            template<typename FieldType, GenerationStage stage>
            class mpt_verifier : public generic_component<FieldType, stage> {
                using typename generic_component<FieldType, stage>::context_type;
                using generic_component<FieldType, stage>::allocate;
                using generic_component<FieldType, stage>::copy_constrain;
                using generic_component<FieldType, stage>::constrain;
                using generic_component<FieldType, stage>::lookup;
                using generic_component<FieldType, stage>::lookup_table;

            public:
                using typename generic_component<FieldType,stage>::TYPE;
                using private_input_type = typename std::conditional<stage == GenerationStage::ASSIGNMENT, std::vector<TYPE>, std::nullptr_t>::type;

                struct input_type{
                    TYPE rlc_challenge;
                    private_input_type proof;
                };

                std::size_t max_mpt;
                std::size_t max_poseidon_size;
                std::size_t account_trie_length;

            public:
                static nil::crypto3::zk::snark::plonk_table_description<FieldType> get_table_description(std::size_t max_mpt_, std::size_t max_poseidon_size_, std::size_t account_trie_length){
                    std::size_t witness_amount = 40;
                    nil::crypto3::zk::snark::plonk_table_description<FieldType> desc(witness_amount, 1, 3, 5);
                    desc.usable_rows_amount = max_mpt_ + max_poseidon_size_;
                    return desc;
                }
                mpt_verifier(context_type &context_object, const input_type &input, std::size_t max_mpt_, std::size_t max_poseidon_size_, std::size_t account_trie_length_
                    ) : max_mpt(max_mpt_),
                        max_poseidon_size(max_poseidon_size_),
                        account_trie_length(account_trie_length_),
                        generic_component<FieldType,stage>(context_object) {

                    using Poseidon_Table = poseidon_table<FieldType,stage>;

                    std::vector<std::size_t> poseidon_lookup_area = {0,1,2};
                    context_type poseidon_ct = context_object.subcontext(poseidon_lookup_area, max_mpt, max_mpt + max_poseidon_size);

                    static constexpr std::size_t OLD_HASH = 0;
                    static constexpr std::size_t NEW_HASH = 1;
                    static constexpr std::size_t OLD_VALUE = 2;
                    static constexpr std::size_t NEW_VALUE = 3;
                    static constexpr std::size_t SIBLING = 4;
                    static constexpr std::size_t SEGMENT_TYPE = 5;
                    static constexpr std::size_t DEPTH = 6;
                    static constexpr std::size_t DIRECTION = 7;
                    static constexpr std::size_t ADDRESS = 8;
                    static constexpr std::size_t PROOF_TYPE = 9;
                    static constexpr std::size_t KEY = 10;
                    static constexpr std::size_t OTHER_KEY = 11;
                    static constexpr std::size_t PATH_TYPE = 12;
                    static constexpr std::size_t OLD_NONCE_CHUNKS = 13;
                    static constexpr std::size_t NEW_NONCE_CHUNKS = 14;
                    static constexpr std::size_t CODE_SIZE_CHUNKS = 15;
                    static constexpr std::size_t Q_LEAF0 = 16;
                    static constexpr std::size_t Q_LEAF123 = 17;
                    static constexpr std::size_t Q_START = 18;
                    static constexpr std::size_t Q_TRIE = 19;
                    static constexpr std::size_t Q_LEAF1 = 20;
                    static constexpr std::size_t Q_LEAF2 = 21;
                    static constexpr std::size_t Q_LEAF3 = 22;
                    static constexpr std::size_t IS_TRIE = 23;
                    static constexpr std::size_t Q_LAST = 24;
                    static constexpr std::size_t IS_PADDING = 25;
                    static constexpr std::size_t OLD_Y = 26;
                    static constexpr std::size_t OLD_YI = 27;
                    static constexpr std::size_t OLD_C = 28;
                    static constexpr std::size_t NEW_Y = 29;
                    static constexpr std::size_t NEW_YI = 30;
                    static constexpr std::size_t NEW_C = 31;
                    static constexpr std::size_t CODE_Y = 32;
                    static constexpr std::size_t CODE_YI = 33;
                    static constexpr std::size_t CODE_C = 34;
                    
                    using value_type = typename FieldType::value_type;
                    using integral_type = typename FieldType::integral_type; 

                    value_type eth_address, mpt_proof_type, storage, account_key;
                    std::pair<TYPE, TYPE> old_root, new_root, nonce;
                    std::vector<std::vector<TYPE>> address_hash_traces, old_account_hash_traces, new_account_hash_traces, leafs;
                    std::vector<TYPE> old_account, new_account;

                    TYPE old_hash[max_mpt], new_hash[max_mpt], old_value[max_mpt], new_value[max_mpt], sibling[max_mpt];
                    TYPE segment[max_mpt], depth[max_mpt], direction[max_mpt], address[max_mpt], proof_type[max_mpt];
                    TYPE key[max_mpt], other_key[max_mpt], path_type[max_mpt];

                    TYPE old_nonce_chunks[max_mpt], new_nonce_chunks[max_mpt], code_size_chunks[max_mpt]; // fix num_chunks = 4
                    TYPE old_Y[max_mpt], old_YI[max_mpt], old_C[max_mpt]; // fix num_chunks = 4
                    TYPE new_Y[max_mpt], new_YI[max_mpt], new_C[max_mpt]; // fix num_chunks = 4
                    TYPE code_Y[max_mpt], code_YI[max_mpt], code_C[max_mpt]; // fix num_chunks = 4
                    TYPE q_leaf0[max_mpt], q_leaf1[max_mpt], q_leaf2[max_mpt], q_leaf3[max_mpt], q_leaf123[max_mpt];
                    TYPE q_start[max_mpt], q_trie[max_mpt], q_last[max_mpt], is_padding[max_mpt];

                    std::pair<TYPE, TYPE> old_msg, new_msg;
                    TYPE old_poseidon_hash, new_poseidon_hash; 
                    std::vector<std::pair<std::pair<TYPE, TYPE>, TYPE>> poseidon_tab_input;

                    size_t bit_size_rc = 16;
                    size_t bit_size_chunk = 16;
                    const integral_type B = integral_type(1) << 64;
                    const integral_type mask = (1 << bit_size_rc) - 1;
                    std::size_t num_rc_chunks = (bit_size_chunk / bit_size_rc) + (bit_size_chunk % bit_size_rc > 0);
                    std::size_t first_chunk_size = bit_size_chunk % bit_size_rc;

                    // // Create input for Poseidon table
                    // for(std::size_t i = 0; i < account_trie_length - 1; i++) {
                    //     old_msg = {input.proof[10 + 7*(i + 1)], input.proof[12 + 7*(i + 1)]};
                    //     old_poseidon_hash = input.proof[10 + 7*i];
                    //     poseidon_tab_input.push_back({old_msg, old_poseidon_hash});
                    //     // new_msg = {address_hash_traces[i + 1][3], address_hash_traces[i + 1][4]};
                    //     // new_poseidon_hash = address_hash_traces[i][3];
                    //     // poseidon_tab_input.push_back({new_msg, new_poseidon_hash});
                    // }                    

                    if constexpr (stage == GenerationStage::ASSIGNMENT) {
                        std::cout << "MPT assign " << input.proof.size() << std::endl;
                        size_t public_input_index = 0;
                        eth_address = input.proof[public_input_index];
                        mpt_proof_type = input.proof[public_input_index + 1];
                        // old_root = (old_root_hi, old_root_lo)
                        old_root = {input.proof[public_input_index + 2], input.proof[public_input_index + 3]};
                        // new_root = (new_root_hi, new_root_lo)
                        new_root = {input.proof[public_input_index + 4], input.proof[public_input_index + 5]};
                        // nonce = (old_nonce, new_nonce)
                        nonce = {input.proof[public_input_index + 6], input.proof[public_input_index + 7]};
                        public_input_index += 7; 
                        // address_hash_traces = (direction[i], domain[i], old_h[i], new_h[i], s[i], is_open_padding[i], is_close_padding[i])
                        for(std::size_t i = 0; i < account_trie_length; i++) {
                            address_hash_traces.push_back({input.proof[public_input_index + 1 + 7*i],
                                                           input.proof[public_input_index + 2 + 7*i],
                                                           input.proof[public_input_index + 3 + 7*i],
                                                           input.proof[public_input_index + 4 + 7*i],
                                                           input.proof[public_input_index + 5 + 7*i],
                                                           input.proof[public_input_index + 6 + 7*i],
                                                           input.proof[public_input_index + 7 + 7*i]});
                        }
                        public_input_index += 7*account_trie_length; 
                        // leafs = (old_leaf, new_leaf) = [(old_h3, s3, 4), (new_h3, s3, 4)]
                        leafs.push_back({input.proof[public_input_index + 1], input.proof[public_input_index + 2], input.proof[public_input_index + 3]});
                        leafs.push_back({input.proof[public_input_index + 4], input.proof[public_input_index + 5], input.proof[public_input_index + 6]});
                        public_input_index += 6; 
                        // old_account_hash_traces and new_account_hash_traces 
                        for(std::size_t i = 0; i < 7; i++) {
                            old_account_hash_traces.push_back({input.proof[public_input_index + 1 + 3*i],
                                                               input.proof[public_input_index + 2 + 3*i],
                                                               input.proof[public_input_index + 3 + 3*i]});
                        }
                        public_input_index += 3*7; 
                        for(std::size_t i = 0; i < 7; i++) {
                            new_account_hash_traces.push_back({input.proof[public_input_index + 1 + 3*i],
                                                               input.proof[public_input_index + 2 + 3*i],
                                                               input.proof[public_input_index + 3 + 3*i]});
                        }
                        std::cout << "public_input_index_prev = " << public_input_index << std::endl;
                        public_input_index += 3*7; 
                        std::cout << "public_input_index_next = " << public_input_index << std::endl;
                        // old_account = [old_nonce, balance, keccak_code_hash_hi, keccak_code_hash_lo, poseidon_code_hash, code_size]
                        // new_account = [new_nonce, balance, keccak_code_hash_hi, keccak_code_hash_lo, poseidon_code_hash, code_size]
                        for(std::size_t i = 0; i < 6; i++) {
                            old_account.push_back(input.proof[public_input_index + 1 + i]);
                            new_account.push_back(input.proof[public_input_index + 7 + i]);
                        }
                        public_input_index += 12; 
                        storage = input.proof[public_input_index + 1];
                        account_key = input.proof[public_input_index + 2];
                        public_input_index += 2; 

                        for (std::size_t i = 0; i < old_account.size(); i++) {
                            // std::cout << "old_account[" << i << "] = " << old_account[i] << std::endl;
                            // std::cout << "new_account[" << i << "] = " << new_account[i] << std::endl;
                            if (i != 0){
                                // verify that all elements except for the nonces are the same in old_account and new_account
                                BOOST_ASSERT(old_account[i] == new_account[i]);
                            }
                        }

                        // construct key and other_key based on the bits of account_key
                        integral_type key_integral = integral_type(account_key.data);
                        key[0] = 0;
                        other_key[0] = 0;
                        for (std::size_t i = 1; i < account_trie_length + 1; i++) {
                            key[i] = value_type(key_integral % 2);
                            key_integral = key_integral >> 1;
                            other_key[i] = key[i]; // this is because the old_path and new_path are the same
                        }

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
                            segment_type[account_trie_length + 1] = 2; 
                            segment_type[account_trie_length + 2] = 3; 
                            segment_type[account_trie_length + 3] = 4; 
                            segment_type[account_trie_length + 4] = 5; 
                        }

                        // q_leaf0, q_leaf123 to be added as selector columns in assignment table
                        // to choose between account_leaf rows
                        for (std::size_t i = 0; i < assignment_table_rows; i++) {
                            q_leaf0[i] = (segment_type[i] == 2) ? 1 : 0; 
                            q_leaf123[i] = (segment_type[i] == 3 || segment_type[i] == 4 || segment_type[i] == 5) ? 1 : 0; ;
                        }

                        // q_start, q_trie, q_leaf_0, q_leaf_1, q_leaf_2, q_leaf_3 to be added as selector columns in assignment table
                        // to choose between different segment types
                        // value_type q_start[assignment_table_rows], q_trie[assignment_table_rows], q_leaf_0[assignment_table_rows];
                        // value_type q_leaf_1[assignment_table_rows], q_leaf_2[assignment_table_rows], q_leaf_3[assignment_table_rows], q_last[assignment_table_rows];
                        for (std::size_t i = 0; i < assignment_table_rows; i++) {
                            q_start[i]  = (segment_type[i] == 0) ? 1 : 0; 
                            q_trie[i]   = (segment_type[i] == 1) ? 1 : 0; 
                            // q_leaf_0[i] = (segment_type[i] == 2) ? 1 : 0; 
                            q_leaf1[i] = (segment_type[i] == 3) ? 1 : 0; 
                            q_leaf2[i] = (segment_type[i] == 4) ? 1 : 0; 
                            q_leaf3[i] = (segment_type[i] == 5) ? 1 : 0; 
                            q_last[i]  = (segment_type[i] == 5) ? 1 : 0; 
                            is_padding[i] = 1;
                        }

                        // split old_nonce, new_nonce, code_size into 4 chunks each of 16-bits
                        integral_type A = integral_type(1) << 16; // fix bit_size_chunk = 16
                        integral_type old_nonce_integral = integral_type(nonce.first.data);
                        integral_type new_nonce_integral = integral_type(nonce.second.data);
                        integral_type code_size_integral = integral_type(old_account[5].data);

                        // for(std::size_t i = 0; i < 4; i++) { 
                        //     old_nonce_chunks[i] = value_type(old_nonce_integral % A);
                        //     new_nonce_chunks[i] = value_type(new_nonce_integral % A);
                        //     code_size_chunks[i] = value_type(code_size_integral % A);
                        //     old_nonce_integral /= A;
                        //     new_nonce_integral /= A;
                        //     code_size_integral /= A;
                        //     std::cout << "..old_nonce_chunks[" << i << "] = " << old_nonce_chunks[i] << std::endl;
                        //     std::cout << "..new_nonce_chunks[" << i << "] = " << new_nonce_chunks[i] << std::endl;
                        //     std::cout << "..code_size_chunks[" << i << "] = " << code_size_chunks[i] << std::endl;
                        // }

                        for(std::size_t i = 0; i < 4; i++) { 
                            old_nonce_chunks[i] = value_type(old_nonce_integral & mask);
                            new_nonce_chunks[i] = value_type(new_nonce_integral & mask);
                            code_size_chunks[i] = value_type(code_size_integral & mask);
                            old_nonce_integral >>= bit_size_rc;
                            new_nonce_integral >>= bit_size_rc;
                            code_size_integral >>= bit_size_rc;
                            // std::cout << "..old_nonce_chunks[" << i << "] = " << old_nonce_chunks[i] << std::endl;
                            // std::cout << "..new_nonce_chunks[" << i << "] = " << new_nonce_chunks[i] << std::endl;
                            // std::cout << "..code_size_chunks[" << i << "] = " << code_size_chunks[i] << std::endl;
                        }

                        integral_type A2 = integral_type(1) << 32;
                        integral_type A3 = integral_type(1) << 48;

                        BOOST_ASSERT(nonce.first == value_type(integral_type(old_nonce_chunks[0].data) + integral_type(old_nonce_chunks[1].data)*A 
                                                        + integral_type(old_nonce_chunks[2].data)*A2 + integral_type(old_nonce_chunks[3].data)*A3));
                        BOOST_ASSERT(nonce.second == value_type(integral_type(new_nonce_chunks[0].data) + integral_type(new_nonce_chunks[1].data)*A 
                                                        + integral_type(new_nonce_chunks[2].data)*A2 + integral_type(new_nonce_chunks[3].data)*A3));  
                        BOOST_ASSERT(old_account[5] == value_type(integral_type(code_size_chunks[0].data) + integral_type(code_size_chunks[1].data)*A 
                                                        + integral_type(code_size_chunks[2].data)*A2 + integral_type(code_size_chunks[3].data)*A3));                                                                

                        integral_type x_integral;
                        integral_type y_integral;

                        // range_check for old_nonce
                        for (std::size_t i = 0; i < 4; ++i) {
                            x_integral = integral_type(old_nonce_chunks[i].data);
                            for (std::size_t j = 0; j < num_rc_chunks; ++j) {
                                y_integral = x_integral & mask;
                                old_Y[i] = y_integral;
                                x_integral >>= bit_size_rc;
                            }
                            if (first_chunk_size != 0) {
                                old_YI[i] = integral_type(old_Y[i].data) * (integral_type(1) << (bit_size_rc - first_chunk_size));
                            }
                        }

                        // range_check for new_nonce
                        for (std::size_t i = 0; i < 4; ++i) {
                            x_integral = integral_type(new_nonce_chunks[i].data);
                            for (std::size_t j = 0; j < num_rc_chunks; ++j) {
                                y_integral = x_integral & mask;
                                new_Y[i] = y_integral;
                                x_integral >>= bit_size_rc;
                            }     
                            if (first_chunk_size != 0) {
                                new_YI[i] = integral_type(new_Y[i].data) * (integral_type(1) << (bit_size_rc - first_chunk_size));
                            }
                        }

                        // range_check for new_nonce
                        for (std::size_t i = 0; i < 4; ++i) {
                            x_integral = integral_type(code_size_chunks[i].data);
                            for (std::size_t j = 0; j < num_rc_chunks; ++j) {
                                y_integral = x_integral & mask;
                                code_Y[i] = y_integral;
                                x_integral >>= bit_size_rc;
                            }
                            if (first_chunk_size != 0) {
                                code_YI[i] = integral_type(code_Y[i].data) * (integral_type(1) << (bit_size_rc - first_chunk_size));
                            }
                        }

                        // range_check for old_nonce
                        for (std::size_t i = 0; i < 4; ++i) {
                            integral_type power = 1;      
                            old_C[i] = old_nonce_chunks[i];
                            for (std::size_t j = 0; j < num_rc_chunks; ++j) {
                                lookup(old_Y[i], "chunk_16_bits/full");
                                old_C[i] -= old_Y[i] * power;
                                power <<= bit_size_rc;
                            }
                            if (first_chunk_size != 0) {
                                lookup(old_YI[i], "chunk_16_bits/full");
                                constrain(old_YI[i] - old_Y[i] * (integral_type(1) << (bit_size_rc - first_chunk_size)));
                            }
                        }

                        // range_check for new_nonce
                        for (std::size_t i = 0; i < 4; ++i) {
                            integral_type power = 1;      
                            new_C[i] = new_nonce_chunks[i];
                            for (std::size_t j = 0; j < num_rc_chunks; ++j) {
                                lookup(new_Y[i], "chunk_16_bits/full");
                                new_C[i] -= new_Y[i] * power;
                                power <<= bit_size_rc;
                            }
                            if (first_chunk_size != 0) {
                                lookup(new_YI[i], "chunk_16_bits/full");
                                constrain(new_YI[i] - new_YI[i] * (integral_type(1) << (bit_size_rc - first_chunk_size)));
                            }
                        }

                        // range_check for code_size
                        for (std::size_t i = 0; i < 4; ++i) {
                            integral_type power = 1;      
                            code_C[i] = code_size_chunks[i];
                            for (std::size_t j = 0; j < num_rc_chunks; ++j) {
                                lookup(code_Y[i], "chunk_16_bits/full");
                                code_C[i] -= code_Y[i] * power;
                                power <<= bit_size_rc;
                            }
                            if (first_chunk_size != 0) {
                                lookup(code_YI[i], "chunk_16_bits/full");
                                constrain(code_YI[i] - code_YI[i] * (integral_type(1) << (bit_size_rc - first_chunk_size)));
                            }
                        }

                        // for(std::size_t i = 4; i < max_mpt; i++) { 
                        //     old_nonce_chunks[i] = 0;
                        //     new_nonce_chunks[i] = 0;
                        //     code_size_chunks[i] = 0;
                        //     old_Y[i] = 0;
                        //     old_YI[i] = 0;
                        //     old_C[i] = 0;
                        //     new_Y[i] = 0;
                        //     new_YI[i] = 0;
                        //     new_C[i] = 0;
                        //     code_Y[i] = 0;
                        //     code_YI[i] = 0;
                        //     code_C[i] = 0;
                        // }

                        for(std::size_t i = 0; i < account_trie_length; i++) { 
                            if (i == 0){
                                old_hash[i] = old_root.first;
                                new_hash[i] = old_root.first;
                                segment[i] = 0;
                                direction[i] = 0;
                                path_type[i] = 0;
                            }
                            else{
                                old_hash[i] = address_hash_traces[i - 1][2];
                                new_hash[i] = address_hash_traces[i - 1][3];
                                segment[i] = 1;
                                direction[i] = address_hash_traces[i - 1][0];
                                path_type[i] = 1;
                            }
                            old_value[i] = address_hash_traces[i][2];
                            new_value[i] = address_hash_traces[i][3];
                            sibling[i] = address_hash_traces[i][4];
                            depth[i] = i;
                            address[i] = eth_address;
                            proof_type[i] = mpt_proof_type;
                        }

                        old_hash[account_trie_length] = old_account_hash_traces[6][2];
                        new_hash[account_trie_length] = new_account_hash_traces[6][2];
                        old_value[account_trie_length] = old_account_hash_traces[6][1];
                        new_value[account_trie_length] = new_account_hash_traces[6][1];
                        sibling[account_trie_length] = old_account_hash_traces[6][0];
                        depth[account_trie_length] = account_trie_length;
                        direction[account_trie_length] = address_hash_traces[account_trie_length - 1][0];
                        // key[account_trie_length] = 0;
                        // other_key[account_trie_length] = 0;
                        path_type[account_trie_length] = 1;

                        old_hash[account_trie_length + 1] = old_account_hash_traces[5][2];
                        new_hash[account_trie_length + 1] = new_account_hash_traces[5][2];
                        old_value[account_trie_length + 1] = old_account_hash_traces[5][0];
                        new_value[account_trie_length + 1] = new_account_hash_traces[5][0];
                        sibling[account_trie_length + 1] = old_account_hash_traces[5][1];
                        depth[account_trie_length + 1] = 0;
                        direction[account_trie_length + 1] = 1;
                        key[account_trie_length + 1] = 0;
                        other_key[account_trie_length + 1] = 0;
                        path_type[account_trie_length + 1] = 1;

                        old_hash[account_trie_length + 2] = old_account_hash_traces[3][2];
                        new_hash[account_trie_length + 2] = new_account_hash_traces[3][2];
                        old_value[account_trie_length + 2] = old_account_hash_traces[3][0];
                        new_value[account_trie_length + 2] = new_account_hash_traces[3][0];
                        sibling[account_trie_length + 2] = old_account_hash_traces[3][1];
                        depth[account_trie_length + 2] = 0;
                        direction[account_trie_length + 2] = 0;
                        key[account_trie_length + 2] = 0;
                        other_key[account_trie_length + 2] = 0;
                        path_type[account_trie_length + 2] = 1;

                        old_hash[account_trie_length + 3] = old_account_hash_traces[2][2];
                        new_hash[account_trie_length + 3] = new_account_hash_traces[2][2];
                        old_value[account_trie_length + 3] = old_account_hash_traces[2][0];
                        new_value[account_trie_length + 3] = new_account_hash_traces[2][0];
                        sibling[account_trie_length + 3] = old_account_hash_traces[2][1];
                        depth[account_trie_length + 3] = 0;
                        direction[account_trie_length + 3] = 0;
                        key[account_trie_length + 3] = 0;
                        other_key[account_trie_length + 3] = 0;
                        path_type[account_trie_length + 3] = 1;

                        old_hash[account_trie_length + 4] = old_account[0]*(integral_type(1) << 64) + old_account[5];
                        new_hash[account_trie_length + 4] = new_account[0]*(integral_type(1) << 64) + new_account[5];
                        old_value[account_trie_length + 4] = old_account[0];
                        new_value[account_trie_length + 4] = new_account[0];
                        sibling[account_trie_length + 4] = old_account[1];
                        depth[account_trie_length + 4] = 0;
                        direction[account_trie_length + 4] = 0;
                        key[account_trie_length + 4] = 0;
                        other_key[account_trie_length + 4] = 0;
                        path_type[account_trie_length + 4] = 1;

                        for(std::size_t i = account_trie_length; i < assignment_table_rows; i++) { 
                            segment[i] = segment_type[i];
                            address[i] = eth_address;
                            proof_type[i] = mpt_proof_type;
                        }

                        // for(std::size_t i = assignment_table_rows; i < max_mpt; i++) { 
                        //     old_hash[i] = 0;
                        //     new_hash[i] = 0;
                        //     old_value[i] = 0;
                        //     new_value[i] = 0;
                        //     sibling[i] = 0;
                        //     segment[i] = 0;
                        //     depth[i] = 0;
                        //     direction[i] = 0;
                        //     address[i] = 0;
                        //     proof_type[i] = 0;
                        //     key[i] = 0;
                        //     other_key[i] = 0;
                        //     path_type[i] = 0;
                        // }

                        // for(std::size_t i = assignment_table_rows; i < max_mpt; i++) { 
                        //     q_leaf0[i] = 0;
                        //     q_leaf123[i] = 0;
                        //     q_leaf1[i] = 0;
                        //     q_leaf2[i] = 0;
                        //     q_leaf3[i] = 0;
                        //     q_start[i] = 0;
                        //     q_trie[i] = 0; 
                        //     q_last[i] = 0;
                        //     is_padding[i] = 0;
                        // }

                        // Create input for Poseidon table
                        for(std::size_t i = 0; i < account_trie_length - 1; i++) {
                            old_msg = {address_hash_traces[i + 1][2], address_hash_traces[i + 1][4]};
                            old_poseidon_hash = address_hash_traces[i][2];
                            poseidon_tab_input.push_back({old_msg, old_poseidon_hash});
                            new_msg = {address_hash_traces[i + 1][3], address_hash_traces[i + 1][4]};
                            new_poseidon_hash = address_hash_traces[i][3];
                            poseidon_tab_input.push_back({new_msg, new_poseidon_hash});
                        }

                        old_msg = {old_account_hash_traces[6][1], old_account_hash_traces[6][0]};
                        old_poseidon_hash = old_account_hash_traces[6][2];
                        poseidon_tab_input.push_back({old_msg, old_poseidon_hash});
                        new_msg = {new_account_hash_traces[6][1], new_account_hash_traces[6][0]};
                        new_poseidon_hash = new_account_hash_traces[6][2];
                        poseidon_tab_input.push_back({new_msg, new_poseidon_hash});

                        old_msg = {old_account_hash_traces[5][0], old_account_hash_traces[5][1]};
                        old_poseidon_hash = old_account_hash_traces[5][2];
                        poseidon_tab_input.push_back({old_msg, old_poseidon_hash});
                        new_msg = {new_account_hash_traces[5][0], new_account_hash_traces[5][1]};
                        new_poseidon_hash = new_account_hash_traces[5][2];
                        poseidon_tab_input.push_back({new_msg, new_poseidon_hash});

                        old_msg = {old_account_hash_traces[3][0], old_account_hash_traces[3][1]};
                        old_poseidon_hash = old_account_hash_traces[3][2];
                        poseidon_tab_input.push_back({old_msg, old_poseidon_hash});
                        new_msg = {new_account_hash_traces[3][0], new_account_hash_traces[3][1]};
                        new_poseidon_hash = new_account_hash_traces[3][2];
                        poseidon_tab_input.push_back({new_msg, new_poseidon_hash});

                        old_msg = {old_account_hash_traces[2][0], old_account_hash_traces[2][1]};
                        old_poseidon_hash = old_account_hash_traces[2][2];
                        poseidon_tab_input.push_back({old_msg, old_poseidon_hash});
                        new_msg = {new_account_hash_traces[2][0], new_account_hash_traces[2][1]};
                        new_poseidon_hash = new_account_hash_traces[2][2];
                        poseidon_tab_input.push_back({new_msg, new_poseidon_hash});

                        Poseidon_Table p_t = Poseidon_Table(poseidon_ct, poseidon_tab_input, max_poseidon_size);

                        const std::vector<TYPE> &hash_value = p_t.hash_value;
                        const std::vector<TYPE> &left_msg = p_t.left_msg;
                        const std::vector<TYPE> &right_msg = p_t.right_msg;

                        // std::cout << "hash_value[0] = " << hash_value[0] << std::endl;
                        // std::cout << "left_msg[0] = " << left_msg[0] << std::endl;
                        // std::cout << "right_msg[0] = " << right_msg[0] << std::endl;
                    } 
                    std::cout << "MPT assignment and circuit construction" << std::endl;

                    for(std::size_t i = 0; i < max_mpt; i++) {
                        allocate(old_hash[i], OLD_HASH, i);
                        allocate(new_hash[i], NEW_HASH, i);
                        allocate(old_value[i], OLD_VALUE, i);
                        allocate(new_value[i], NEW_VALUE, i);
                        allocate(sibling[i], SIBLING, i);
                        allocate(segment[i], SEGMENT_TYPE, i);
                        allocate(depth[i], DEPTH, i);
                        allocate(direction[i], DIRECTION, i);
                        allocate(address[i], ADDRESS, i);
                        allocate(proof_type[i], PROOF_TYPE, i);
                        allocate(key[i], KEY, i);
                        allocate(other_key[i], OTHER_KEY, i);
                        allocate(path_type[i], PATH_TYPE, i);
                        allocate(old_nonce_chunks[i], OLD_NONCE_CHUNKS, i);
                        allocate(new_nonce_chunks[i], NEW_NONCE_CHUNKS, i);
                        allocate(code_size_chunks[i], CODE_SIZE_CHUNKS, i);
                        allocate(q_leaf0[i], Q_LEAF0, i);
                        allocate(q_leaf123[i], Q_LEAF123, i);
                        allocate(q_start[i], Q_START, i);
                        allocate(q_trie[i], Q_TRIE, i);
                        allocate(q_leaf1[i], Q_LEAF1, i);
                        allocate(q_leaf2[i], Q_LEAF2, i);
                        allocate(q_leaf3[i], Q_LEAF3, i);
                        allocate(q_last[i], Q_LAST, i);
                        allocate(is_padding[i], IS_PADDING, i);
                        allocate(old_Y[i], OLD_Y, i);
                        allocate(old_YI[i], OLD_YI, i);
                        allocate(old_C[i], OLD_C, i);
                        allocate(new_Y[i], NEW_Y, i);
                        allocate(new_YI[i], NEW_YI, i);
                        allocate(new_C[i], NEW_C, i);
                        allocate(code_Y[i], CODE_Y, i);
                        allocate(code_YI[i], CODE_YI, i);
                        allocate(code_C[i], CODE_C, i);
                    }

                    if constexpr( stage == GenerationStage::CONSTRAINTS ){
                        std::cout << "MPT circuit " << std::endl;
                        std::vector<TYPE> every;

                        // 1. Shared Constraints: 1.1. for segment_type == account_trie = 1
                        every.push_back(context_object.relativize(segment[0]*(1 - segment[0])*(2 - segment[0])*(3 - segment[0])*(4 - segment[0])*(5 - segment[0]), 0));
                        every.push_back(context_object.relativize(is_padding[1]*(2 - segment[1])*(3 - segment[1])*(4 - segment[1])*(5 - segment[1])*(depth[1] - depth[0] - 1), -1));
                        every.push_back(context_object.relativize(direction[0] * (1 - direction[0]), 0));
                        every.push_back(context_object.relativize(segment[0]*(2 - segment[0])*(3 - segment[0])*(4 - segment[0])*(5 - segment[0])*(key[0] - direction[0]), 0));
                        every.push_back(context_object.relativize(segment[0]*(2 - segment[0])*(3 - segment[0])*(4 - segment[0])*(5 - segment[0])*(other_key[0] - direction[0]), 0));

                        // 1. Shared Constraints: 1.2. for segment_type != account_trie != 1
                        every.push_back(context_object.relativize(segment[0]*(1 - segment[0])*depth[0], 0));
                        every.push_back(context_object.relativize(segment[0]*(1 - segment[0])*key[0], 0));
                        every.push_back(context_object.relativize(segment[0]*(1 - segment[0])*other_key[0], 0));

                        // 3. Constraints for mpt_proof_type = nonce_changed = 1: 3.1. segment type transisions
                        every.push_back(context_object.relativize(q_leaf0[0]*(1 - q_leaf0[0]), 0));
                        every.push_back(context_object.relativize(q_leaf1[0]*(1 - q_leaf1[0]), 0));
                        every.push_back(context_object.relativize(q_leaf2[0]*(1 - q_leaf2[0]), 0));
                        every.push_back(context_object.relativize(q_leaf3[0]*(1 - q_leaf3[0]), 0));
                        every.push_back(context_object.relativize(q_start[0]*(1 - q_start[0]), 0));
                        every.push_back(context_object.relativize(q_trie[0]*(1 - q_trie[0]), 0));
                        every.push_back(context_object.relativize(q_leaf123[0]*(1 - q_leaf123[0]), 0));
                        every.push_back(context_object.relativize(q_start[0]*segment[1]*(1 - segment[1])*(2 - segment[1]), 0)); // should it be 0 or +1 here?
                        every.push_back(context_object.relativize(q_trie[0]*segment[1]*(1 - segment[1])*(2 - segment[1]), 0));
                        every.push_back(context_object.relativize(q_leaf0[0]*segment[1]*(3 - segment[1]), 0));
                        every.push_back(context_object.relativize(q_leaf1[0]*segment[1]*(4 - segment[1]), 0)); 
                        every.push_back(context_object.relativize(q_leaf2[0]*(5 - segment[1]), 0)); 
                        every.push_back(context_object.relativize(segment[0]*(1 - segment[0])*(2 - segment[0])*(3 - segment[0])*(4 - segment[0])*segment[1], 0)); 

                        // 3. Constraints for mpt_proof_type = nonce_changed = 1: 3.2. constraints for segment types
                        every.push_back(context_object.relativize(q_leaf0[0]*(direction[0] - 1), 0));
                        every.push_back(context_object.relativize(q_leaf123[0]*direction[0], 0));

                        // 3. Constraints for mpt_proof_type = nonce_changed = 1: 3.3. constraints for old_nonce, new_nonce, code_size
                        // - Range check components for old_nonce, new_nonce, code_size: range_check_multi components added in the generate_circuit function
                        every.push_back(context_object.relativize(old_C[0], 0));
                        every.push_back(context_object.relativize(new_C[0], 0));
                        every.push_back(context_object.relativize(code_C[0], 0));
                        // - verify that code_size in old_account and new_account are equal
                        every.push_back(context_object.relativize(q_last[0]*(1 - q_last[0]), 0));
                        every.push_back(context_object.relativize(q_last[0]*(old_hash[0] - old_value[0] * B - new_hash[0] + new_value[0] * B), 0));

                        for( std::size_t i = 0; i < every.size(); i++ ){
                            context_object.relative_constrain(every[i], 0, max_mpt - 1);
                        }

                        // // range check constraints
                        // for( std::size_t i = 0; i < 4; i++ ){
                        //     constrain(old_C[i]);
                        //     constrain(new_C[i]);
                        //     constrain(code_C[i]);
                        // }

                        // Alternative representation of constraints
                        for(std::size_t i = 0; i < max_mpt - 1; i++) {
                            constrain(q_start[i]*segment[i]*(1 - segment[i + 1])*(2 - segment[i + 1]));
                            constrain(q_trie[i]*segment[i]*(1 - segment[i + 1])*(2 - segment[i + 1]));
                            constrain(q_leaf0[i]*segment[i + 1]*(3 - segment[i + 1]));
                            constrain(q_leaf1[i]*segment[i + 1]*(4 - segment[i + 1]));
                            constrain(q_leaf2[i]*(5 - segment[i + 1]));
                            constrain(segment[i]*(1 - segment[i])*(2 - segment[i])*(3 - segment[i])*(4 - segment[i])*segment[i + 1]);
                        }

                        for(std::size_t i = 1; i < max_mpt; i++) {
                            constrain(is_padding[i]*(2 - segment[i])*(3 - segment[i])*(4 - segment[i])*(5 - segment[i])*(depth[i] - depth[i - 1] - 1));
                        }

                        for(std::size_t i = 0; i < max_mpt; i++) {
                            constrain(segment[i]*(2 - segment[i])*(3 - segment[i])*(4 - segment[i])*(5 - segment[i])*(key[i] - direction[i]));
                            constrain(segment[i]*(2 - segment[i])*(3 - segment[i])*(4 - segment[i])*(5 - segment[i])*(other_key[i] - direction[i]));
                        }
                    }

                    for(std::size_t i = 0; i < account_trie_length - 1; i++) {
                        copy_constrain(old_value[i], old_hash[i + 1]);
                        copy_constrain(new_value[i], new_hash[i + 1]);
                        copy_constrain(address[i], address[i + 1]);
                        copy_constrain(proof_type[i], proof_type[i + 1]);
                    }
                    // for(std::size_t i = 0; i < 4; i++) {
                    //     copy_constrain(X[i], old_nonce_chunks[i]);
                    // }

                    // for(std::size_t i = 0; i < 20; i++) {
                    //     constrain(proof[i] - trace[i]);
                    //     constrain(proof[i] + trace[i] - 2*proof[i]);
                    // }

                    // for(std::size_t i = 0; i < 19; i++) {
                    //     constrain(proof[i] - proof[i + 1]);
                    // }
                }
            };
        }
    }
}