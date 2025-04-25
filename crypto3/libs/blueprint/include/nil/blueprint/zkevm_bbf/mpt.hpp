//---------------------------------------------------------------------------//
// Copyright (c) 2025 Alexey Yashunsky <a.yashunsky@nil.foundation>
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
#pragma once

#include <nil/crypto3/bench/scoped_profiler.hpp>
#include <nil/crypto3/zk/snark/arithmetization/plonk/constraint_system.hpp>
#include <nil/blueprint/zkevm_bbf/types/hashed_buffers.hpp>

#include <nil/blueprint/blueprint/plonk/assignment.hpp>
#include <nil/blueprint/blueprint/plonk/circuit.hpp>
#include <nil/blueprint/component.hpp>

#include <nil/blueprint/bbf/generic.hpp>
#include <nil/blueprint/zkevm_bbf/util.hpp>
#include <nil/blueprint/zkevm_bbf/subcomponents/rlp_table.hpp>
#include <nil/blueprint/zkevm_bbf/subcomponents/keccak_table.hpp>

namespace nil::blueprint::bbf {

    enum mpt_node_type { EXTENSION = 0, BRANCH = 1, LEAF = 2 };

    struct mpt_node {
        enum mpt_node_type type;
        std::vector<std::vector<zkevm_word_type>> value;
    };

    struct mpt_path {
        zkevm_word_type slotNumber;  // TODO change this
        std::vector<mpt_node> proof;
    };

    template<typename FieldType, GenerationStage stage>
    class mpt : public generic_component<FieldType, stage> {
        using typename generic_component<FieldType, stage>::context_type;
        using RLPTable = typename bbf::rlp_table<FieldType, stage>;
        using KeccakTable = typename bbf::keccak_table<FieldType, stage>;
        using generic_component<FieldType, stage>::allocate;
        using generic_component<FieldType, stage>::copy_constrain;
        using generic_component<FieldType, stage>::constrain;
        using generic_component<FieldType, stage>::lookup;
        using generic_component<FieldType, stage>::lookup_table;

      public:
        using typename generic_component<FieldType, stage>::table_params;
        using typename generic_component<FieldType, stage>::TYPE;

        struct input_type {
            std::vector<mpt_path> paths;
            TYPE rlc_challenge;
        };

        // using input_type =
        //     typename std::conditional<stage == GenerationStage::ASSIGNMENT,
        //                                 _input_type, std::nullptr_t>::type;

        using value = typename FieldType::value_type;
        using integral_type = nil::crypto3::multiprecision::big_uint<257>;

        static table_params get_minimal_requirements(std::size_t max_mpt_size) {
            return {
                    .witnesses = 1452,
                    .public_inputs = 0,
                    .constants = 0,
                    .rows = max_mpt_size + 2178};
        }

        static void allocate_public_inputs(context_type &context, input_type &input,
                                           std::size_t max_mpt_size) {}

        struct leaf_rlp_data{
            std::vector<std::array<std::array<TYPE, 110>, 2>> data;
            std::vector<std::array<std::array<TYPE, 110>, 2>> index;
            std::vector<std::array<std::array<TYPE, 110>, 2>> index_is_last_I;
            std::vector<std::array<std::array<TYPE, 110>, 2>> index_is_last_R;
            std::vector<std::array<std::array<TYPE, 110>, 2>> is_last;
            std::vector<std::array<std::array<TYPE, 110>, 2>> rlc;
            std::vector<std::array<std::array<TYPE, 2>,   2>> prefix;
            std::vector<std::array<std::array<TYPE, 2>,   2>> prefix_index;
            std::vector<std::array<std::array<TYPE, 2>,   2>> prefix_rlc;
            std::vector<std::array<TYPE, 2>> second_prefix_is_last;
            // lengths without considering rlp prefixes
            std::vector<std::array<TYPE, 2>> len_low;
            std::vector<std::array<TYPE, 2>> len_high;
            // first element flag for rlp lookup
            std::vector<std::array<TYPE, 2>> first_element_flag;
            std::vector<std::array<TYPE, 2>> first_element;
        };

        struct node_rlp_data {
            std::vector<std::array<TYPE, 3>> prefix;
            std::vector<std::array<TYPE, 3>> prefix_rlc;
            // the first rlp prefix is not last and its hash and index is known
            std::vector<TYPE> second_prefix_is_last;
            std::vector<TYPE> third_prefix_is_last;
            std::vector<std::array<TYPE, 2>> prefix_index;
            std::vector<TYPE> len_low;
            std::vector<TYPE> len_high;
            std::vector<TYPE> hash_low;
            std::vector<TYPE> hash_high;

        };

        void initialize_node_rlp_data(node_rlp_data &node, std::size_t max_mpt_size) {
            node.prefix.resize(max_mpt_size);
            node.second_prefix_is_last.resize(max_mpt_size);
            node.third_prefix_is_last.resize(max_mpt_size);
            node.prefix_index.resize(max_mpt_size);
            node.prefix_rlc.resize(max_mpt_size);
            node.len_low.resize(max_mpt_size);
            node.len_high.resize(max_mpt_size);
            node.hash_low.resize(max_mpt_size);
            node.hash_high.resize(max_mpt_size);
        }

        void initialize_leaf_rlp_data(leaf_rlp_data &leaf, std::size_t max_mpt_size ) {
            leaf.data.resize(max_mpt_size);
            leaf.index.resize(max_mpt_size);
            leaf.rlc.resize(max_mpt_size);
            leaf.index_is_last_I.resize(max_mpt_size);
            leaf.index_is_last_R.resize(max_mpt_size);
            leaf.is_last.resize(max_mpt_size);
            leaf.prefix.resize(max_mpt_size);
            leaf.prefix_index.resize(max_mpt_size);
            leaf.prefix_rlc.resize(max_mpt_size);
            leaf.second_prefix_is_last.resize(max_mpt_size);
            leaf.len_low.resize(max_mpt_size);
            leaf.len_high.resize(max_mpt_size);
            leaf.first_element_flag.resize(max_mpt_size);
            leaf.first_element.resize(max_mpt_size);
        }

        mpt(context_type &context_object, const input_type &input,
            std::size_t max_mpt_size)
            : generic_component<FieldType, stage>(context_object) {

            std::vector<std::size_t> keccak_lookup_area;
            std::vector<std::size_t> rlp_lookup_area;
            std::vector<std::array<TYPE, 32>> parent_hash(max_mpt_size);
            std::vector<std::array<TYPE, 32>> key_part(max_mpt_size);
            std::vector<TYPE> key_length(max_mpt_size);
            std::vector<TYPE> node_type(max_mpt_size);
            std::vector<TYPE> node_type_inv_2(max_mpt_size);
            std::vector<TYPE> r(max_mpt_size);
            std::vector<TYPE> depth(max_mpt_size);
            std::vector<std::array<TYPE, 32>> key(max_mpt_size);
            std::size_t node_num = 0;
            typename KeccakTable::private_input_type keccak_buffers;

            std::array<std::vector<std::array<TYPE, 110>>, 16> child;
            leaf_rlp_data leaf;
            node_rlp_data node;
            // TYPE rlc_challenge = 53;


            for (std::size_t i = 0; i < 16; i++) {
                child[i].resize(max_mpt_size);
            }
            initialize_leaf_rlp_data(leaf, max_mpt_size);
            initialize_node_rlp_data(node, max_mpt_size);
            
            if constexpr (stage == GenerationStage::ASSIGNMENT) {
                for (std::size_t i = 0; i < max_mpt_size; i++) {
                    for (size_t j = 0; j < 2; j++) {
                        leaf.first_element_flag[i][j] = 0;
                        for (size_t k = 0; k < 110; k++) {
                            leaf.is_last[i][j][k] = 1;
                        }
                    }
                }
                for (size_t i = 0; i < max_mpt_size; i++) {
                    node.second_prefix_is_last[i] = 1;
                    for (size_t j = 0; j < 2; j++)
                    {
                        leaf.second_prefix_is_last[i][j] = 1;
                    }
                }

                // assignment
                for (auto &p : input.paths) {  // enumerate paths
                    std::cout << "slot number = " << std::hex << p.slotNumber << std::dec
                              << std::endl;

                    //    std::array<uint8_t,64> slotNumber = w_to_4(p.slotNumber);
                    std::array<uint8_t, 32> slotNumber = w_to_8(p.slotNumber);
                    std::vector<uint8_t> buffer(slotNumber.begin(), slotNumber.end());
                    zkevm_word_type path_key = nil::blueprint::zkevm_keccak_hash(buffer);
                    std::cout << "path key = " << std::hex << path_key << std::dec
                              << std::endl;

                    zkevm_word_type key_suffix = path_key;
                    std::size_t accumulated_length = 0;
                    //    std::size_t node_depth = 0;
                    //    zkevm_word_type parent_hash = 0;
                    for (auto &n : p.proof) {
                        
                        std::cout << "node type = " << n.type << std::endl;
                        std::cout << "[" << std::endl;
                        std::size_t node_key_length = 0;
                            //    parent_hash[node_num] = w_to_4(parent_hash);
                            //    parent_hash_1[node_num] = w_hi<FieldType>(parent_hash);
                            if (n.type != BRANCH) {
                                zkevm_word_type k0;
                                if (n.value.at(0)[0] > 0x0F) {
                                    k0 = n.value.at(0)[0] >> 4;
                                    node_key_length++;
                                }
                                for (size_t i = 1; i < n.value.at(0).size(); i++) {
                                    node_key_length += 2;
                                }
                                if ((k0 == 1) || (k0 == 3)) {
                                    node_key_length--;  // then we only skip the first hex
                                                        // symbol
                                } else {
                                    node_key_length -= 2;  // otherwise, the second hex is 0
                                                        // and we skip it too
                                }
                        }
                        else {
                            node_key_length = 1;
                        }
                        key_length[node_num] = node_key_length;
                        std::cout << "Node key length = " << node_key_length << std::endl;

                        accumulated_length += node_key_length;
                        std::cout << "Accumulated length = " << accumulated_length
                                  << std::endl;

                        zkevm_word_type node_key_part =
                            key_suffix >> 4 * (64 - accumulated_length);
                        auto words = w_8(
                            node_key_part);  // we expect it to fit into one field element
                                             // always! TODO we need to fix this. In a
                                             // newly generated tree root is a leaf node
                        for (size_t i = 0; i < 32; i++) {
                            key_part[node_num][i] = zkevm_word_type(words[i]);
                        }

                        std::cout << "Node key part = " << std::hex << node_key_part
                                  << std::dec << std::endl;
                        key_suffix &=
                            (zkevm_word_type(1) << 4 * (64 - accumulated_length)) - 1;
                        std::cout << "key suffix: " << std::hex << key_suffix << std::dec
                                  << std::endl;

                        node_type[node_num] = static_cast<size_t>(n.type);
                        if (node_type[node_num] != 2) {
                            node_type_inv_2[node_num] =
                                (2 - node_type[node_num]).inversed();
                        } else {
                            node_type_inv_2[node_num] = 1;
                        }
                        r[node_num] =
                            1 - (2 - node_type[node_num]) * node_type_inv_2[node_num];
                        words = w_8(path_key);
                        for (size_t i = 0; i < 32; i++) {
                            key[node_num][i] = zkevm_word_type(words[i]);
                        }


                        std::size_t child_num = 0;
                        for (auto &v : n.value) {
                            std::cout <<"    value = ";
                            if (child_num < 16) {  // branch nodes have an empty 17-th value
                                for (size_t i = 0; i < v.size(); i++) {
                                    if (v[i] <= 0x0F)
                                        std::cout <<"0" << std::hex << v[i] << std::dec;
                                    else
                                        std::cout << std::hex << v[i] << std::dec;
                                    if (n.type == LEAF) {
                                        leaf.data[node_num][child_num][i] = v[i];
                                        leaf.is_last[node_num][child_num][i] = 0;
                                    } else if (n.type == BRANCH) {
                                        child[child_num][node_num][i] = v[i];
                                    }
                                }
                                if (n.type == LEAF) {
                                    if (v.size() > 0) {
                                        leaf.is_last[node_num][child_num][v.size() - 1] = 1;
                                    }
                                    if (v.size() == 0 || (v.size() == 1 && v[0] < 128)) {
                                        if (v.size() == 1)
                                            leaf.first_element[node_num][child_num] = v[0];
                                        else
                                            leaf.first_element[node_num][child_num] = 0;
                                        leaf.first_element_flag[node_num][child_num] = 1;
                                    }
                                    std::cout << " size: " << v.size();
                                }
                            }
                            child_num++;
                            std::cout << std::endl;
                        }
                        std::cout << "]" << std::endl;

                        if (n.type == LEAF) {
                            std::vector<zkevm_word_type> key = n.value.at(0);
                            std::vector<zkevm_word_type> value = n.value.at(1);
                            std::size_t total_length = get_leaf_key_length(key) + get_leaf_key_length(value);
                            std::size_t rlp_encoding_index;
                            std::vector<std::uint8_t> hash_input(532);
                            TYPE rlc_accumulator;
                            encode_node_data(node_num, node, total_length, rlp_encoding_index, hash_input, rlc_accumulator, input.rlc_challenge);
                            encode_leaf_data(node_num, leaf, key, value, rlp_encoding_index, hash_input, rlc_accumulator, input.rlc_challenge);
                            zkevm_word_type hash = calculate_keccak(hash_input, rlp_encoding_index);
                            std::cout << "node hash: " << std::hex << hash << std::dec << std::endl;
                            std::cout << "rlc: " << rlc_accumulator<< std::endl;
                            std::vector<uint8_t> buffer(hash_input.begin(), hash_input.begin() + rlp_encoding_index);
                            keccak_buffers.new_buffer(buffer);
                            store_node_hash(node_num, node, hash);
                            print_leaf_node(node_num, node, leaf,
                                hash,
                                key.size(),
                                value.size()
                            );
                            std::cout << "innnn " << 
                            std::hex << node.hash_high[node_num] + 1 - 1 << std::dec << " "
                            << 
                            std::hex << node.hash_low[node_num] + 1 - 1 << std::dec << " "
                            <<
                    leaf.rlc[node_num][1][109]
                             << std::endl;
                        }
                        node_num++;
                        //    node_depth++;
                    }
                }
            }

            // allocation
            for (std::size_t i = 0; i < max_mpt_size; i++) {
                size_t column_index = 0;
                for (std::size_t j = 0; j < 32; j++) {
                    allocate(parent_hash[i][column_index++], j, i);
                }

                for (std::size_t j = 0; j < 32; j++) {
                    allocate(key_part[i][j], column_index++, i);
                }
                allocate(key_length[i], column_index++, i);
                allocate(node_type[i], column_index++, i);
                for (std::size_t j = 0; j < 32; j++) {
                    allocate(key[i][j], column_index++, i);
                }
                allocate(node_type_inv_2[i], column_index++, i);
                allocate(r[i], column_index++, i);

                // node
                
                // rlp len
                allocate(node.len_low[i], column_index ++, i);
                allocate(node.len_high[i], column_index ++, i);
                allocate(node.hash_low[i], column_index ++, i);
                allocate(node.hash_high[i], column_index ++, i);
                // prefix
                allocate(node.prefix[i][0], column_index ++, i);
                allocate(node.prefix_rlc[i][0], column_index ++, i);
                allocate(node.second_prefix_is_last[i], column_index ++, i);
                allocate(node.third_prefix_is_last[i], column_index ++, i);
                allocate(node.prefix[i][1], column_index ++, i);
                allocate(node.prefix_rlc[i][1], column_index ++, i);
                allocate(node.prefix_index[i][0], column_index ++, i);
                allocate(node.prefix[i][2], column_index ++, i);
                allocate(node.prefix_rlc[i][2], column_index ++, i);
                allocate(node.prefix_index[i][1], column_index ++, i);

                // children
                for (std::size_t j = 0; j < 2; j++) {
                    // rlp len
                    allocate(leaf.len_low[i][j], column_index ++, i);
                    allocate(leaf.len_high[i][j], column_index ++, i);
                    // prefix
                    allocate(leaf.prefix[i][j][0], column_index++, i);
                    allocate(leaf.prefix_rlc[i][j][0], column_index++, i);
                    allocate(leaf.prefix_index[i][j][0], column_index++, i);
                    allocate(leaf.prefix[i][j][1], column_index++, i);
                    allocate(leaf.prefix_rlc[i][j][1], column_index++, i);
                    allocate(leaf.prefix_index[i][j][1], column_index++, i);
                    allocate(leaf.second_prefix_is_last[i][j], column_index++, i);

                    // encoding
                    for (std::size_t k = 0; k < 110; k++) {
                        allocate(leaf.data[i][j][k], column_index++, i);
                        allocate(leaf.rlc[i][j][k], column_index++, i);
                        allocate(leaf.is_last[i][j][k], column_index++, i);
                        allocate(leaf.index[i][j][k], column_index++, i);
                        allocate(leaf.index_is_last_I[i][j][k], column_index++, i);
                        allocate(leaf.index_is_last_R[i][j][k], column_index++, i);
                    }
                }

            }


            for (std::size_t i = 0; i < RLPTable::get_witness_amount(); i++) {
                rlp_lookup_area.push_back(i);
            }
            context_type rlp_ct = context_object.subcontext(rlp_lookup_area, 5, 2178);
            RLPTable rlpt = RLPTable(rlp_ct);

            for( std::size_t i = 0; i < KeccakTable::get_witness_amount(); i++){
                keccak_lookup_area.push_back(i);
            }
            context_type keccak_ct = context_object.subcontext( keccak_lookup_area, 2178+5, 1 + 1);
            KeccakTable k_t = KeccakTable(keccak_ct, {input.rlc_challenge, keccak_buffers}, 1);

            if constexpr (stage == GenerationStage::CONSTRAINTS) {
                for (size_t i = 0; i < max_mpt_size; i++) {
                    constrain(node_type[i] * (1 - node_type[i]) * (2 - node_type[i]));
                    // r[i] = 1 -> node is leaf (type 2)
                    // constrain((2 - node_type[i]) * r[i]);
                    // node.encoded[i][0] if [0xc0, 0xf7] 
                    // constrain(r[i] * (32 - node.encoded[i][3]) *
                    //           (48 - node.encoded[i][3]));  // change this to
                                                                // first-nibble isntead
                }

                std::size_t leaf_num = 4;

                std::size_t leaf_data_size = leaf.data[leaf_num][0].size();

                std::vector<TYPE> node_rlp_lookup = {
                    node.prefix[leaf_num][0], 
                    node.prefix[leaf_num][1],
                    node.prefix[leaf_num][2],
                    0,
                    0,
                    0,
                    node.len_low[leaf_num], 
                    node.len_high[leaf_num],
                    node.second_prefix_is_last[leaf_num],
                    node.third_prefix_is_last[leaf_num]
                };

                std::vector<TYPE> key_rlp_lookup = {
                    leaf.prefix[leaf_num][0][0],
                    leaf.prefix[leaf_num][0][1],
                    0,
                    leaf.first_element[leaf_num][0],
                    leaf.first_element_flag[leaf_num][0],
                    1,
                    leaf.len_low[leaf_num][0], 
                    leaf.len_high[leaf_num][0],
                    // 1,
                    leaf.second_prefix_is_last[leaf_num][0],
                    1
                };

                std::vector<TYPE> value_rlp_lookup = {
                    leaf.prefix[leaf_num][1][0],
                    leaf.prefix[leaf_num][1][1],
                    0,
                    leaf.first_element[leaf_num][1],
                    leaf.first_element_flag[leaf_num][1],
                    1,
                    leaf.len_low[leaf_num][1], 
                    leaf.len_high[leaf_num][1],
                    leaf.second_prefix_is_last[leaf_num][1],
                    1
                };

                std::vector<TYPE> keccak_lookup = {
                    1,
                    leaf.rlc[leaf_num][1][leaf_data_size-1],
                    node.hash_high[leaf_num],
                    node.hash_low[leaf_num]
                };
                lookup(node_rlp_lookup, "rlp_table");
                lookup(key_rlp_lookup, "rlp_table");
                lookup(value_rlp_lookup, "rlp_table");
                lookup(keccak_lookup, "keccak_table");
                constrain(node.second_prefix_is_last[leaf_num]*(1 - node.second_prefix_is_last[leaf_num]));
                constrain(node.prefix[leaf_num][1] * node.second_prefix_is_last[leaf_num]);
                constrain(node.prefix[leaf_num][2] * node.third_prefix_is_last[leaf_num]);
                constrain(leaf.second_prefix_is_last[leaf_num][1] * (1 - leaf.second_prefix_is_last[leaf_num][1]));
                constrain(leaf.second_prefix_is_last[leaf_num][0] * (1 - leaf.second_prefix_is_last[leaf_num][0]));
                constrain(node.prefix_rlc[leaf_num][0] - 
/* total length */      ((1 + 1 - node.second_prefix_is_last[leaf_num] + 1 - node.third_prefix_is_last[leaf_num] + node.len_low[leaf_num] + 0x100 * node.len_high[leaf_num])
                        * 53 + node.prefix[leaf_num][0]));

                constrain(node.prefix_rlc[leaf_num][1] - ((1 - node.second_prefix_is_last[leaf_num]) * (node.prefix_rlc[leaf_num][0] * 53 + node.prefix[leaf_num][1]) + node.second_prefix_is_last[leaf_num] * node.prefix_rlc[leaf_num][0]));
                constrain(node.prefix_rlc[leaf_num][2] - ((1 - node.third_prefix_is_last[leaf_num]) *  (node.prefix_rlc[leaf_num][1] * 53 + node.prefix[leaf_num][2]) + node.third_prefix_is_last[leaf_num] * node.prefix_rlc[leaf_num][1]));

                constrain(-(node.len_low[leaf_num] + 0x100 * node.len_high[leaf_num])
                          + leaf.len_low[leaf_num][0] + 0x100 * leaf.len_high[leaf_num][0] 
                          + leaf.len_low[leaf_num][1] + 0x100 * leaf.len_high[leaf_num][1] 
                          + 3 - leaf.second_prefix_is_last[leaf_num][1]);

                // node first rlp prefix is always keccak 0 index
                constrain(node.prefix_index[leaf_num][0] - (1 - node.second_prefix_is_last[leaf_num]));
                constrain(node.prefix_index[leaf_num][1] * node.third_prefix_is_last[leaf_num] + (2-node.prefix_index[leaf_num][1])*(1-node.third_prefix_is_last[leaf_num]));
                for (size_t k = 0; k < 2; k++) {
                    if (k == 0) {
                        constrain(leaf.prefix_index[leaf_num][k][0] - 1 - (1 - node.second_prefix_is_last[leaf_num]) + (1 - node.third_prefix_is_last[leaf_num]));
                        constrain(leaf.prefix_rlc[leaf_num][k][0] - (node.prefix_rlc[leaf_num][2] * 53 + leaf.prefix[leaf_num][0][0]));
                    } else {
                        constrain(leaf.prefix_index[leaf_num][k][0] - 
                            (leaf.len_low[leaf_num][k-1] + leaf.len_high[leaf_num][k-1] * 0x100 + leaf.prefix_index[leaf_num][k-1][0] + 1 - leaf.second_prefix_is_last[leaf_num][k-1] + 1));
                        constrain(leaf.prefix_rlc[leaf_num][k][0] - (leaf.rlc[leaf_num][k-1][leaf_data_size-1] * 53 + leaf.prefix[leaf_num][k][0]));
                    }
                    constrain(leaf.prefix_index[leaf_num][k][1] - (1 - leaf.second_prefix_is_last[leaf_num][k]) * (leaf.prefix_index[leaf_num][k][0] + 1));
                    constrain(leaf.prefix_rlc[leaf_num][k][1] - ((1 - leaf.second_prefix_is_last[leaf_num][k]) * (leaf.prefix_rlc[leaf_num][k][0] * 53 + leaf.prefix[leaf_num][k][1]) + leaf.second_prefix_is_last[leaf_num][k] * leaf.prefix_rlc[leaf_num][k][0]));
                    constrain(leaf.index[leaf_num][k][0] - (1 - leaf.second_prefix_is_last[leaf_num][k]) - leaf.prefix_index[leaf_num][k][0] - 1);
                    constrain(leaf.rlc[leaf_num][k][0] - (leaf.prefix_rlc[leaf_num][k][1] * 53 + leaf.data[leaf_num][k][0]));

                    constrain(leaf.data[leaf_num][k][0] * leaf.is_last[leaf_num][k][0]);
                    for (size_t i = 1; i < leaf_data_size; i++) {
                        constrain((1 - leaf.is_last[leaf_num][k][i]) * leaf.is_last[leaf_num][k][i]);
    
                        constrain((1 - leaf.is_last[leaf_num][k][i]) * leaf.is_last[leaf_num][k][i-1]);
                        constrain(leaf.index_is_last_R[leaf_num][k][i] - (1 - 
                            leaf.index_is_last_I[leaf_num][k][i] * ((leaf.len_low[leaf_num][k] + leaf.len_high[leaf_num][k] * 0x100) - (leaf.index[leaf_num][k][i] - leaf.index[leaf_num][k][0] + 1))));
                        constrain(((leaf.len_low[leaf_num][k] + leaf.len_high[leaf_num][k] * 0x100) - (leaf.index[leaf_num][k][i] - leaf.index[leaf_num][k][0] + 1)) * leaf.index_is_last_R[leaf_num][k][i]);
                        constrain(leaf.is_last[leaf_num][k][i] - leaf.index_is_last_R[leaf_num][k][i] - leaf.is_last[leaf_num][k][i-1]);
                        constrain(leaf.index[leaf_num][k][i] * leaf.is_last[leaf_num][k][i-1]);
                        constrain((leaf.index[leaf_num][k][i] - leaf.index[leaf_num][k][i-1] - 1) * (1 - leaf.is_last[leaf_num][k][i-1]));
                        constrain(leaf.data[leaf_num][k][i] * leaf.is_last[leaf_num][k][i-1]);
                        constrain(leaf.rlc[leaf_num][k][i] - (leaf.is_last[leaf_num][k][i-1] * leaf.rlc[leaf_num][k][i-1] + (1 - leaf.is_last[leaf_num][k][i-1]) * (leaf.rlc[leaf_num][k][i-1] * 53 + leaf.data[leaf_num][k][i])));
                    }
                }

                // constrain(child_prefix_index[4][0][1] - (1 - child_second_prefix_is_last[4][0])*(child_prefix_index[4][0][0] + 1));
                // constrain(child_index[0][4][0] - (1 - child_second_prefix_is_last[4][0]) - child_prefix_index[4][0][0] - 1);
                // for (size_t i = 1; i < 110; i++) {
                //     constrain((1 - child_is_last[0][4][i]) * child_is_last[0][4][i]);

                //     constrain((1 - child_is_last[0][4][i]) * child_is_last[0][4][i-1]);
                //     constrain(child_index_is_last_R[0][4][i] - (1 - 
                //         child_index_is_last_I[0][4][i] * ((child_len_low[4][0] + child_len_high[4][0] * 0x100) - (child_index[0][4][i] - child_index[0][4][0] + 1))));
                //     constrain(((child_len_low[4][0] + child_len_high[4][0] * 0x100) - (child_index[0][4][i] - child_index[0][4][0] + 1))*child_index_is_last_R[0][4][i]);
                //     constrain(child_is_last[0][4][i] - child_index_is_last_R[0][4][i] - child_is_last[0][4][i-1]);
                //     constrain(child_index[0][4][i] * child_is_last[0][4][i-1]);
                //     constrain((child_index[0][4][i] - child_index[0][4][i-1] - 1) * (1 - child_is_last[0][4][i-1]));
                // }

                  


                // tmp = {node_rlp_encoded[4][0], node_rlp_encoded[4][1], node_len_low[4], node_len_high[4]};
                // constraints
                //    for (size_t i = 0; i < max_mpt_size; i++) {
                //     for(std::size_t j = 0; j < 16; j++) {
                //         for(std::size_t k = 0; k < 64; k++) {
                //             std::cout << std::hex <<  child[j][i][k] << std::dec;
                //         }
                //         std::cout << std::endl;
                //     }
                //     std::cout << "new" << std::endl;
                // }
                // for (size_t i = 0; i < max_mpt_size; i++)
                // {
                //     constrain(node_type[i] * (node_type[i] - 1) * (node_type[i] - 2));
                //     // TYPE R = (node_type[i]-1) * (node_type[i] - 2);
                //     for(std::size_t j = 0; j < 16; j++) {
                //         for(std::size_t k = 0; k < 64; k++) {
                //             if (k == 0){
                //                 constrain(child[j][i][1] = !is_zero(child[j][i][0]));
                //             } else {
                //                 constrain(child[j][i][2*k+1] = child[j][i][2*k-1] + (1
                //                 - child[j][i][2*k-1] * is_zero(child[j][i][2*k]) ));
                //             }
                //             constrain(child[j][i][2*k]*(1 - child[j][i][2*k]));
                //         }
                //         // allocate(child_0[j][i], 6 + 2*j,i);
                //         // allocate(child_1[j][i], 6 + 2*j + 1,i);
                //     }
            }
        }

        size_t get_rlp_encoded_length(TYPE first_byte, size_t length) {
            size_t rlp_encoded_length;
            BOOST_ASSERT_MSG(length <= 110, "None of our supported byte arrays should go beyond this number yet!");
            if (length == 1 && first_byte <= 0x7F) {
                rlp_encoded_length = length;
            } else if (length <= 55) {
                rlp_encoded_length = length + 1;
            } else {
                rlp_encoded_length = length + 2;
            }
            return rlp_encoded_length;
        }
        
        std::size_t get_leaf_key_length(std::vector<zkevm_word_type> key) {
            TYPE key_first_byte = key[0];
            size_t key_length = key.size();
            BOOST_ASSERT_MSG(key_length <= 32, "leaf node key length exceeded!");
            return get_rlp_encoded_length(key_first_byte, key_length);
        }
        
        std::size_t get_leaf_value_length(std::vector<zkevm_word_type> value) {
            TYPE value_first_byte = value[0];
            size_t value_length = value.size();
            BOOST_ASSERT_MSG(value_length <= 110, "leaf node value length exceeded!");
            return get_rlp_encoded_length(value_first_byte, value_length);
        }

        void encode_node_data(std::size_t node_num, node_rlp_data &node, std::size_t total_length, std::size_t &rlp_encoding_index, std::vector<std::uint8_t> &hash_input, TYPE &rlc_accumulator, TYPE rlc_challenge) {
            rlp_encoding_index = 0;
            if (total_length > 55) {
                std::size_t length_length = 0;
                std::size_t temp = total_length;

                while(temp > 0) {
                    temp >>= 8;
                    length_length ++;
                }
                node.prefix[node_num][0] = 0xF7 + length_length;
                node.prefix[node_num][1] = total_length;
                node.prefix[node_num][2] = 0;
                node.prefix_index[node_num][0] = rlp_encoding_index+1;

                node.second_prefix_is_last[node_num] = 0;
                node.third_prefix_is_last[node_num] = 1;

                hash_input[rlp_encoding_index++] = 0xF7 + length_length;
                hash_input[rlp_encoding_index++] = total_length;

                node.prefix_rlc[node_num][0] = (total_length+2) * rlc_challenge + node.prefix[node_num][0];
                rlc_accumulator = node.prefix_rlc[node_num][0];
                node.prefix_rlc[node_num][1] = rlc_accumulator * rlc_challenge + node.prefix[node_num][1];
                rlc_accumulator = node.prefix_rlc[node_num][1];
                node.prefix_rlc[node_num][2] = rlc_accumulator;
            } else {
                node.prefix[node_num][0] = 0xC0 + total_length;
                node.second_prefix_is_last[node_num] = 1;
                node.third_prefix_is_last[node_num] = 1;
                node.prefix_index[node_num][0] = 0;

                hash_input[rlp_encoding_index++] = uint8_t((0xC0 + total_length) & 0xFF);
                node.prefix_rlc[node_num][0] = (total_length+1) * rlc_challenge + node.prefix[node_num][0];
                rlc_accumulator = node.prefix_rlc[node_num][0];
                node.prefix_rlc[node_num][1] = rlc_accumulator;
                node.prefix_rlc[node_num][2] = rlc_accumulator;
            }

            node.len_low[node_num] = total_length & 0xFF;
            node.len_high[node_num] = (total_length >> 8) & 0xFF;
        }

        void store_node_hash(std::size_t node_num, node_rlp_data &node, zkevm_word_type hash) {
            node.hash_low[node_num] = w_lo<FieldType>(hash);
            node.hash_high[node_num] = w_hi<FieldType>(hash);
        }

        void encode_leaf_data(std::size_t node_num, leaf_rlp_data &leaf, std::vector<zkevm_word_type> key, std::vector<zkevm_word_type> value, std::size_t& rlp_encoding_index, std::vector<std::uint8_t> &hash_input, TYPE &rlc_accumulator, TYPE rlc_challenge) {
            if (key.size() == 1) { // first byte of key in leaf nodes is always less than 0x7F due to leaf node encoding
                // TODO child_prefix_is_last[nodenum][0][0] must be true
            } else if (key.size() <= 33) {
                leaf.prefix[node_num][0][0] = 0x80 + key.size();
                leaf.second_prefix_is_last[node_num][0] = 1;
                leaf.prefix_index[node_num][0][0] = rlp_encoding_index;

                hash_input[rlp_encoding_index++] = uint8_t(0x80 + key.size());

                leaf.prefix_rlc[node_num][0][0] = rlc_accumulator * rlc_challenge + leaf.prefix[node_num][0][0];
                rlc_accumulator = leaf.prefix_rlc[node_num][0][0];
                leaf.prefix_rlc[node_num][0][1] = rlc_accumulator;
            }

            leaf.len_low[node_num][0] = key.size();
            leaf.len_high[node_num][0] = 0;
            // maximum lengths: 
            //      rlp encoded leaf node = 144 + 2 bytes
            //      key = 33 bytes
            //      value = 108 bytes
            //      rlp encoded key = 34 bytes
            //      rlp encoded value = 110 bytes


            for (size_t j = 0; j < key.size(); j++) {
                leaf.index[node_num][0][j] = rlp_encoding_index;
                hash_input[rlp_encoding_index++] = uint8_t(key[j]);

                leaf.rlc[node_num][0][j] = rlc_accumulator * rlc_challenge + leaf.data[node_num][0][j];
                rlc_accumulator = leaf.rlc[node_num][0][j];
            }
            for (size_t j = key.size(); j < leaf.rlc[node_num][0].size(); j++) {
                leaf.rlc[node_num][0][j] = rlc_accumulator;
            }
            
            if (value.size() == 1 && value[0] <= 0x7F) {
                // TODO
            } else if (value.size() <= 55) {
                leaf.prefix[node_num][1][0] = 0x80 + value.size();
                leaf.prefix_index[node_num][1][0] = rlp_encoding_index;
                hash_input[rlp_encoding_index++] = uint8_t(0x80 + value.size());

                leaf.prefix_rlc[node_num][1][0] = rlc_accumulator * rlc_challenge + leaf.prefix[node_num][1][0];
                rlc_accumulator = leaf.prefix_rlc[node_num][1][0];
                leaf.prefix_rlc[node_num][1][1] = rlc_accumulator;
            } else {
                leaf.prefix[node_num][1][0] = 0xB8;
                leaf.prefix_index[node_num][1][0] = rlp_encoding_index;
                leaf.prefix[node_num][1][1] = value.size();
                leaf.prefix_index[node_num][1][1] = rlp_encoding_index+1;
                leaf.second_prefix_is_last[node_num][1] = 0;
                
                hash_input[rlp_encoding_index++] = uint8_t(0xB8);
                hash_input[rlp_encoding_index++] = value.size();

                leaf.prefix_rlc[node_num][1][0] = rlc_accumulator * rlc_challenge + leaf.prefix[node_num][1][0];
                rlc_accumulator = leaf.prefix_rlc[node_num][1][0];
                leaf.prefix_rlc[node_num][1][1] = rlc_accumulator * rlc_challenge + leaf.prefix[node_num][1][1];
                rlc_accumulator = leaf.prefix_rlc[node_num][1][1];
            }

            leaf.len_low[node_num][1] = value.size();
            leaf.len_high[node_num][1] = 0;

            for (size_t j = 0; j < value.size(); j++) {
                leaf.index[node_num][1][j] = rlp_encoding_index;
                hash_input[rlp_encoding_index++] = uint8_t(value[j]);

                leaf.rlc[node_num][1][j] = rlc_accumulator * rlc_challenge + leaf.data[node_num][1][j];
                rlc_accumulator = leaf.rlc[node_num][1][j];
            }
            for (size_t j = value.size(); j < leaf.rlc[node_num][1].size(); j++) {
                leaf.rlc[node_num][1][j] = rlc_accumulator;
            }


            for (size_t k = 0; k < 2; k++) {
                TYPE len = leaf.len_low[node_num][k] + leaf.len_high[node_num][k] * 0x100;
                for (size_t j = 0; j < 110; j++) {
                    if ( leaf.index[node_num][k][j] - leaf.index[node_num][k][0] == len - 1) {
                        leaf.index_is_last_I[node_num][k][j] = 0;
                    } else {
                        leaf.index_is_last_I[node_num][k][j] = 
                            (len - 1 - (leaf.index[node_num][k][j] - leaf.index[node_num][k][0])).inversed();
                    }
                    leaf.index_is_last_R[node_num][k][j] = 1 - 
                        (len - 1 - (leaf.index[node_num][k][j] - leaf.index[node_num][k][0])) 
                        * leaf.index_is_last_I[node_num][k][j];
                }
            }
        }

        zkevm_word_type calculate_keccak(std::vector<std::uint8_t> hash_input, std::size_t total_length) {
            std::vector<uint8_t> buffer(hash_input.begin(), hash_input.begin() + total_length);
            zkevm_word_type hash = nil::blueprint::zkevm_keccak_hash(buffer);
            return hash;
        }

        void print_leaf_node(std::size_t node_num, node_rlp_data &node, leaf_rlp_data &leaf, zkevm_word_type hash, size_t key_data_len, size_t value_data_len) {
            TYPE hash_low = w_lo<FieldType>(hash);
            TYPE hash_high = w_hi<FieldType>(hash);

            std::cout << "rlp prefix:" << std::endl;
            std::cout << "\tdata\tindex\n";

            std::cout << "\t" << std::hex << node.prefix[node_num][0] << std::dec << "\t"
                      << std::hex << hash_high << std::dec << "\t"
                      << std::hex << hash_low << std::dec << "\t"
                      << std::hex << 0 << std::dec << std::endl;
            std::cout << "\t" << std::hex << node.prefix[node_num][1] << std::dec << "\t"
                      << std::hex << node.prefix_index[node_num][0] << std::dec << std::endl;
            std::cout << "\t" << std::hex << node.prefix[node_num][2] << std::dec << "\t"
                      << std::hex << node.prefix_index[node_num][1] << std::dec << std::endl;
            
            std::cout << "node rlp second prefix is last:\n "
                      << std::hex << node.second_prefix_is_last[node_num] << std::dec << std::endl;
            std::cout << "node rlp len low and high: \n"
                      << std::hex << node.len_low[node_num] << std::dec << "\t"
                      << std::hex << node.len_high[node_num] << std::dec << std::endl;
            
            std::cout << "key prefix: \n\tdata\tindex\n\t";
            std::cout << std::hex << leaf.prefix[node_num][0][0] << std::dec << "\t"
                      << std::hex << leaf.prefix_index[node_num][0][0] << std::dec << std::endl;
            std::cout << "second is last\tlen_low\tlen_high\tfirst_element_flag\tfirst_element\n\t";
            std::cout << std::hex << leaf.second_prefix_is_last[node_num][0] << std::dec << "\t"
                      << std::hex << leaf.len_low[node_num][0] << std::dec << "\t"
                      << std::hex << leaf.len_high[node_num][0] << std::dec << "\t\t"
                      << std::hex << leaf.first_element_flag[node_num][0] << std::dec << "\t\t"
                      << std::hex << leaf.first_element[node_num][0] << std::dec << std::endl;


            std::cout << "key:\n\tdata\tindex\n";
            for (size_t i = 0; i < key_data_len; i++) {
                std::cout << "\t"
                          << std::hex << leaf.data[node_num][0][i] << std::dec << "\t" 
                          << std::hex << leaf.index[node_num][0][i] << std::dec << std::endl;
            }
        
            std::cout << "value prefix: \n\tdata\tindex\n";
            std::cout << "\t" << std::hex << leaf.prefix[node_num][1][0] << std::dec << "\t" 
                      << std::hex << leaf.prefix_index[node_num][1][0] << std::dec << std::endl;
            std::cout << "\t" << std::hex << leaf.prefix[node_num][1][1] << std::dec << "\t"  
                      << std::hex << leaf.prefix_index[node_num][1][1] << std::dec << std::endl;

            std::cout << "second is last\tlen_high\tlen_low\tfirst_element_flag\tfirst_element\n\t";
            std::cout << std::hex << leaf.second_prefix_is_last[node_num][1] << std::dec << "\t"
                      << std::hex << leaf.len_high[node_num][1] << std::dec << "\t"
                      << std::hex << leaf.len_low[node_num][1] << std::dec << "\t"
                      << std::hex << leaf.first_element_flag[node_num][1] << std::dec << "\t\t"
                      << std::hex << leaf.first_element[node_num][1] << std::dec << std::endl;
            std::cout << "value: \n";
            for (size_t i = 0; i < value_data_len; i++) {
                std::cout << "\t"
                          << std::hex << leaf.data[node_num][1][i] << std::dec << "\t" 
                          << std::hex << leaf.index[node_num][1][i] << std::dec << std::endl;
            }
        }
    };
}  // namespace nil::blueprint::bbf
