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

    using child = typename std::vector<zkevm_word_type>;

    struct mpt_node {
        enum mpt_node_type type;
        // the node content. 
        // for now only supports leafs and extensions
        // chunks are byte size
        std::array<child, 2> data;
    };

    template<typename FieldType, GenerationStage stage>
    class mpt_hasher : public generic_component<FieldType, stage> {
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
            std::vector<mpt_node> nodes;
            TYPE rlc_challenge;
        };

        // using input_type =
        //     typename std::conditional<stage == GenerationStage::ASSIGNMENT,
        //                                 _input_type, std::nullptr_t>::type;

        using value = typename FieldType::value_type;
        using integral_type = nil::crypto3::multiprecision::big_uint<257>;

        static table_params get_minimal_requirements(std::size_t max_mpt_hasher_size) {
            return {
                    .witnesses = 1356,
                    .public_inputs = 0,
                    .constants = 0,
                    .rows = max_mpt_hasher_size + 2178};
        }

        static void allocate_public_inputs(context_type &context, input_type &input,
                                           std::size_t max_mpt_hasher_size) {}

        struct node_content{
            std::array<std::array<TYPE, 110>, 2> data;
            std::array<std::array<TYPE, 110>, 2> index;
            std::array<std::array<TYPE, 110>, 2> index_is_last_I;
            std::array<std::array<TYPE, 110>, 2> index_is_last_R;
            std::array<std::array<TYPE, 110>, 2> is_last;
            std::array<std::array<TYPE, 110>, 2> rlc;
            std::array<std::array<TYPE, 2>,   2> prefix;
            std::array<std::array<TYPE, 2>,   2> prefix_index;
            std::array<std::array<TYPE, 2>,   2> prefix_rlc;
            std::array<TYPE, 2> second_prefix_is_last;
            // lengths without considering rlp prefixes
            std::array<TYPE, 2> len_low;
            std::array<TYPE, 2> len_high;
            // first element flag for rlp lookup
            std::array<TYPE, 2> first_element_flag;
            std::array<TYPE, 2> first_element;
        };

        struct node_rlp_data {
            TYPE not_padding;
            std::array<TYPE, 3> prefix;
            std::array<TYPE, 3> prefix_rlc;
            // the first rlp prefix is not last and its hash and index is known
            TYPE second_prefix_is_last;
            TYPE third_prefix_is_last;
            std::array<TYPE, 2> prefix_index;
            TYPE len_low;
            TYPE len_high;
            TYPE hash_low;
            TYPE hash_high;
            // the key-value stored in this node
            node_content content;

        };

        void initialize_node_rlp_data(std::vector<node_rlp_data> &nodes) {
            for (auto &node : nodes) {
                node.second_prefix_is_last = 1;
                node.third_prefix_is_last = 1;
                node.prefix[0] = 0xC0;
                store_node_hash(node, calculate_keccak({}, 0));
                for (size_t i = 0; i < 2; i++) {
                    for (size_t k = 0; k < 110; k++) {
                        node.content.is_last[i][k] = 1;
                    }
                    node.content.second_prefix_is_last[i] = 1;
                    node.content.first_element_flag[i] = 1;
                }
            }
        }

        mpt_hasher(context_type &context_object, const input_type &input,
            std::size_t max_mpt_hasher_size)
            : generic_component<FieldType, stage>(context_object) {

            std::vector<std::size_t> keccak_lookup_area;
            std::size_t keccak_max_blocks = 10;
            // std::size_t keccak_max_blocks = 10;
            std::vector<std::size_t> rlp_lookup_area;
            std::vector<TYPE> node_type(max_mpt_hasher_size);
            // std::vector<TYPE> node_type_inv_2(max_mpt_hasher_size);
            // std::vector<TYPE> r(max_mpt_hasher_size);
            std::size_t node_num = 0;
            typename KeccakTable::private_input_type keccak_buffers;
            std::vector<node_rlp_data> nodes(max_mpt_hasher_size);
            
            if constexpr (stage == GenerationStage::ASSIGNMENT) {
                keccak_buffers.new_buffer(std::vector<uint8_t>{});
                initialize_node_rlp_data(nodes);
                // assignment
                for (size_t i = 0; i < input.nodes.size(); i++) {
                    mpt_node mn = input.nodes[i];
                    node_rlp_data n = nodes[i];
                    std::vector<zkevm_word_type> key = mn.data[0];
                    std::vector<zkevm_word_type> value = mn.data[1];
                    std::size_t total_length = get_leaf_key_length(key) + get_leaf_value_length(value);
                    std::size_t rlp_encoding_index;
                    std::vector<std::uint8_t> hash_input(532);
                    TYPE rlc_accumulator;
                    encode_node_data(nodes[i], total_length, rlp_encoding_index, hash_input, rlc_accumulator, input.rlc_challenge);
                    encode_leaf_data(nodes[i].content, key, value, rlp_encoding_index, hash_input, rlc_accumulator, input.rlc_challenge);
                    zkevm_word_type hash = calculate_keccak(hash_input, rlp_encoding_index);
                    std::cout << "node hash: " << std::hex << hash << std::dec << std::endl;
                    // std::cout << "rlc: " << rlc_accumulator<< std::endl;
                    std::vector<uint8_t> buffer(hash_input.begin(), hash_input.begin() + rlp_encoding_index);
                    keccak_buffers.new_buffer(buffer);
                    store_node_hash(nodes[i], hash);
                    // print_leaf_node(nodes[i], hash, key.size(), value.size());
                }
            }

            // allocation
            for (std::size_t i = 0; i < max_mpt_hasher_size; i++) {
                size_t column_index = 0;
                allocate(node_type[i], column_index++, i);
                // for (std::size_t j = 0; j < 32; j++) {
                //     allocate(key[i][j], column_index++, i);
                // }
                // allocate(node_type_inv_2[i], column_index++, i);
                // allocate(r[i], column_index++, i);

                // node
                allocate(nodes[i].not_padding, column_index ++, i);
                
                // rlp len
                allocate(nodes[i].len_low, column_index ++, i);
                allocate(nodes[i].len_high, column_index ++, i);
                allocate(nodes[i].hash_low, column_index ++, i);
                allocate(nodes[i].hash_high, column_index ++, i);
                // prefix
                allocate(nodes[i].prefix[0], column_index ++, i);
                allocate(nodes[i].prefix_rlc[0], column_index ++, i);
                allocate(nodes[i].second_prefix_is_last, column_index ++, i);
                allocate(nodes[i].third_prefix_is_last, column_index ++, i);
                allocate(nodes[i].prefix[1], column_index ++, i);
                allocate(nodes[i].prefix_rlc[1], column_index ++, i);
                allocate(nodes[i].prefix_index[0], column_index ++, i);
                allocate(nodes[i].prefix[2], column_index ++, i);
                allocate(nodes[i].prefix_rlc[2], column_index ++, i);
                allocate(nodes[i].prefix_index[1], column_index ++, i);

                // children
                for (std::size_t j = 0; j < 2; j++) {
                    // rlp len
                    allocate(nodes[i].content.len_low[j], column_index ++, i);
                    allocate(nodes[i].content.len_high[j], column_index ++, i);
                    // prefix
                    allocate(nodes[i].content.prefix[j][0], column_index++, i);
                    allocate(nodes[i].content.prefix_rlc[j][0], column_index++, i);
                    allocate(nodes[i].content.prefix_index[j][0], column_index++, i);
                    allocate(nodes[i].content.prefix[j][1], column_index++, i);
                    allocate(nodes[i].content.prefix_rlc[j][1], column_index++, i);
                    allocate(nodes[i].content.prefix_index[j][1], column_index++, i);
                    allocate(nodes[i].content.second_prefix_is_last[j], column_index++, i);
                    allocate(nodes[i].content.first_element_flag[j], column_index++, i);

                    // encoding
                    for (std::size_t k = 0; k < 110; k++) {
                        allocate(nodes[i].content.data[j][k], column_index++, i);
                        allocate(nodes[i].content.rlc[j][k], column_index++, i);
                        allocate(nodes[i].content.is_last[j][k], column_index++, i);
                        allocate(nodes[i].content.index[j][k], column_index++, i);
                        allocate(nodes[i].content.index_is_last_I[j][k], column_index++, i);
                        allocate(nodes[i].content.index_is_last_R[j][k], column_index++, i);
                    }
                }

            }


            for (std::size_t i = 0; i < RLPTable::get_witness_amount(); i++) {
                rlp_lookup_area.push_back(i);
            }
            context_type rlp_ct = context_object.subcontext(rlp_lookup_area, max_mpt_hasher_size, 2178);
            RLPTable rlpt = RLPTable(rlp_ct);

            for( std::size_t i = 0; i < KeccakTable::get_witness_amount(); i++){
                keccak_lookup_area.push_back(i);
            }
            context_type keccak_ct = context_object.subcontext( keccak_lookup_area, 2178 + max_mpt_hasher_size, keccak_max_blocks);
            KeccakTable k_t = KeccakTable(keccak_ct, {input.rlc_challenge, keccak_buffers}, keccak_max_blocks);

            if constexpr (stage == GenerationStage::CONSTRAINTS) {
                node_rlp_data n = nodes[0];
                node_content c = n.content;
                    // constrain(node_type[i] * (1 - node_type[i]) * (2 - node_type[i]));
                    // r[i] = 1 -> node is leaf (type 2)
                    // constrain((2 - node_type[i]) * r[i]);
                    // node.encoded[i][0] if [0xc0, 0xf7] 
                    // constrain(r[i] * (32 - node.encoded[i][3]) *
                    //           (48 - node.encoded[i][3]));  // change this to
                                                                // first-nibble isntead
                std::size_t leaf_data_size = n.content.data[0].size();
                std::vector<TYPE> node_rlp_lookup = {
                    n.prefix[0], 
                    n.prefix[1],
                    n.prefix[2],
                    0,
                    0,
                    0,
                    n.len_low, 
                    n.len_high,
                    n.second_prefix_is_last,
                    n.third_prefix_is_last
                };

                std::vector<TYPE> key_rlp_lookup = {
                    c.prefix[0][0],
                    c.prefix[0][1],
                    0,
                    c.first_element[0],
                    c.first_element_flag[0],
                    1,
                    c.len_low[0], 
                    c.len_high[0],
                    // 1,
                    c.second_prefix_is_last[0],
                    1
                };

                std::vector<TYPE> value_rlp_lookup = {
                    c.prefix[1][0],
                    c.prefix[1][1],
                    0,
                    c.first_element[1],
                    c.first_element_flag[1],
                    1,
                    c.len_low[1], 
                    c.len_high[1],
                    c.second_prefix_is_last[1],
                    1
                };

                std::vector<TYPE> keccak_lookup = {
                    1,
                    c.rlc[1][leaf_data_size-1] * n.not_padding,
                    n.hash_high,
                    n.hash_low
                };
                context_object.relative_lookup(context_object.relativize(node_rlp_lookup, 0), "rlp_table", 0, max_mpt_hasher_size - 1);
                context_object.relative_lookup(context_object.relativize(key_rlp_lookup, 0), "rlp_table", 0, max_mpt_hasher_size - 1);
                context_object.relative_lookup(context_object.relativize(value_rlp_lookup, 0), "rlp_table", 0, max_mpt_hasher_size - 1);
                context_object.relative_lookup(context_object.relativize(keccak_lookup, 0), "keccak_table", 0, max_mpt_hasher_size - 1);
                
                std::vector<TYPE> consts;
                consts.push_back(context_object.relativize((n.second_prefix_is_last*(1 - n.second_prefix_is_last)), 0));
                consts.push_back(context_object.relativize((n.prefix[1] * n.second_prefix_is_last), 0));
                consts.push_back(context_object.relativize((n.prefix[2] * n.third_prefix_is_last), 0));
                consts.push_back(context_object.relativize((c.second_prefix_is_last[1] * (1 - c.second_prefix_is_last[1])), 0));
                consts.push_back(context_object.relativize((c.second_prefix_is_last[0] * (1 - c.second_prefix_is_last[0])), 0));
                consts.push_back(context_object.relativize((n.not_padding * (n.prefix_rlc[0] - 
/* total length */      ((1 + 1 - n.second_prefix_is_last + 1 - n.third_prefix_is_last + n.len_low + 0x100 * n.len_high)
                        * 53 + n.prefix[0]))), 0));

                consts.push_back(context_object.relativize((n.prefix_rlc[1] - ((1 - n.second_prefix_is_last) * (n.prefix_rlc[0] * 53 + n.prefix[1]) + n.second_prefix_is_last * n.prefix_rlc[0])), 0));
                consts.push_back(context_object.relativize((n.prefix_rlc[2] - ((1 - n.third_prefix_is_last) *  (n.prefix_rlc[1] * 53 + n.prefix[2]) + n.third_prefix_is_last * n.prefix_rlc[1])), 0));

                consts.push_back(context_object.relativize((n.not_padding * (-(n.len_low + 0x100 * n.len_high)
                        + c.len_low[0] + 0x100 * c.len_high[0] 
                        + c.len_low[1] + 0x100 * c.len_high[1] 
                        + 3 - c.second_prefix_is_last[1])), 0));

                // node first rlp prefix is always keccak 0 index
                consts.push_back(context_object.relativize((n.prefix_index[0] - (1 - n.second_prefix_is_last)), 0));
                consts.push_back(context_object.relativize((n.prefix_index[1] * n.third_prefix_is_last + (2-n.prefix_index[1])*(1-n.third_prefix_is_last)), 0));
                for (size_t k = 0; k < 2; k++) {
                    if (k == 0) {
                        consts.push_back(context_object.relativize(c.prefix_index[k][0] - n.not_padding - (1 - n.second_prefix_is_last) + (1 - n.third_prefix_is_last), 0));
                        consts.push_back(context_object.relativize(c.prefix_rlc[k][0] - (n.prefix_rlc[2] * 53 + c.prefix[0][0]), 0));
                    } else {
                        consts.push_back(context_object.relativize(c.prefix_index[k][0] - 
                            (c.len_low[k-1] + c.len_high[k-1] * 0x100 + c.prefix_index[k-1][0] + n.not_padding - c.second_prefix_is_last[k-1] + 1), 0));
                        consts.push_back(context_object.relativize(c.prefix_rlc[k][0] - (c.rlc[k-1][leaf_data_size-1] * 53 + c.prefix[k][0]), 0));
                    }
                    consts.push_back(context_object.relativize(c.prefix_index[k][1] - (1 - c.second_prefix_is_last[k]) * (c.prefix_index[k][0] + n.not_padding), 0));
                    consts.push_back(context_object.relativize(c.prefix_rlc[k][1] - ((1 - c.second_prefix_is_last[k]) * (c.prefix_rlc[k][0] * 53 + c.prefix[k][1]) + c.second_prefix_is_last[k] * c.prefix_rlc[k][0]), 0));
                    consts.push_back(context_object.relativize(c.index[k][0] - (1 - c.second_prefix_is_last[k]) - c.prefix_index[k][0] - n.not_padding, 0));
                    consts.push_back(context_object.relativize(c.rlc[k][0] - (c.prefix_rlc[k][1] * 53 + c.data[k][0]), 0));

                    consts.push_back(context_object.relativize(c.data[k][0] * c.is_last[k][0], 0));
                    for (size_t i = 1; i < leaf_data_size; i++) {
                        consts.push_back(context_object.relativize((1 - c.is_last[k][i]) * c.is_last[k][i], 0));
                        consts.push_back(context_object.relativize((1 - c.is_last[k][i]) * c.is_last[k][i-1], 0));
                        
                        consts.push_back(context_object.relativize(n.not_padding * (c.index_is_last_R[k][i] - (1 - 
                            c.index_is_last_I[k][i] * ((c.len_low[k] + c.len_high[k] * 0x100) - (c.index[k][i] - c.index[k][0] + 1)))), 0));
                        consts.push_back(context_object.relativize(((c.len_low[k] + c.len_high[k] * 0x100) - (c.index[k][i] - c.index[k][0] + 1)) * c.index_is_last_R[k][i], 0));
                        consts.push_back(context_object.relativize(c.is_last[k][i] - c.index_is_last_R[k][i] - c.is_last[k][i-1], 0));
                        consts.push_back(context_object.relativize(c.index[k][i] * c.is_last[k][i-1], 0));
                        consts.push_back(context_object.relativize((c.index[k][i] - c.index[k][i-1] - 1) * (1 - c.is_last[k][i-1]), 0));
                        consts.push_back(context_object.relativize(c.data[k][i] * c.is_last[k][i-1], 0));
                        consts.push_back(context_object.relativize(c.rlc[k][i] - (c.is_last[k][i-1] * c.rlc[k][i-1] + (1 - c.is_last[k][i-1]) * (c.rlc[k][i-1] * 53 + c.data[k][i])), 0));
                    }
                }
                for (size_t i = 0; i < consts.size(); i++) {
                    context_object.relative_constrain(consts[i], 0, max_mpt_hasher_size - 1);
                }
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

        void encode_node_data(node_rlp_data &node, std::size_t total_length, std::size_t &rlp_encoding_index, std::vector<std::uint8_t> &hash_input, TYPE &rlc_accumulator, TYPE rlc_challenge) {
            rlp_encoding_index = 0;
            if (total_length > 55) {
                std::size_t length_length = 0;
                std::size_t temp = total_length;

                while(temp > 0) {
                    temp >>= 8;
                    length_length ++;
                }
                node.prefix[0] = 0xF7 + length_length;
                node.prefix[1] = total_length;
                node.prefix[2] = 0;
                node.prefix_index[0] = rlp_encoding_index+1;

                node.second_prefix_is_last = 0;
                node.third_prefix_is_last = 1;

                hash_input[rlp_encoding_index++] = 0xF7 + length_length;
                hash_input[rlp_encoding_index++] = total_length;

                node.prefix_rlc[0] = (total_length+2) * rlc_challenge + node.prefix[0];
                rlc_accumulator = node.prefix_rlc[0];
                node.prefix_rlc[1] = rlc_accumulator * rlc_challenge + node.prefix[1];
                rlc_accumulator = node.prefix_rlc[1];
                node.prefix_rlc[2] = rlc_accumulator;
            } else {
                node.prefix[0] = 0xC0 + total_length;
                node.second_prefix_is_last = 1;
                node.third_prefix_is_last = 1;
                node.prefix_index[0] = 0;

                hash_input[rlp_encoding_index++] = uint8_t((0xC0 + total_length) & 0xFF);
                node.prefix_rlc[0] = (total_length+1) * rlc_challenge + node.prefix[0];
                rlc_accumulator = node.prefix_rlc[0];
                node.prefix_rlc[1] = rlc_accumulator;
                node.prefix_rlc[2] = rlc_accumulator;
            }

            node.len_low = total_length & 0xFF;
            node.len_high = (total_length >> 8) & 0xFF;
            node.not_padding = 1;
        }

        void store_node_hash(node_rlp_data &node, zkevm_word_type hash) {
            node.hash_low = w_lo<FieldType>(hash);
            node.hash_high = w_hi<FieldType>(hash);
        }

        void encode_leaf_data(node_content &content, std::vector<zkevm_word_type> key, std::vector<zkevm_word_type> value, std::size_t& rlp_encoding_index, std::vector<std::uint8_t> &hash_input, TYPE &rlc_accumulator, TYPE rlc_challenge) {
            std::vector<std::vector<zkevm_word_type>> data = {key, value}; 
            for (size_t i = 0; i < data.size(); i++) {
                // std::cout <<"    value = ";
                auto d = data[i];
                for (size_t j = 0; j < d.size(); j++) {
                    // if (d[j] <= 0x0F)
                    //     std::cout <<"0" << std::hex << d[j] << std::dec;
                    // else
                    //     std::cout << std::hex << d[j] << std::dec;
                    content.data[i][j] = d[j];
                    content.is_last[i][j] = 0;
                }
                if (d.size() > 0) {
                    content.is_last[i][d.size() - 1] = 1;
                }
                if (d.size() == 0 || (d.size() == 1 && d[0] < 128)) {
                    if (d.size() == 1)
                        content.first_element[i] = d[0];
                    content.first_element_flag[i] = 1;
                } else {
                    content.first_element_flag[i] = 0;
                }
                // std::cout << " size: " << d.size();
                // std::cout << std::endl;
            }
            // std::cout << "]" << std::endl;

            if (key.size() == 1) { // first byte of key in leaf nodes is always less than 0x7F due to leaf node encoding
                // TODO child_prefix_is_last[nodenum][0][0] must be true
            } else if (key.size() <= 33) {
                content.prefix[0][0] = 0x80 + key.size();
                content.second_prefix_is_last[0] = 1;
                content.prefix_index[0][0] = rlp_encoding_index;

                hash_input[rlp_encoding_index++] = uint8_t(0x80 + key.size());

                content.prefix_rlc[0][0] = rlc_accumulator * rlc_challenge + content.prefix[0][0];
                rlc_accumulator = content.prefix_rlc[0][0];
                content.prefix_rlc[0][1] = rlc_accumulator;
            }

            content.len_low[0] = key.size();
            content.len_high[0] = 0;
            // maximum lengths: 
            //      rlp encoded leaf node = 144 + 2 bytes
            //      key = 33 bytes
            //      value = 108 bytes
            //      rlp encoded key = 34 bytes
            //      rlp encoded value = 110 bytes


            for (size_t j = 0; j < key.size(); j++) {
                content.index[0][j] = rlp_encoding_index;
                hash_input[rlp_encoding_index++] = uint8_t(key[j]);

                content.rlc[0][j] = rlc_accumulator * rlc_challenge + content.data[0][j];
                rlc_accumulator = content.rlc[0][j];
            }
            for (size_t j = key.size(); j < content.rlc[0].size(); j++) {
                content.rlc[0][j] = rlc_accumulator;
            }
            
            if (value.size() == 1 && value[0] <= 0x7F) {
                // TODO
            } else if (value.size() <= 55) {
                content.prefix[1][0] = 0x80 + value.size();
                content.prefix_index[1][0] = rlp_encoding_index;
                hash_input[rlp_encoding_index++] = uint8_t(0x80 + value.size());

                content.prefix_rlc[1][0] = rlc_accumulator * rlc_challenge + content.prefix[1][0];
                rlc_accumulator = content.prefix_rlc[1][0];
                content.prefix_rlc[1][1] = rlc_accumulator;
            } else {
                content.prefix[1][0] = 0xB8;
                content.prefix_index[1][0] = rlp_encoding_index;
                content.prefix[1][1] = value.size();
                content.prefix_index[1][1] = rlp_encoding_index+1;
                content.second_prefix_is_last[1] = 0;
                
                hash_input[rlp_encoding_index++] = uint8_t(0xB8);
                hash_input[rlp_encoding_index++] = value.size();

                content.prefix_rlc[1][0] = rlc_accumulator * rlc_challenge + content.prefix[1][0];
                rlc_accumulator = content.prefix_rlc[1][0];
                content.prefix_rlc[1][1] = rlc_accumulator * rlc_challenge + content.prefix[1][1];
                rlc_accumulator = content.prefix_rlc[1][1];
            }

            content.len_low[1] = value.size();
            content.len_high[1] = 0;

            for (size_t j = 0; j < value.size(); j++) {
                content.index[1][j] = rlp_encoding_index;
                hash_input[rlp_encoding_index++] = uint8_t(value[j]);

                content.rlc[1][j] = rlc_accumulator * rlc_challenge + content.data[1][j];
                rlc_accumulator = content.rlc[1][j];
            }
            for (size_t j = value.size(); j < content.rlc[1].size(); j++) {
                content.rlc[1][j] = rlc_accumulator;
            }


            for (size_t k = 0; k < 2; k++) {
                TYPE len = content.len_low[k] + content.len_high[k] * 0x100;
                for (size_t j = 0; j < 110; j++) {
                    if ( content.index[k][j] - content.index[k][0] == len - 1) {
                        content.index_is_last_I[k][j] = 0;
                    } else {
                        content.index_is_last_I[k][j] = 
                            (len - 1 - (content.index[k][j] - content.index[k][0])).inversed();
                    }
                    content.index_is_last_R[k][j] = 1 - 
                        (len - 1 - (content.index[k][j] - content.index[k][0])) 
                        * content.index_is_last_I[k][j];
                }
            }
        }

        zkevm_word_type calculate_keccak(std::vector<std::uint8_t> hash_input, std::size_t total_length) {
            std::vector<uint8_t> buffer(hash_input.begin(), hash_input.begin() + total_length);
            zkevm_word_type hash = nil::blueprint::zkevm_keccak_hash(buffer);
            return hash;
        }

        void print_leaf_node(node_rlp_data &node, zkevm_word_type hash, size_t key_data_len, size_t value_data_len) {
            node_content content = node.content;
            TYPE hash_low = w_lo<FieldType>(hash);
            TYPE hash_high = w_hi<FieldType>(hash);

            std::cout << "rlp prefix:" << std::endl;
            std::cout << "\tdata\tindex\n";

            std::cout << "\t" << std::hex << node.prefix[0] << std::dec << "\t"
                      << std::hex << hash_high << std::dec << "\t"
                      << std::hex << hash_low << std::dec << "\t"
                      << std::hex << 0 << std::dec << std::endl;
            std::cout << "\t" << std::hex << node.prefix[1] << std::dec << "\t"
                      << std::hex << node.prefix_index[0] << std::dec << std::endl;
            std::cout << "\t" << std::hex << node.prefix[2] << std::dec << "\t"
                      << std::hex << node.prefix_index[1] << std::dec << std::endl;
            
            std::cout << "node rlp second prefix is last:\n "
                      << std::hex << node.second_prefix_is_last << std::dec << std::endl;
            std::cout << "node rlp len low and high: \n"
                      << std::hex << node.len_low << std::dec << "\t"
                      << std::hex << node.len_high << std::dec << std::endl;
            
            std::cout << "key prefix: \n\tdata\tindex\n\t";
            std::cout << std::hex << content.prefix[0][0] << std::dec << "\t"
                      << std::hex << content.prefix_index[0][0] << std::dec << std::endl;
            std::cout << "second is last\tlen_low\tlen_high\tfirst_element_flag\tfirst_element\n\t";
            std::cout << std::hex << content.second_prefix_is_last[0] << std::dec << "\t"
                      << std::hex << content.len_low[0] << std::dec << "\t"
                      << std::hex << content.len_high[0] << std::dec << "\t\t"
                      << std::hex << content.first_element_flag[0] << std::dec << "\t\t"
                      << std::hex << content.first_element[0] << std::dec << std::endl;


            std::cout << "key:\n\tdata\tindex\n";
            for (size_t i = 0; i < key_data_len; i++) {
                std::cout << "\t"
                          << std::hex << content.data[0][i] << std::dec << "\t" 
                          << std::hex << content.index[0][i] << std::dec << std::endl;
            }
        
            std::cout << "value prefix: \n\tdata\tindex\n";
            std::cout << "\t" << std::hex << content.prefix[1][0] << std::dec << "\t" 
                      << std::hex << content.prefix_index[1][0] << std::dec << std::endl;
            std::cout << "\t" << std::hex << content.prefix[1][1] << std::dec << "\t"  
                      << std::hex << content.prefix_index[1][1] << std::dec << std::endl;

            std::cout << "second is last\tlen_high\tlen_low\tfirst_element_flag\tfirst_element\n\t";
            std::cout << std::hex << content.second_prefix_is_last[1] << std::dec << "\t"
                      << std::hex << content.len_high[1] << std::dec << "\t"
                      << std::hex << content.len_low[1] << std::dec << "\t"
                      << std::hex << content.first_element_flag[1] << std::dec << "\t\t"
                      << std::hex << content.first_element[1] << std::dec << std::endl;
            std::cout << "value: \n";
            for (size_t i = 0; i < value_data_len; i++) {
                std::cout << "\t"
                          << std::hex << content.data[1][i] << std::dec << "\t" 
                          << std::hex << content.index[1][i] << std::dec << std::endl;
            }
        }
    };
}  // namespace nil::blueprint::bbf
