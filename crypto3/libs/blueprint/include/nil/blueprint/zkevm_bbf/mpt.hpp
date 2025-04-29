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

        void allocate_leaf_node_variables(std::size_t max_mpt_hasher_size) {
            leaf_node_not_padding.resize(max_mpt_hasher_size);
            leaf_node_prefix.resize(max_mpt_hasher_size);
            leaf_node_second_prefix_is_last.resize(max_mpt_hasher_size);
            leaf_node_third_prefix_is_last.resize(max_mpt_hasher_size);
            leaf_node_prefix_index.resize(max_mpt_hasher_size);
            leaf_node_prefix_rlc.resize(max_mpt_hasher_size);
            leaf_node_len_low.resize(max_mpt_hasher_size);
            leaf_node_len_high.resize(max_mpt_hasher_size);
            leaf_node_hash_low.resize(max_mpt_hasher_size);
            leaf_node_hash_high.resize(max_mpt_hasher_size);
            node_type.resize(max_mpt_hasher_size);
        }

        void allocate_leaf_internal_variables(std::size_t max_mpt_hasher_size ) {
            leaf_internal_data.resize(max_mpt_hasher_size);
            leaf_internal_index.resize(max_mpt_hasher_size);
            leaf_internal_rlc.resize(max_mpt_hasher_size);
            leaf_internal_index_is_last_I.resize(max_mpt_hasher_size);
            leaf_internal_index_is_last_R.resize(max_mpt_hasher_size);
            leaf_internal_is_last.resize(max_mpt_hasher_size);
            leaf_internal_prefix.resize(max_mpt_hasher_size);
            leaf_internal_prefix_index.resize(max_mpt_hasher_size);
            leaf_internal_prefix_rlc.resize(max_mpt_hasher_size);
            leaf_internal_second_prefix_is_last.resize(max_mpt_hasher_size);
            leaf_internal_len_low.resize(max_mpt_hasher_size);
            leaf_internal_len_high.resize(max_mpt_hasher_size);
            leaf_internal_first_element_flag.resize(max_mpt_hasher_size);
            leaf_internal_first_element.resize(max_mpt_hasher_size);
        }

        void allocate_witness_variables(std::size_t size) {
            allocate_leaf_node_variables(size);
            allocate_leaf_internal_variables(size);
        }

        void initialize_leaf_data(std::size_t size) {
            for (size_t i = 0; i < size; i++) {
                leaf_node_second_prefix_is_last[i] = 1;
                leaf_node_third_prefix_is_last[i] = 1;
                leaf_node_prefix[i][0] = 0xC0;
                store_node_hash(i, calculate_keccak({}, 0));
                for (size_t j = 0; j < 2; j++) {
                    for (size_t k = 0; k < 110; k++) {
                        leaf_internal_is_last[i][j][k] = 1;
                    }
                    leaf_internal_second_prefix_is_last[i][j] = 1;
                    leaf_internal_first_element_flag[i][j] = 1;
                }
            }
        }

        mpt_hasher(context_type &context_object, const input_type &input,
            std::size_t max_mpt_hasher_size)
            : generic_component<FieldType, stage>(context_object) {
            // initialization
            std::vector<std::size_t> keccak_lookup_area;
            std::size_t keccak_max_blocks = 10;
            std::vector<std::size_t> rlp_lookup_area;
            // std::vector<TYPE> node_type_inv_2(max_mpt_hasher_size);
            // std::vector<TYPE> r(max_mpt_hasher_size);
            std::size_t node_num = 0;
            typename KeccakTable::private_input_type keccak_buffers;
            allocate_witness_variables(max_mpt_hasher_size);

            if constexpr (stage == GenerationStage::ASSIGNMENT) {
                keccak_buffers.new_buffer(std::vector<uint8_t>{});
                initialize_leaf_data(max_mpt_hasher_size);
                // assignment
                for (size_t i = 0; i < input.nodes.size(); i++) {
                    mpt_node mn = input.nodes[i];
                    std::vector<zkevm_word_type> key = mn.data[0];
                    std::vector<zkevm_word_type> value = mn.data[1];
                    std::size_t total_length = get_leaf_key_length(key) + get_leaf_value_length(value);
                    std::size_t rlp_encoding_index;
                    std::vector<std::uint8_t> hash_input(532);
                    TYPE rlc_accumulator;
                    encode_node_data(i, total_length, rlp_encoding_index, hash_input, rlc_accumulator, input.rlc_challenge);
                    encode_leaf_data(i, key, value, rlp_encoding_index, hash_input, rlc_accumulator, input.rlc_challenge);
                    zkevm_word_type hash = calculate_keccak(hash_input, rlp_encoding_index);
                    std::cout << "node hash: " << std::hex << hash << std::dec << std::endl;
                    std::vector<uint8_t> buffer(hash_input.begin(), hash_input.begin() + rlp_encoding_index);
                    keccak_buffers.new_buffer(buffer);
                    store_node_hash(i, hash);
                    // print_leaf_node(i, hash, key.size(), value.size());
                }
            }

            // allocation
            for (std::size_t i = 0; i < max_mpt_hasher_size; i++) {
                size_t column_index = 0;
                // allocate(node_type[i], column_index++, i);
                // for (std::size_t j = 0; j < 32; j++) {
                //     allocate(key[i][j], column_index++, i);
                // }
                // allocate(node_type_inv_2[i], column_index++, i);
                // allocate(r[i], column_index++, i);

                // node
                allocate(leaf_node_not_padding[i], column_index ++, i);
                
                // rlp len
                allocate(leaf_node_len_low[i], column_index ++, i);
                allocate(leaf_node_len_high[i], column_index ++, i);
                allocate(leaf_node_hash_low[i], column_index ++, i);
                allocate(leaf_node_hash_high[i], column_index ++, i);
                // prefix
                allocate(leaf_node_prefix[i][0], column_index ++, i);
                allocate(leaf_node_prefix_rlc[i][0], column_index ++, i);
                allocate(leaf_node_second_prefix_is_last[i], column_index ++, i);
                allocate(leaf_node_third_prefix_is_last[i], column_index ++, i);
                allocate(leaf_node_prefix[i][1], column_index ++, i);
                allocate(leaf_node_prefix_rlc[i][1], column_index ++, i);
                allocate(leaf_node_prefix_index[i][0], column_index ++, i);
                allocate(leaf_node_prefix[i][2], column_index ++, i);
                allocate(leaf_node_prefix_rlc[i][2], column_index ++, i);
                allocate(leaf_node_prefix_index[i][1], column_index ++, i);

                // children
                for (std::size_t j = 0; j < 2; j++) {
                    // rlp len
                    allocate(leaf_internal_len_low[i][j], column_index ++, i);
                    allocate(leaf_internal_len_high[i][j], column_index ++, i);
                    // prefix
                    allocate(leaf_internal_prefix[i][j][0], column_index++, i);
                    allocate(leaf_internal_prefix_rlc[i][j][0], column_index++, i);
                    allocate(leaf_internal_prefix_index[i][j][0], column_index++, i);
                    allocate(leaf_internal_prefix[i][j][1], column_index++, i);
                    allocate(leaf_internal_prefix_rlc[i][j][1], column_index++, i);
                    allocate(leaf_internal_prefix_index[i][j][1], column_index++, i);
                    allocate(leaf_internal_second_prefix_is_last[i][j], column_index++, i);
                    allocate(leaf_internal_first_element_flag[i][j], column_index++, i);

                    // encoding
                    for (std::size_t k = 0; k < 110; k++) {
                        allocate(leaf_internal_data[i][j][k], column_index++, i);
                        allocate(leaf_internal_rlc[i][j][k], column_index++, i);
                        allocate(leaf_internal_is_last[i][j][k], column_index++, i);
                        allocate(leaf_internal_index[i][j][k], column_index++, i);
                        allocate(leaf_internal_index_is_last_I[i][j][k], column_index++, i);
                        allocate(leaf_internal_index_is_last_R[i][j][k], column_index++, i);
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
                    std::size_t leaf_data_size = leaf_internal_data[0][0].size();

                    std::vector<TYPE> node_rlp_lookup = {
                        leaf_node_prefix[0][0], 
                        leaf_node_prefix[0][1],
                        leaf_node_prefix[0][2],
                        0,
                        0,
                        0,
                        leaf_node_len_low[0], 
                        leaf_node_len_high[0],
                        leaf_node_second_prefix_is_last[0],
                        leaf_node_third_prefix_is_last[0]
                    };
                    std::vector<TYPE> key_rlp_lookup = {
                        leaf_internal_prefix[0][0][0],
                        leaf_internal_prefix[0][0][1],
                        0,
                        leaf_internal_first_element[0][0],
                        leaf_internal_first_element_flag[0][0],
                        1,
                        leaf_internal_len_low[0][0], 
                        leaf_internal_len_high[0][0],
                        // 1,
                        leaf_internal_second_prefix_is_last[0][0],
                        1
                    };

                    std::vector<TYPE> value_rlp_lookup = {
                        leaf_internal_prefix[0][1][0],
                        leaf_internal_prefix[0][1][1],
                        0,
                        leaf_internal_first_element[0][1],
                        leaf_internal_first_element_flag[0][1],
                        1,
                        leaf_internal_len_low[0][1], 
                        leaf_internal_len_high[0][1],
                        leaf_internal_second_prefix_is_last[0][1],
                        1
                    };

                    std::vector<TYPE> keccak_lookup = {
                        1,
                        leaf_internal_rlc[0][1][leaf_data_size-1] * leaf_node_not_padding[0],
                        leaf_node_hash_high[0],
                        leaf_node_hash_low[0]
                    };
                    // std::vector<TYPE> tmp;
                    context_object.relative_lookup(context_object.relativize(node_rlp_lookup, 0), "rlp_table", 0, max_mpt_hasher_size - 1);
                    context_object.relative_lookup(context_object.relativize(key_rlp_lookup, 0), "rlp_table", 0, max_mpt_hasher_size - 1);
                    context_object.relative_lookup(context_object.relativize(value_rlp_lookup, 0), "rlp_table", 0, max_mpt_hasher_size - 1);
                    context_object.relative_lookup(context_object.relativize(keccak_lookup, 0), "keccak_table", 0, max_mpt_hasher_size - 1);

                    std::vector<TYPE> consts;

                    consts.push_back(context_object.relativize(leaf_node_second_prefix_is_last[0]*(1 - leaf_node_second_prefix_is_last[0]), 0));
                    consts.push_back(context_object.relativize(leaf_node_prefix[0][1] * leaf_node_second_prefix_is_last[0], 0));
                    consts.push_back(context_object.relativize(leaf_node_prefix[0][2] * leaf_node_third_prefix_is_last[0], 0));
                    consts.push_back(context_object.relativize(leaf_internal_second_prefix_is_last[0][1] * (1 - leaf_internal_second_prefix_is_last[0][1]), 0));
                    consts.push_back(context_object.relativize(leaf_internal_second_prefix_is_last[0][0] * (1 - leaf_internal_second_prefix_is_last[0][0]), 0));
                    consts.push_back(context_object.relativize(leaf_node_not_padding[0] * (leaf_node_prefix_rlc[0][0] - 
    /* total length */      ((1 + 1 - leaf_node_second_prefix_is_last[0] + 1 - leaf_node_third_prefix_is_last[0] + leaf_node_len_low[0] + 0x100 * leaf_node_len_high[0])
                            * 53 + leaf_node_prefix[0][0])), 0));

                    consts.push_back(context_object.relativize(leaf_node_prefix_rlc[0][1] - ((1 - leaf_node_second_prefix_is_last[0]) * (leaf_node_prefix_rlc[0][0] * 53 + leaf_node_prefix[0][1]) + leaf_node_second_prefix_is_last[0] * leaf_node_prefix_rlc[0][0]), 0));
                    consts.push_back(context_object.relativize(leaf_node_prefix_rlc[0][2] - ((1 - leaf_node_third_prefix_is_last[0]) *  (leaf_node_prefix_rlc[0][1] * 53 + leaf_node_prefix[0][2]) + leaf_node_third_prefix_is_last[0] * leaf_node_prefix_rlc[0][1]), 0));

                    consts.push_back(context_object.relativize(leaf_node_not_padding[0] * (-(leaf_node_len_low[0] + 0x100 * leaf_node_len_high[0])
                            + leaf_internal_len_low[0][0] + 0x100 * leaf_internal_len_high[0][0] 
                            + leaf_internal_len_low[0][1] + 0x100 * leaf_internal_len_high[0][1] 
                            + 3 - leaf_internal_second_prefix_is_last[0][1]), 0));

                    // node first rlp prefix is always keccak 0 index
                    consts.push_back(context_object.relativize(leaf_node_prefix_index[0][0] - (1 - leaf_node_second_prefix_is_last[0]), 0));
                    consts.push_back(context_object.relativize(leaf_node_prefix_index[0][1] * leaf_node_third_prefix_is_last[0] + (2-leaf_node_prefix_index[0][1])*(1-leaf_node_third_prefix_is_last[0]), 0));

                    for (size_t j = 0; j < 2; j++) {
                        if (j == 0) {
                            consts.push_back(context_object.relativize(leaf_internal_prefix_index[0][j][0] - leaf_node_not_padding[0] - (1 - leaf_node_second_prefix_is_last[0]) + (1 - leaf_node_third_prefix_is_last[0]), 0));
                            consts.push_back(context_object.relativize(leaf_internal_prefix_rlc[0][j][0] - (leaf_node_prefix_rlc[0][2] * 53 + leaf_internal_prefix[0][0][0]), 0));
                        } else {
                            consts.push_back(context_object.relativize(leaf_internal_prefix_index[0][j][0] - 
                                (leaf_internal_len_low[0][j-1] + leaf_internal_len_high[0][j-1] * 0x100 + leaf_internal_prefix_index[0][j-1][0] + leaf_node_not_padding[0] - leaf_internal_second_prefix_is_last[0][j-1] + 1), 0));
                            consts.push_back(context_object.relativize(leaf_internal_prefix_rlc[0][j][0] - (leaf_internal_rlc[0][j-1][leaf_data_size-1] * 53 + leaf_internal_prefix[0][j][0]), 0));
                        }
                        consts.push_back(context_object.relativize(leaf_internal_prefix_index[0][j][1] - (1 - leaf_internal_second_prefix_is_last[0][j]) * (leaf_internal_prefix_index[0][j][0] + leaf_node_not_padding[0]), 0));
                        consts.push_back(context_object.relativize(leaf_internal_prefix_rlc[0][j][1] - ((1 - leaf_internal_second_prefix_is_last[0][j]) * (leaf_internal_prefix_rlc[0][j][0] * 53 + leaf_internal_prefix[0][j][1]) + leaf_internal_second_prefix_is_last[0][j] * leaf_internal_prefix_rlc[0][j][0]), 0));
                        consts.push_back(context_object.relativize(leaf_internal_index[0][j][0] - (1 - leaf_internal_second_prefix_is_last[0][j]) - leaf_internal_prefix_index[0][j][0] - leaf_node_not_padding[0], 0));
                        consts.push_back(context_object.relativize(leaf_internal_rlc[0][j][0] - (leaf_internal_prefix_rlc[0][j][1] * 53 + leaf_internal_data[0][j][0]), 0));

                        consts.push_back(context_object.relativize(leaf_internal_data[0][j][0] * leaf_internal_is_last[0][j][0], 0));
                        for (size_t k = 1; k < leaf_data_size; k++) {
                            consts.push_back(context_object.relativize((1 - leaf_internal_is_last[0][j][k]) * leaf_internal_is_last[0][j][k], 0));
                            consts.push_back(context_object.relativize((1 - leaf_internal_is_last[0][j][k]) * leaf_internal_is_last[0][j][k-1], 0));
                            
                            consts.push_back(context_object.relativize(leaf_node_not_padding[0] * (leaf_internal_index_is_last_R[0][j][k] - (1 - 
                                leaf_internal_index_is_last_I[0][j][k] * ((leaf_internal_len_low[0][j] + leaf_internal_len_high[0][j] * 0x100) - (leaf_internal_index[0][j][k] - leaf_internal_index[0][j][0] + 1)))), 0));
                            consts.push_back(context_object.relativize(((leaf_internal_len_low[0][j] + leaf_internal_len_high[0][j] * 0x100) - (leaf_internal_index[0][j][k] - leaf_internal_index[0][j][0] + 1)) * leaf_internal_index_is_last_R[0][j][k], 0));
                            consts.push_back(context_object.relativize(leaf_internal_is_last[0][j][k] - leaf_internal_index_is_last_R[0][j][k] - leaf_internal_is_last[0][j][k-1], 0));
                            consts.push_back(context_object.relativize(leaf_internal_index[0][j][k] * leaf_internal_is_last[0][j][k-1], 0));
                            consts.push_back(context_object.relativize((leaf_internal_index[0][j][k] - leaf_internal_index[0][j][k-1] - 1) * (1 - leaf_internal_is_last[0][j][k-1]), 0));
                            consts.push_back(context_object.relativize(leaf_internal_data[0][j][k] * leaf_internal_is_last[0][j][k-1], 0));
                            consts.push_back(context_object.relativize(leaf_internal_rlc[0][j][k] - (leaf_internal_is_last[0][j][k-1] * leaf_internal_rlc[0][j][k-1] + (1 - leaf_internal_is_last[0][j][k-1]) * (leaf_internal_rlc[0][j][k-1] * 53 + leaf_internal_data[0][j][k])), 0));
                        }
                    }

                    for (size_t i = 0; i < consts.size(); i++) {
                        context_object.relative_constrain(consts[i], 0, max_mpt_hasher_size - 1);
                    }
                // for (size_t i = 0; i < max_mpt_hasher_size; i++) {
                    // constrain(node_type[i] * (1 - node_type[i]) * (2 - node_type[i]));
                    // r[i] = 1 -> node is leaf (type 2)
                    // constrain((2 - node_type[i]) * r[i]);
                    // node.encoded[i][0] if [0xc0, 0xf7] 
                    // constrain(r[i] * (32 - node.encoded[i][3]) *
                    //           (48 - node.encoded[i][3]));  // change this to
                                                                // first-nibble isntead
    //                 std::vector<TYPE> node_rlp_lookup = {
    //                     leaf_node_prefix[i][0], 
    //                     leaf_node_prefix[i][1],
    //                     leaf_node_prefix[i][2],
    //                     0,
    //                     0,
    //                     0,
    //                     leaf_node_len_low[i], 
    //                     leaf_node_len_high[i],
    //                     leaf_node_second_prefix_is_last[i],
    //                     leaf_node_third_prefix_is_last[i]
    //                 };
    //                 std::vector<TYPE> key_rlp_lookup = {
    //                     leaf_internal_prefix[i][0][0],
    //                     leaf_internal_prefix[i][0][1],
    //                     0,
    //                     leaf_internal_first_element[i][0],
    //                     leaf_internal_first_element_flag[i][0],
    //                     1,
    //                     leaf_internal_len_low[i][0], 
    //                     leaf_internal_len_high[i][0],
    //                     // 1,
    //                     leaf_internal_second_prefix_is_last[i][0],
    //                     1
    //                 };

    //                 std::vector<TYPE> value_rlp_lookup = {
    //                     leaf_internal_prefix[i][1][0],
    //                     leaf_internal_prefix[i][1][1],
    //                     0,
    //                     leaf_internal_first_element[i][1],
    //                     leaf_internal_first_element_flag[i][1],
    //                     1,
    //                     leaf_internal_len_low[i][1], 
    //                     leaf_internal_len_high[i][1],
    //                     leaf_internal_second_prefix_is_last[i][1],
    //                     1
    //                 };

    //                 std::vector<TYPE> keccak_lookup = {
    //                     1,
    //                     leaf_internal_rlc[i][1][leaf_data_size-1] * leaf_node_not_padding[i],
    //                     leaf_node_hash_high[i],
    //                     leaf_node_hash_low[i]
    //                 };
    //                 lookup(node_rlp_lookup, "rlp_table");
    //                 lookup(key_rlp_lookup, "rlp_table");
    //                 lookup(value_rlp_lookup, "rlp_table");
    //                 lookup(keccak_lookup, "keccak_table");
    //                 constrain(leaf_node_second_prefix_is_last[i]*(1 - leaf_node_second_prefix_is_last[i]));
    //                 constrain(leaf_node_prefix[i][1] * leaf_node_second_prefix_is_last[i]);
    //                 constrain(leaf_node_prefix[i][2] * leaf_node_third_prefix_is_last[i]);
    //                 constrain(leaf_internal_second_prefix_is_last[i][1] * (1 - leaf_internal_second_prefix_is_last[i][1]));
    //                 constrain(leaf_internal_second_prefix_is_last[i][0] * (1 - leaf_internal_second_prefix_is_last[i][0]));
    //                 constrain(leaf_node_not_padding[i] * (leaf_node_prefix_rlc[i][0] - 
    // /* total length */      ((1 + 1 - leaf_node_second_prefix_is_last[i] + 1 - leaf_node_third_prefix_is_last[i] + leaf_node_len_low[i] + 0x100 * leaf_node_len_high[i])
    //                         * 53 + leaf_node_prefix[i][0])));

    //                 constrain(leaf_node_prefix_rlc[i][1] - ((1 - leaf_node_second_prefix_is_last[i]) * (leaf_node_prefix_rlc[i][0] * 53 + leaf_node_prefix[i][1]) + leaf_node_second_prefix_is_last[i] * leaf_node_prefix_rlc[i][0]));
    //                 constrain(leaf_node_prefix_rlc[i][2] - ((1 - leaf_node_third_prefix_is_last[i]) *  (leaf_node_prefix_rlc[i][1] * 53 + leaf_node_prefix[i][2]) + leaf_node_third_prefix_is_last[i] * leaf_node_prefix_rlc[i][1]));

    //                 constrain(leaf_node_not_padding[i] * (-(leaf_node_len_low[i] + 0x100 * leaf_node_len_high[i])
    //                         + leaf_internal_len_low[i][0] + 0x100 * leaf_internal_len_high[i][0] 
    //                         + leaf_internal_len_low[i][1] + 0x100 * leaf_internal_len_high[i][1] 
    //                         + 3 - leaf_internal_second_prefix_is_last[i][1]));

    //                 // node first rlp prefix is always keccak 0 index
    //                 constrain(leaf_node_prefix_index[i][0] - (1 - leaf_node_second_prefix_is_last[i]));
    //                 constrain(leaf_node_prefix_index[i][1] * leaf_node_third_prefix_is_last[i] + (2-leaf_node_prefix_index[i][1])*(1-leaf_node_third_prefix_is_last[i]));
    //                 for (size_t j = 0; j < 2; j++) {
    //                     if (j == 0) {
    //                         constrain(leaf_internal_prefix_index[i][j][0] - leaf_node_not_padding[i] - (1 - leaf_node_second_prefix_is_last[i]) + (1 - leaf_node_third_prefix_is_last[i]));
    //                         constrain(leaf_internal_prefix_rlc[i][j][0] - (leaf_node_prefix_rlc[i][2] * 53 + leaf_internal_prefix[i][0][0]));
    //                     } else {
    //                         constrain(leaf_internal_prefix_index[i][j][0] - 
    //                             (leaf_internal_len_low[i][j-1] + leaf_internal_len_high[i][j-1] * 0x100 + leaf_internal_prefix_index[i][j-1][0] + leaf_node_not_padding[i] - leaf_internal_second_prefix_is_last[i][j-1] + 1));
    //                         constrain(leaf_internal_prefix_rlc[i][j][0] - (leaf_internal_rlc[i][j-1][leaf_data_size-1] * 53 + leaf_internal_prefix[i][j][0]));
    //                     }
    //                     constrain(leaf_internal_prefix_index[i][j][1] - (1 - leaf_internal_second_prefix_is_last[i][j]) * (leaf_internal_prefix_index[i][j][0] + leaf_node_not_padding[i]));
    //                     constrain(leaf_internal_prefix_rlc[i][j][1] - ((1 - leaf_internal_second_prefix_is_last[i][j]) * (leaf_internal_prefix_rlc[i][j][0] * 53 + leaf_internal_prefix[i][j][1]) + leaf_internal_second_prefix_is_last[i][j] * leaf_internal_prefix_rlc[i][j][0]));
    //                     constrain(leaf_internal_index[i][j][0] - (1 - leaf_internal_second_prefix_is_last[i][j]) - leaf_internal_prefix_index[i][j][0] - leaf_node_not_padding[i]);
    //                     constrain(leaf_internal_rlc[i][j][0] - (leaf_internal_prefix_rlc[i][j][1] * 53 + leaf_internal_data[i][j][0]));

    //                     constrain(leaf_internal_data[i][j][0] * leaf_internal_is_last[i][j][0]);
    //                     for (size_t k = 1; k < leaf_data_size; k++) {
    //                         constrain((1 - leaf_internal_is_last[i][j][k]) * leaf_internal_is_last[i][j][k]);
    //                         constrain((1 - leaf_internal_is_last[i][j][k]) * leaf_internal_is_last[i][j][k-1]);
                            
    //                         constrain(leaf_node_not_padding[i] * (leaf_internal_index_is_last_R[i][j][k] - (1 - 
    //                             leaf_internal_index_is_last_I[i][j][k] * ((leaf_internal_len_low[i][j] + leaf_internal_len_high[i][j] * 0x100) - (leaf_internal_index[i][j][k] - leaf_internal_index[i][j][0] + 1)))));
    //                         constrain(((leaf_internal_len_low[i][j] + leaf_internal_len_high[i][j] * 0x100) - (leaf_internal_index[i][j][k] - leaf_internal_index[i][j][0] + 1)) * leaf_internal_index_is_last_R[i][j][k]);
    //                         constrain(leaf_internal_is_last[i][j][k] - leaf_internal_index_is_last_R[i][j][k] - leaf_internal_is_last[i][j][k-1]);
    //                         constrain(leaf_internal_index[i][j][k] * leaf_internal_is_last[i][j][k-1]);
    //                         constrain((leaf_internal_index[i][j][k] - leaf_internal_index[i][j][k-1] - 1) * (1 - leaf_internal_is_last[i][j][k-1]));
    //                         constrain(leaf_internal_data[i][j][k] * leaf_internal_is_last[i][j][k-1]);
    //                         constrain(leaf_internal_rlc[i][j][k] - (leaf_internal_is_last[i][j][k-1] * leaf_internal_rlc[i][j][k-1] + (1 - leaf_internal_is_last[i][j][k-1]) * (leaf_internal_rlc[i][j][k-1] * 53 + leaf_internal_data[i][j][k])));
    //                     }
    //                 }
    //         }
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

        void encode_node_data(std::size_t index, std::size_t total_length, std::size_t &rlp_encoding_index, std::vector<std::uint8_t> &hash_input, TYPE &rlc_accumulator, TYPE rlc_challenge) {
            rlp_encoding_index = 0;
            if (total_length > 55) {
                std::size_t length_length = 0;
                std::size_t temp = total_length;

                while(temp > 0) {
                    temp >>= 8;
                    length_length ++;
                }
                leaf_node_prefix[index][0] = 0xF7 + length_length;
                leaf_node_prefix[index][1] = total_length;
                leaf_node_prefix[index][2] = 0;
                leaf_node_prefix_index[index][0] = rlp_encoding_index+1;

                leaf_node_second_prefix_is_last[index] = 0;
                leaf_node_third_prefix_is_last[index] = 1;

                hash_input[rlp_encoding_index++] = 0xF7 + length_length;
                hash_input[rlp_encoding_index++] = total_length;

                leaf_node_prefix_rlc[index][0] = (total_length+2) * rlc_challenge + leaf_node_prefix[index][0];
                rlc_accumulator = leaf_node_prefix_rlc[index][0];
                leaf_node_prefix_rlc[index][1] = rlc_accumulator * rlc_challenge + leaf_node_prefix[index][1];
                rlc_accumulator = leaf_node_prefix_rlc[index][1];
                leaf_node_prefix_rlc[index][2] = rlc_accumulator;
            } else {
                leaf_node_prefix[index][0] = 0xC0 + total_length;
                leaf_node_second_prefix_is_last[index] = 1;
                leaf_node_third_prefix_is_last[index] = 1;
                leaf_node_prefix_index[index][0] = 0;

                hash_input[rlp_encoding_index++] = uint8_t((0xC0 + total_length) & 0xFF);
                leaf_node_prefix_rlc[index][0] = (total_length+1) * rlc_challenge + leaf_node_prefix[index][0];
                rlc_accumulator = leaf_node_prefix_rlc[index][0];
                leaf_node_prefix_rlc[index][1] = rlc_accumulator;
                leaf_node_prefix_rlc[index][2] = rlc_accumulator;
            }

            leaf_node_len_low[index] = total_length & 0xFF;
            leaf_node_len_high[index] = (total_length >> 8) & 0xFF;
            leaf_node_not_padding[index] = 1;
        }

        void store_node_hash(std::size_t index, zkevm_word_type hash) {
            leaf_node_hash_low[index] = w_lo<FieldType>(hash);
            leaf_node_hash_high[index] = w_hi<FieldType>(hash);
        }

        void encode_leaf_data(std::size_t index, std::vector<zkevm_word_type> key, std::vector<zkevm_word_type> value, std::size_t& rlp_encoding_index, std::vector<std::uint8_t> &hash_input, TYPE &rlc_accumulator, TYPE rlc_challenge) {
            std::vector<std::vector<zkevm_word_type>> data = {key, value}; 
            for (size_t i = 0; i < data.size(); i++) {
                // std::cout <<"    value = ";
                auto d = data[i];
                for (size_t j = 0; j < d.size(); j++) {
                    // if (d[j] <= 0x0F)
                    //     std::cout <<"0" << std::hex << d[j] << std::dec;
                    // else
                    //     std::cout << std::hex << d[j] << std::dec;
                    leaf_internal_data[index][i][j] = d[j];
                    leaf_internal_is_last[index][i][j] = 0;
                }
                if (d.size() > 0) {
                    leaf_internal_is_last[index][i][d.size() - 1] = 1;
                }
                if (d.size() == 0 || (d.size() == 1 && d[0] < 128)) {
                    if (d.size() == 1)
                        leaf_internal_first_element[index][i] = d[0];
                    leaf_internal_first_element_flag[index][i] = 1;
                } else {
                    leaf_internal_first_element_flag[index][i] = 0;
                }
                // std::cout << " size: " << d.size();
                // std::cout << std::endl;
            }
            // std::cout << "]" << std::endl;

            if (key.size() == 1) { // first byte of key in leaf nodes is always less than 0x7F due to leaf node encoding
                // TODO child_prefix_is_last[nodenum][0][0] must be true
            } else if (key.size() <= 33) {
                leaf_internal_prefix[index][0][0] = 0x80 + key.size();
                leaf_internal_second_prefix_is_last[index][0] = 1;
                leaf_internal_prefix_index[index][0][0] = rlp_encoding_index;

                hash_input[rlp_encoding_index++] = uint8_t(0x80 + key.size());

                leaf_internal_prefix_rlc[index][0][0] = rlc_accumulator * rlc_challenge + leaf_internal_prefix[index][0][0];
                rlc_accumulator = leaf_internal_prefix_rlc[index][0][0];
                leaf_internal_prefix_rlc[index][0][1] = rlc_accumulator;
            }

            leaf_internal_len_low[index][0] = key.size();
            leaf_internal_len_high[index][0] = 0;
            // maximum lengths: 
            //      rlp encoded leaf node = 144 + 2 bytes
            //      key = 33 bytes
            //      value = 108 bytes
            //      rlp encoded key = 34 bytes
            //      rlp encoded value = 110 bytes


            for (size_t j = 0; j < key.size(); j++) {
                leaf_internal_index[index][0][j] = rlp_encoding_index;
                hash_input[rlp_encoding_index++] = uint8_t(key[j]);

                leaf_internal_rlc[index][0][j] = rlc_accumulator * rlc_challenge + leaf_internal_data[index][0][j];
                rlc_accumulator = leaf_internal_rlc[index][0][j];
            }
            for (size_t j = key.size(); j < leaf_internal_rlc[index][0].size(); j++) {
                leaf_internal_rlc[index][0][j] = rlc_accumulator;
            }
            
            if (value.size() == 1 && value[0] <= 0x7F) {
                // TODO
            } else if (value.size() <= 55) {
                leaf_internal_prefix[index][1][0] = 0x80 + value.size();
                leaf_internal_prefix_index[index][1][0] = rlp_encoding_index;
                hash_input[rlp_encoding_index++] = uint8_t(0x80 + value.size());

                leaf_internal_prefix_rlc[index][1][0] = rlc_accumulator * rlc_challenge + leaf_internal_prefix[index][1][0];
                rlc_accumulator = leaf_internal_prefix_rlc[index][1][0];
                leaf_internal_prefix_rlc[index][1][1] = rlc_accumulator;
            } else {
                leaf_internal_prefix[index][1][0] = 0xB8;
                leaf_internal_prefix_index[index][1][0] = rlp_encoding_index;
                leaf_internal_prefix[index][1][1] = value.size();
                leaf_internal_prefix_index[index][1][1] = rlp_encoding_index+1;
                leaf_internal_second_prefix_is_last[index][1] = 0;
                
                hash_input[rlp_encoding_index++] = uint8_t(0xB8);
                hash_input[rlp_encoding_index++] = value.size();

                leaf_internal_prefix_rlc[index][1][0] = rlc_accumulator * rlc_challenge + leaf_internal_prefix[index][1][0];
                rlc_accumulator = leaf_internal_prefix_rlc[index][1][0];
                leaf_internal_prefix_rlc[index][1][1] = rlc_accumulator * rlc_challenge + leaf_internal_prefix[index][1][1];
                rlc_accumulator = leaf_internal_prefix_rlc[index][1][1];
            }

            leaf_internal_len_low[index][1] = value.size();
            leaf_internal_len_high[index][1] = 0;

            for (size_t j = 0; j < value.size(); j++) {
                leaf_internal_index[index][1][j] = rlp_encoding_index;
                hash_input[rlp_encoding_index++] = uint8_t(value[j]);

                leaf_internal_rlc[index][1][j] = rlc_accumulator * rlc_challenge + leaf_internal_data[index][1][j];
                rlc_accumulator = leaf_internal_rlc[index][1][j];
            }
            for (size_t j = value.size(); j < leaf_internal_rlc[index][1].size(); j++) {
                leaf_internal_rlc[index][1][j] = rlc_accumulator;
            }


            for (size_t k = 0; k < 2; k++) {
                TYPE len = leaf_internal_len_low[index][k] + leaf_internal_len_high[index][k] * 0x100;
                for (size_t j = 0; j < 110; j++) {
                    if ( leaf_internal_index[index][k][j] - leaf_internal_index[index][k][0] == len - 1) {
                        leaf_internal_index_is_last_I[index][k][j] = 0;
                    } else {
                        leaf_internal_index_is_last_I[index][k][j] = 
                            (len - 1 - (leaf_internal_index[index][k][j] - leaf_internal_index[index][k][0])).inversed();
                    }
                    leaf_internal_index_is_last_R[index][k][j] = 1 - 
                        (len - 1 - (leaf_internal_index[index][k][j] - leaf_internal_index[index][k][0])) 
                        * leaf_internal_index_is_last_I[index][k][j];
                }
            }
        }

        zkevm_word_type calculate_keccak(std::vector<std::uint8_t> hash_input, std::size_t total_length) {
            std::vector<uint8_t> buffer(hash_input.begin(), hash_input.begin() + total_length);
            zkevm_word_type hash = nil::blueprint::zkevm_keccak_hash(buffer);
            return hash;
        }

        void print_leaf_node(std::size_t index, zkevm_word_type hash, size_t key_data_len, size_t value_data_len) {
            TYPE hash_low = w_lo<FieldType>(hash);
            TYPE hash_high = w_hi<FieldType>(hash);

            std::cout << "rlp prefix:" << std::endl;
            std::cout << "\tdata\tindex\n";

            std::cout << "\t" << std::hex << leaf_node_prefix[index][0] << std::dec << "\t"
                      << std::hex << hash_high << std::dec << "\t"
                      << std::hex << hash_low << std::dec << "\t"
                      << std::hex << 0 << std::dec << std::endl;
            std::cout << "\t" << std::hex << leaf_node_prefix[index][1] << std::dec << "\t"
                      << std::hex << leaf_node_prefix_index[index][0] << std::dec << std::endl;
            std::cout << "\t" << std::hex << leaf_node_prefix[index][2] << std::dec << "\t"
                      << std::hex << leaf_node_prefix_index[index][1] << std::dec << std::endl;
            
            std::cout << "node rlp second prefix is last:\n "
                      << std::hex << leaf_node_second_prefix_is_last[index] << std::dec << std::endl;
            std::cout << "node rlp len low and high: \n"
                      << std::hex << leaf_node_len_low[index] << std::dec << "\t"
                      << std::hex << leaf_node_len_high[index] << std::dec << std::endl;
            
            std::cout << "key prefix: \n\tdata\tindex\n\t";
            std::cout << std::hex << leaf_internal_prefix[index][0][0] << std::dec << "\t"
                      << std::hex << leaf_internal_prefix_index[index][0][0] << std::dec << std::endl;
            std::cout << "second is last\tlen_low\tlen_high\tfirst_element_flag\tfirst_element\n\t";
            std::cout << std::hex << leaf_internal_second_prefix_is_last[index][0] << std::dec << "\t"
                      << std::hex << leaf_internal_len_low[index][0] << std::dec << "\t"
                      << std::hex << leaf_internal_len_high[index][0] << std::dec << "\t\t"
                      << std::hex << leaf_internal_first_element_flag[index][0] << std::dec << "\t\t"
                      << std::hex << leaf_internal_first_element[index][0] << std::dec << std::endl;


            std::cout << "key:\n\tdata\tindex\n";
            for (size_t i = 0; i < key_data_len; i++) {
                std::cout << "\t"
                          << std::hex << leaf_internal_data[index][0][i] << std::dec << "\t" 
                          << std::hex << leaf_internal_index[index][0][i] << std::dec << std::endl;
            }
        
            std::cout << "value prefix: \n\tdata\tindex\n";
            std::cout << "\t" << std::hex << leaf_internal_prefix[index][1][0] << std::dec << "\t" 
                      << std::hex << leaf_internal_prefix_index[index][1][0] << std::dec << std::endl;
            std::cout << "\t" << std::hex << leaf_internal_prefix[index][1][1] << std::dec << "\t"  
                      << std::hex << leaf_internal_prefix_index[index][1][1] << std::dec << std::endl;

            std::cout << "second is last\tlen_high\tlen_low\tfirst_element_flag\tfirst_element\n\t";
            std::cout << std::hex << leaf_internal_second_prefix_is_last[index][1] << std::dec << "\t"
                      << std::hex << leaf_internal_len_high[index][1] << std::dec << "\t"
                      << std::hex << leaf_internal_len_low[index][1] << std::dec << "\t"
                      << std::hex << leaf_internal_first_element_flag[index][1] << std::dec << "\t\t"
                      << std::hex << leaf_internal_first_element[index][1] << std::dec << std::endl;
            std::cout << "value: \n";
            for (size_t i = 0; i < value_data_len; i++) {
                std::cout << "\t"
                          << std::hex << leaf_internal_data[index][1][i] << std::dec << "\t" 
                          << std::hex << leaf_internal_index[index][1][i] << std::dec << std::endl;
            }
        }
    
      protected:
        // leaf-nodes node
        std::vector<TYPE> leaf_node_not_padding;
        std::vector<std::array<TYPE, 3>> leaf_node_prefix;
        std::vector<std::array<TYPE, 3>> leaf_node_prefix_rlc;
        // the first rlp prefix is not last and its hash and index is known
        std::vector<TYPE> leaf_node_second_prefix_is_last;
        std::vector<TYPE> leaf_node_third_prefix_is_last;
        std::vector<std::array<TYPE, 2>> leaf_node_prefix_index;
        std::vector<TYPE> leaf_node_len_low;
        std::vector<TYPE> leaf_node_len_high;
        std::vector<TYPE> leaf_node_hash_low;
        std::vector<TYPE> leaf_node_hash_high;

        // leaf-nodes internals
        std::vector<std::array<std::array<TYPE, 110>, 2>> leaf_internal_data;
        std::vector<std::array<std::array<TYPE, 110>, 2>> leaf_internal_index;
        std::vector<std::array<std::array<TYPE, 110>, 2>> leaf_internal_index_is_last_I;
        std::vector<std::array<std::array<TYPE, 110>, 2>> leaf_internal_index_is_last_R;
        std::vector<std::array<std::array<TYPE, 110>, 2>> leaf_internal_is_last;
        std::vector<std::array<std::array<TYPE, 110>, 2>> leaf_internal_rlc;
        std::vector<std::array<std::array<TYPE, 2>,   2>> leaf_internal_prefix;
        std::vector<std::array<std::array<TYPE, 2>,   2>> leaf_internal_prefix_index;
        std::vector<std::array<std::array<TYPE, 2>,   2>> leaf_internal_prefix_rlc;
        std::vector<std::array<TYPE, 2>> leaf_internal_second_prefix_is_last;
        // lengths without considering rlp prefixes
        std::vector<std::array<TYPE, 2>> leaf_internal_len_low;
        std::vector<std::array<TYPE, 2>> leaf_internal_len_high;
        // first element flag for rlp lookup
        std::vector<std::array<TYPE, 2>> leaf_internal_first_element_flag;
        std::vector<std::array<TYPE, 2>> leaf_internal_first_element;
        std::vector<TYPE> node_type;

    };
}  // namespace nil::blueprint::bbf
