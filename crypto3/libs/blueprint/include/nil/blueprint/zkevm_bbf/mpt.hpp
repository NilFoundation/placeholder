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

#include <nil/blueprint/blueprint/plonk/assignment.hpp>
#include <nil/blueprint/blueprint/plonk/circuit.hpp>
#include <nil/blueprint/component.hpp>

#include <nil/blueprint/bbf/generic.hpp>
#include <nil/blueprint/zkevm_bbf/util.hpp>
#include <nil/blueprint/zkevm_bbf/subcomponents/rlp_table.hpp>

namespace nil::blueprint::bbf {

    enum mpt_node_type { extension = 0, branch = 1, leaf = 2 };

    struct mpt_node {
        enum mpt_node_type type;
        std::vector<std::vector<zkevm_word_type>> value;
    };

    struct mpt_path {
        zkevm_word_type slotNumber;  // TODO change this
        std::vector<mpt_node> proof;
    };

    class mpt_paths_vector : public std::vector<mpt_path> {};

    template<typename FieldType, GenerationStage stage>
    class mpt : public generic_component<FieldType, stage> {
        using typename generic_component<FieldType, stage>::context_type;
        using RLPTable = typename bbf::rlp_table<FieldType, stage>;
        using generic_component<FieldType, stage>::allocate;
        using generic_component<FieldType, stage>::copy_constrain;
        using generic_component<FieldType, stage>::constrain;
        using generic_component<FieldType, stage>::lookup;
        using generic_component<FieldType, stage>::lookup_table;

      public:
        using typename generic_component<FieldType, stage>::table_params;
        using typename generic_component<FieldType, stage>::TYPE;

        using input_type =
            typename std::conditional<stage == GenerationStage::ASSIGNMENT,
                                      mpt_paths_vector, std::nullptr_t>::type;

        using value = typename FieldType::value_type;
        using integral_type = nil::crypto3::multiprecision::big_uint<257>;

        static table_params get_minimal_requirements(std::size_t max_mpt_size) {
            return {
                    .witnesses = 13141,
                    .public_inputs = 0,
                    .constants = 0,
                    .rows = max_mpt_size + 2178};
        }

        static void allocate_public_inputs(context_type &context, input_type &input,
                                           std::size_t max_mpt_size) {}

        mpt(context_type &context_object, const input_type &input,
            std::size_t max_mpt_size)
            : generic_component<FieldType, stage>(context_object) {

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

            std::array<std::vector<std::array<TYPE, 110>>, 16> child;
            std::array<std::vector<std::array<TYPE, 110>>, 16> child_hashes_low;
            std::array<std::vector<std::array<TYPE, 110>>, 16> child_hashes_high;
            std::array<std::vector<std::array<TYPE, 110>>, 16> child_hashes_indices;
            std::array<std::vector<std::array<TYPE, 110>>, 16> child_hashes_indices_is_last_I;
            std::array<std::vector<std::array<TYPE, 110>>, 16> child_hashes_indices_is_last_R;
            std::array<std::vector<std::array<TYPE, 110>>, 16> child_is_last;

            std::vector<std::array<std::uint8_t, 532>> hash_input(max_mpt_size);
            std::vector<std::array<TYPE, 532>> node_rlp_encoded(max_mpt_size);

            std::vector<std::array<TYPE, 3>> node_rlp_prefix(max_mpt_size);
            // the first rlp prefix is not last and its hash and index is known
            std::vector<TYPE> node_rlp_second_prefix_is_last(max_mpt_size);
            std::vector<TYPE> node_rlp_third_prefix_is_last(max_mpt_size);
            std::vector<std::array<TYPE, 2>> node_rlp_prefix_hashes_low(max_mpt_size);
            std::vector<std::array<TYPE, 2>> node_rlp_prefix_hashes_high(max_mpt_size);
            std::vector<std::array<TYPE, 2>> node_rlp_prefix_hashes_indices(max_mpt_size);
            std::vector<TYPE> node_rlp_len_low(max_mpt_size);
            std::vector<TYPE> node_rlp_len_high(max_mpt_size);

            std::vector<std::array<std::array<TYPE, 2>, 16>> child_rlp_prefix(max_mpt_size);
            std::vector<std::array<std::array<TYPE, 2>, 16>> child_rlp_prefix_hashes_low(max_mpt_size);
            std::vector<std::array<std::array<TYPE, 2>, 16>> child_rlp_prefix_hashes_high(max_mpt_size);
            std::vector<std::array<std::array<TYPE, 2>, 16>> child_rlp_prefix_hashes_indices(max_mpt_size);
            std::vector<std::array<TYPE, 16>> child_rlp_second_prefix_is_last(max_mpt_size);

            // lengths without considering rlp prefixes
            std::vector<std::array<TYPE, 16>> child_rlp_len_low(max_mpt_size);
            std::vector<std::array<TYPE, 16>> child_rlp_len_high(max_mpt_size);
            // first element flag for rlp lookup
            std::vector<std::array<TYPE, 16>> child_rlp_first_element_flag(max_mpt_size);
            std::vector<std::array<TYPE, 16>> child_rlp_first_element(max_mpt_size);


            for (std::size_t i = 0; i < 16; i++) {
                child[i].resize(max_mpt_size);
                child_hashes_low[i].resize(max_mpt_size);
                child_hashes_high[i].resize(max_mpt_size);
                child_hashes_indices[i].resize(max_mpt_size);
                child_hashes_indices_is_last_I[i].resize(max_mpt_size);
                child_hashes_indices_is_last_R[i].resize(max_mpt_size);
                child_is_last[i].resize(max_mpt_size);
            }
            
            if constexpr (stage == GenerationStage::ASSIGNMENT) {
                for (std::size_t i = 0; i < 16; i++) {
                    for (size_t j = 0; j < max_mpt_size; j++) {
                        child_rlp_first_element_flag[j][i] = 0;
                        for (size_t k = 0; k < 110; k++) {
                            child_is_last[i][j][k] = 1;
                        }
                    }
                }
                for (size_t i = 0; i < max_mpt_size; i++) {
                    node_rlp_second_prefix_is_last[i] = 1;
                    // node_rlp_len_low_is_last[i] = 1;
                    // node_rlp_len_high_is_last[i] = 1;
                    for (size_t j = 0; j < 16; j++)
                    {
                        child_rlp_second_prefix_is_last[i][j] = 1;
                        // child_rlp_len_low_is_last[i][j] = 1;
                        // child_rlp_len_high_is_last[i][j] = 1;
                    }
                }

                // assignment
                for (auto &p : input) {  // enumerate paths
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
                            if (n.type != branch) {
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
                                    child[child_num][node_num][i] = v[i];
                                    child_is_last[child_num][node_num][i] = 0;
                                }
                                if (v.size() > 0) {
                                    child_is_last[child_num][node_num][v.size() - 1] = 1;
                                }
                                if (v.size() == 0 || (v.size() == 1 && v[0] < 128)) {
                                    if (v.size() == 1)
                                        child_rlp_first_element[node_num][child_num] = v[0];
                                    else
                                        child_rlp_first_element[node_num][child_num] = 0;
                                    child_rlp_first_element_flag[node_num][child_num] = 1;
                                }
                                std::cout << " size: " << v.size();
                            }
                            child_num++;
                            std::cout << std::endl;
                        }
                        std::cout << "]" << std::endl;

                        if (n.type == leaf) {
                            zkevm_word_type key_first_byte = n.value.at(0)[0];
                            size_t key_length = n.value.at(0).size();
                            zkevm_word_type key_first_nibble;
                            if (key_first_byte > 0x0F) {
                                key_first_nibble =  key_first_byte >> 4;
                            } else {
                                key_first_nibble = key_first_byte;
                            }
                            std::size_t key_rlp_encoded_length;
                            if (key_length == 1 && key_first_byte <= 0x7F) {
                                key_rlp_encoded_length = key_length;
                            } else if (key_length <= 32) {
                                key_rlp_encoded_length = key_length + 1;
                            } else {
                                // TODO throw error
                            }



                            size_t value_length = n.value.at(1).size();
                            TYPE value_first_byte = child[1][node_num][0];
                            size_t value_rlp_encoded_length;
                            
                            if (value_length == 1 && value_first_byte <= 0x7F) {
                                value_rlp_encoded_length = value_length;
                            } else if (value_length <= 55) {
                                value_rlp_encoded_length = value_length + 1;
                            } else if (value_length <= 110) {
                                value_rlp_encoded_length = value_length + 2;
                            } else {
                                // TODO throw error
                            }

                            std::size_t total_length = key_rlp_encoded_length + value_rlp_encoded_length;
                            std::cout << "total length " << total_length << " " << key_rlp_encoded_length << " " << value_rlp_encoded_length << " " << n.value.at(1).size() << std::endl;
                            std::size_t rlp_encoding_index = 0;
                            
                            if (total_length > 55) {

                                std::size_t length_length = 0;
                                std::size_t temp = total_length;

                                while(temp > 0) {
                                    temp >>= 8;
                                    length_length ++;
                                }
                                node_rlp_prefix[node_num][0] = 0xF7 + length_length;
                                node_rlp_prefix[node_num][1] = total_length;
                                node_rlp_prefix[node_num][2] = 0;
                                node_rlp_prefix_hashes_indices[node_num][0] = rlp_encoding_index+1;

                                node_rlp_second_prefix_is_last[node_num] = 0;
                                node_rlp_third_prefix_is_last[node_num] = 1;

                                hash_input[node_num][rlp_encoding_index] = 0xF7 + length_length;
                                node_rlp_encoded[node_num][rlp_encoding_index ++] = 0xF7 + length_length;
                                hash_input[node_num][rlp_encoding_index] = total_length;
                                node_rlp_encoded[node_num][rlp_encoding_index ++] = total_length;
                            } else {
                                node_rlp_prefix[node_num][0] = 0xC0 + total_length;
                                node_rlp_second_prefix_is_last[node_num] = 1;
                                node_rlp_third_prefix_is_last[node_num] = 1;
                                node_rlp_prefix_hashes_indices[node_num][0] = 0;

                                hash_input[node_num][rlp_encoding_index] = uint8_t((0xC0 + total_length) & 0xFF);
                                node_rlp_encoded[node_num][rlp_encoding_index ++] = 0xC0 + total_length;
                            }

                            node_rlp_len_low[node_num] = total_length & 0xFF;
                            node_rlp_len_high[node_num] = (total_length >> 8) & 0xFF;

                            if (key_length == 1) { // first byte of key in leaf nodes is always less than 0x7F due to leaf node encoding
                                // TODO child_rlp_prefix_is_last[nodenum][0][0] must be true
                                // child_rlp_prefix[node_num][0][0] = 0x80 + key_length;

                                // hash_input[node_num][rlp_encoding_index] = uint8_t(0x80 + key_length);
                                // node_rlp_encoded[node_num][rlp_encoding_index ++] = 0x80 + key_length;
                            } else if (key_length <= 33) {
                                child_rlp_prefix[node_num][0][0] = 0x80 + key_length;
                                child_rlp_second_prefix_is_last[node_num][0] = 1;
                                child_rlp_prefix_hashes_indices[node_num][0][0] = rlp_encoding_index;
                                child_rlp_prefix_hashes_indices[node_num][0][1] = 0;

                                hash_input[node_num][rlp_encoding_index] = uint8_t(0x80 + key_length);
                                node_rlp_encoded[node_num][rlp_encoding_index ++] = 0x80 + key_length;

                            } else if (key_length > 33) {
                                // TODO throw error
                            }

                            child_rlp_len_low[node_num][0] = key_length;
                            child_rlp_len_high[node_num][0] = 0;
                            // maximum lengths: 
                            //      rlp encoded leaf node = 144 + 2 bytes
                            //      key = 33 bytes
                            //      value = 108 bytes
                            //      rlp encoded key = 34 bytes
                            //      rlp encoded value = 110 bytes


                            for (size_t j = 0; j < key_length; j++) {
                                zkevm_word_type kj = n.value.at(0)[j];
                                hash_input[node_num][rlp_encoding_index] = uint8_t(kj);
                                child_hashes_indices[0][node_num][j] = rlp_encoding_index;
                                node_rlp_encoded[node_num][rlp_encoding_index ++ ] = kj;
                            }
                            if (value_length == 1 && value_first_byte <= 0x7F) {
                                // TODO
                            } else if (value_length <= 55) {
                                child_rlp_prefix[node_num][1][0] = 0x80 + value_length;
                                child_rlp_prefix_hashes_indices[node_num][1][0] = rlp_encoding_index;
                                child_rlp_prefix_hashes_indices[node_num][1][1] = 0;
                                hash_input[node_num][rlp_encoding_index] = uint8_t(0x80 + value_length);
                                node_rlp_encoded[node_num][rlp_encoding_index ++] = 0x80 + value_length;
                            } else if (value_length <= 110) {
                                child_rlp_prefix[node_num][1][0] = 0xB8;
                                child_rlp_prefix_hashes_indices[node_num][1][0] = rlp_encoding_index;
                                child_rlp_prefix[node_num][1][1] = value_length;
                                child_rlp_prefix_hashes_indices[node_num][1][1] = rlp_encoding_index+1;
                                child_rlp_second_prefix_is_last[node_num][1] = 0;
                                

                                hash_input[node_num][rlp_encoding_index] = uint8_t(0xB8);
                                node_rlp_encoded[node_num][rlp_encoding_index ++] = 0xB8;
                                hash_input[node_num][rlp_encoding_index] = value_length;
                                node_rlp_encoded[node_num][rlp_encoding_index ++] = value_length;
                            } else if (value_length > 110) {
                                // TODO throw error
                            }

                            child_rlp_len_low[node_num][1] = value_length;
                            child_rlp_len_high[node_num][1] = 0;

                            for (size_t j = 0; j < value_length; j++) {
                                zkevm_word_type kj = n.value.at(1)[j];
                                hash_input[node_num][rlp_encoding_index] = uint8_t(kj);
                                child_hashes_indices[1][node_num][j] = rlp_encoding_index;
                                node_rlp_encoded[node_num][rlp_encoding_index ++] = kj;
                            }

                            std::cout << "printing: " << std::endl;
                            for (size_t i = 0; i < rlp_encoding_index; i++)
                            {
                                if (node_rlp_encoded[node_num][i] <= 0xF)
                                    std::cout << "0" << std::hex << node_rlp_encoded[node_num][i] << std::dec;
                                else
                                    std::cout << std::hex << node_rlp_encoded[node_num][i] << std::dec;
                            }
                            std::vector<uint8_t> buffer(hash_input[node_num].begin(), hash_input[node_num].begin()+rlp_encoding_index);
                            zkevm_word_type hash = nil::blueprint::zkevm_keccak_hash(buffer);
                            TYPE hash_low = w_lo<FieldType>(hash);
                            TYPE hash_high = w_hi<FieldType>(hash);
                            std::cout << "\nnode hash = " << std::hex << hash << std::dec << std::endl;
                            std::cout << std::endl;



                            // rlp_encoding_index = 1;

                            if (total_length > 55) {
                                // node_rlp_prefix_hashes_low[node_num][0] = hash_low;
                                // node_rlp_prefix_hashes_high[node_num][0] = hash_high;

                                node_rlp_prefix_hashes_low[node_num][0] = hash_low;
                                node_rlp_prefix_hashes_high[node_num][0] = hash_high;
                                // node_rlp_prefix_hashes_indices[node_num][0] = rlp_encoding_index++;
                            } 
                            // else {
                                // node_rlp_prefix_hashes_low[node_num][0] = hash_low;
                                // node_rlp_prefix_hashes_high[node_num][0] = hash_high;
                                // rlp_encoding_index++;
                            // }
                            // node_rlp_prefix_hashes_indices[node_num][1] = 0;
                            node_rlp_prefix_hashes_low[node_num][1] = 0;
                            node_rlp_prefix_hashes_high[node_num][1] = 0;

                            if (key_length == 1 && key_first_byte > 0x7F || key_length <= 32) {
                                child_rlp_prefix_hashes_low[node_num][0][0] = hash_low;
                                child_rlp_prefix_hashes_high[node_num][0][0] = hash_high;
                                // child_rlp_prefix_hashes_indices[node_num][0][0] = rlp_encoding_index++;
                            }

                            for (size_t j = 0; j < key_length; j++) {
                                child_hashes_low[0][node_num][j] = hash_low;
                                child_hashes_high[0][node_num][j] = hash_high;
                                // child_hashes_indices[0][node_num][j] = rlp_encoding_index;
                                // TYPE kj = (n.value.at(0) >> 8 * (key_length - j - 1)) & 0xFF;
                                node_rlp_encoded[node_num][rlp_encoding_index ++ ] = child[0][node_num][j];
                            }




                            if (value_length == 1 && value_first_byte <= 0x7F) {
                                // TODO
                            } else if (value_length <= 55) {
                                child_rlp_prefix_hashes_low[node_num][1][0] = hash_low;
                                child_rlp_prefix_hashes_high[node_num][1][0] = hash_high;
                                rlp_encoding_index++;
                            } else if (value_length <= 110) {
                                child_rlp_prefix_hashes_low[node_num][1][0] = hash_low;
                                child_rlp_prefix_hashes_high[node_num][1][0] = hash_high;
                                rlp_encoding_index++;
                                child_rlp_prefix_hashes_low[node_num][1][1] = hash_low;
                                child_rlp_prefix_hashes_high[node_num][1][1] = hash_high;
                                rlp_encoding_index++;
                            } else if (value_length > 110) {
                                // TODO throw error
                            }

                            for (size_t j = 0; j < value_length; j++) {
                                child_hashes_low[1][node_num][j] = hash_low;
                                child_hashes_high[1][node_num][j] = hash_high;
                                // child_hashes_indices[1][node_num][j] = rlp_encoding_index;
                                // TYPE kj = (n.value.at(0) >> 8 * (key_length - j - 1)) & 0xFF;
                                // node_rlp_encoded[node_num][rlp_encoding_index ++ ] = child[1][node_num][j];
                            }


                            for (size_t k = 0; k < 16; k++) {
                                TYPE len = child_rlp_len_low[node_num][k] + child_rlp_len_high[node_num][k] * 0x100;
                                for (size_t j = 0; j < 110; j++) {
                                    if ( child_hashes_indices[k][node_num][j] - child_hashes_indices[k][node_num][0] == len - 1) {
                                        child_hashes_indices_is_last_I[k][node_num][j] = 0;
                                    } else {
                                        child_hashes_indices_is_last_I[k][node_num][j] = 
                                            (len - 1 - (child_hashes_indices[k][node_num][j] - child_hashes_indices[k][node_num][0])).inversed();
                                    }
                                    child_hashes_indices_is_last_R[k][node_num][j] = 1 - 
                                        (len - 1 - (child_hashes_indices[k][node_num][j] - child_hashes_indices[k][node_num][0])) 
                                        * child_hashes_indices_is_last_I[k][node_num][j];
                                    // if (k < 2 && j > 0) {
                                    //     std::cout << "is last " << len << " " << j << " " << child_is_last[k][node_num][j] << " "
                                    //         << child_hashes_indices_is_last_R[k][node_num][j] << std::endl;
                                    // }
                                }
                            }

                 


                            std::cout << "rlp prefix:" << std::endl;
                            std::cout << "\tdata\thash_lower\t\t\t\thash_higher\t\t\t\tindex\n";

                            std::cout << "\t" << std::hex << node_rlp_prefix[node_num][0] << std::dec << "\t"
                                      << std::hex << hash_low << std::dec << "\t"
                                      << std::hex << hash_high << std::dec << "\t"
                                      << std::hex << 0 << std::dec << std::endl;
                            std::cout << "\t" << std::hex << node_rlp_prefix[node_num][1] << std::dec << "\t"
                                      << std::hex << node_rlp_prefix_hashes_low[node_num][0] << std::dec << "\t"
                                      << std::hex << node_rlp_prefix_hashes_high[node_num][0] << std::dec << "\t"
                                      << std::hex << node_rlp_prefix_hashes_indices[node_num][0] << std::dec << std::endl;
                            std::cout << "\t" << std::hex << node_rlp_prefix[node_num][2] << std::dec << "\t"
                                      << std::hex << node_rlp_prefix_hashes_low[node_num][1] << std::dec << "\t"
                                      << std::hex << node_rlp_prefix_hashes_high[node_num][1] << std::dec << "\t"
                                      << std::hex << node_rlp_prefix_hashes_indices[node_num][1] << std::dec << std::endl;
                            
                            std::cout << "node rlp second prefix is last:\n "
                                      << std::hex << node_rlp_second_prefix_is_last[node_num] << std::dec << std::endl;
                            std::cout << "node rlp len low and high: \n"
                                      << std::hex << node_rlp_len_low[node_num] << std::dec << "\t"
                                      << std::hex << node_rlp_len_high[node_num] << std::dec << std::endl;
                            
                            std::cout << "key prefix: \n\tdata\thash_low\t\t\t\thash_high\t\t\t\tindex\n\t";
                            std::cout << std::hex << child_rlp_prefix[node_num][0][0] << std::dec << "\t"
                                      << std::hex << child_rlp_prefix_hashes_low[node_num][0][0] << std::dec << "\t"
                                      << std::hex << child_rlp_prefix_hashes_high[node_num][0][0] << std::dec << "\t"
                                      << std::hex << child_rlp_prefix_hashes_indices[node_num][0][0] << std::dec << std::endl;
                            std::cout << "second is last\tlen_low\tlen_high\tfirst_element_flag\tfirst_element\n\t";
                            std::cout << std::hex << child_rlp_second_prefix_is_last[node_num][0] << std::dec << "\t"
                                      << std::hex << child_rlp_len_low[node_num][0] << std::dec << "\t"
                                      << std::hex << child_rlp_len_high[node_num][0] << std::dec << "\t\t"
                                      << std::hex << child_rlp_first_element_flag[node_num][0] << std::dec << "\t\t"
                                      << std::hex << child_rlp_first_element[node_num][0] << std::dec << std::endl;


                            std::cout << "key: \n\tdata\thash_low\t\t\t\thash_high\t\t\t\tindex\n";
                            for (size_t i = 0; i < key_length; i++) {
                                std::cout << "\t"
                                          << std::hex << child[0][node_num][i] << std::dec << "\t" 
                                          << std::hex << child_hashes_low[0][node_num][i] << std::dec << "\t"
                                          << std::hex << child_hashes_high[0][node_num][i] << std::dec << "\t" 
                                          << std::hex << child_hashes_indices[0][node_num][i] << std::dec << std::endl;
                            }
                            


                            std::cout << "value prefix: \n\tdata\thash_low\t\t\t\thash_high\t\t\t\tindex\n";
                            std::cout << "\t" << std::hex << child_rlp_prefix[node_num][1][0] << std::dec << "\t" 
                                      << std::hex << child_rlp_prefix_hashes_low[node_num][1][0] << std::dec << "\t"
                                      << std::hex << child_rlp_prefix_hashes_high[node_num][1][0] << std::dec << "\t" 
                                      << std::hex << child_rlp_prefix_hashes_indices[node_num][1][0] << std::dec << std::endl;
                            std::cout << "\t" << std::hex << child_rlp_prefix[node_num][1][1] << std::dec << "\t" 
                                      << std::hex << child_rlp_prefix_hashes_low[node_num][1][1] << std::dec << "\t" 
                                      << std::hex << child_rlp_prefix_hashes_high[node_num][1][1] << std::dec << "\t" 
                                      << std::hex << child_rlp_prefix_hashes_indices[node_num][1][1] << std::dec << std::endl;

                            std::cout << "second is last\tlen_low\tlen_high\tfirst_element_flag\tfirst_element\n\t";
                            std::cout << std::hex << child_rlp_second_prefix_is_last[node_num][11] << std::dec << "\t"
                                      << std::hex << child_rlp_len_low[node_num][1] << std::dec << "\t"
                                      << std::hex << child_rlp_len_high[node_num][1] << std::dec << "\t"
                                      << std::hex << child_rlp_first_element_flag[node_num][1] << std::dec << "\t\t"
                                      << std::hex << child_rlp_first_element[node_num][1] << std::dec << std::endl;
                            std::cout << "value: \n";
                            for (size_t i = 0; i < value_length; i++) {
                                std::cout << i << " " << std::hex << child[1][node_num][i] << std::dec << "\t" 
                                          << std::hex << child_hashes_low[1][node_num][i] << std::dec << "\t" 
                                          << std::hex << child_hashes_high[1][node_num][i] << std::dec << "\t" 
                                          << std::hex << child_hashes_indices[1][node_num][i] << std::dec << std::endl;
                            }
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
                allocate(node_rlp_len_low[i], column_index ++, i);
                allocate(node_rlp_len_high[i], column_index ++, i);
                // prefix
                allocate(node_rlp_prefix[i][0], column_index ++, i);
                allocate(node_rlp_second_prefix_is_last[i], column_index ++, i);
                allocate(node_rlp_third_prefix_is_last[i], column_index ++, i);
                allocate(node_rlp_prefix[i][1], column_index ++, i);
                allocate(node_rlp_prefix_hashes_low[i][0], column_index ++, i);
                allocate(node_rlp_prefix_hashes_high[i][0], column_index ++, i);
                allocate(node_rlp_prefix_hashes_indices[i][0], column_index ++, i);
                allocate(node_rlp_prefix[i][2], column_index ++, i);
                allocate(node_rlp_prefix_hashes_low[i][1], column_index ++, i);
                allocate(node_rlp_prefix_hashes_high[i][1], column_index ++, i);
                allocate(node_rlp_prefix_hashes_indices[i][1], column_index ++, i);
                //encoding
                for (size_t j = 0; j < 532; j++) {
                    allocate(node_rlp_encoded[i][j], column_index++, i);
                }

                // children
                for (std::size_t j = 0; j < 16; j++) {
                    // rlp len
                    allocate(child_rlp_len_low[i][j], column_index ++, i);
                    allocate(child_rlp_len_high[i][j], column_index ++, i);
                    // prefix
                    allocate(child_rlp_prefix[i][j][0], column_index++, i);
                    allocate(child_rlp_prefix_hashes_low[i][j][0], column_index++, i);
                    allocate(child_rlp_prefix_hashes_high[i][j][0], column_index++, i);
                    allocate(child_rlp_prefix_hashes_indices[i][j][0], column_index++, i);
                    allocate(child_rlp_prefix[i][j][1], column_index++, i);
                    allocate(child_rlp_prefix_hashes_low[i][j][1], column_index++, i);
                    allocate(child_rlp_prefix_hashes_high[i][j][1], column_index++, i);
                    allocate(child_rlp_prefix_hashes_indices[i][j][1], column_index++, i);
                    allocate(child_rlp_second_prefix_is_last[i][j], column_index++, i);

                    // encoding
                    for (std::size_t k = 0; k < 110; k++) {
                        allocate(child[j][i][k], column_index++, i);
                        allocate(child_is_last[j][i][k], column_index++, i);
                        allocate(child_hashes_low[j][i][k], column_index++, i);
                        allocate(child_hashes_high[j][i][k], column_index++, i);
                        allocate(child_hashes_indices[j][i][k], column_index++, i);
                        allocate(child_hashes_indices_is_last_I[j][i][k], column_index++, i);
                        allocate(child_hashes_indices_is_last_R[j][i][k], column_index++, i);
                    }
                }

            }

            for (std::size_t i = 0; i < RLPTable::get_witness_amount(); i++) {
                rlp_lookup_area.push_back(i);
            }
            context_type rlp_ct = context_object.subcontext(
                rlp_lookup_area, 5, 2178);

            RLPTable rlpt = RLPTable(rlp_ct);


            // std::cout << "node types \n";
            // for (size_t i = 0; i < max_mpt_size; i++) {
            //     std::cout << node_type[i] << " " << node_type[i] * (1 - node_type[i]) * (2 - node_type[i]) << "\n";
            // }
            // std::cout << std::hex << node_rlp_prefix[4][0] << std::dec << " " <<
            // std::hex << node_rlp_prefix[4][1] << std::dec << " " <<
            // std::hex << node_rlp_prefix[4][2] << std::dec << " " <<
            // std::hex << 0 << std::dec << " " <<
            // std::hex << 0 << std::dec << " " <<
            // std::hex << 0 << std::dec << " " <<
            // std::hex << node_rlp_len_low[4] << std::dec << " " <<
            // std::hex << node_rlp_len_high[4] << std::dec << std::endl;


            if constexpr (stage == GenerationStage::CONSTRAINTS) {
                for (size_t i = 0; i < max_mpt_size; i++) {
                    constrain(node_type[i] * (1 - node_type[i]) * (2 - node_type[i]));
                    // r[i] = 1 -> node is leaf (type 2)
                    // constrain((2 - node_type[i]) * r[i]);
                    // node_rlp_encoded[i][0] if [0xc0, 0xf7] 
                    // constrain(r[i] * (32 - node_rlp_encoded[i][3]) *
                    //           (48 - node_rlp_encoded[i][3]));  // change this to
                                                                // first-nibble isntead
                }



                std::vector<TYPE> node_rlp_lookup = {
                    node_rlp_prefix[4][0], 
                    node_rlp_prefix[4][1],
                    node_rlp_prefix[4][2],
                    0,
                    0,
                    0,
                    node_rlp_len_low[4], 
                    node_rlp_len_high[4],
                    node_rlp_second_prefix_is_last[4],
                    node_rlp_third_prefix_is_last[4]
                };

                std::vector<TYPE> key_rlp_lookup = {
                    child_rlp_prefix[4][0][0],
                    child_rlp_prefix[4][0][1],
                    0,
                    child_rlp_first_element[4][0],
                    child_rlp_first_element_flag[4][0],
                    1,
                    child_rlp_len_low[4][0], 
                    child_rlp_len_high[4][0],
                    // 1,
                    child_rlp_second_prefix_is_last[4][0],
                    1
                };

                std::vector<TYPE> value_rlp_lookup = {
                    child_rlp_prefix[4][1][0],
                    child_rlp_prefix[4][1][1],
                    0,
                    child_rlp_first_element[4][1],
                    child_rlp_first_element_flag[4][1],
                    1,
                    child_rlp_len_low[4][1], 
                    child_rlp_len_high[4][1],
                    child_rlp_second_prefix_is_last[4][1],
                    1
                };
                lookup(node_rlp_lookup, "rlp_table");
                lookup(key_rlp_lookup, "rlp_table");
                lookup(value_rlp_lookup, "rlp_table");
                constrain(child_rlp_second_prefix_is_last[4][1] * (1 - child_rlp_second_prefix_is_last[4][1]));

                constrain(-(node_rlp_len_low[4] + 0x100 * node_rlp_len_high[4])
                          + child_rlp_len_low[4][0] + 0x100 * child_rlp_len_high[4][0] 
                          + child_rlp_len_low[4][1] + 0x100 * child_rlp_len_high[4][1] 
                          + 3 - child_rlp_second_prefix_is_last[4][1]);

                // node first rlp prefix is keccak 0 index
                constrain(node_rlp_prefix_hashes_indices[4][0] - (1 - node_rlp_second_prefix_is_last[4]));
                constrain(node_rlp_prefix_hashes_indices[4][1] * node_rlp_third_prefix_is_last[4] + (2-node_rlp_prefix_hashes_indices[4][1])*(1-node_rlp_third_prefix_is_last[4]));
                for (size_t k = 0; k < 2; k++) {
                    if (k == 0) {
                        constrain(child_rlp_prefix_hashes_indices[4][k][0] - 1 - (1 - node_rlp_second_prefix_is_last[4]) + (1 - node_rlp_third_prefix_is_last[4]));
                    } else {
                        constrain(child_rlp_prefix_hashes_indices[4][k][0] - 
                            (child_rlp_len_low[4][k-1] + child_rlp_len_high[4][k-1] * 0x100 + child_rlp_prefix_hashes_indices[4][k-1][0] + 1 - child_rlp_second_prefix_is_last[4][k-1] + 1));
                    }
                    constrain(child_rlp_prefix_hashes_indices[4][k][1] - (1 - child_rlp_second_prefix_is_last[4][k])*(child_rlp_prefix_hashes_indices[4][k][0] + 1));
                    constrain(child_hashes_indices[k][4][0] - (1 - child_rlp_second_prefix_is_last[4][k]) - child_rlp_prefix_hashes_indices[4][k][0] - 1);
                    for (size_t i = 1; i < 110; i++) {
                        constrain((1 - child_is_last[k][4][i]) * child_is_last[k][4][i]);
    
                        constrain((1 - child_is_last[k][4][i]) * child_is_last[k][4][i-1]);
                        constrain(child_hashes_indices_is_last_R[k][4][i] - (1 - 
                            child_hashes_indices_is_last_I[k][4][i] * ((child_rlp_len_low[4][k] + child_rlp_len_high[4][k] * 0x100) - (child_hashes_indices[k][4][i] - child_hashes_indices[k][4][0] + 1))));
                        constrain(((child_rlp_len_low[4][k] + child_rlp_len_high[4][k] * 0x100) - (child_hashes_indices[k][4][i] - child_hashes_indices[k][4][0] + 1))*child_hashes_indices_is_last_R[k][4][i]);
                        constrain(child_is_last[k][4][i] - child_hashes_indices_is_last_R[k][4][i] - child_is_last[k][4][i-1]);
                        constrain(child_hashes_indices[k][4][i] * child_is_last[k][4][i-1]);
                        constrain((child_hashes_indices[k][4][i] - child_hashes_indices[k][4][i-1] - 1) * (1 - child_is_last[k][4][i-1]));
                    } 
                }
                
                // constrain(child_rlp_prefix_hashes_indices[4][0][1] - (1 - child_rlp_second_prefix_is_last[4][0])*(child_rlp_prefix_hashes_indices[4][0][0] + 1));
                // constrain(child_hashes_indices[0][4][0] - (1 - child_rlp_second_prefix_is_last[4][0]) - child_rlp_prefix_hashes_indices[4][0][0] - 1);
                // for (size_t i = 1; i < 110; i++) {
                //     constrain((1 - child_is_last[0][4][i]) * child_is_last[0][4][i]);

                //     constrain((1 - child_is_last[0][4][i]) * child_is_last[0][4][i-1]);
                //     constrain(child_hashes_indices_is_last_R[0][4][i] - (1 - 
                //         child_hashes_indices_is_last_I[0][4][i] * ((child_rlp_len_low[4][0] + child_rlp_len_high[4][0] * 0x100) - (child_hashes_indices[0][4][i] - child_hashes_indices[0][4][0] + 1))));
                //     constrain(((child_rlp_len_low[4][0] + child_rlp_len_high[4][0] * 0x100) - (child_hashes_indices[0][4][i] - child_hashes_indices[0][4][0] + 1))*child_hashes_indices_is_last_R[0][4][i]);
                //     constrain(child_is_last[0][4][i] - child_hashes_indices_is_last_R[0][4][i] - child_is_last[0][4][i-1]);
                //     constrain(child_hashes_indices[0][4][i] * child_is_last[0][4][i-1]);
                //     constrain((child_hashes_indices[0][4][i] - child_hashes_indices[0][4][i-1] - 1) * (1 - child_is_last[0][4][i-1]));
                // }

                  


                // tmp = {node_rlp_encoded[4][0], node_rlp_encoded[4][1], node_rlp_len_low[4], node_rlp_len_high[4]};
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
    };
}  // namespace nil::blueprint::bbf
