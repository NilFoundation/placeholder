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

#include <nil/crypto3/zk/snark/arithmetization/plonk/constraint_system.hpp>
#include <nil/crypto3/bench/scoped_profiler.hpp>

#include <nil/blueprint/blueprint/plonk/assignment.hpp>
#include <nil/blueprint/blueprint/plonk/circuit.hpp>
#include <nil/blueprint/component.hpp>

#include <nil/blueprint/bbf/generic.hpp>
#include <nil/blueprint/zkevm_bbf/util.hpp>
#include <nil/blueprint/zkevm_bbf/subcomponents/child_hash_table.hpp>

namespace nil::blueprint::bbf {

enum mpt_node_type { extension = 0, branch = 1, leaf = 2 };

struct mpt_node {
   enum mpt_node_type type;
   std::vector<zkevm_word_type> value;
};

struct mpt_path {
    zkevm_word_type slotNumber; // TODO change this
    std::vector<mpt_node> proof;
};

class mpt_paths_vector : public std::vector<mpt_path> {
};

template<typename FieldType, GenerationStage stage>
class mpt : public generic_component<FieldType, stage> {
    using typename generic_component<FieldType, stage>::context_type;
    using generic_component<FieldType, stage>::allocate;
    using generic_component<FieldType, stage>::copy_constrain;
    using generic_component<FieldType, stage>::constrain;
    using generic_component<FieldType, stage>::lookup;
    using generic_component<FieldType, stage>::lookup_table;
    using ChildTable = child_hash_table<FieldType, stage>;

public:
    using typename generic_component<FieldType, stage>::table_params;
    using typename generic_component<FieldType, stage>::TYPE;

    using input_type = typename std::conditional<stage==GenerationStage::ASSIGNMENT, mpt_paths_vector, std::nullptr_t>::type;

    using value = typename FieldType::value_type;
    using integral_type = nil::crypto3::multiprecision::big_uint<257>;

    static table_params get_minimal_requirements(std::size_t max_mpt_size) {
        return {
            .witnesses = 1000,
            .public_inputs = 0,
            .constants = 0,
            .rows = max_mpt_size + max_mpt_size + 40
        };
    }

    static void allocate_public_inputs(
            context_type &context, input_type &input,
            std::size_t max_mpt_size) {}

    mpt(context_type &context_object,
        const input_type &input,
        std::size_t max_mpt_size) : generic_component<FieldType,stage>(context_object) {

        using integral_type = typename FieldType::integral_type;

        std::array<std::vector<TYPE>,32> parent_hash;           // parent_hash[32][max_mpt_size]
        std::array<std::array<std::vector<TYPE>,32>,16> child;  // child[16][32][max_mpt_size]
        // rlp_child: the RLP prefix of each child
        std::array<std::vector<TYPE>,16> rlp_child;             // rlp_child[16][max_mpt_size]
        std::array<std::vector<TYPE>,32> key_part;              // key_part[32][max_mpt_size]
        std::vector<TYPE> key_part_length(max_mpt_size);        // key_part_length[max_mpt_size]
        std::vector<TYPE> node_type(max_mpt_size);              // node_type[max_mpt_size]
        std::vector<TYPE> depth(max_mpt_size);                  // depth[max_mpt_size]

        // key_prefix: the RLP prefix key (for ext and leaf nodes)
        std::array<std::vector<TYPE>,32> key_prefix;            // key_prefix[32][max_mpt_size]
        // rlp_node: the RLP prefix of each node (has max 3 bytes)
        std::array<std::vector<TYPE>,3> rlp_node;               // rlp_node[3][max_mpt_size]
        std::vector<TYPE> is_padding(max_mpt_size);             // is_padding[max_mpt_size]
        std::array<std::vector<TYPE>,16> child_sum_inverse;     // child_sum_inverse[16][max_mpt_size]

        // child0_length_bytes: size of key in bytes (for ext and leaf nodes)
        std::vector<TYPE> child0_length_bytes(max_mpt_size);    // child0_length_bytes[max_mpt_size]

        // child1_length_bytes: size of value in bytes (for ext fixed = 32 and leaf nodes)
        std::vector<TYPE> child1_length_bytes(max_mpt_size);    // child1_length_bytes[max_mpt_size]

        // node_num_of_bytes: number of bytes that compose the size of node = 1 or 2
        std::vector<TYPE> node_num_of_bytes(max_mpt_size);      // node_num_of_bytes[max_mpt_size]

        // node_length: bytes that compose the size of node 
        std::array<std::vector<TYPE>,2> node_length;            // node_length[2][max_mpt_size]

        // child_choice: selector columns -> 1 for the right child, 0 for all the rest
        std::array<std::vector<TYPE>,16> child_choice;          // child_choice[16][max_mpt_size]

        std::array<std::vector<TYPE>,32> correct_child_hash;    // correct_child_hash[32][max_mpt_size]
        std::array<std::vector<TYPE>,32> key_reconstruct;       // key_reconstruct[32][max_mpt_size]
        std::array<std::vector<TYPE>,32> key_concatenation;     // key_concatenation[32][max_mpt_size]

        for(std::size_t i = 0; i < 32; i++) {
            parent_hash[i].resize(max_mpt_size);
            correct_child_hash[i].resize(max_mpt_size);
            key_reconstruct[i].resize(max_mpt_size);
            key_concatenation[i].resize(max_mpt_size);
            for(std::size_t j = 0; j < 16; j++) {
                child[j][i].resize(max_mpt_size);
            }
            key_part[i].resize(max_mpt_size);
            key_prefix[i].resize(max_mpt_size);
        }

        for(std::size_t i = 0; i < 16; i++) {
            rlp_child[i].resize(max_mpt_size);
            child_sum_inverse[i].resize(max_mpt_size);
            child_choice[i].resize(max_mpt_size);
        }

        for(std::size_t i = 0; i < 3; i++) {
            rlp_node[i].resize(max_mpt_size);
        }
        for(std::size_t i = 0; i < 2; i++) {
            node_length[i].resize(max_mpt_size);
        }

        // input for child_hash_table
        typename ChildTable::input_type child_hash_tab_input;
        std::vector<TYPE> child_vector(35);
        std::vector<TYPE> table_test_input(max_mpt_size);
        // columns of child_hash_table
        std::vector<std::size_t> child_hash_lookup_area;
        std::vector<std::size_t> table_lookup_area;
        std::vector<TYPE> path_num(max_mpt_size);

        if constexpr (stage == GenerationStage::ASSIGNMENT) {
           // assignment
           std::size_t node_num = 0;

           for(auto &p : input) { // enumerate paths
               std::cout << "slot number = " << std::hex << p.slotNumber << std::dec << std::endl;

               std::array<uint8_t,32> slotNumber = w_to_8(p.slotNumber);
               std::vector<uint8_t> buffer(slotNumber.begin(), slotNumber.end());
               zkevm_word_type path_key = nil::blueprint::zkevm_keccak_hash(buffer);
               std::cout << "path key = " << std::hex << path_key << std::dec << std::endl;

               zkevm_word_type key_suffix = path_key;
               zkevm_word_type accumulated_key = path_key;
               std::size_t accumulated_length = 0;
               std::size_t node_depth = 0;

               for(auto &n : p.proof) {
                   std::cout << "node type = " << n.type << std::endl;
                   std::cout << "[" << std::endl;

                   std::size_t node_key_length = 0;     // size of key in each node (bytes)- for branch = 1
                   std::size_t node_value_length = 0;   // size of value in each node (bytes) - for ext/leaf nodes
                   std::size_t node_key_bytes = 0;      // num of bytes in key
                   std::size_t node_value_bytes = 0;    // num of bytes in value
                   std::size_t total_value_length = 0;  // total size of value to be hashed

                   if (n.type != branch) { // extension or leaf
                        std::vector<uint8_t> hash_input;
                        zkevm_word_type first_value = n.value.at(0);
                        while(first_value > 0) {
                            first_value >>= 4;
                            node_key_length++;
                        }
                        node_key_bytes = ceil(node_key_length/2);
                        child0_length_bytes[node_num] = node_key_bytes;

                        std::array<uint8_t,32> key_value = w_to_8(n.value.at(0));
                        std::vector<uint8_t> byte_vector;
                        size_t rlp_key_prefix;

                        for(std::size_t i = (32 - node_key_bytes); i < 32; i++) {
                            byte_vector.push_back(key_value[i]);
                        }

                        if (node_key_bytes != 1){
                            rlp_key_prefix = 128 + node_key_bytes;
                            byte_vector.emplace(byte_vector.begin(), rlp_key_prefix);
                        }
                        else{
                            rlp_key_prefix = 0;
                        }
                        rlp_child[0][node_num] = rlp_key_prefix;

                        hash_input.insert( hash_input.end(), byte_vector.begin(), byte_vector.end() );

                        zkevm_word_type k0 = n.value.at(0) >> 4*(node_key_length - 1);
                        if ((k0 == 1) || (k0 == 3)) {
                            node_key_length--; // then we only skip the first hex symbol
                        } else {
                            node_key_length -= 2; // otherwise, the second hex is 0 and we skip it too
                        }

                        if (n.type == extension) {
                            size_t rlp_value_prefix,  rlp_node_prefix0, rlp_node_prefix1;
                            std::array<uint8_t,32> node_value = w_to_8(n.value.at(1));

                            std::vector<uint8_t> byte_vector(node_value.begin(), node_value.end());
                            rlp_value_prefix = 128 + 32;
                            rlp_child[1][node_num] = rlp_value_prefix;
                            child1_length_bytes[node_num] = 32;
                            byte_vector.emplace(byte_vector.begin(), rlp_value_prefix);
                            hash_input.insert( hash_input.end(), byte_vector.begin(), byte_vector.end() );
                            total_value_length = hash_input.size();

                            if (node_key_bytes + 34 <= 55){
                                rlp_node_prefix0 = 192 + 34;
                                rlp_node[0][node_num] = rlp_node_prefix0;
                                node_length[0][node_num] = total_value_length;
                                node_num_of_bytes[node_num] = 1;
                                hash_input.emplace(hash_input.begin(), rlp_node_prefix0);
                            }
                            else{
                                rlp_node_prefix1 = node_key_bytes + 34;
                                rlp_node_prefix0 = 247 + 1;
                                rlp_node[1][node_num] = rlp_node_prefix1;
                                rlp_node[0][node_num] = rlp_node_prefix0;
                                node_length[0][node_num] = total_value_length;
                                node_num_of_bytes[node_num] = 1;
                                hash_input.emplace(hash_input.begin(), rlp_node_prefix1);
                                hash_input.emplace(hash_input.begin(), rlp_node_prefix0);
                            }
                            zkevm_word_type hash_value = nil::blueprint::zkevm_keccak_hash(hash_input);
                            std::array<std::uint8_t,32> hash_value_byte = w_to_8(hash_value);
                            for(std::size_t i = 0; i < 32; i++) {
                                parent_hash[i][node_num] = hash_value_byte[i];
                            }
                            std::cout << "hash value = " << std::hex << hash_value << std::dec << std::endl;
                        } else {
                            size_t rlp_value_prefix,  rlp_node_prefix0, rlp_node_prefix1;
                            zkevm_word_type second_value = n.value.at(1);
                            while(second_value > 0) {
                                second_value >>= 4;
                                node_value_length++;
                            }
                            node_value_bytes = ceil(node_value_length/2);
                            child1_length_bytes[node_num] = node_value_bytes;

                            std::array<uint8_t,32> node_value = w_to_8(n.value.at(1));
                            std::vector<uint8_t> byte_vector;
                            for(std::size_t i = (32 - node_value_bytes); i < 32; i++) {
                                byte_vector.push_back(node_value[i]);
                            }
                            rlp_value_prefix = 128 + node_value_bytes;
                            rlp_child[1][node_num] = rlp_value_prefix;
                            rlp_node_prefix0 = 192 + node_key_bytes + node_value_bytes + 2;
                            rlp_node[0][node_num] = rlp_node_prefix0;
                            byte_vector.emplace(byte_vector.begin(), rlp_value_prefix);
                            hash_input.insert( hash_input.end(), byte_vector.begin(), byte_vector.end() );
                            total_value_length = hash_input.size();
                            hash_input.emplace(hash_input.begin(), rlp_node_prefix0);

                            if (total_value_length <= 55){
                                node_length[0][node_num] = total_value_length;
                                node_num_of_bytes[node_num] = 1;
                            }
                            else if ( (total_value_length <= 256) && (total_value_length > 55) ){
                                node_length[0][node_num] = total_value_length;
                                node_num_of_bytes[node_num] = 1;
                            }
                            else{
                                node_length[1][node_num] = total_value_length & 0xff;
                                node_length[0][node_num] = (total_value_length - (total_value_length & 0xff)) >> 8;
                                node_num_of_bytes[node_num] = 2;
                            }

                            zkevm_word_type hash_value = nil::blueprint::zkevm_keccak_hash(hash_input);
                            std::array<std::uint8_t,32> hash_value_byte = w_to_8(hash_value);
                            for(std::size_t i = 0; i < 32; i++) {
                                parent_hash[i][node_num] = hash_value_byte[i];
                            }
                            std::cout << "hash value = " << std::hex << hash_value << std::dec << std::endl;
                        }
                   } else { // branch node
                       std::size_t count0 = 0;
                       std::size_t size_of_branch, s0, s1;
                       std::vector<uint8_t> hash_input;
                       size_t rlp_child_prefix, rlp_node_prefix0, rlp_node_prefix1, rlp_node_prefix2;
                       for(std::size_t i = 0; i < 16; i++) {
                            if (n.value.at(i) == 0){
                                rlp_child_prefix = 128;
                                hash_input.push_back(rlp_child_prefix);
                                count0++;
                            }
                            else{
                                rlp_child_prefix = 128 + 32;
                                std::array<uint8_t,32> branch_value = w_to_8(n.value.at(i));
                                std::vector<uint8_t> byte_vector(branch_value.begin(), branch_value.end());
                                byte_vector.emplace(byte_vector.begin(), rlp_child_prefix);
                                hash_input.insert( hash_input.end(), byte_vector.begin(), byte_vector.end() );
                            }
                            rlp_child[i][node_num] = rlp_child_prefix;
                       }
                       hash_input.push_back(128); //this is the RLP(value) for the value (which is always 0) in branch nodes

                       size_of_branch = count0 + 33*(16 - count0) + 1;

                       if (count0 < 9){
                            rlp_node_prefix2 = size_of_branch & 0xff;
                            rlp_node_prefix1 = (size_of_branch - rlp_node_prefix2) >> 8;
                            rlp_node_prefix0 = 247 + 2;
                            node_length[1][node_num] = size_of_branch & 0xff;
                            node_length[0][node_num] = (size_of_branch - rlp_node_prefix2) >> 8;
                            node_num_of_bytes[node_num] = 2;
                            hash_input.emplace(hash_input.begin(), rlp_node_prefix2);
                            hash_input.emplace(hash_input.begin(), rlp_node_prefix1);
                            hash_input.emplace(hash_input.begin(), rlp_node_prefix0);
                       }
                       else{
                            rlp_node_prefix2 = 0;
                            rlp_node_prefix1 = size_of_branch;
                            rlp_node_prefix0 = 247 + 1;
                            node_length[0][node_num] = size_of_branch;
                            node_num_of_bytes[node_num] = 1;
                            hash_input.emplace(hash_input.begin(), rlp_node_prefix1);
                            hash_input.emplace(hash_input.begin(), rlp_node_prefix0);
                       }
                       rlp_node[2][node_num] = rlp_node_prefix2;
                       rlp_node[1][node_num] = rlp_node_prefix1;
                       rlp_node[0][node_num] = rlp_node_prefix0;

                       zkevm_word_type hash_value = nil::blueprint::zkevm_keccak_hash(hash_input);
                       std::array<std::uint8_t,32> hash_value_byte = w_to_8(hash_value);
                       for(std::size_t i = 0; i < 32; i++) {
                           parent_hash[i][node_num] = hash_value_byte[i];
                       }

                       std::cout << "hash value = " << std::hex << hash_value << std::dec << std::endl;

                       node_key_length = 1;
                   }
                   key_part_length[node_num] = node_key_length;
                   std::cout << "Node key length = " << node_key_length << std::endl;

                   accumulated_length += node_key_length;
                   std::cout << "Accumulated length = " << accumulated_length << std::endl;

                   zkevm_word_type node_key_accumulated = accumulated_key >> 4*(64 - accumulated_length);
                   std::array<std::uint8_t,32> key_accumulated_byte = w_to_8(node_key_accumulated);
                   for(std::size_t i = 0; i < 32; i++) {
                        key_concatenation[i][node_num] = key_accumulated_byte[i];
                   }
                   std::cout << "accumulated key = " << std::hex << node_key_accumulated << std::dec << std::endl;

                   zkevm_word_type node_key_part = key_suffix >> 4*(64 - accumulated_length);
                   std::array<std::uint8_t,32> key_part_byte = w_to_8(node_key_part);
                   for(std::size_t i = 0; i < 32; i++) {
                       key_part[i][node_num] = key_part_byte[i];
                   }
                   std::cout << "Node key part = " << std::hex << node_key_part << std::dec << std::endl;

                   key_suffix &= (zkevm_word_type(1) << 4*(64 - accumulated_length)) - 1;
                   std::cout << "key suffix: " << std::hex << key_suffix << std::dec << std::endl;

                   node_type[node_num] = static_cast<size_t>(n.type);
                   depth[node_num] = node_depth;

                   std::array<std::uint8_t,32> path_key_byte = w_to_8(path_key);
                   for(std::size_t i = 0; i < 32; i++) {
                       key_prefix[i][node_num] = path_key_byte[i];
                   }

                   std::size_t child_num = 0;
                   for(auto &v : n.value) {
                       std::cout << "    value = " << std::hex << v << std::dec << std::endl;
                       if (child_num < 16) { // branch nodes have an empty 17-th value
                           std::array<std::uint8_t,32> child_value_byte = w_to_8(v);
                           for(std::size_t i = 0; i < 32; i++) {
                               child[child_num][i][node_num] = child_value_byte[i];
                           }
                       }
                       child_num++;
                   }
                   std::cout << "]" << std::endl;

                   is_padding[node_num] = 1;

                   node_num++;
                   node_depth++;
               }
           }

           for(std::size_t i = 0; i < node_num - 1 ; i++) {
               // in the only case we really need it, the key certainly fits into one (lowest) byte
               size_t key = static_cast<size_t>(key_part[31][i].data.base());
               child_choice[node_type[i] == 1 ? key : 1][i] = 1;
               for(std::size_t j = 0; j < 32; j++) { // j = 0,..,31 is the byte number
                   // std::cout << "Checking hash in row " << i << std::endl;
                   BOOST_ASSERT_MSG(child[node_type[i] == 1 ? key : 1][j][i] == parent_hash[j][i + 1], "hash does not match");
               }
           }

           for(std::size_t i = 0; i < node_num; i++) {
                size_t key = static_cast<size_t>(key_part[31][i].data.base());
                child_hash_tab_input.push_back(1);
                path_num[i] = 1;
                for(std::size_t b = 0; b < 32; b++) {
                    child_hash_tab_input.push_back(key_concatenation[b][i]);
                }
                for(std::size_t b = 0; b < 32; b++) {
                    if (i < node_num - 1){
                        correct_child_hash[b][i] = child[node_type[i] == 1 ? key : 1][b][i];
                        // child_hash_tab_input.push_back(child[node_type[i] == 1 ? key : 1][b][i]);
                    }
                }
           }

            for(std::size_t i = 0; i < node_num; i++) {
                for(std::size_t b = 0; b < 32; b++) {
                    key_reconstruct[b][i] = key_concatenation[b][i];
                }
            }
        }

        // allocation
        for(std::size_t i = 0; i < max_mpt_size; i++) {
            // columns 0-31
            for(std::size_t j = 0; j < 32; j++) {
                allocate(parent_hash[j][i],j,i);
            }
            // columns 32-543
            for(std::size_t j = 0; j < 16; j++) { // the 16 children
                for(std::size_t b = 0; b < 32; b++) { // the 32 bytes of each child
                    allocate(child[j][b][i], 32 + 32*j + b, i);
                }
            }
            // columns 544-559
            for(std::size_t j = 0; j < 16; j++) {
                allocate(rlp_child[j][i], 554 + j, i);
            }
            // columns 570-601
            for(std::size_t j = 0; j < 32; j++) {
                allocate(key_part[j][i], 570 + j, i);
            }
            allocate(key_part_length[i], 602,i);
            
            allocate(node_type[i],  603,i);
            allocate(depth[i],      604,i);

            // columns 605-636
            for(std::size_t j = 0; j < 32; j++) {
                allocate(key_prefix[j][i], 605 + j, i);
            }

            // columns 637-640
            for(std::size_t j = 0; j < 3; j++) {
                allocate(rlp_node[j][i],637 + j,i);
            }
            allocate(is_padding[i],       641,i);
            allocate(child0_length_bytes[i],       642,i);
            allocate(child1_length_bytes[i],       643,i);
            for(std::size_t j = 0; j < 2; j++) {
                allocate(node_length[j][i], 644 + j, i);
            }
            allocate(node_num_of_bytes[i],       646,i);
            for(std::size_t j = 0; j < 16; j++) {
                allocate(child_choice[j][i], 663 + j, i);
            }
            for(std::size_t j = 0; j < 32; j++) {
                allocate(key_concatenation[j][i], 679 + j, i);
            }
            allocate(path_num[i], 711, i);
            for(std::size_t j = 0; j < 32; j++) {
                allocate(key_reconstruct[j][i], j, max_mpt_size + i);
            }
            for(std::size_t j = 0; j < 32; j++) {
                allocate(correct_child_hash[j][i], 32 + j, max_mpt_size + i);
            }
        }

        std::vector<std::size_t> lookup_cols;
        for(std::size_t i = 0; i < 64; i++) {
            lookup_cols.push_back(i);
        }

        std::vector<TYPE> lookup_table_input(64);  
        lookup_table("dynamic_child_hash",lookup_cols,max_mpt_size,max_mpt_size + max_mpt_size);
        for(std::size_t i = 0; i < max_mpt_size - 1; i++) {
            for(std::size_t b = 0; b < 32; b++) {
                lookup_table_input[b] = key_concatenation[b][i];
            }
            for(std::size_t b = 0; b < 32; b++) {
                lookup_table_input[32 + b] = parent_hash[b][i + 1];
            }
            lookup(lookup_table_input,"dynamic_child_hash");
        }

        for(std::size_t i = 64; i < 97; i++) {
            table_lookup_area.push_back(i);
        }

        context_type test_ct = context_object.subcontext(table_lookup_area, max_mpt_size, max_mpt_size + max_mpt_size);
        std::cout << "max_mpt_size = " << max_mpt_size << std::endl;
        ChildTable ch_t(test_ct, child_hash_tab_input, max_mpt_size);

        std::vector<TYPE> lookup_table_sub_input(33);  
        for(std::size_t i = 0; i < max_mpt_size; i++) {
            lookup_table_sub_input[0] = path_num[i];
            for(std::size_t b = 0; b < 32; b++) {
                lookup_table_sub_input[b + 1] = key_concatenation[b][i];
            }
            // for(std::size_t b = 0; b < 32; b++) {
            //     lookup_table_sub_input[33 + b] = parent_hash[b][i + 1];
            // }
            lookup(lookup_table_sub_input,"child_hash_table");
        }

        std::array<std::vector<TYPE>,16> child_sum;     // these two are non-allocated expressions
        std::array<std::vector<TYPE>,16> child_is_zero; // child_is_zero[j] = 1 if child[j] = 0...0, 0 otherwise
        for(std::size_t j = 0; j < 16; j++) {
            child_sum[j].resize(max_mpt_size);
            child_is_zero[j].resize(max_mpt_size);
        }

        // constraints
        for(std::size_t i = 0; i < max_mpt_size; i++) {
            constrain(is_padding[i] * (1 - is_padding[i]) );
            for(std::size_t j = 0; j < 16; j++) {
                for(std::size_t b = 0; b < 32; b++) {
                    child_sum[j][i] += child[j][b][i];
                }
                if constexpr (stage == GenerationStage::ASSIGNMENT) {
                    child_sum_inverse[j][i] = child_sum[j][i].is_zero() ? 0 : child_sum[j][i].inversed();
                }
                allocate(child_sum_inverse[j][i], 647 + j, i);
                child_is_zero[j][i] = 1 - child_sum_inverse[j][i] * child_sum[j][i];
                constrain(child_sum[j][i] * child_is_zero[j][i]);
                
                // constraints for branch node RLP
                constrain(is_padding[i] * node_type[i] * (2 - node_type[i]) * (160 - rlp_child[j][i]) * (128 - rlp_child[j][i]) );
                constrain(is_padding[i] * node_type[i] * (2 - node_type[i]) * (247 + node_num_of_bytes[i] - rlp_node[0][i]) );
                constrain(is_padding[i] * node_type[i] * (2 - node_type[i]) * (node_length[0][i] - rlp_node[1][i]) );
                constrain(is_padding[i] * node_type[i] * (2 - node_type[i]) * (node_length[1][i] - rlp_node[2][i]) );
            }

            // constraints for extension node RLP
            constrain(is_padding[i] * (1 - node_type[i]) * (2 - node_type[i]) * (rlp_child[0][i]) * (128 + child0_length_bytes[i] - rlp_child[0][i]) );
            constrain(is_padding[i] * (1 - node_type[i]) * (2 - node_type[i]) * (160 - rlp_child[1][i]) );
            constrain(is_padding[i] * (1 - node_type[i]) * (2 - node_type[i]) * (rlp_node[2][i]) );
            constrain(is_padding[i] * (1 - node_type[i]) * (2 - node_type[i]) * (rlp_node[1][i]) * (node_length[0][i] - rlp_node[1][i]) );
            constrain(is_padding[i] * (1 - node_type[i]) * (2 - node_type[i]) * (192 + node_length[0][i] - rlp_node[0][i]) * (247 + node_num_of_bytes[i] - rlp_node[0][i]) );
            // constrain(is_padding[i] * (1 - node_type[i]) * (2 - node_type[i]) * (rlp_node[0][i]) );

            // constraints for storage leaf RLP
            constrain(is_padding[i] * node_type[i] * (1 - node_type[i]) * (rlp_child[0][i]) * (128 + child0_length_bytes[i] - rlp_child[0][i]) );
            constrain(is_padding[i] * node_type[i] * (1 - node_type[i]) * (128 + child1_length_bytes[i] - rlp_child[1][i]) );
            constrain(is_padding[i] * node_type[i] * (1 - node_type[i]) * (rlp_node[2][i]) * (node_length[1][i] - rlp_node[2][i]) );
            constrain(is_padding[i] * node_type[i] * (1 - node_type[i]) * (rlp_node[2][i]) * (node_length[0][i] - rlp_node[1][i]) );
            constrain(is_padding[i] * node_type[i] * (1 - node_type[i]) * (192 + node_length[0][i] - rlp_node[0][i]) * (247 + node_num_of_bytes[i] - rlp_node[0][i]) );

            constrain(is_padding[i] * node_type[i] * (1 - node_type[i]) * (2 - node_type[i]));
            if (i > 0) constrain(is_padding[i] * (depth[i] - depth[i - 1] - 1));
        }

        for(std::size_t i = 0; i < max_mpt_size - 1; i++) {
            for(std::size_t b = 0; b < 32; b++) {
                constrain(is_padding[i] * (2 - node_type[i]) * ( parent_hash[b][i + 1] - (child[0][b][i]  * child_choice[0][i] 
                                                                                        + child[1][b][i]  * child_choice[1][i]
                                                                                        + child[2][b][i]  * child_choice[2][i]
                                                                                        + child[3][b][i]  * child_choice[3][i]
                                                                                        + child[4][b][i]  * child_choice[4][i]
                                                                                        + child[5][b][i]  * child_choice[5][i]
                                                                                        + child[6][b][i]  * child_choice[6][i]
                                                                                        + child[7][b][i]  * child_choice[7][i]
                                                                                        + child[8][b][i]  * child_choice[8][i]
                                                                                        + child[9][b][i]  * child_choice[9][i]
                                                                                        + child[10][b][i] * child_choice[10][i]
                                                                                        + child[11][b][i] * child_choice[11][i]
                                                                                        + child[12][b][i] * child_choice[12][i]
                                                                                        + child[13][b][i] * child_choice[13][i]
                                                                                        + child[14][b][i] * child_choice[14][i]
                                                                                        + child[15][b][i] * child_choice[15][i]) ) );                                                              
            }
            constrain(is_padding[i] * (2 - node_type[i]) * ( 1 - (child_choice[0][i] + child_choice[1][i] + child_choice[2][i] + child_choice[3][i] 
                                     + child_choice[4][i] + child_choice[5][i] + child_choice[6][i] + child_choice[7][i] 
                                     + child_choice[8][i] + child_choice[9][i] + child_choice[10][i] + child_choice[11][i] 
                                     + child_choice[12][i] + child_choice[13][i] + child_choice[14][i] + child_choice[15][i]) ) );
            constrain( child_choice[0][i] * (1 - child_choice[0][i]) );
            constrain( child_choice[1][i] * (1 - child_choice[1][i]) );
            constrain( child_choice[2][i] * (1 - child_choice[2][i]) );
            constrain( child_choice[3][i] * (1 - child_choice[3][i]) );
            constrain( child_choice[4][i] * (1 - child_choice[4][i]) );
            constrain( child_choice[5][i] * (1 - child_choice[5][i]) );
            constrain( child_choice[6][i] * (1 - child_choice[6][i]) );
            constrain( child_choice[7][i] * (1 - child_choice[7][i]) );
            constrain( child_choice[8][i] * (1 - child_choice[8][i]) );
            constrain( child_choice[9][i] * (1 - child_choice[9][i]) );
            constrain( child_choice[10][i] * (1 - child_choice[10][i]) );
            constrain( child_choice[11][i] * (1 - child_choice[11][i]) );
            constrain( child_choice[12][i] * (1 - child_choice[12][i]) );
            constrain( child_choice[13][i] * (1 - child_choice[13][i]) );
            constrain( child_choice[14][i] * (1 - child_choice[14][i]) );
            constrain( child_choice[15][i] * (1 - child_choice[15][i]) );
        }

        if constexpr (stage == GenerationStage::CONSTRAINTS) {
           // some constraint-only stuff (for optimization)
        }
    }
};
}
