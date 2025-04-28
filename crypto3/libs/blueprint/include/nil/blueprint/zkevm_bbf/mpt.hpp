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
    using ChildTable = typename bbf::child_hash_table<FieldType, stage>;
    using generic_component<FieldType, stage>::allocate;
    using generic_component<FieldType, stage>::copy_constrain;
    using generic_component<FieldType, stage>::constrain;
    using generic_component<FieldType, stage>::lookup;
    using generic_component<FieldType, stage>::lookup_table;

public:
    using typename generic_component<FieldType, stage>::table_params;
    using typename generic_component<FieldType, stage>::TYPE;

    using input_type = typename std::conditional<stage==GenerationStage::ASSIGNMENT, mpt_paths_vector, std::nullptr_t>::type;

    using value = typename FieldType::value_type;
    using integral_type = nil::crypto3::multiprecision::big_uint<257>;

    static table_params get_minimal_requirements(std::size_t max_mpt_size) {
        return {
            .witnesses = 800 + 35,
            .public_inputs = 0,
            .constants = 0,
            .rows = 2*max_mpt_size 
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

        for(std::size_t i = 0; i < 32; i++) {
            parent_hash[i].resize(max_mpt_size);
            correct_child_hash[i].resize(max_mpt_size);
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
        std::vector<std::vector<TYPE>> child_hash_tab_input;
        std::vector<TYPE> child_vector(35);
        // columns of child_hash_table
        std::vector<std::size_t> child_hash_lookup_area;

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

           for(std::size_t i = 0; i < node_num - 1 ; i++) {
                size_t key = static_cast<size_t>(key_part[31][i].data.base());
                child_vector[0] = 1;
                child_vector[1] = node_type[i];
                child_vector[2] = (node_type[i] == 1) ? key : 1;

                for(std::size_t b = 0; b < 32; b++) {
                    child_vector[b + 3] = child[node_type[i] == 1 ? key : 1][b][i];
                    correct_child_hash[b][i] = child[node_type[i] == 1 ? key : 1][b][i];
                }
                child_hash_tab_input.push_back(child_vector);
           }

        //    for( std::size_t i = 0; i < ChildTable::get_witness_amount(); i++){
        //         child_hash_lookup_area.push_back(i);
        //    }
        //    context_type child_hash_ct = context_object.subcontext(child_hash_lookup_area, max_mpt_size, 2*max_mpt_size);
        //    ChildTable c_t = ChildTable(child_hash_ct, child_hash_tab_input, max_mpt_size);

        //    for(std::size_t i = 0; i < node_num - 1 ; i++) {
        //         for(std::size_t b = 0; b < 32; b++) {
        //                 BOOST_ASSERT_MSG( parent_hash[b][i + 1] == c_t.child_hash[b][i], "hash does not match");
        //                 // lookup(parent_hash[b][i + 1], "child_hash_table");
        //         }
        //    }  

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
                allocate(correct_child_hash[j][i], 679 + j, i);
            }
        }

        std::vector<std::size_t> lookup_cols;
        for(std::size_t i = 679; i < 711; i++) {
            lookup_cols.push_back(i);
        }

        std::vector<TYPE> child_hash_check(32);  
        lookup_table("dummy_dynamic",lookup_cols,0,max_mpt_size);
        for(std::size_t i = 0; i < max_mpt_size - 1; i++) {
            for(std::size_t b = 0; b < 32; b++) {
                child_hash_check[b] = parent_hash[b][i + 1];
            }
            lookup(child_hash_check,"dummy_dynamic");
        }

        // for( std::size_t i = 0; i < ChildTable::get_witness_amount(); i++){
        //     child_hash_lookup_area.push_back(i);
        // }
        // context_type child_hash_ct = context_object.subcontext(child_hash_lookup_area, max_mpt_size, 2*max_mpt_size);
        // ChildTable c_t = ChildTable(child_hash_ct, node_type[0], max_mpt_size);

        // std::vector<TYPE> child_hash_lookup = {
        //     1,
        //     1,
        //     1, 
        //     parent_hash[0][1],
        //     parent_hash[1][1],
        //     parent_hash[2][1],
        //     parent_hash[3][1],
        //     parent_hash[4][1],
        //     parent_hash[5][1],
        //     parent_hash[6][1],
        //     parent_hash[7][1],
        //     parent_hash[8][1],
        //     parent_hash[9][1],
        //     parent_hash[10][1],
        //     parent_hash[11][1],
        //     parent_hash[12][1],
        //     parent_hash[13][1],
        //     parent_hash[14][1],
        //     parent_hash[15][1],
        //     parent_hash[16][1],
        //     parent_hash[17][1],
        //     parent_hash[18][1],
        //     parent_hash[19][1],
        //     parent_hash[20][1],
        //     parent_hash[21][1],
        //     parent_hash[22][1],
        //     parent_hash[23][1],
        //     parent_hash[24][1],
        //     parent_hash[25][1],
        //     parent_hash[26][1],
        //     parent_hash[27][1],
        //     parent_hash[28][1],
        //     parent_hash[29][1],
        //     parent_hash[30][1],
        //     parent_hash[31][1]     
        // };

        // lookup(child_hash_lookup, "child_hash_table");

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
/*
        std::size_t START_OP = rw_op_to_num(rw_operation_type::start);
        std::size_t STACK_OP = rw_op_to_num(rw_operation_type::stack);
        std::size_t MEMORY_OP = rw_op_to_num(rw_operation_type::memory);
        std::size_t STORAGE_OP = rw_op_to_num(rw_operation_type::storage);
        std::size_t TRANSIENT_STORAGE_OP = rw_op_to_num(rw_operation_type::transient_storage);
        std::size_t CALL_CONTEXT_OP = rw_op_to_num(rw_operation_type::call_context);
        std::size_t ACCOUNT_OP = rw_op_to_num(rw_operation_type::account);
        std::size_t TX_REFUND_OP = rw_op_to_num(rw_operation_type::tx_refund_op);
        std::size_t TX_ACCESS_LIST_ACCOUNT_OP = rw_op_to_num(rw_operation_type::tx_access_list_account);
        std::size_t TX_ACCESS_LIST_ACCOUNT_STORAGE_OP = rw_op_to_num(rw_operation_type::tx_access_list_account_storage);
        std::size_t TX_LOG_OP = rw_op_to_num(rw_operation_type::tx_log);
        std::size_t TX_RECEIPT_OP = rw_op_to_num(rw_operation_type::tx_receipt);
        std::size_t PADDING_OP = rw_op_to_num(rw_operation_type::padding);

        PROFILE_SCOPE("Rw circuit constructor, total time");
        std::vector<std::size_t> rw_table_area;
        for( std::size_t i = 0; i < rw_table_type::get_witness_amount(); i++ ) rw_table_area.push_back(i);

        context_type rw_table_ct = context_object.subcontext(rw_table_area,0,max_rw_size);
        rw_table_type t(rw_table_ct, input, max_rw_size, false);

        const std::vector<TYPE>  &op = t.op;
        const std::vector<TYPE>  &id = t.id;
        const std::vector<TYPE>  &address = t.address;
        const std::vector<TYPE>  &storage_key_hi = t.storage_key_hi;
        const std::vector<TYPE>  &storage_key_lo = t.storage_key_lo;
        const std::vector<TYPE>  &field_type = t.field_type;
        const std::vector<TYPE>  &rw_id = t.rw_id;
        const std::vector<TYPE>  &is_write = t.is_write;
        const std::vector<TYPE>  &value_hi = t.value_hi;
        const std::vector<TYPE>  &value_lo = t.value_lo;

        std::vector<std::array<TYPE,op_bits_amount>> op_bits(max_rw_size);
        std::vector<std::array<TYPE,diff_index_bits_amount>> diff_index_bits(max_rw_size);
        std::vector<TYPE> is_first(max_rw_size);
        std::vector<std::array<TYPE,chunks_amount>> chunks(max_rw_size);
        std::vector<TYPE> diff(max_rw_size);
        std::vector<TYPE> inv_diff(max_rw_size);
        std::vector<TYPE> value_before_hi(max_rw_size);
        std::vector<TYPE> value_before_lo(max_rw_size);
        std::vector<TYPE> state_root_hi(max_rw_size);
        std::vector<TYPE> state_root_lo(max_rw_size);
        std::vector<TYPE> state_root_before_hi(max_rw_size);
        std::vector<TYPE> state_root_before_lo(max_rw_size);
        std::vector<TYPE> is_last(max_rw_size);
        std::vector<TYPE> sorted;
        std::vector<TYPE> sorted_prev;

        if constexpr (stage == GenerationStage::ASSIGNMENT) {
            auto rw_trace = input;
            std::cout << "RW trace.size = " << rw_trace.size() << std::endl;
            for( std::size_t i = 0; i < rw_trace.size(); i++ ){
                integral_type mask = (1 << op_bits_amount);
                for( std::size_t j = 0; j < op_bits_amount; j++){
                    mask >>= 1;
                    op_bits[i][j] = (((static_cast<unsigned>(rw_trace[i].op) & mask) == 0) ? 0 : 1);
                }
                std::size_t cur_chunk = 0;
                // id
                mask = 0xffff0000;
                chunks[i][cur_chunk++] = (mask & integral_type(rw_trace[i].call_id)) >> 16;
                mask = 0xffff;
                chunks[i][cur_chunk++] = (mask & integral_type(rw_trace[i].call_id));

                // address
                mask = 0xffff;
                mask <<= (16 * 9);
                for( std::size_t j = 0; j < address_chunks_amount; j++){
                    chunks[i][cur_chunk++] = (((mask & integral_type(rw_trace[i].address)) >> (16 * (9-j))));
                    mask >>= 16;
                }

                // storage_key
                mask = 0xffff;
                mask <<= (16 * 15);
                for( std::size_t j = 0; j < storage_key_chunks_amount; j++){
                    chunks[i][cur_chunk++] = (((mask & integral_type(rw_trace[i].storage_key)) >> (16 * (15-j))));
                    mask >>= 16;
                }

                // rw_id
                mask = 0xffff;
                mask <<= 16;
                chunks[i][cur_chunk++] = (mask & rw_trace[i].rw_counter) >> 16;
                mask >>= 16;
                chunks[i][cur_chunk++] = (mask & rw_trace[i].rw_counter);

                sorted_prev = sorted;
                sorted = {op[i]};
                for( std::size_t j = 0; j < chunks_amount; j++ ){
                    sorted.push_back(chunks[i][j]);
                    if( j == 12 ) sorted.push_back(field_type[i]);
                }

                if( i == 0) continue;
                std::size_t diff_ind;
                for( diff_ind= 0; diff_ind < chunks_amount; diff_ind++ ){
                    if(sorted[diff_ind] != sorted_prev[diff_ind]) break;
                }
                if( op[i] != START_OP && op[i] != PADDING_OP && diff_ind < 30){
                    is_first[i] = 1;
                    if(i != 0) is_last[i-1] = 1;
                }
                if( diff_ind > 30 ){
                    value_before_hi[i] = w_hi<FieldType>(rw_trace[i].initial_value);
                    value_before_lo[i] = w_lo<FieldType>(rw_trace[i].initial_value);
                } else {
                    value_before_hi[i] = value_before_hi[i-1];
                    value_before_lo[i] = value_before_lo[i-1];
                }
                mask = (1 << diff_index_bits_amount);
                for( std::size_t j = 0; j < diff_index_bits_amount; j++){
                    mask >>= 1;
                    diff_index_bits[i][j] = (((diff_ind & mask) == 0) ? 0 : 1);
                }
                diff[i] = sorted[diff_ind] - sorted_prev[diff_ind];
                inv_diff[i] = diff[i] == 0? 0: diff[i].inversed();
            }
            for( std::size_t i = rw_trace.size(); i < max_rw_size; i++ ){
                integral_type mask = (1 << op_bits_amount);
                for( std::size_t j = 0; j < op_bits_amount; j++){
                    mask >>= 1;
                    op_bits[i][j] = (((PADDING_OP & mask) == 0) ? 0 : 1);
                }
            }
        }
        for( std::size_t i = 0; i < max_rw_size; i++){
            if( i % 20 == 0)  std::cout << "."; std::cout.flush();
            std::size_t cur_column = rw_table_type::get_witness_amount();
            for( std::size_t j = 0; j < op_bits_amount; j++){
                allocate(op_bits[i][j], ++cur_column, i);
            };

            for( std::size_t k = 0; k < chunks_amount; k++){
                allocate(chunks[i][k], ++cur_column, i);
            }
            for( std::size_t j = 0; j < diff_index_bits_amount; j++){
                allocate(diff_index_bits[i][j], ++cur_column, i);
            }
            allocate(value_before_hi[i], ++cur_column, i);
            allocate(value_before_lo[i], ++cur_column, i);
            allocate(diff[i], ++cur_column, i); lookup(diff[i], "chunk_16_bits/full");
            allocate(inv_diff[i], ++cur_column, i);
            allocate(is_first[i], ++cur_column, i);
            allocate(is_last[i], ++cur_column, i);
            allocate(state_root_hi[i], ++cur_column, i);
            allocate(state_root_lo[i], ++cur_column, i);
            allocate(state_root_before_hi[i], ++cur_column, i);
            allocate(state_root_before_lo[i], ++cur_column, i);
        }
        std::cout << std::endl;
        if constexpr (stage == GenerationStage::CONSTRAINTS) {
            std::vector<TYPE> every_row_constraints;
            std::vector<TYPE> non_first_row_constraints;
            std::vector<TYPE> chunked_16_lookups;
            for( std::size_t j = 0; j < diff_index_bits_amount; j++){
                every_row_constraints.push_back(context_object.relativize(diff_index_bits[1][j] * (diff_index_bits[1][j] - 1), -1));
            }
            for( std::size_t k = 0; k < chunks_amount; k++){
                chunked_16_lookups.push_back(context_object.relativize(chunks[1][k], -1));
            }
            TYPE op_bit_composition;
            for( std::size_t j = 0; j < op_bits_amount; j++){
                every_row_constraints.push_back(context_object.relativize(op_bits[1][j] * (op_bits[1][j] - 1), -1));
                if(j == 0) {
                    op_bit_composition = op_bits[1][j];
                } else {
                    op_bit_composition *= 2;
                    op_bit_composition += op_bits[1][j];
                }
            }
            every_row_constraints.push_back(context_object.relativize(op_bit_composition - op[1], -1));

            TYPE id_composition;
            std::size_t cur_chunk = 0;
            id_composition = chunks[1][cur_chunk++]; id_composition *= (1<<16);
            id_composition += chunks[1][cur_chunk++];
            every_row_constraints.push_back(context_object.relativize(id[1] - id_composition, -1));

            TYPE addr_composition;
            addr_composition = chunks[1][cur_chunk++]; addr_composition *= (1<<16); //1
            addr_composition += chunks[1][cur_chunk++]; addr_composition *= (1<<16); //2
            addr_composition += chunks[1][cur_chunk++]; addr_composition *= (1<<16); //3
            addr_composition += chunks[1][cur_chunk++]; addr_composition *= (1<<16); //4
            addr_composition += chunks[1][cur_chunk++]; addr_composition *= (1<<16); //5
            addr_composition += chunks[1][cur_chunk++]; addr_composition *= (1<<16); //6
            addr_composition += chunks[1][cur_chunk++]; addr_composition *= (1<<16); //7
            addr_composition += chunks[1][cur_chunk++]; addr_composition *= (1<<16); //8
            addr_composition += chunks[1][cur_chunk++]; addr_composition *= (1<<16); //9
            addr_composition += chunks[1][cur_chunk++];
            every_row_constraints.push_back(context_object.relativize(address[1] - addr_composition, -1));

            TYPE storage_key_hi_comp;
            storage_key_hi_comp = chunks[1][cur_chunk++]; storage_key_hi_comp *= (1<<16); //1
            storage_key_hi_comp += chunks[1][cur_chunk++]; storage_key_hi_comp *= (1<<16); //2
            storage_key_hi_comp += chunks[1][cur_chunk++]; storage_key_hi_comp *= (1<<16); //3
            storage_key_hi_comp += chunks[1][cur_chunk++]; storage_key_hi_comp *= (1<<16); //4
            storage_key_hi_comp += chunks[1][cur_chunk++]; storage_key_hi_comp *= (1<<16); //5
            storage_key_hi_comp += chunks[1][cur_chunk++]; storage_key_hi_comp *= (1<<16); //6
            storage_key_hi_comp += chunks[1][cur_chunk++]; storage_key_hi_comp *= (1<<16); //7
            storage_key_hi_comp += chunks[1][cur_chunk++];
            every_row_constraints.push_back(context_object.relativize(storage_key_hi[1] - storage_key_hi_comp, -1));

            TYPE storage_key_lo_comp;
            storage_key_lo_comp = chunks[1][cur_chunk++]; storage_key_lo_comp *= (1<<16); //1
            storage_key_lo_comp += chunks[1][cur_chunk++]; storage_key_lo_comp *= (1<<16); //2
            storage_key_lo_comp += chunks[1][cur_chunk++]; storage_key_lo_comp *= (1<<16); //3
            storage_key_lo_comp += chunks[1][cur_chunk++]; storage_key_lo_comp *= (1<<16); //4
            storage_key_lo_comp += chunks[1][cur_chunk++]; storage_key_lo_comp *= (1<<16); //5
            storage_key_lo_comp += chunks[1][cur_chunk++]; storage_key_lo_comp *= (1<<16); //6
            storage_key_lo_comp += chunks[1][cur_chunk++]; storage_key_lo_comp *= (1<<16); //7
            storage_key_lo_comp += chunks[1][cur_chunk++];
            every_row_constraints.push_back(context_object.relativize(storage_key_lo[1] - storage_key_lo_comp, -1));

            TYPE rw_id_composition;
            rw_id_composition = chunks[1][cur_chunk++]; rw_id_composition *= (1<<16);
            rw_id_composition += chunks[1][cur_chunk++];
            every_row_constraints.push_back(context_object.relativize(rw_id[1] - rw_id_composition, -1));

            sorted_prev = {op[0]};
            sorted = {op[1]};
            for( std::size_t j = 0; j < chunks_amount; j++ ){
                sorted_prev.push_back(chunks[0][j]);
                sorted.push_back(chunks[1][j]);
                if( j == 12 ) {
                    sorted_prev.push_back(field_type[0]);
                    sorted.push_back(field_type[1]);
                }
            }

            TYPE start_selector = bit_tag_selector(op_bits[1], START_OP);
            TYPE stack_selector = bit_tag_selector(op_bits[1], STACK_OP);
            TYPE memory_selector = bit_tag_selector(op_bits[1], MEMORY_OP);
            TYPE storage_selector = bit_tag_selector(op_bits[1], STORAGE_OP);
            TYPE transient_storage_selector = bit_tag_selector(op_bits[1], TRANSIENT_STORAGE_OP);
            TYPE call_context_selector = bit_tag_selector(op_bits[1], CALL_CONTEXT_OP);
            TYPE account_selector = bit_tag_selector(op_bits[1], ACCOUNT_OP);
            TYPE tx_refund_selector = bit_tag_selector(op_bits[1], TX_REFUND_OP);
            TYPE tx_access_list_account_selector = bit_tag_selector(op_bits[1], TX_ACCESS_LIST_ACCOUNT_OP);
            TYPE tx_access_list_account_storage_selector = bit_tag_selector(op_bits[1], TX_ACCESS_LIST_ACCOUNT_STORAGE_OP);
            TYPE tx_log_selector = bit_tag_selector(op_bits[1], TX_LOG_OP);
            TYPE tx_receipt_selector = bit_tag_selector(op_bits[1], TX_RECEIPT_OP);
            TYPE padding_selector = bit_tag_selector(op_bits[1], PADDING_OP);

            for( std::size_t diff_ind = 0; diff_ind < sorted.size(); diff_ind++ ){
                TYPE diff_ind_selector = bit_tag_selector<diff_index_bits_amount>(diff_index_bits[1], diff_ind);
                for(std::size_t less_diff_ind = 0; less_diff_ind < diff_ind; less_diff_ind++){
                    non_first_row_constraints.push_back(context_object.relativize((op[1] - PADDING_OP) * diff_ind_selector * (sorted[less_diff_ind]-sorted_prev[less_diff_ind]),-1));
                }
                non_first_row_constraints.push_back( context_object.relativize((op[1] - PADDING_OP) * diff_ind_selector * (sorted[diff_ind] - sorted_prev[diff_ind] - diff[1]), -1));
            }

            every_row_constraints.push_back(context_object.relativize(is_write[1] * (is_write[1]-1), -1));
            every_row_constraints.push_back(context_object.relativize(is_first[1] * (is_first[1]-1), -1));
            every_row_constraints.push_back(context_object.relativize((diff[1] * inv_diff[1] - 1) * diff[1], -1));
            every_row_constraints.push_back(context_object.relativize((diff[1] * inv_diff[1] - 1) * inv_diff[1], -1));
            every_row_constraints.push_back(context_object.relativize(is_first[1] * (is_first[1] - 1), -1));
            every_row_constraints.push_back(context_object.relativize(is_last[1] * (is_last[1] - 1), -1));
            every_row_constraints.push_back(context_object.relativize((op[1] - START_OP) * (op[1] - PADDING_OP) * (is_first[1] - 1) * (diff_index_bits[1][0] - 1), -1));
            every_row_constraints.push_back(context_object.relativize((op[1] - START_OP) * (op[1] - PADDING_OP) * (is_first[1] - 1) * (diff_index_bits[1][1] - 1), -1));
            every_row_constraints.push_back(context_object.relativize((op[1] - START_OP) * (op[1] - PADDING_OP) * (is_first[1] - 1) * (diff_index_bits[1][2] - 1), -1));
            every_row_constraints.push_back(context_object.relativize((op[1] - START_OP) * (op[1] - PADDING_OP) * (is_first[1] - 1) * (diff_index_bits[1][3] - 1), -1));

            non_first_row_constraints.push_back(context_object.relativize((op[0] - START_OP) * (op[0] - PADDING_OP)
                * is_last[0] * diff_index_bits[1][0]
                * diff_index_bits[1][1] * diff_index_bits[1][2]
                * diff_index_bits[1][3], -1));
            every_row_constraints.push_back(context_object.relativize((op[1] - START_OP) * (op[1] - PADDING_OP) * (is_first[1] - 1) * (value_before_hi[1] - value_before_hi[0]), -1));
            every_row_constraints.push_back(context_object.relativize((op[1] - START_OP) * (op[1] - PADDING_OP) * (is_first[1] - 1) * (value_before_lo[1] - value_before_lo[0]), -1));


    //                     // Specific constraints for START
            std::map<std::size_t, std::vector<TYPE>> special_constraints;
            special_constraints[START_OP].push_back(context_object.relativize(start_selector * storage_key_hi[1], -1));
            special_constraints[START_OP].push_back(context_object.relativize(start_selector * storage_key_lo[1], -1));
            special_constraints[START_OP].push_back(context_object.relativize(start_selector * id[1], -1));
            special_constraints[START_OP].push_back(context_object.relativize(start_selector * address[1], -1));
            special_constraints[START_OP].push_back(context_object.relativize(start_selector * field_type[1], -1));
            special_constraints[START_OP].push_back(context_object.relativize(start_selector * rw_id[1], -1));
            special_constraints[START_OP].push_back(context_object.relativize(start_selector * value_before_hi[1], -1));
            special_constraints[START_OP].push_back(context_object.relativize(start_selector * value_before_lo[1], -1));
            special_constraints[START_OP].push_back(context_object.relativize(start_selector * state_root_hi[1], -1));
            special_constraints[START_OP].push_back(context_object.relativize(start_selector * state_root_lo[1], -1));
            special_constraints[START_OP].push_back(context_object.relativize(start_selector * state_root_before_hi[1], -1));
            special_constraints[START_OP].push_back(context_object.relativize(start_selector * state_root_before_lo[1], -1));

            // Specific constraints for STACK
            special_constraints[STACK_OP].push_back(context_object.relativize(stack_selector * field_type[1], -1));
            special_constraints[STACK_OP].push_back(context_object.relativize(stack_selector * is_first[1] * (1 - is_write[1]), -1));  // 4. First stack operation is obviously write
            //if(i!=0) {
                non_first_row_constraints.push_back(context_object.relativize(stack_selector * (address[1] - address[0]) * (is_write[1] - 1), -1));                  // 5. First operation is always write
                non_first_row_constraints.push_back(context_object.relativize(stack_selector * (1 - is_first[1]) * (address[1] - address[0]) * (address[1] - address[0] - 1), -1));      // 6. Stack pointer always grows and only by one
                non_first_row_constraints.push_back(context_object.relativize(stack_selector * (1 - is_first[1]) * (state_root_hi[1] - state_root_before_hi[0]), -1));
                non_first_row_constraints.push_back(context_object.relativize(stack_selector * (1 - is_first[1]) * (state_root_lo[1] - state_root_before_lo[0]), -1));
            //}
            special_constraints[STACK_OP].push_back(context_object.relativize(stack_selector * storage_key_hi[1], -1));
            special_constraints[STACK_OP].push_back(context_object.relativize(stack_selector * storage_key_lo[1], -1));
            special_constraints[STACK_OP].push_back(context_object.relativize(stack_selector * value_before_hi[1], -1));
            special_constraints[STACK_OP].push_back(context_object.relativize(stack_selector * value_before_lo[1], -1));
            chunked_16_lookups.push_back(context_object.relativize(stack_selector * address[1], -1));
            chunked_16_lookups.push_back(context_object.relativize(1023 - stack_selector * address[1], -1));

            // Specific constraints for MEMORY
            // address is 32 bit
            //if( i != 0 )
                non_first_row_constraints.push_back(context_object.relativize(memory_selector * (is_first[1] - 1) * (is_write[1] - 1) * (value_lo[1] - value_lo[0]), -1));       // 4. for read operations value is equal to previous value
            special_constraints[MEMORY_OP].push_back(context_object.relativize(memory_selector * value_hi[1], -1));
            special_constraints[MEMORY_OP].push_back(context_object.relativize(memory_selector * is_first[1] * (is_write[1] - 1) * value_lo[1], -1));
            special_constraints[MEMORY_OP].push_back(context_object.relativize(memory_selector * field_type[1], -1));
            special_constraints[MEMORY_OP].push_back(context_object.relativize(memory_selector * storage_key_hi[1], -1));
            special_constraints[MEMORY_OP].push_back(context_object.relativize(memory_selector * storage_key_lo[1], -1));
            special_constraints[MEMORY_OP].push_back(context_object.relativize(memory_selector * value_before_hi[1], -1));
            special_constraints[MEMORY_OP].push_back(context_object.relativize(memory_selector * value_before_lo[1], -1));
            special_constraints[MEMORY_OP].push_back(context_object.relativize(memory_selector * (1 - is_first[1]) * (state_root_hi[1] - state_root_before_hi[1]), -1));
            special_constraints[MEMORY_OP].push_back(context_object.relativize(memory_selector * (1 - is_first[1]) * (state_root_lo[1] - state_root_before_lo[1]), -1));
            chunked_16_lookups.push_back(context_object.relativize(memory_selector * value_lo[1], -1));
            chunked_16_lookups.push_back(context_object.relativize(255 - memory_selector * value_lo[1], -1));


            // Specific constraints for STORAGE
            // lookup to MPT circuit
            // field is 0
            special_constraints[STORAGE_OP].push_back(context_object.relativize(storage_selector * field_type[1], -1));
            //lookup_constrain({"MPT table", {
            //    storage_selector * addr,
            //    storage_selector * field,
            //    storage_selector * storage_key_hi,
            //    storage_selector * storage_key_lo,
            //    storage_selector * value_before_hi,
            //    storage_selector * value_before_lo,
            //    storage_selector * value_hi,
            //    storage_selector * value_lo,
            //    storage_selector * state_root_hi,
            //    storage_selector * state_root_lo
            //}});

            // Specific constraints for TRANSIENT_STORAGE
            // field is 0
            special_constraints[TRANSIENT_STORAGE_OP].push_back(context_object.relativize(transient_storage_selector * field_type[1], -1));

            // Specific constraints for CALL_CONTEXT
            // address, storage_key, initial_value, value_prev are 0
            // state_root = state_root_prev
            // range_check for field_flag
            special_constraints[CALL_CONTEXT_OP].push_back(context_object.relativize(call_context_selector * address[1], -1));
            special_constraints[CALL_CONTEXT_OP].push_back(context_object.relativize(call_context_selector * storage_key_hi[1], -1));
            special_constraints[CALL_CONTEXT_OP].push_back(context_object.relativize(call_context_selector * storage_key_lo[1], -1));
            special_constraints[CALL_CONTEXT_OP].push_back(context_object.relativize(call_context_selector * (1 - is_first[1]) * (state_root_hi[1] - state_root_before_hi[1]), -1));
            special_constraints[CALL_CONTEXT_OP].push_back(context_object.relativize(call_context_selector * (1 - is_first[1]) * (state_root_lo[1] - state_root_before_lo[1]), -1));
            special_constraints[CALL_CONTEXT_OP].push_back(context_object.relativize(call_context_selector * value_before_hi[1], -1));
            special_constraints[CALL_CONTEXT_OP].push_back(context_object.relativize(call_context_selector * value_before_lo[1], -1));

            // Specific constraints for ACCOUNT_OP
            // id, storage_key 0
            // field_tag -- Range
            // MPT lookup for last access
            // value and value_prev consistency
            special_constraints[ACCOUNT_OP].push_back(context_object.relativize(account_selector * id[1], -1));
            special_constraints[ACCOUNT_OP].push_back(context_object.relativize(account_selector * storage_key_hi[1], -1));
            special_constraints[ACCOUNT_OP].push_back(context_object.relativize(account_selector * storage_key_lo[1], -1));
            //lookup_constrain({"MPT table", {
            //    storage_selector * is_last * addr,
            //    storage_selector * is_last * field,
            //    storage_selector * is_last * storage_key_hi,
            //    storage_selector * is_last * storage_key_lo,
            //    storage_selector * is_last * value_before_hi,
            //    storage_selector * is_last * value_before_lo,
            //    storage_selector * is_last * value_hi,
            //    storage_selector * is_last * value_lo,
            //    storage_selector * is_last * state_root_hi,
            //    storage_selector * is_last * state_root_lo,
            //    storage_selector * is_last * state_root_before_hi,
            //    storage_selector * is_last * state_root_before_lo
            //}});

            // Specific constraints for TX_REFUND_OP
            // address, field_tag and storage_key are 0
            // state_root eqauls state_root_prev
            // initial_value is 0
            // if first access is Read then value = 0
            special_constraints[TX_REFUND_OP].push_back(context_object.relativize(tx_refund_selector * address[1], -1));
            special_constraints[TX_REFUND_OP].push_back(context_object.relativize(tx_refund_selector * field_type[1], -1));
            special_constraints[TX_REFUND_OP].push_back(context_object.relativize(tx_refund_selector * storage_key_hi[1], -1));
            special_constraints[TX_REFUND_OP].push_back(context_object.relativize(tx_refund_selector * storage_key_lo[1], -1));
            special_constraints[TX_REFUND_OP].push_back(context_object.relativize(tx_refund_selector * is_first[1] * (1-is_write[1]) * value_hi[1], -1));
            special_constraints[TX_REFUND_OP].push_back(context_object.relativize(tx_refund_selector * is_first[1] * (1-is_write[1]) * value_lo[1], -1));
            special_constraints[TX_REFUND_OP].push_back(context_object.relativize(tx_refund_selector * (state_root_hi[1] - state_root_before_hi[1]), -1));
            special_constraints[TX_REFUND_OP].push_back(context_object.relativize(tx_refund_selector * (state_root_lo[1] - state_root_before_lo[1]), -1));

            // Specific constraints for TX_ACCESS_LIST_ACCOUNT_OP
            // field_tag and storage_key are 0
            // value is boolean
            // initial_value is 0
            // state_root eqauls state_root_prev
            // value column at previous rotation equals value_prev at current rotation
            special_constraints[TX_ACCESS_LIST_ACCOUNT_OP].push_back(context_object.relativize(tx_access_list_account_selector * field_type[1], -1));
            special_constraints[TX_ACCESS_LIST_ACCOUNT_OP].push_back(context_object.relativize(tx_access_list_account_selector * storage_key_hi[1], -1));
            special_constraints[TX_ACCESS_LIST_ACCOUNT_OP].push_back(context_object.relativize(tx_access_list_account_selector * storage_key_lo[1], -1));
            special_constraints[TX_ACCESS_LIST_ACCOUNT_OP].push_back(context_object.relativize(tx_access_list_account_selector * value_hi[1], -1));
            special_constraints[TX_ACCESS_LIST_ACCOUNT_OP].push_back(context_object.relativize(tx_access_list_account_selector * value_lo[1] * (1 - value_lo[1]), -1));
            special_constraints[TX_ACCESS_LIST_ACCOUNT_OP].push_back(context_object.relativize(tx_access_list_account_selector * (state_root_hi[1] - state_root_before_hi[1]), -1));
            special_constraints[TX_ACCESS_LIST_ACCOUNT_OP].push_back(context_object.relativize(tx_access_list_account_selector * (state_root_lo[1] - state_root_before_lo[1]), -1));
            //if(i != 0)
                non_first_row_constraints.push_back(context_object.relativize(tx_access_list_account_selector * (1 - is_first[1]) * (value_hi[0] - value_before_hi[1]), -1));
            //if(i != 0)
                non_first_row_constraints.push_back(context_object.relativize(tx_access_list_account_selector * (1 - is_first[1]) * (value_lo[0] - value_before_lo[1]), -1));

            // Specific constraints for
            //    field_tag is 0
            //    value is boolean
            //    initial_value is 0
            //    state_root equals state_root_prev
            //    value column at previous rotation equals value_prev at current rotation
            special_constraints[TX_ACCESS_LIST_ACCOUNT_STORAGE_OP].push_back(context_object.relativize(tx_access_list_account_selector * field_type[1], -1));
            special_constraints[TX_ACCESS_LIST_ACCOUNT_STORAGE_OP].push_back(context_object.relativize(tx_access_list_account_selector * value_hi[1], -1));
            special_constraints[TX_ACCESS_LIST_ACCOUNT_STORAGE_OP].push_back(context_object.relativize(tx_access_list_account_selector * value_lo[1] * (1 - value_lo[1]), -1));
            special_constraints[TX_ACCESS_LIST_ACCOUNT_STORAGE_OP].push_back(context_object.relativize(tx_access_list_account_selector * (state_root_hi[1] - state_root_before_hi[1]), -1));
            special_constraints[TX_ACCESS_LIST_ACCOUNT_STORAGE_OP].push_back(context_object.relativize(tx_access_list_account_selector * (state_root_lo[1] - state_root_before_lo[1]), -1));
            //if(i != 0)
                non_first_row_constraints.push_back(context_object.relativize(tx_access_list_account_selector * (1 - is_first[1]) * (value_hi[0] - value_before_hi[1]), -1));
            //if(i != 0)
                non_first_row_constraints.push_back(context_object.relativize(tx_access_list_account_selector * (1 - is_first[1]) * (value_lo[0] - value_before_lo[1]), -1));


            // Specific constraints for TX_LOG_OP
            //  is_write is true
            //  initial_value is 0
            //  state_root eqauls state_root_prev
            //  value_prev equals initial_value
            //  address 64 bits
            special_constraints[TX_LOG_OP].push_back(context_object.relativize(tx_log_selector * (1 - is_write[1]), -1));
            special_constraints[TX_LOG_OP].push_back(context_object.relativize(tx_log_selector * (state_root_hi[1] - state_root_before_hi[1]), -1));
            special_constraints[TX_LOG_OP].push_back(context_object.relativize(tx_log_selector * (state_root_lo[1] - state_root_before_lo[1]), -1));
            special_constraints[TX_LOG_OP].push_back(context_object.relativize(tx_log_selector * value_before_hi[1], -1));
            special_constraints[TX_LOG_OP].push_back(context_object.relativize(tx_log_selector * value_before_lo[1], -1));

            // Specific constraints for TX_RECEIPT_OP
            // address and storage_key are 0
            //  field_tag is boolean (according to EIP-658)
            //  tx_id increases by 1 and value increases as well if tx_id changes
            //  tx_id is 1 if it's the first row and tx_id is in 11 bits range
            //  state root is the same
            //  value_prev is 0 and initial_value is 0
            special_constraints[TX_RECEIPT_OP].push_back(context_object.relativize(tx_receipt_selector * address[1], -1));
            special_constraints[TX_RECEIPT_OP].push_back(context_object.relativize(tx_receipt_selector * storage_key_hi[1], -1));
            special_constraints[TX_RECEIPT_OP].push_back(context_object.relativize(tx_receipt_selector * storage_key_lo[1], -1));

            // Specific constraints for PADDING
            special_constraints[PADDING_OP].push_back(context_object.relativize(padding_selector * address[1], -1));
            special_constraints[PADDING_OP].push_back(context_object.relativize(padding_selector * storage_key_hi[1], -1));
            special_constraints[PADDING_OP].push_back(context_object.relativize(padding_selector * storage_key_lo[1], -1));
            special_constraints[PADDING_OP].push_back(context_object.relativize(padding_selector * id[1], -1));
            special_constraints[PADDING_OP].push_back(context_object.relativize(padding_selector * address[1], -1));
            special_constraints[PADDING_OP].push_back(context_object.relativize(padding_selector * field_type[1], -1));
            special_constraints[PADDING_OP].push_back(context_object.relativize(padding_selector * rw_id[1], -1));
            special_constraints[PADDING_OP].push_back(context_object.relativize(padding_selector * state_root_hi[1], -1));
            special_constraints[PADDING_OP].push_back(context_object.relativize(padding_selector * state_root_lo[1], -1));
            special_constraints[PADDING_OP].push_back(context_object.relativize(padding_selector * state_root_before_hi[1], -1));
            special_constraints[PADDING_OP].push_back(context_object.relativize(padding_selector * state_root_before_lo[1], -1));
            special_constraints[PADDING_OP].push_back(context_object.relativize(padding_selector * value_hi[1], -1));
            special_constraints[PADDING_OP].push_back(context_object.relativize(padding_selector * value_lo[1], -1));
            special_constraints[PADDING_OP].push_back(context_object.relativize(padding_selector * value_before_hi[1], -1));
            special_constraints[PADDING_OP].push_back(context_object.relativize(padding_selector * value_before_lo[1], -1));

            std::size_t max_constraints = 0;
            for(const auto&[k,constr] : special_constraints){
                if( constr.size() > max_constraints) max_constraints = constr.size();
            }
            for( std::size_t i = 0; i < max_constraints; i++ ){
                TYPE constraint;
                for(const auto&[k,constr] : special_constraints){
                    if( constr.size() > i ) constraint += constr[i];
                }
                every_row_constraints.push_back(constraint);
            }

            {
                PROFILE_SCOPE("RW circuit constraints row definition")
                std::vector<std::size_t> every_row;
                std::vector<std::size_t> non_first_row;
                for( std::size_t i = 0; i < max_rw_size; i++){
                    every_row.push_back(i);
                    if( i!= 0 ) non_first_row.push_back(i);
                }
                for( auto& constraint: every_row_constraints){
                    context_object.relative_constrain(constraint, 0, max_rw_size-1);
                }
                for( auto &constraint:chunked_16_lookups ){
                    std::vector<TYPE> tmp = {constraint};
                    context_object.relative_lookup(tmp, "chunk_16_bits/full", 0, max_rw_size-1);
                }
                for( auto &constraint: non_first_row_constraints ){
                    context_object.relative_constrain(constraint, 1, max_rw_size - 1);
                }
            }
        }
        std::cout << std::endl;
*/
    }
};
}
