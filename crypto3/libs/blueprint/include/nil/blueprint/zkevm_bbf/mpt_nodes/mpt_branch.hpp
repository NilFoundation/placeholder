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

#include <nil/blueprint/zkevm_bbf/types/mpt_trie.hpp>

namespace nil::blueprint::bbf {

template<typename FieldType, GenerationStage stage>
class mpt_branch : public generic_component<FieldType, stage> {
    using typename generic_component<FieldType, stage>::context_type;
    using generic_component<FieldType, stage>::allocate;
    using generic_component<FieldType, stage>::copy_constrain;
    using generic_component<FieldType, stage>::constrain;
    using generic_component<FieldType, stage>::lookup;
    using generic_component<FieldType, stage>::lookup_table;

public:
    using typename generic_component<FieldType, stage>::table_params;
    using typename generic_component<FieldType, stage>::TYPE;

/*
    using private_input = typename std::conditional<stage==GenerationStage::ASSIGNMENT, mpt_node, std::nullptr_t>::type;

    struct mpt_node_input_type {
        TYPE node_type;
        std::array<TYPE,32> node_key_prefix;
        TYPE key_prefix_length;
        private_input node_data;
    };
*/
    using input_type = mpt_node_input_type<FieldType, stage>;

    using value_type = typename FieldType::value_type;
    using integral_type = nil::crypto3::multiprecision::big_uint<257>;

/*
    // will probably be never used
    static table_params get_minimal_requirements() {
        return {
            .witnesses = 850,
            .public_inputs = 0,
            .constants = 0,
            .rows = 1
        };
    }

    static void allocate_public_inputs(
            context_type &context, input_type &input) {}
*/
    mpt_branch(context_type &context_object,
        const input_type &input) : generic_component<FieldType,stage>(context_object) {

        std::array<TYPE,32> parent_hash; // the hash for reference to the node from parent node
        std::array<std::array<TYPE,32>,16> child; // 16 32-byte child hashes
        std::array<TYPE,16> rlp_child; // RLP prefixes for each child
        std::array<TYPE,2>  node_length; // length of the encoded node
        TYPE node_num_of_bytes; // the number of bytes required to store node length (1 or 2)
        std::array<TYPE,3>  rlp_node; // RLP prefix of the entire node
        std::array<TYPE,16> child_sum_inverse; // inverses of child hash bytes' sums

        if constexpr (stage == GenerationStage::ASSIGNMENT) {
            std::size_t count0 = 0; // the number of zero entries in branch hashes
            std::size_t size_of_branch, s0, s1;
            std::vector<uint8_t> hash_input;
            size_t rlp_child_prefix, rlp_node_prefix0, rlp_node_prefix1, rlp_node_prefix2;

            mpt_node n = input.node_data;

            for(std::size_t i = 0; i < 16; i++) {
                if (n.value.at(i) == 0){
                    rlp_child_prefix = 128;
                    hash_input.push_back(rlp_child_prefix);
                    count0++;
                } else {
                    rlp_child_prefix = 128 + 32;
                    std::array<uint8_t,32> branch_value = w_to_8(n.value.at(i));
                    std::vector<uint8_t> byte_vector(branch_value.begin(), branch_value.end());
                    byte_vector.emplace(byte_vector.begin(), rlp_child_prefix);
                    hash_input.insert( hash_input.end(), byte_vector.begin(), byte_vector.end() );
                }
                rlp_child[i] = rlp_child_prefix;
            }
            hash_input.push_back(128); //this is the RLP(value) for the value (which is always 0) in branch nodes

            size_of_branch = count0 + 33*(16 - count0) + 1;

            if (count0 < 9) {
                rlp_node_prefix2 = size_of_branch & 0xff; // lower byte of rlp_node_prefix
                rlp_node_prefix1 = size_of_branch >> 8;   // upper byte of rlp_node_prefix
                rlp_node_prefix0 = 247 + 2;
                node_length[1] = rlp_node_prefix2;
                node_length[0] = rlp_node_prefix1;
                node_num_of_bytes = 2;
                hash_input.emplace(hash_input.begin(), rlp_node_prefix2);
                hash_input.emplace(hash_input.begin(), rlp_node_prefix1);
                hash_input.emplace(hash_input.begin(), rlp_node_prefix0);
            } else {
                rlp_node_prefix2 = 0;
                rlp_node_prefix1 = size_of_branch;
                rlp_node_prefix0 = 247 + 1;
                node_length[0] = size_of_branch;
                node_num_of_bytes = 1;
                hash_input.emplace(hash_input.begin(), rlp_node_prefix1);
                hash_input.emplace(hash_input.begin(), rlp_node_prefix0);
            }
            rlp_node[2] = rlp_node_prefix2;
            rlp_node[1] = rlp_node_prefix1;
            rlp_node[0] = rlp_node_prefix0;

            zkevm_word_type hash_value = nil::blueprint::zkevm_keccak_hash(hash_input);
            std::array<std::uint8_t,32> hash_value_byte = w_to_8(hash_value);
            for(std::size_t i = 0; i < 32; i++) {
                parent_hash[i] = hash_value_byte[i];
            }

//            std::cout << "hash value = " << std::hex << hash_value << std::dec << std::endl;
            std::size_t child_num = 0;
            for(auto &v : n.value) {
//                std::cout << "    value = " << std::hex << v << std::dec << std::endl;
                if (child_num < 16) { // branch nodes have an empty 17-th value
                    std::array<std::uint8_t,32> child_value_byte = w_to_8(v);
                    for(std::size_t i = 0; i < 32; i++) {
                        child[child_num][i] = child_value_byte[i];
                    }
                }
                child_num++;
            }
        }

        // NB: parent_hash allocations should precede everything else according to mpt_dynamic structure
        for(std::size_t i = 0; i < 32; i++) {
            allocate(parent_hash[i]);
        }

        for(std::size_t i = 0; i < 16; i++) { // the 16 children
            for(std::size_t b = 0; b < 32; b++) { // the 32 bytes of each child
                allocate(child[i][b]);
            }
        }
        for(std::size_t i = 0; i < 16; i++) {
            allocate(rlp_child[i]);
        }
        for(std::size_t i = 0; i < 3; i++) {
            allocate(rlp_node[i]);
        }

        allocate(node_num_of_bytes);
        constrain((node_num_of_bytes - 1) * (node_num_of_bytes - 2));

        std::array<TYPE,16> child_sum;     // these two are non-allocated expressions
        std::array<TYPE,16> child_is_zero; // child_is_zero[j] = 1 if child[j] = 0...0, 0 otherwise

        // constraints
        for(std::size_t j = 0; j < 16; j++) {
            for(std::size_t b = 0; b < 32; b++) {
                child_sum[j] += child[j][b];
            }
            if constexpr (stage == GenerationStage::ASSIGNMENT) {
                child_sum_inverse[j] = child_sum[j].is_zero() ? 0 : child_sum[j].inversed();
            }
            allocate(child_sum_inverse[j]);
            child_is_zero[j] = 1 - child_sum_inverse[j] * child_sum[j];
            constrain(child_sum[j] * child_is_zero[j]);

            constrain((160 - rlp_child[j]) * (128 - rlp_child[j])); // TODO : maybe this is implied by smth else?
            constrain(247 + node_num_of_bytes - rlp_node[0] );
            // constrain((node_length[0] - rlp_node[1]) ); // TODO: do we really need two equal cells for that?!
            // constrain((node_length[1] - rlp_node[2]) ); // ibid
        }

        // computation of node_key_prefix << 4
        std::array<TYPE,32> shifted_node_key_prefix; // the result goes here
        std::array<TYPE,31> upper_next_node_key_prefix; // the upper 4 bits in each next byte of node_key_prefix except the last

        for (std::size_t i = 0; i < 32; i++) {
            // NB: all keys are in big-endian
            if (i < 31) {
                if constexpr (stage == GenerationStage::ASSIGNMENT) {
                    unsigned char next_key_prefix_byte = static_cast<unsigned char>(input.node_key_prefix[i+1].data.base());
                    upper_next_node_key_prefix[i] = next_key_prefix_byte >> 4;
                }
                allocate(upper_next_node_key_prefix[i]);
                // upper_next_node_key_prefix[i] is 4 bits:
                lookup(upper_next_node_key_prefix[i], "chunk_16_bits/8bits");
                lookup(16 * upper_next_node_key_prefix[i], "chunk_16_bits/8bits");
            }

            TYPE next_overflow = (i < 31) ? upper_next_node_key_prefix[i] : 0;

            if constexpr (stage == GenerationStage::ASSIGNMENT) {
                unsigned char key_prefix_byte = static_cast<unsigned char>(input.node_key_prefix[i].data.base());
                shifted_node_key_prefix[i] = ((key_prefix_byte << 4) & 0xff) + next_overflow;
            }
            allocate(shifted_node_key_prefix[i]);
            // shifted_node_key_prefix[i] is 8 bits
            lookup(shifted_node_key_prefix[i], "chunk_16_bits/8bits");

            constrain( (input.node_key_prefix[i] * 16 + next_overflow)
                       - (shifted_node_key_prefix[i] + 256 * (i > 0 ? upper_next_node_key_prefix[i-1] : 0)) );
        }

        // Establish node connections via key_to_hash table
        for(std::size_t j = 0; j < 16; j++) { // loop through child nodes
            std::vector<TYPE> k2h_query = {input.trie_id * (1 - child_is_zero[j])}; // the trie id
            for(std::size_t i = 0; i < 31; i++) {
                k2h_query.push_back(shifted_node_key_prefix[i] * (1 - child_is_zero[j])); // the key_prefix
            }
            // last byte of the key_prefix, we add the child number
            k2h_query.push_back((shifted_node_key_prefix[31] + j) * (1 - child_is_zero[j]));
            k2h_query.push_back((input.key_prefix_length + 1) * (1 - child_is_zero[j])); // key_prefix is 1 symbol longer
            for(std::size_t i = 0; i < 32; i++) {
                k2h_query.push_back(child[j][i]); // bytes of the hash to check
            }
            lookup(k2h_query, "key_to_hash");
        }
    }
};
} // namespace nil::blueprint::bbf
