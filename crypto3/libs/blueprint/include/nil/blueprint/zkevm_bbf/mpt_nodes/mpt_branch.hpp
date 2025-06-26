//---------------------------------------------------------------------------//
// Copyright (c) 2025 Alexey Yashunsky <a.yashunsky@nil.foundation>
// Copyright (c) 2025 Georgios Fotiadis <gfotiadis@nil.foundation>
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
        TYPE rlc_challenge;
        std::array<TYPE,32> node_key_prefix;
        TYPE key_prefix_length;
        TYPE parent_key_length;
        std::array<TYPE,32> shifted_key_prefix;
        TYPE branch_key;
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
            .witnesses = 900,
            .public_inputs = 0,
            .constants = 0,
            .rows = 1
        };
    }

    static void allocate_public_inputs(
            context_type &context, input_type &input) {}
*/
    static std::size_t get_witness_amount(){
        return 900;
    }

    // These cells are interfaces to internal data
    std::array<TYPE, 32> parent_hash; // the hash for reference to the node from parent node
    std::array<std::array<TYPE, 32>, 16> child; // 16 32-byte child hashes

    std::array<TYPE, 32> child_accumulated_key;
    TYPE child_nibble_present;
    std::array<TYPE, 16> child_last_nibble;
    std::array<TYPE, 15> child_accumulated_key_last_byte;

    mpt_branch(context_type &context_object,
        const input_type &input) : generic_component<FieldType,stage>(context_object) {

        std::array<TYPE, 16> child_sum_inverse; // inverses of child hash bytes' sums
        std::array<TYPE, 16> child_is_zero; // child_is_zero[j] = 1 if child[j] = 0...0, 0 otherwise
        std::array<TYPE, 2> node_length; // length of the encoded node, two bytes at most, big-endian
        TYPE node_length_upper_inverse; // the inverse of node_length[0], if exists

        // cells for computing RLC (for keccak connection)
        TYPE rlc_value_node_prefix;
        std::array<std::array<TYPE, 16>, 16> rlc_value_child;

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
            }
            hash_input.push_back(128); //this is the RLP(value) for the value (which is always 0) in branch nodes

            size_of_branch = count0 + 33*(16 - count0) + 1;

            if (count0 < 9) {
                rlp_node_prefix2 = size_of_branch & 0xff; // lower byte of rlp_node_prefix
                rlp_node_prefix1 = size_of_branch >> 8;   // upper byte of rlp_node_prefix
                rlp_node_prefix0 = 247 + 2;
                node_length[1] = rlp_node_prefix2;
                node_length[0] = rlp_node_prefix1;
                hash_input.emplace(hash_input.begin(), rlp_node_prefix2);
                hash_input.emplace(hash_input.begin(), rlp_node_prefix1);
                hash_input.emplace(hash_input.begin(), rlp_node_prefix0);
            } else {
                rlp_node_prefix2 = 0;
                rlp_node_prefix1 = size_of_branch;
                rlp_node_prefix0 = 247 + 1;
                node_length[1] = size_of_branch;
                node_length[0] = 0;
                hash_input.emplace(hash_input.begin(), rlp_node_prefix1);
                hash_input.emplace(hash_input.begin(), rlp_node_prefix0);
            }

            zkevm_word_type hash_value = nil::blueprint::zkevm_keccak_hash(hash_input);
            input.keccak_buffers->new_buffer({hash_input, hash_value});

            std::array<std::uint8_t,32> hash_value_byte = w_to_8(hash_value);
            for(std::size_t i = 0; i < 32; i++) {
                parent_hash[i] = hash_value_byte[i];
            }

            // std::cout << "hash value = " << std::hex << hash_value << std::dec << std::endl;
            std::size_t child_num = 0;
            BOOST_LOG_TRIVIAL(trace) << "branches:\n";
            std::stringstream ss;
            for(auto &v : n.value) {
                // std::cout << "    value = " << std::hex << v << std::dec << std::endl;
                if (child_num < 16) { // branch nodes have an empty 17-th value
                    ss << child_num << " ";
                    std::array<std::uint8_t,32> child_value_byte = w_to_8(v);
                    for(std::size_t i = 0; i < 32; i++) {
                        child[child_num][i] = child_value_byte[i];
                        ss << std::hex << child[child_num][i] << std::dec << " ";
                    }
                    ss << std::endl;
                }
                child_num++;
            }
            BOOST_LOG_TRIVIAL(trace) << ss.str();
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

        child_nibble_present = 1 - input.node_nibble_present;
        allocate(child_nibble_present);

        for(std::size_t i = 0; i < 31; i++) {
            child_accumulated_key[i] = child_nibble_present * input.node_accumulated_key[i]
                                         + (1 - child_nibble_present) * input.node_accumulated_key[i+1];
            allocate(child_accumulated_key[i]);
        }
        child_accumulated_key[31] = child_nibble_present * input.node_accumulated_key[31]
                                      + (1 - child_nibble_present) * 16 * input.node_last_nibble;
        allocate(child_accumulated_key[31]);

        for(std::size_t i = 0; i < 15; i++) {
            child_accumulated_key_last_byte[i] = child_accumulated_key[31] + (1 - child_nibble_present) * (i + 1);
            allocate(child_accumulated_key_last_byte[i]);
        }
        for(std::size_t i = 0; i < 16; i++) {
            child_last_nibble[i] = child_nibble_present * i; // Yes, we need a zero column (i == 0) for the lookup table!
            allocate(child_last_nibble[i]);
        }

        // expressions for generating constraints
        std::array<TYPE,16> child_sum;     // these two are non-allocated expressions:
        std::array<TYPE,16> rlp_child;     // RLP prefixes for each child (not allocated), 128 or 160, depending on child_is_zero[j]
        std::array<TYPE,3>  rlp_node;      // RLP prefix of the entire node (not allocated)
        TYPE count0_expr;                  // expression for counting 0 hashes in the node

        // checking each hash for being 0 and computing each hash's RLP prefix
        for(std::size_t j = 0; j < 16; j++) {
            for(std::size_t b = 0; b < 32; b++) {
                child_sum[j] += child[j][b];
            }
            if constexpr (stage == GenerationStage::ASSIGNMENT) {
                child_sum_inverse[j] = child_sum[j].is_zero() ? 0 : child_sum[j].inversed();
            }
            allocate(child_sum_inverse[j]);

            child_is_zero[j] = 1 - child_sum_inverse[j] * child_sum[j];
            allocate(child_is_zero[j]);

            constrain(child_sum[j] * child_is_zero[j]);

            count0_expr += child_is_zero[j];

            rlp_child[j] = child_is_zero[j] * 128 + (1 - child_is_zero[j]) * 160;
        }

        // node length in bytes and node RLP prefix
        allocate(node_length[0]);
        lookup(node_length[0], "chunk_16_bits/8bits");
        allocate(node_length[1]);
        lookup(node_length[1], "chunk_16_bits/8bits");
        constrain(256*node_length[0] + node_length[1] - (count0_expr + 33*(16 - count0_expr) + 1));
        if constexpr (stage == GenerationStage::ASSIGNMENT) {
            node_length_upper_inverse = node_length[0].is_zero() ? 0 : node_length[0].inversed();
        }
        allocate(node_length_upper_inverse);
        TYPE length_is_one_byte = 1 - node_length[0] * node_length_upper_inverse;
        constrain(node_length[0] * length_is_one_byte);
        rlp_node[0] = 247 + 2 - length_is_one_byte;
        rlp_node[1] = length_is_one_byte * node_length[1] + (1 - length_is_one_byte) * node_length[0];
        rlp_node[2] = (1 - length_is_one_byte) * node_length[1];

        // RLC value computation
        TYPE RLC = input.rlc_challenge;

        // total length of hashed sequence = node_length + (2 or 3, depending on length_is_one_byte)
        rlc_value_node_prefix = 256*node_length[0] + node_length[1] + 3 - length_is_one_byte;

        // RLP node prefix
        // the first two bytes of RLP node prefix are always present
        for (std::size_t i = 0; i < 2; i++) {
            rlc_value_node_prefix *= RLC;
            rlc_value_node_prefix += rlp_node[i];
        }
        // the third byte is optional
        rlc_value_node_prefix *= length_is_one_byte + (1 - length_is_one_byte)*RLC;
        rlc_value_node_prefix += (1 - length_is_one_byte) * rlp_node[2];
        allocate(rlc_value_node_prefix);

        std::array<TYPE, 16> rlc_value_child_prefix; // non-allocated expressions for RLC of the RLP child prefix
        // loop through the children
        for (std::size_t j = 0; j < 16; j++) {
             // we start with the node prefix or the last computed byte of an RLC for the previous child node
             rlc_value_child_prefix[j] = (j == 0) ? rlc_value_node_prefix : rlc_value_child[j-1][15];
             rlc_value_child_prefix[j] *= RLC;
             rlc_value_child_prefix[j] += rlp_child[j];
             // we store only _one_ RLC for each _pair_ of bytes in a child hash
             // loop through pairs of bytes
             for(std::size_t b = 0; b < 16; b++) {
                 rlc_value_child[j][b] = (b == 0) ? rlc_value_child_prefix[j] : rlc_value_child[j][b-1];

                 // Normally we should be multiplying the added bytes by (1 - child_is_zero[j]),
                 // but if a child is zero, all its bytes are zero, and we can just add them thoughtlessly :)
                 rlc_value_child[j][b] *= child_is_zero[j] + (1 - child_is_zero[j])*RLC;
                 rlc_value_child[j][b] += child[j][2*b]; // first byte in pair

                 rlc_value_child[j][b] *= child_is_zero[j] + (1 - child_is_zero[j])*RLC;
                 rlc_value_child[j][b] += child[j][2*b + 1]; // second byte in pair

                 allocate(rlc_value_child[j][b]);
             }
        }

        TYPE rlc_result = rlc_value_child[15][15] * RLC + 128; // The last symdol in the buffer is a zero
        zkevm_word_type power_of_2 = zkevm_word_type(1) << (31 * 8);
        auto keccak_tuple = chunks8_to_chunks16<TYPE>(parent_hash);
        BOOST_LOG_TRIVIAL(trace) << "rlc_result = " << rlc_result << std::endl;
        keccak_tuple.emplace(keccak_tuple.begin(), rlc_result);
        lookup(keccak_tuple, "keccak_table");
    }
};
} // namespace nil::blueprint::bbf
