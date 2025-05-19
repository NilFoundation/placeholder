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
class mpt_extension : public generic_component<FieldType, stage> {
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
    mpt_extension(context_type &context_object,
        const input_type &input) : generic_component<FieldType,stage>(context_object) {

        std::array<TYPE,32> parent_hash;
        TYPE key_length_bytes;
        // std::array<TYPE, 2> rlp_child; // extension nodes have only two children: key and value
        TYPE node_length;
        std::array<TYPE, 2> rlp_node_prefix; // rlp_node prefix for an extension node fits into 2 values
        std::array<TYPE, 32> key_part;   // key_part[32]
        std::array<TYPE, 32> ext_value;  // ext_value[32]
        TYPE rlp_key_prefix, rlp_value_prefix;

        TYPE value_length_bytes = 32; // instead of allocating we use it as a constant for now
        TYPE node_num_of_bytes = 1; // node_num_of_bytes: number of bytes that compose the size of node = 1 or 2. Always 1 for extensions?

        if constexpr (stage == GenerationStage::ASSIGNMENT) {
            mpt_node n = input.node_data;

            std::vector<uint8_t> hash_input;
            std::size_t node_key_length = n.len.at(0);
            std::size_t node_key_bytes = ceil(node_key_length/2);

            key_length_bytes = node_key_bytes;

            std::array<uint8_t,32> key_value = w_to_8(n.value.at(0));
            std::vector<uint8_t> byte_vector;
            size_t rlp_prefix; // RLP for the key in extension node

            for(std::size_t i = (32 - node_key_bytes); i < 32; i++) {
                byte_vector.push_back(key_value[i]);
            }

            if (node_key_bytes != 1) { // if size of key is not 1-byte, RLP is (128 + size of key)
                rlp_prefix = 128 + node_key_bytes;
                byte_vector.emplace(byte_vector.begin(), rlp_prefix);
            } else { // if size of key is 1-byte, there is no RLP prefix
                rlp_prefix = 0;
            }
            // rlp_child[0] = rlp_key_prefix;
            rlp_key_prefix = rlp_prefix;

            hash_input.insert( hash_input.end(), byte_vector.begin(), byte_vector.end() );

            zkevm_word_type k0 = n.value.at(0) >> 4*(node_key_length - 1);
            if ((k0 == 1) || (k0 == 3)) {
                node_key_length--; // then we only skip the first hex symbol
            } else {
                node_key_length -= 2; // otherwise, the second hex is 0 and we skip it too
            }

            // size_t rlp_value_prefix; // RLP for the value in ext nodes
            size_t rlp_node_prefix0, rlp_node_prefix1; // RLP prefixes for the whole node (2-bytes)
            std::array<uint8_t,32> node_value = w_to_8(n.value.at(1));

            std::vector<uint8_t> value_byte_vector(node_value.begin(), node_value.end());
            rlp_prefix = 128 + 32; // value in ext node is a hash, so always 32-bytes, hence RLP = 0xa0
            // rlp_child[1] = rlp_value_prefix;
            rlp_value_prefix = rlp_prefix;
            value_byte_vector.emplace(value_byte_vector.begin(), rlp_prefix);
            hash_input.insert( hash_input.end(), value_byte_vector.begin(), value_byte_vector.end() );
            std::size_t total_value_length = hash_input.size(); // size of value to be hashed: rlp_key||key||rlp_value||value

            // here...
            if (total_value_length <= 55) {
                rlp_node_prefix0 = 192 + total_value_length;
                rlp_node_prefix[0] = rlp_node_prefix0;
                node_length = total_value_length;
                hash_input.emplace(hash_input.begin(), rlp_node_prefix0);
            } else {
                rlp_node_prefix1 = node_key_bytes + 34;
                rlp_node_prefix0 = 247 + 1;
                rlp_node_prefix[1] = rlp_node_prefix1;
                rlp_node_prefix[0] = rlp_node_prefix0;
                node_length = total_value_length;
                hash_input.emplace(hash_input.begin(), rlp_node_prefix1);
                hash_input.emplace(hash_input.begin(), rlp_node_prefix0);
            }

            for(std::size_t i = 0; i < hash_input.size(); i++) {
                std::cout << "hash_input[" << i << "] = " << std::hex << unsigned(hash_input[i]) << std::dec << std::endl;
            }

            std::cout << "node_key_bytes = " << std::hex << node_key_bytes << std::dec << std::endl;
            std::cout << "total_value_length = " << total_value_length << std::endl;

            zkevm_word_type hash_value = nil::blueprint::zkevm_keccak_hash(hash_input);
            std::array<std::uint8_t,32> hash_value_byte = w_to_8(hash_value);
            for(std::size_t i = 0; i < 32; i++) {
                parent_hash[i] = hash_value_byte[i];
            }
            std::cout << "hash value = " << std::hex << hash_value << std::dec << std::endl;

            // zkevm_word_type node_key_part = n.value.at(0);
            // std::array<std::uint8_t,32> key_part_byte = w_to_8(node_key_part);
            for(std::size_t i = 0; i < 32; i++) {
                key_part[i] = key_value[i];
                ext_value[i] = node_value[i];
            }

            std::cout << "[" << std::endl;
            for(auto &v : n.value) {
                std::cout << "    value = " << std::hex << v << std::dec << std::endl;
            }
            std::cout << "]" << std::endl;

            std::cout << "key_length_bytes = " << key_length_bytes << std::endl;
        }

        // NB: parent_hash allocations should precede everything else according to mpt_dynamic structure
        // col 0-31: parent_hash bytes
        for(std::size_t i = 0; i < 32; i++) {
            allocate(parent_hash[i]);
        }
        // col 32: length of key part before RLP prefix (in bytes)
        allocate(key_length_bytes);
        // col 33: length of ext node before RLP prefix (in bytes): 
        // rlp_key_prefix || key_part || rlp_value_prefix || value
        allocate(node_length);
        // col 34: RLP prefix of ext node key part (in bytes)
        allocate(rlp_key_prefix);
        // col 35: RLP prefix of ext node value (in bytes)
        allocate(rlp_value_prefix);
        // col 36-37: RLP prefix of ext node (in bytes)
        for(std::size_t i = 0; i < 2; i++) {
            // allocate(rlp_child[i]);
            allocate(rlp_node_prefix[i]);
        }
        // col 38-69: key part of ext node (in bytes)
        for(std::size_t i = 0; i < 32; i++) {
            allocate(key_part[i]);
        }
        // col 70-101: value of ext node (in bytes)
        for(std::size_t i = 0; i < 32; i++) {
            allocate(ext_value[i]);
        }

        constrain(rlp_key_prefix * (128 + key_length_bytes - rlp_key_prefix) );
        constrain(160 - rlp_value_prefix); // if rlp_child[1] is constant, we don't need to allocate and constrain it
        constrain(rlp_node_prefix[1] * (node_length - rlp_node_prefix[1]) );
        constrain((192 + node_length - rlp_node_prefix[0]) * (247 + node_num_of_bytes - rlp_node_prefix[0]) );
    }
};
} // namespace nil::blueprint::bbf