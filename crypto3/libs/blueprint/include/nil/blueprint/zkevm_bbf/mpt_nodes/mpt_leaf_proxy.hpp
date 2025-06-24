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
class mpt_leaf_proxy : public generic_component<FieldType, stage> {
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
            .witnesses = 32,
            .public_inputs = 0,
            .constants = 0,
            .rows = 1
        };
    }

    static void allocate_public_inputs(
            context_type &context, input_type &input) {}
*/
    static std::size_t get_witness_amount(){
        return 32;
    }

    std::array<TYPE,32> parent_hash;

    mpt_leaf_proxy(context_type &context_object,
        const input_type &input) : generic_component<FieldType,stage>(context_object) {

        if constexpr (stage == GenerationStage::ASSIGNMENT) {
            mpt_node n = input.node_data;

            std::vector<uint8_t> hash_input;
            std::size_t node_key_length = n.len.at(0);
            std::size_t node_key_bytes = ceil(node_key_length/2);

            std::array<uint8_t,32> key_value = w_to_8(n.value.at(0));
            std::vector<uint8_t> byte_vector;
            size_t rlp_key_prefix; // RLP for the key in extension node

            for(std::size_t i = (32 - node_key_bytes); i < 32; i++) {
                byte_vector.push_back(key_value[i]);
            }

            if (node_key_bytes != 1) { // if size of key is not 1-byte, RLP is (128 + size of key)
                rlp_key_prefix = 128 + node_key_bytes;
                byte_vector.emplace(byte_vector.begin(), rlp_key_prefix);
            } else { // if size of key is 1-byte, there is no RLP prefix
                rlp_key_prefix = 0;
            }

            hash_input.insert( hash_input.end(), byte_vector.begin(), byte_vector.end() );

            zkevm_word_type k0 = n.value.at(0) >> 4*(node_key_length - 1);
            if ((k0 == 1) || (k0 == 3)) {
                node_key_length--; // then we only skip the first hex symbol
            } else {
                node_key_length -= 2; // otherwise, the second hex is 0 and we skip it too
            }

            std::size_t rlp_value_prefix,  rlp_node_prefix0, rlp_node_prefix1;
            zkevm_word_type second_value = n.value.at(1);
            std::size_t node_value_length = n.len.at(1);
            std::size_t node_value_bytes = ceil(node_value_length/2);

            std::array<uint8_t,32> node_value = w_to_8(n.value.at(1));
            std::vector<uint8_t> value_byte_vector;
            for(std::size_t i = (32 - node_value_bytes); i < 32; i++) {
                value_byte_vector.push_back(node_value[i]);
            }
            rlp_value_prefix = 128 + node_value_bytes;
            rlp_node_prefix0 = 192 + node_key_bytes + node_value_bytes + 1 + (second_value > 127);
            if (second_value > 127) value_byte_vector.emplace(value_byte_vector.begin(), rlp_value_prefix);
            hash_input.insert( hash_input.end(), value_byte_vector.begin(), value_byte_vector.end() );
            std::size_t total_value_length = hash_input.size();
            hash_input.emplace(hash_input.begin(), rlp_node_prefix0);

            zkevm_word_type hash_value = nil::blueprint::zkevm_keccak_hash(hash_input);
            std::array<std::uint8_t,32> hash_value_byte = w_to_8(hash_value);
            for(std::size_t i = 0; i < 32; i++) {
                parent_hash[i] = hash_value_byte[i];
            }
            std::cout << "leaf hash value = " << std::hex << hash_value << std::dec << std::endl;
        }

        // NB: parent_hash allocations should precede everything else according to mpt_dynamic structure
        for(std::size_t i = 0; i < 32; i++) {
            allocate(parent_hash[i]);
        }
    }
};
} // namespace nil::blueprint::bbf
