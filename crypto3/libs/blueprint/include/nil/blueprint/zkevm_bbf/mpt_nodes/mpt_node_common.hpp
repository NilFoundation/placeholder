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
class mpt_node_common : public generic_component<FieldType, stage> {
    using typename generic_component<FieldType, stage>::context_type;
    using generic_component<FieldType, stage>::allocate;
    using generic_component<FieldType, stage>::copy_constrain;
    using generic_component<FieldType, stage>::constrain;
    using generic_component<FieldType, stage>::lookup;
    using generic_component<FieldType, stage>::lookup_table;

public:
    using typename generic_component<FieldType, stage>::table_params;
    using typename generic_component<FieldType, stage>::TYPE;

    using input_type = typename std::conditional<stage==GenerationStage::ASSIGNMENT, mpt_node_id, std::nullptr_t>::type;

    using value_type = typename FieldType::value_type;
    using integral_type = nil::crypto3::multiprecision::big_uint<257>;

/*
    // will probably be never used
    static table_params get_minimal_requirements() {
        return {
            .witnesses = 32, // TODO
            .public_inputs = 0,
            .constants = 0,
            .rows = 1
        };
    }

    static void allocate_public_inputs(
            context_type &context, input_type &input) {}
*/
    // Table columns, listed by order of allocation into the table
    TYPE                              trie_id;           // ids of the trie
    std::array<TYPE, NODE_TYPE_COUNT> type_selector;     // node type selector columns (0/1)

    std::array<TYPE,32> key_prefix;                      // key prefix that identifies the node in the row
    TYPE                key_prefix_length;               // length in half-bytes (i.e. 4-bit chunks)
    TYPE                key_prefix_length_inversed;      // the inverse of the prefix length (see below)
    std::array<TYPE,32> key_prefix_lower;                // the lower 4 bits of each key_prefix byte
    std::array<TYPE,32> shifted_key_prefix;              // key_prefix >> 4

    TYPE                parent_key_length;               // Parent key length (0 = root, >= 1 = branch or ext)
    TYPE                parent_key_length_inverse;       // inverse of parent_key_length
    TYPE                parent_is_ext;
//    TYPE                parent_key_length_dec_inverse;   // inverse of (parent_key_length - 1)
    std::array<TYPE, 4> branch_key_bit;                  // the bits of key_prefix_lower[31] (the parent key if parent is branch)

    // non-allocated values
    TYPE no_parent;
    TYPE parent_is_branch;
    std::array<TYPE, 16> branch_selector; // branch_selector[j] == 1  <=>  parent_is_branch && (branch_key == j)

    mpt_node_common(context_type &context_object,
        const input_type &input) : generic_component<FieldType,stage>(context_object) {

        if constexpr (stage == GenerationStage::ASSIGNMENT) {
            trie_id = input.trie_id;

            // TODO : is this necessary? They are probably 0-initialized anyway.
            for(std::size_t type_index = 0; type_index < NODE_TYPE_COUNT; type_index++) {
                type_selector[type_index] = 0;
            }
            type_selector[input.type] = 1; // put a 1 into the selector column that corresponds to our node type

            std::array<std::uint8_t,32> key_prefix_byte = w_to_8(input.key_prefix);
            std::array<std::uint8_t,32> shifted_key_prefix_byte = w_to_8(input.key_prefix >> 4);

            for(std::size_t i = 0; i < 32; i++) {
                key_prefix[i] = key_prefix_byte[i];
                key_prefix_lower[i] = key_prefix_byte[i] & 0xF;
                shifted_key_prefix[i] = shifted_key_prefix_byte[i];
            }
            key_prefix_length = input.key_prefix_length;
            parent_key_length = input.parent_key_length;
            parent_is_ext = input.parent_is_ext;
//std::cout << "PKL = " << parent_key_length << ", ";
        } // end Assignment-specific code

        allocate(trie_id);
        for(std::size_t type_index = 0; type_index < NODE_TYPE_COUNT; type_index++) {
            allocate(type_selector[type_index]); // NB: constrained in upper-level component
        }

        TYPE key_prefix_sum; // non-allocated expression for constrain generation
        for(std::size_t i = 0; i < 32; i++) {
            allocate(key_prefix[i]);
            key_prefix_sum += key_prefix[i];
        }
        allocate(key_prefix_length);
        if constexpr (stage == GenerationStage::ASSIGNMENT) {
            key_prefix_length_inversed = key_prefix_length.is_zero() ? 0 : key_prefix_length.inversed();
        }
        allocate(key_prefix_length_inversed);
        constrain(key_prefix_length * (1 - key_prefix_length * key_prefix_length_inversed));
            // the following constraint ensures that key_prefix_length == 0  =>  key_prefix == (0,...,0)
        constrain(key_prefix_sum * (1 - key_prefix_length * key_prefix_length_inversed));

        for(std::size_t i = 0; i < 32; i++) {
            allocate(key_prefix_lower[i]);
        }
        for(std::size_t i = 0; i < 32; i++) {
            allocate(shifted_key_prefix[i]);

            // per-byte constraints of the relation: shifted_key_prefix * 16 + key_prefix_lower[31] = key_prefix
            constrain(shifted_key_prefix[i] * 16 + key_prefix_lower[i]
                       - (( i > 0 ? key_prefix_lower[i-1] : 0 ) * 256 + key_prefix[i]));
        }

        allocate(parent_key_length);
        if constexpr (stage == GenerationStage::ASSIGNMENT) {
            parent_key_length_inverse = parent_key_length.is_zero() ? 0 : parent_key_length.inversed();
//            parent_key_length_dec_inverse = (parent_key_length - 1).is_zero() ?  0 : (parent_key_length - 1).inversed();
        }
        allocate(parent_key_length_inverse);
//        allocate(parent_key_length_dec_inverse);

        no_parent = 1 - parent_key_length * parent_key_length_inverse; // <=> parent_length == 0
        constrain( parent_key_length * no_parent );

        allocate(parent_is_ext);
        constrain(parent_is_ext * (1 - parent_is_ext));

        TYPE parent_is_branch  = (1 - no_parent) * (1 - parent_is_ext); // has parent and it's not an extension

        TYPE branch_key = key_prefix_lower[31];
        TYPE branch_key_expr;
        for(std::size_t i = 0; i < 4; i++) {
            if constexpr (stage == GenerationStage::ASSIGNMENT) {
               branch_key_bit[i] = (branch_key.to_integral() >> i) & 1;
            }
            allocate(branch_key_bit[i]);
            constrain(branch_key_bit[i] * (1 - branch_key_bit[i]));
            branch_key_expr += branch_key_bit[i] * (1 << i);
        }
        constrain(branch_key - branch_key_expr);

        for(std::size_t j = 0; j < 16; j++) {
            branch_selector[j] = parent_is_branch;
            for(std::size_t i = 0; i < 4; i++) {
                branch_selector[j] *= ((j >> i) & 1) ? branch_key_bit[i] : (1 - branch_key_bit[i]);
            }
        }
/*
if constexpr (stage == GenerationStage::ASSIGNMENT) {
std::cout << ", is_branch = " << parent_is_branch << ", Branch selectors: ";
        for(std::size_t j = 0; j < 16; j++) {
std::cout << branch_selector[j] << " ";
        }
}
std::cout << std::endl;
*/
    }
};
} // namespace nil::blueprint::bbf
