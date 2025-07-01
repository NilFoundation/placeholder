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
    static std::size_t get_witness_amount(){
        return 44;
    }

    // Table columns, listed by order of allocation into the table
    TYPE                              trie_id;       // ids of the trie
    std::array<TYPE, NODE_TYPE_COUNT> type_selector; // node type selector columns (0/1)

    std::array<TYPE,32> accumulated_key;             // accumulated_key possible without the last nibble
    TYPE                last_nibble;                 // the last nibble (if it is there)
    TYPE                nibble_present;              // 0/1 indicator of whether the nibble is present == accumulated_key_length % 2

    TYPE                accumulated_key_length;      // length in half-bytes (i.e. 4-bit chunks)
    TYPE                accumulated_key_length_half; // = accumulated_key_length / 2
    TYPE                accumulated_key_length_inversed;  // the inverse of the accumulated key length (see below)

    TYPE                parent_key_length;           // Parent key length (0 = root, >= 1 = branch or ext)
    TYPE                parent_key_length_inverse;   // inverse of parent_key_length
    TYPE                parent_is_ext;               // parent is extension node (0/1)

    // non-allocated values
    TYPE no_parent;
    TYPE parent_is_branch;

    mpt_node_common(context_type &context_object,
        const input_type &input) : generic_component<FieldType,stage>(context_object) {

        if constexpr (stage == GenerationStage::ASSIGNMENT) {
            trie_id = input.trie_id;

            // TODO : is this necessary? They are probably 0-initialized anyway.
            for(std::size_t type_index = 0; type_index < NODE_TYPE_COUNT; type_index++) {
                type_selector[type_index] = 0;
            }
            type_selector[input.type] = 1; // put a 1 into the selector column that corresponds to our node type

            std::array<std::uint8_t,32> accumulated_key_byte = w_to_8(input.accumulated_key);
            std::array<std::uint8_t,32> shifted_accumulated_key_byte = w_to_8(input.accumulated_key >> 4);

            accumulated_key_length = input.accumulated_key_length;
            nibble_present = static_cast<std::size_t>(accumulated_key_length.to_integral() % 2);
            accumulated_key_length_half = static_cast<std::size_t>(accumulated_key_length.to_integral() / 2);
            last_nibble = nibble_present.is_zero() ? 0 : accumulated_key_byte[31] & 0xF;

            for(std::size_t i = 0; i < 32; i++) {
                accumulated_key[i] = nibble_present.is_zero() ? accumulated_key_byte[i] : shifted_accumulated_key_byte[i];
            }
            parent_key_length = input.parent_key_length;
            parent_is_ext = input.parent_is_ext;
        } // end Assignment-specific code

        allocate(trie_id);
        for(std::size_t type_index = 0; type_index < NODE_TYPE_COUNT; type_index++) {
            allocate(type_selector[type_index]); // NB: constrained in upper-level component
        }

        // the accumulated key representation
        TYPE accumulated_key_sum; // non-allocated expression for constrain generation
        for(std::size_t i = 0; i < 32; i++) {
            allocate(accumulated_key[i]);
            accumulated_key_sum += accumulated_key[i];
        }
        allocate(last_nibble); // TODO: range-check [0;15]
        allocate(nibble_present);

        // the accumulated key length and its constraints
        allocate(accumulated_key_length);
        if constexpr (stage == GenerationStage::ASSIGNMENT) {
            accumulated_key_length_inversed = accumulated_key_length.is_zero() ? 0 : accumulated_key_length.inversed();
        }
        allocate(accumulated_key_length_inversed);
        constrain(accumulated_key_length * (1 - accumulated_key_length * accumulated_key_length_inversed));
        // the following constraints ensures that accumulated_key_length == 0  =>  accumulated_key == (0,...,0)
        constrain(accumulated_key_sum * (1 - accumulated_key_length * accumulated_key_length_inversed));
        constrain(nibble_present * (1 - accumulated_key_length * accumulated_key_length_inversed));

        allocate(accumulated_key_length_half); // needs basic range-check only (i.e. 8bit range-check)
        constrain(nibble_present * (1 - nibble_present));
        constrain(2 * accumulated_key_length_half + nibble_present - accumulated_key_length);

        allocate(parent_key_length);
        if constexpr (stage == GenerationStage::ASSIGNMENT) {
            parent_key_length_inverse = parent_key_length.is_zero() ? 0 : parent_key_length.inversed();
        }
        allocate(parent_key_length_inverse);

        no_parent = 1 - parent_key_length * parent_key_length_inverse; // <=> parent_length == 0
        constrain( parent_key_length * no_parent );

        allocate(parent_is_ext);
        constrain(parent_is_ext * (1 - parent_is_ext));

        parent_is_branch  = (1 - no_parent) * (1 - parent_is_ext); // has parent and it's not an extension
    }
};
} // namespace nil::blueprint::bbf
