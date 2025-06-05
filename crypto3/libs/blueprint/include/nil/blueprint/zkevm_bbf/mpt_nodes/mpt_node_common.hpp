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
        return 123;
    }

    // Table columns, listed by order of allocation into the table
    TYPE                              trie_id;       // ids of the trie
    std::array<TYPE, NODE_TYPE_COUNT> type_selector; // node type selector columns (0/1)

    std::array<TYPE,32> accumulated_key;             // accumulated_key identifies the node in the row
    TYPE                accumulated_key_length;      // length in half-bytes (i.e. 4-bit chunks)
    TYPE                accumulated_key_length_inversed;  // the inverse of the accumulated key length (see below)
    std::array<TYPE,32> accumulated_key_lower;       // the lower 4 bits of each accumulated_key byte
    std::array<TYPE,32> shifted_accumulated_key;     // accumulated_key >> 4

    TYPE                parent_key_length;           // Parent key length (0 = root, >= 1 = branch or ext)
    TYPE                parent_key_length_inverse;   // inverse of parent_key_length
    TYPE                parent_is_ext;               // parent is extension node (0/1)
                                                     // NB: only branch nodes can have extension nodes as parents but it's
                                                     // easier to define everything related to extension parents in the
                                                     // common part.

    std::array<TYPE, 4> branch_key_bit;              // the bits of accumulated_key_lower[31] (the parent key if parent is branch)
    TYPE                pkl_is_odd;                  // the lowest bit of parent_key_length
    TYPE                parent_key_length_bytes;     // parent_key_length / 2 = length in bytes
    // auxiliary cells for defining I(x) = 1 iff x == parent_key_length
    // I(x) = I1(x / 8) * I2(x % 8)
    std::array<TYPE, 4> pkl_indic_1 = {0,0,0,0};     // I1 indicator function for parent_key_length
    std::array<TYPE, 8> pkl_indic_2 = {0,0,0,0,0,0,0,0}; // I2 indicator function for parent_key_length

    // non-allocated values
    TYPE no_parent;
    TYPE parent_is_branch;
    std::array<TYPE, 16> branch_selector; // branch_selector[j] == 1  <=>  parent_is_branch && (branch_key == j)
    std::array<TYPE, 32> parent_accumulated_key; // key prefix of the parent defined according to parent_key_length

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

            for(std::size_t i = 0; i < 32; i++) {
                accumulated_key[i] = accumulated_key_byte[i];
                accumulated_key_lower[i] = accumulated_key_byte[i] & 0xF;
                shifted_accumulated_key[i] = shifted_accumulated_key_byte[i];
            }
            accumulated_key_length = input.accumulated_key_length;
            parent_key_length = input.parent_key_length;
            pkl_is_odd = static_cast<std::size_t>(parent_key_length.to_integral() % 2);
            parent_key_length_bytes = static_cast<std::size_t>(parent_key_length.to_integral() / 2);

            parent_is_ext = input.parent_is_ext;

            pkl_indic_1[static_cast<std::size_t>(parent_key_length_bytes.to_integral() / 8)] = 1;
            pkl_indic_2[static_cast<std::size_t>(parent_key_length_bytes.to_integral() % 8)] = 1;
//std::cout << "PKL = " << parent_key_length << ", ";
        } // end Assignment-specific code

        allocate(trie_id);
        for(std::size_t type_index = 0; type_index < NODE_TYPE_COUNT; type_index++) {
            allocate(type_selector[type_index]); // NB: constrained in upper-level component
        }

        TYPE accumulated_key_sum; // non-allocated expression for constrain generation
        for(std::size_t i = 0; i < 32; i++) {
            allocate(accumulated_key[i]);
            accumulated_key_sum += accumulated_key[i];
        }
        allocate(accumulated_key_length);
        if constexpr (stage == GenerationStage::ASSIGNMENT) {
            accumulated_key_length_inversed = accumulated_key_length.is_zero() ? 0 : accumulated_key_length.inversed();
        }
        allocate(accumulated_key_length_inversed);
        constrain(accumulated_key_length * (1 - accumulated_key_length * accumulated_key_length_inversed));
            // the following constraint ensures that accumulated_key_length == 0  =>  accumulated_key == (0,...,0)
        constrain(accumulated_key_sum * (1 - accumulated_key_length * accumulated_key_length_inversed));

        for(std::size_t i = 0; i < 32; i++) {
            allocate(accumulated_key_lower[i]);
        }
        for(std::size_t i = 0; i < 32; i++) {
            allocate(shifted_accumulated_key[i]);

            // per-byte constraints of the relation: shifted_accumulated_key * 16 + accumulated_key_lower[31] = accumulated_key
            constrain(shifted_accumulated_key[i] * 16 + accumulated_key_lower[i]
                       - (( i > 0 ? accumulated_key_lower[i-1] : 0 ) * 256 + accumulated_key[i]));
        }

        allocate(parent_key_length);
        if constexpr (stage == GenerationStage::ASSIGNMENT) {
            parent_key_length_inverse = parent_key_length.is_zero() ? 0 : parent_key_length.inversed();
        }
        allocate(parent_key_length_inverse);

        no_parent = 1 - parent_key_length * parent_key_length_inverse; // <=> parent_length == 0
        constrain( parent_key_length * no_parent );

        allocate(parent_is_ext);
        constrain(parent_is_ext * (1 - parent_is_ext));

        TYPE parent_is_branch  = (1 - no_parent) * (1 - parent_is_ext); // has parent and it's not an extension

        TYPE branch_key = accumulated_key_lower[31];
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

        allocate(pkl_is_odd);
        constrain( pkl_is_odd * (1 - pkl_is_odd) );
        allocate(parent_key_length_bytes); // TODO: additional constraints?
        constrain(2*parent_key_length_bytes + pkl_is_odd - parent_key_length);

        TYPE indic1_sum;
        TYPE indic1_value;
        for(std::size_t i = 0; i < 4; i++) {
            allocate(pkl_indic_1[i]);
            constrain( pkl_indic_1[i] * (1 - pkl_indic_1[i]) );
            indic1_sum += pkl_indic_1[i];
            indic1_value += pkl_indic_1[i] * i;
        }
        constrain( indic1_sum * (1 - indic1_sum) );

        TYPE indic2_sum;
        TYPE indic2_value;
        for(std::size_t i = 0; i < 8; i++) {
            allocate(pkl_indic_2[i]);
            constrain( pkl_indic_2[i] * (1 - pkl_indic_2[i]) );
            indic2_sum += pkl_indic_2[i];
            indic2_value += pkl_indic_2[i] * i;
        }
        constrain( indic2_sum * (1 - indic2_sum) );
        constrain( indic1_value * 8 + indic2_value - parent_key_length_bytes );

        // the byte sequence to use for parent_accumulated_key definition
        std::array<TYPE, 32> source_bytes;
        // either accumulated_key or shifted_accumulated_key depending on pkl_is_odd
        for(std::size_t i = 0; i < 32; i++) {
            source_bytes[i] = pkl_is_odd * shifted_accumulated_key[i] + (1 - pkl_is_odd) * accumulated_key[i];
        }
        // different possible values for parent_key_length
        for(std::size_t l = 0; l < 32; l++) {
            TYPE selector = pkl_indic_1[l / 8] * pkl_indic_2[l % 8];
            for(std::size_t i = 0; i < 32; i++) {
                if (i >= l) {
                    parent_accumulated_key[i] += source_bytes[i - l] * selector;
                }
            }
        }
    }
};
} // namespace nil::blueprint::bbf
