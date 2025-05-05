//---------------------------------------------------------------------------//
// Copyright (c) 2024 Elena Tatuzova <e.tatuzova@nil.foundation>
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

#include <numeric>
#include <algorithm>

#include <nil/blueprint/zkevm_bbf/big_field/opcodes/abstract_opcode.hpp>

namespace nil::blueprint::bbf::zkevm_big_field{
    template<typename FieldType, GenerationStage stage>
    class zkevm_revert_bbf : generic_component<FieldType, stage> {
        using typename generic_component<FieldType, stage>::context_type;
        using generic_component<FieldType, stage>::allocate;
        using generic_component<FieldType, stage>::copy_constrain;
        using generic_component<FieldType, stage>::constrain;
        using generic_component<FieldType, stage>::lookup;
        using generic_component<FieldType, stage>::lookup_table;
    public:
        using typename generic_component<FieldType,stage>::TYPE;
        using value_type = typename FieldType::value_type;
        constexpr static const value_type two_128 = 0x100000000000000000000000000000000_big_uint254;
        using Word_Size = typename zkevm_big_field::word_size<FieldType, stage>;
        using Memory_Cost = typename zkevm_big_field::memory_cost<FieldType, stage>;

        zkevm_revert_bbf(context_type &context_object, const opcode_input_type<FieldType, stage> &current_state):
            generic_component<FieldType,stage>(context_object, false)
        {
            TYPE offset;
            TYPE length, length_inv, is_length_zero;
            TYPE modified_items;
            TYPE current_mem, next_mem, memory_expansion_cost, memory_expansion_size, S;

            if constexpr( stage == GenerationStage::ASSIGNMENT ){
                offset = w_lo<FieldType>(current_state.stack_top());
                length = w_lo<FieldType>(current_state.stack_top(1));
                length_inv = length == 0? 0: length.inversed();
                is_length_zero = length == 0? 0: 1;
                modified_items = current_state.modified_items_amount();

                current_mem = current_state.memory_size();
                next_mem = length.is_zero()? current_mem : std::max(offset + length, current_mem);
                S = next_mem > current_mem;
            }
            allocate(offset, 32, 0);
            allocate(length, 33, 0);
            allocate(length_inv, 34, 0);
            allocate(is_length_zero, 35, 0);
            allocate(modified_items, 36, 0);
            allocate(current_mem, 37, 0);
            allocate(next_mem, 38, 0);
            allocate(S, 39, 0);
            allocate(memory_expansion_cost, 40, 0);
            allocate(memory_expansion_size, 41, 0);

            // // is_length_zero correctness
            constrain(length * (length *length_inv - 1));
            constrain(length_inv * (length *length_inv - 1));
            constrain(is_length_zero - length * length_inv);

            // memory_expansion
            constrain(S * (S - 1));
            constrain(S * (next_mem - offset - length) + (1 - S) * (next_mem - current_mem));

            std::vector<std::size_t> word_size_lookup_area = {32, 33, 34};
            allocate(memory_expansion_cost, 35, 1);
            allocate(memory_expansion_size, 36, 1);
            std::vector<std::size_t> memory_cost_lookup_area = {42, 43, 44, 45, 46, 47};

            context_type word_size_ct = context_object.subcontext(word_size_lookup_area, 1, 1);

            context_type current_memory_ct = context_object.subcontext(memory_cost_lookup_area, 0, 1);
            context_type next_memory_ct = context_object.subcontext(memory_cost_lookup_area, 1, 1);

            Memory_Cost current_memory = Memory_Cost(current_memory_ct, current_mem);
            Memory_Cost next_memory = Memory_Cost(next_memory_ct, next_mem);
            memory_expansion_cost = next_memory.cost - current_memory.cost;
            memory_expansion_size = (next_memory.word_size - current_memory.word_size) * 32;
            Word_Size minimum_word = Word_Size(word_size_ct, length);


            if constexpr( stage == GenerationStage::CONSTRAINTS ){
                // constrain(current_state.pc_next() - current_state.pc(0) - 1);                   // PC transition
                constrain(current_state.gas(0) - current_state.gas_next() - memory_expansion_cost);               // GAS transition
                // constrain(current_state.stack_size(0) - current_state.stack_size_next() - 2);   // stack_size transition
                // constrain(current_state.memory_size(0) - current_state.memory_size_next());     // memory_size transition
                constrain(current_state.rw_counter_next() - current_state.rw_counter(0) - modified_items - 2 * length - 2);   // rw_counter transition

                // TODO: If we should process reverting transactions, append end_transaction option for next opcode.
                // Now only CALL revert-s supported now
                constrain((current_state.opcode_next() - TYPE(std::size_t(opcode_to_number(zkevm_opcode::end_call)))));

                // Stack reading correctness
                lookup(rw_table<FieldType, stage>::stack_lookup(
                    current_state.call_id(0),
                    current_state.stack_size(0) - 1,
                    current_state.rw_counter(0),
                    TYPE(0),// is_write
                    TYPE(0),// hi bytes are 0
                    offset
                ), "zkevm_rw");
                lookup(rw_table<FieldType, stage>::stack_lookup(
                    current_state.call_id(0),
                    current_state.stack_size(0) - 2,
                    current_state.rw_counter(0) +1,
                    TYPE(0),// is_write
                    TYPE(0),// hi bytes are 0
                    length
                ), "zkevm_rw");

                // Modified_items, returndatasize correctness
                lookup({
                    TYPE(1),
                    TYPE(std::size_t(rw_operation_type::state_call_context)),
                    current_state.call_id(0),
                    std::size_t(state_call_context_fields::modified_items),
                    TYPE(0),    //field
                    TYPE(0),    //storage_key_hi
                    TYPE(0),    //storage_key_lo
                    current_state.call_id(0) + std::size_t(state_call_context_fields::modified_items),
                    TYPE(0),    //is_write
                    TYPE(0),    //value_hi
                    modified_items,
                    TYPE(0),    //previous_value_hi
                    modified_items,
                    TYPE(0),    //initial_value_hi
                    modified_items
                }, "zkevm_state_opcode");

                lookup(rw_table<FieldType, stage>::call_context_lookup(
                    current_state.call_id(0),
                    std::size_t(call_context_field::returndata_size),
                    TYPE(0),
                    length
                ), "zkevm_rw");
            }
        }
    };

    template<typename FieldType>
    class zkevm_revert_operation : public opcode_abstract<FieldType> {
    public:
        virtual void fill_context(
            typename generic_component<FieldType, GenerationStage::ASSIGNMENT>::context_type &context,
            const opcode_input_type<FieldType, GenerationStage::ASSIGNMENT> &current_state
        )  override {
            zkevm_revert_bbf<FieldType, GenerationStage::ASSIGNMENT> bbf_obj(context, current_state);
        }
        virtual void fill_context(
            typename generic_component<FieldType, GenerationStage::CONSTRAINTS>::context_type &context,
            const opcode_input_type<FieldType, GenerationStage::CONSTRAINTS> &current_state
        )  override {
            zkevm_revert_bbf<FieldType, GenerationStage::CONSTRAINTS> bbf_obj(context, current_state);
        }
        virtual std::size_t rows_amount() override {
            return 2; // We use two rows because don't want to use 4 lookups to copy table instead of 2
        }
    };
}

