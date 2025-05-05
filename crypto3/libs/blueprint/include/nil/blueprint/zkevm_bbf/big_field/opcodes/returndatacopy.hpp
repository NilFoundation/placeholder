//---------------------------------------------------------------------------//
// Copyright (c) 2024 Antoine Cyr <antoinecyr@nil.foundation>
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

#include <algorithm>
#include <numeric>

#include <nil/blueprint/zkevm_bbf/big_field/opcodes/abstract_opcode.hpp>

namespace nil::blueprint::bbf::zkevm_big_field{
    template<typename FieldType, GenerationStage stage>
    class zkevm_returndatacopy_bbf : generic_component<FieldType, stage> {
        using typename generic_component<FieldType, stage>::context_type;
        using generic_component<FieldType, stage>::allocate;
        using generic_component<FieldType, stage>::copy_constrain;
        using generic_component<FieldType, stage>::constrain;
        using generic_component<FieldType, stage>::lookup;
        using generic_component<FieldType, stage>::lookup_table;

        public:
        using typename generic_component<FieldType, stage>::TYPE;

        zkevm_returndatacopy_bbf(
            context_type &context_object,
            const opcode_input_type<FieldType, stage> &current_state)
            : generic_component<FieldType, stage>(context_object, false) {
            using Word_Size = typename zkevm_big_field::word_size<FieldType, stage>;
            using Memory_Cost = typename zkevm_big_field::memory_cost<FieldType, stage>;

            TYPE destOffset, offset, length, length_inv, is_length_zero;
            TYPE current_mem, next_mem,
                memory_expansion_cost, memory_expansion_size, S;
            TYPE lastcall_id;

            if constexpr (stage == GenerationStage::ASSIGNMENT) {
                destOffset = w_lo<FieldType>(current_state.stack_top());
                offset = w_lo<FieldType>(current_state.stack_top(1));
                length = w_lo<FieldType>(current_state.stack_top(2));
                current_mem = current_state.memory_size();
                next_mem = length.is_zero()? current_mem: std::max(destOffset + length, current_mem);
                S = next_mem > current_mem;
                length_inv = length == 0 ? 0: length.inversed();
                lastcall_id = current_state.lastsubcall_id();
                is_length_zero = length == 0 ? 0: 1;
            }
            allocate(destOffset, 32, 0);
            allocate(offset, 33, 0);
            allocate(length, 34, 0);
            allocate(current_mem, 35, 0);
            allocate(next_mem, 36, 0);
            allocate(S, 37, 0);
            allocate(length_inv, 38, 0);
            allocate(lastcall_id, 39, 0);
            allocate(is_length_zero, 40, 0);

            // length_inv is correct
            constrain(length * (length * length_inv - 1));
            constrain(length_inv * (length * length_inv - 1));
            constrain(is_length_zero - length * length_inv);

            constrain(S * (S - 1));
            constrain(S * (next_mem - destOffset - length) +
                        (1 - S) * (next_mem - current_mem));

            std::vector<std::size_t> word_size_lookup_area = {32, 33, 34};
            allocate(memory_expansion_cost, 35, 1);
            allocate(memory_expansion_size, 36, 1);
            std::vector<std::size_t> memory_cost_lookup_area = {42, 43, 44,
                                                                45, 46, 47};

            context_type word_size_ct =
                context_object.subcontext(word_size_lookup_area, 1, 1);

            context_type current_memory_ct =
                context_object.subcontext(memory_cost_lookup_area, 0, 1);
            context_type next_memory_ct =
                context_object.subcontext(memory_cost_lookup_area, 1, 1);

            Memory_Cost current_memory =
                Memory_Cost(current_memory_ct, current_mem);
            Memory_Cost next_memory = Memory_Cost(next_memory_ct, next_mem);
            memory_expansion_cost = next_memory.cost - current_memory.cost;
            memory_expansion_size =
                (next_memory.word_size - current_memory.word_size) * 32;

            Word_Size minimum_word = Word_Size(word_size_ct, length);

            if constexpr (stage == GenerationStage::CONSTRAINTS) {
                constrain(current_state.pc_next() - current_state.pc(0) -
                            1);  // PC transition
                constrain(current_state.gas(0) - current_state.gas_next() - 3 -
                            3 * minimum_word.size - memory_expansion_cost);  // GAS transition
                constrain(current_state.stack_size(0) -
                            current_state.stack_size_next() -
                            3);  // stack_size transition
                constrain(
                    current_state.memory_size_next() -
                    current_state.memory_size(0) - memory_expansion_size);  // memory_size transition
                constrain(current_state.rw_counter_next() -
                            current_state.rw_counter(0) -
                            4 - 2 * length);  // rw_counter transition
                lookup(rw_table<FieldType, stage>::stack_lookup(
                    current_state.call_id(0),
                    current_state.stack_size(0) - 1,
                    current_state.rw_counter(0),
                    TYPE(0),  // is_write
                    TYPE(0),
                    destOffset
                ), "zkevm_rw");
                lookup(rw_table<FieldType, stage>::stack_lookup(
                    current_state.call_id(0),
                    current_state.stack_size(0) - 2,
                    current_state.rw_counter(0) + 1,
                    TYPE(0),  // is_write
                    TYPE(0),
                    offset
                ), "zkevm_rw");
                lookup(rw_table<FieldType, stage>::stack_lookup(
                    current_state.call_id(0),
                    current_state.stack_size(0) - 3,
                    current_state.rw_counter(0) + 2,
                    TYPE(0),  // is_write
                    TYPE(0),
                    length
                ), "zkevm_rw");
                lookup(rw_table<FieldType, stage>::call_context_editable_lookup(
                    current_state.call_id(0),
                    std::size_t(call_context_field::lastcall_id),
                    current_state.rw_counter(0) + 3,
                    TYPE(0),    // is_write
                    TYPE(0),
                    lastcall_id
                ), "zkevm_rw");
                lookup({
                    is_length_zero,                                                         // is_first
                    TYPE(0),                                                                     // is_write
                    is_length_zero * TYPE(copy_op_to_num(copy_operand_type::returndata)),   // cp_type
                    TYPE(0),                                                                     // id_hi
                    is_length_zero * lastcall_id,                              // id_lo
                    is_length_zero * offset,                                   // counter_1
                    is_length_zero * (current_state.rw_counter(0) + 4),        // counter_2
                    length
                }, "zkevm_copy");
                lookup({
                    is_length_zero,                                                      // is_first
                    is_length_zero,                                                      // is_write
                    is_length_zero * TYPE(copy_op_to_num(copy_operand_type::memory)),    // cp_type
                    TYPE(0),                                                                  // id_hi
                    is_length_zero * current_state.call_id(0),                           // id_lo
                    is_length_zero * destOffset,                                             // counter_1
                    is_length_zero * (current_state.rw_counter(0) + 4 + length),         // counter_2
                    length
                }, "zkevm_copy");
            }
        }
    };

    template<typename FieldType>
    class zkevm_returndatacopy_operation : public opcode_abstract<FieldType> {
        public:
        virtual std::size_t rows_amount() override { return 2; }
        virtual void fill_context(
            typename generic_component<
                FieldType, GenerationStage::ASSIGNMENT>::context_type &context,
            const opcode_input_type<FieldType, GenerationStage::ASSIGNMENT>
                &current_state) override {
            zkevm_returndatacopy_bbf<FieldType, GenerationStage::ASSIGNMENT>
                bbf_obj(context, current_state);
        }
        virtual void fill_context(
            typename generic_component<
                FieldType, GenerationStage::CONSTRAINTS>::context_type &context,
            const opcode_input_type<FieldType, GenerationStage::CONSTRAINTS>
                &current_state) override {
            zkevm_returndatacopy_bbf<FieldType, GenerationStage::CONSTRAINTS>
                bbf_obj(context, current_state);
        }
    };
}