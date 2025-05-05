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

#include <algorithm>
#include <numeric>

#include <nil/blueprint/zkevm_bbf/types/zkevm_word.hpp>
#include <nil/blueprint/zkevm_bbf/big_field/subcomponents/memory_cost.hpp>
#include <nil/blueprint/zkevm_bbf/big_field/subcomponents/word_size.hpp>
#include <nil/blueprint/zkevm_bbf/big_field/opcodes/abstract_opcode.hpp>

namespace nil::blueprint::bbf::zkevm_big_field{
    template<typename FieldType, GenerationStage stage>
    class zkevm_mstore8_bbf : generic_component<FieldType, stage> {
        using typename generic_component<FieldType, stage>::context_type;
        using generic_component<FieldType, stage>::allocate;
        using generic_component<FieldType, stage>::copy_constrain;
        using generic_component<FieldType, stage>::constrain;
        using generic_component<FieldType, stage>::lookup;
        using generic_component<FieldType, stage>::lookup_table;

        public:
        using typename generic_component<FieldType, stage>::TYPE;

        zkevm_mstore8_bbf(
            context_type &context_object,
            const opcode_input_type<FieldType, stage> &current_state)
            : generic_component<FieldType, stage>(context_object, false) {
            using Word_Size = typename zkevm_big_field::word_size<FieldType, stage>;
            using Memory_Cost = typename zkevm_big_field::memory_cost<FieldType, stage>;
            TYPE offset, length, current_mem, next_mem, memory_expansion_cost,
                memory_expansion_size, S;
            std::vector<TYPE> value(32);
            length = 1;
            if constexpr (stage == GenerationStage::ASSIGNMENT) {
                auto offsetess = w_to_16(current_state.stack_top())[15];
                offset = offsetess;
                current_mem = current_state.memory_size();
                next_mem = std::max(offset + length, current_mem);
                S = next_mem > current_mem;
                auto bytes = w_to_8(current_state.stack_top(1));
                for (std::size_t i = 0; i < 32; i++) {
                    value[i] = bytes[i];
                }
            }
            for (std::size_t i = 0; i < 16; i++) {
                allocate(value[i], i + 16,
                            0);  // Values are range-checked by RW circuit, so use
                                // non-range-checked columns
                allocate(value[i + 16], i + 16,
                            1);  // Values are range-checked by RW circuit, so use
                                // non-range-checked columns
            }

            allocate(offset, 32, 0);
            allocate(length, 33, 0);
            allocate(current_mem, 34, 0);
            allocate(next_mem, 35, 0);
            allocate(S, 36, 0);
            constrain(S * (S - 1));
            constrain(S * (next_mem - offset - length) +
                        (1 - S) * (next_mem - current_mem));

            allocate(memory_expansion_cost, 37, 0);
            allocate(memory_expansion_size, 38, 0);
            std::vector<std::size_t> memory_cost_lookup_area = {42, 43, 44,
                                                                45, 46, 47};
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

            if constexpr (stage == GenerationStage::CONSTRAINTS) {
                constrain(current_state.pc_next() - current_state.pc(1) -
                            1);  // PC transition
                constrain(current_state.gas(0) - current_state.gas_next() - 3 -
                            memory_expansion_cost);  // GAS transition
                constrain(current_state.stack_size(1) -
                            current_state.stack_size_next() -
                            2);  // stack_size transition
                constrain(current_state.memory_size(0) - current_mem);  // memory_size transition
                constrain(current_state.memory_size_next() - next_mem);  // memory_size transition
                constrain(current_state.rw_counter_next() -
                            current_state.rw_counter(1) -
                            3);  // rw_counter transition
                auto V_128 = chunks8_to_chunks128<TYPE>(value);

                std::vector<TYPE> tmp;
                tmp = rw_table<FieldType, stage>::stack_lookup(
                    current_state.call_id(1),
                    current_state.stack_size(1) - 1,
                    current_state.rw_counter(1),
                    TYPE(0),                                               // is_write
                    TYPE(0),                                               // hi bytes are 0
                    offset
                );
                lookup(tmp, "zkevm_rw");
                tmp = rw_table<FieldType, stage>::stack_lookup(
                    current_state.call_id(1),
                    current_state.stack_size(1) - 2,
                    current_state.rw_counter(1) + 1,
                    TYPE(0),                                               // is_write
                    V_128.first,
                    V_128.second
                );
                lookup(tmp, "zkevm_rw");

                tmp = rw_table<FieldType, stage>::memory_lookup(
                    current_state.call_id(1),
                    offset,
                    current_state.rw_counter(1) + 2,
                    TYPE(1),                                               // is_write
                    value[31]
                );
                lookup(tmp, "zkevm_rw");
            }
        }
    };

    template<typename FieldType>
    class zkevm_mstore8_operation : public opcode_abstract<FieldType> {
        public:
        virtual void fill_context(
            typename generic_component<
                FieldType, GenerationStage::ASSIGNMENT>::context_type &context,
            const opcode_input_type<FieldType, GenerationStage::ASSIGNMENT>
                &current_state) override {
            zkevm_mstore8_bbf<FieldType, GenerationStage::ASSIGNMENT> bbf_obj(
                context, current_state);
        }
        virtual void fill_context(
            typename generic_component<
                FieldType, GenerationStage::CONSTRAINTS>::context_type &context,
            const opcode_input_type<FieldType, GenerationStage::CONSTRAINTS>
                &current_state) override {
            zkevm_mstore8_bbf<FieldType, GenerationStage::CONSTRAINTS> bbf_obj(
                context, current_state);
        }
        virtual std::size_t rows_amount() override { return 2; }
    };
}