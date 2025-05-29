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

#include <nil/blueprint/zkevm_bbf/types/zkevm_word.hpp>
#include <nil/blueprint/zkevm_bbf/big_field/subcomponents/memory_cost.hpp>
#include <nil/blueprint/zkevm_bbf/big_field/opcodes/abstract_opcode.hpp>

namespace nil::blueprint::bbf::zkevm_big_field{
    template<typename FieldType, GenerationStage stage>
    class zkevm_logx_bbf : generic_component<FieldType, stage> {
        using typename generic_component<FieldType, stage>::context_type;
        using generic_component<FieldType, stage>::allocate;
        using generic_component<FieldType, stage>::copy_constrain;
        using generic_component<FieldType, stage>::constrain;
        using generic_component<FieldType, stage>::lookup;
        using generic_component<FieldType, stage>::lookup_table;

        public:
        using typename generic_component<FieldType, stage>::TYPE;

        zkevm_logx_bbf(context_type &context_object,
                        const opcode_input_type<FieldType, stage> &current_state,
                        std::size_t x)
            : generic_component<FieldType, stage>(context_object, false) {
            using Memory_Cost = typename zkevm_big_field::memory_cost<FieldType, stage>;

            TYPE offset, length, current_mem, next_mem, memory_expansion_size,
                memory_expansion_cost, S;
            std::vector<TYPE> topics_lo(x);
            std::vector<TYPE> topics_hi(x);

            if constexpr (stage == GenerationStage::ASSIGNMENT) {
                offset = w_lo<FieldType>(current_state.stack_top());
                length = w_lo<FieldType>(current_state.stack_top(1));
                current_mem = current_state.memory_size();
                next_mem = length.is_zero()
                                ? current_mem
                                : std::max(offset + length, current_mem);
                S = next_mem > current_mem;
                for (std::size_t i = 0; i < x; i++) {
                    topics_lo[i] =
                        w_lo<FieldType>(current_state.stack_top(2 + i));
                    topics_hi[i] =
                        w_hi<FieldType>(current_state.stack_top(2 + i));
                }
            }

            allocate(offset, 32, 0);
            allocate(length, 33, 0);
            allocate(current_mem, 34, 0);
            allocate(next_mem, 35, 0);
            allocate(S, 36, 0);
            for (std::size_t i = 0; i < x; i++) {
                allocate(topics_lo[i], 37 + 2 * i, 0);
                allocate(topics_hi[i], 38 + 2 * i, 0);
            }

            constrain(S * (S - 1));
            constrain(S * (next_mem - offset - length) +
                        (1 - S) * (next_mem - current_mem));

            std::vector<std::size_t> memory_cost_lookup_area_1 = {32, 33, 34,
                                                                    35, 36, 37};
            std::vector<std::size_t> memory_cost_lookup_area_2 = {38, 39, 40,
                                                                    41, 42, 43};
            allocate(memory_expansion_cost, 45, 0);
            allocate(memory_expansion_size, 46, 0);

            context_type current_memory_ct =
                context_object.subcontext(memory_cost_lookup_area_1, 1, 1);
            context_type next_memory_ct =
                context_object.subcontext(memory_cost_lookup_area_2, 1, 1);

            Memory_Cost current_memory =
                Memory_Cost(current_memory_ct, current_mem);
            Memory_Cost next_memory = Memory_Cost(next_memory_ct, next_mem);
            memory_expansion_cost = next_memory.cost - current_memory.cost;
            memory_expansion_size =
                (next_memory.word_size - current_memory.word_size) * 32;

            if constexpr (stage == GenerationStage::CONSTRAINTS) {
                constrain(current_state.pc_next() - current_state.pc(0) - 1);  // PC transition
                constrain(current_state.gas(0) - current_state.gas_next() -
                            375 * (1 + x) - 8 * length -
                            memory_expansion_cost);  // GAS transition
                constrain(current_state.stack_size(0) - current_state.stack_size_next() - 2 - x);  // stack_size transition
                constrain(current_state.memory_size(0) - current_mem);  // memory_size transition
                constrain(current_state.memory_size_next() - next_mem);  // memory_size transition
                constrain(current_state.rw_counter_next() -
                            current_state.rw_counter(0) - 2 - x -
                            length);  // rw_counter transition
                std::vector<TYPE> tmp;
                tmp = rw_table<FieldType, stage>::stack_lookup(
                    current_state.call_id(0),
                    current_state.stack_size(0) - 1,
                    current_state.rw_counter(0),
                    TYPE(0),  // is_write
                    TYPE(0),
                    offset
                );
                lookup(tmp, "zkevm_rw");
                tmp = rw_table<FieldType, stage>::stack_lookup(
                    current_state.call_id(0),
                    current_state.stack_size(0) - 2,
                    current_state.rw_counter(0) + 1,
                    TYPE(0),  // is_write
                    TYPE(0),
                    length
                );
                lookup(tmp, "zkevm_rw");
                for (std::size_t i = 0; i < x; i++) {
                    tmp = rw_table<FieldType, stage>::stack_lookup(
                        current_state.call_id(0),
                        current_state.stack_size(0) - 3 - i,
                        current_state.rw_counter(0) + 2 + i,
                        TYPE(0),  // is_write
                        topics_hi[i],
                        topics_lo[i]
                    );
                    lookup(tmp, "zkevm_rw");
                }
            }
        }
    };

    template<typename FieldType>
    class zkevm_logx_operation : public opcode_abstract<FieldType> {
        public:
        virtual std::size_t rows_amount() override { return 2; }
        virtual void fill_context(
            typename generic_component<
                FieldType, GenerationStage::ASSIGNMENT>::context_type &context,
            const opcode_input_type<FieldType, GenerationStage::ASSIGNMENT>
                &current_state) override {
            zkevm_logx_bbf<FieldType, GenerationStage::ASSIGNMENT> bbf_obj(
                context, current_state, x);
        }
        virtual void fill_context(
            typename generic_component<
                FieldType, GenerationStage::CONSTRAINTS>::context_type &context,
            const opcode_input_type<FieldType, GenerationStage::CONSTRAINTS>
                &current_state) override {
            zkevm_logx_bbf<FieldType, GenerationStage::CONSTRAINTS> bbf_obj(
                context, current_state, x);
        }
        zkevm_logx_operation(std::size_t _x) : x(_x) {}

        protected:
        std::size_t x;
    };
}