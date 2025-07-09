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
#include <nil/blueprint/zkevm_bbf/small_field/subcomponents/memory_range.hpp>
#include <nil/blueprint/zkevm_bbf/small_field/subcomponents/memory_cost.hpp>
#include <nil/blueprint/zkevm_bbf/small_field/subcomponents/max_30.hpp>
#include <nil/blueprint/zkevm_bbf/small_field/subcomponents/word_size.hpp>
#include <nil/blueprint/zkevm_bbf/small_field/opcodes/abstract_opcode.hpp>

namespace nil::blueprint::bbf::zkevm_small_field{
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
            : generic_component<FieldType, stage>(context_object, false)
        {
            using Memory_Cost = typename zkevm_small_field::memory_cost<FieldType, stage>;
            using Max_30 = typename zkevm_small_field::max_30<FieldType, stage>;
            using Word_Size = typename zkevm_small_field::word_size<FieldType, stage>;
            using Memory_Range = typename zkevm_small_field::memory_range<FieldType, stage>;

            // 1.Process offset
            std::vector<std::size_t> memory_range_area;
            for( std::size_t i = 0; i < Memory_Range::range_checked_witness_amount; i++ ) {
                memory_range_area.push_back(i);
            }
            for( std::size_t i = 0; i < Memory_Range::non_range_checked_witness_amount; i++ ) {
                memory_range_area.push_back(47 - i);
            }

            context_type memory_offset_ct = context_object.subcontext(memory_range_area, 0, 1);
            typename Memory_Range::input_type offset_input;
            if constexpr (stage == GenerationStage::ASSIGNMENT) {
                offset_input = current_state.stack_top();
            }
            Memory_Range memory_offset(memory_offset_ct, offset_input);
            auto offset_chunks = memory_offset.chunks;

            TYPE is_overflow = memory_offset.is_overflow;
            allocate(is_overflow, 45, 1);

            // 2. Calculate maximum memory word index touched by this operation
            std::vector<std::size_t> max_area = {19, 20, 21, 42, 43, 44};
            context_type word_size_ct = context_object.subcontext({0, 1, 2}, 1, 1);
            Word_Size word_size_obj(word_size_ct, memory_offset.value + 1);

            context_type new_memory_ct = context_object.subcontext(max_area, 1, 1);

            // 3. Calculate new memory size
            TYPE current_mem;
            if constexpr (stage == GenerationStage::ASSIGNMENT) {
                current_mem = (current_state.memory_size() + 31) / 32;
                BOOST_LOG_TRIVIAL(trace) << "\t"
                    << "Offset = " << std::hex << current_state.stack_top()
                    << " is_overflow: " << is_overflow << std::dec;
            }
            allocate(current_mem, 46, 1);
            Max_30 new_memory_obj(new_memory_ct, word_size_obj.size, current_mem);

            TYPE new_mem = new_memory_obj.max;
            allocate(new_mem, 47, 1);

            // 4. Calculate proposed operation gas cost
            if constexpr (stage == GenerationStage::ASSIGNMENT) {
                BOOST_LOG_TRIVIAL(trace) << "\tmemory_size:" << current_mem << " => " << new_mem;
            }
            context_type current_memory_cost_ct = context_object.subcontext({3, 4, 5, 6, 7, 8}, 1, 1);
            Memory_Cost current_memory_cost_obj(current_memory_cost_ct, current_mem);

            context_type new_memory_cost_ct = context_object.subcontext({9, 10, 11, 12, 13, 14}, 1, 1);
            Memory_Cost new_memory_cost_obj(new_memory_cost_ct, new_mem);

            TYPE pre_cost = 3 + new_memory_cost_obj.cost - current_memory_cost_obj.cost;
            allocate(pre_cost, 41, 1);

            // 5. Allocate value received from stack
            std::array<TYPE, 32> bytes;
            if constexpr( stage == GenerationStage::ASSIGNMENT ) {
                auto val = w_to_8(current_state.stack_top(1));
                for (std::size_t i = 0; i < 32; i++) {
                    bytes[i] = val[i];
                }
            }
            for( std::size_t i = 0; i < 32; i++ ) {
                allocate(bytes[i], 22 + i%16, i/16);
            }

            TYPE need_lookup = 1 - is_overflow;
            if constexpr (stage == GenerationStage::CONSTRAINTS) {
                constrain(current_state.pc_next() - current_state.pc(1) - 1);                                   // PC transition
                constrain(is_overflow * (current_state.gas_next() + 1));                                        // GAS transition in the case of overflow
                constrain((1 - is_overflow) * (current_state.gas(1) - current_state.gas_next() - pre_cost));    // GAS transition without overflow
                constrain(current_state.stack_size(1) - current_state.stack_size_next() - 2);                   // stack_size transition
                constrain(current_state.memory_size(0) - current_mem);                                          // current_mem variable correctness
                constrain(is_overflow * (current_state.memory_size_next() - current_state.memory_size(1)));     // memory_size transition in the case of overflow
                constrain((1 - is_overflow) * (current_state.memory_size_next() - new_mem));                    // memory_size transition without overflow
                constrain(current_state.rw_counter_next() - current_state.rw_counter(1) - 2 - need_lookup);     // rw_counter transition

                lookup(rw_256_table<FieldType, stage>::stack_16_bit_lookup(
                    current_state.call_id(1),
                    current_state.stack_size(1) - 1,
                    current_state.rw_counter(1),
                    TYPE(0),                                               // is_write
                    offset_chunks
                ), "zkevm_rw_256");
                lookup(rw_256_table<FieldType, stage>::stack_8_bit_lookup(
                    current_state.call_id(1),
                    current_state.stack_size(1) - 2,
                    current_state.rw_counter(1) + 1,
                    TYPE(0),                                               // is_write
                    bytes
                ), "zkevm_rw_256");
                std::vector<TYPE> tmp = rw_8_table<FieldType, stage>::memory_lookup(
                    current_state.call_id(0),
                    memory_offset.value,
                    current_state.rw_counter(0) + 2,
                    TYPE(1),                                               // is_write
                    bytes[31]
                );
                for( std::size_t j = 0; j < tmp.size(); j++ ) tmp[j] = tmp[j] * need_lookup;
                lookup(tmp, "zkevm_rw_8");
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
            zkevm_mstore8_bbf<FieldType, GenerationStage::ASSIGNMENT> bbf_obj(context, current_state);
        }
        virtual void fill_context(
            typename generic_component<
                FieldType, GenerationStage::CONSTRAINTS>::context_type &context,
            const opcode_input_type<FieldType, GenerationStage::CONSTRAINTS>
                &current_state) override {
            zkevm_mstore8_bbf<FieldType, GenerationStage::CONSTRAINTS> bbf_obj(context, current_state);
        }
        virtual std::size_t rows_amount() override { return 2; }
    };
}