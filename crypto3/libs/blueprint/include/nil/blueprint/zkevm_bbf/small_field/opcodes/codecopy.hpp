//---------------------------------------------------------------------------//
// Copyright (c) 2025 Antoine Cyr <antoinecyr@nil.foundation>
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

#include <nil/blueprint/zkevm_bbf/small_field/opcodes/abstract_opcode.hpp>

#include <nil/blueprint/zkevm_bbf/small_field/subcomponents/memory_range.hpp>
#include <nil/blueprint/zkevm_bbf/small_field/subcomponents/memory_cost.hpp>
#include <nil/blueprint/zkevm_bbf/small_field/subcomponents/word_size.hpp>
#include <nil/blueprint/zkevm_bbf/small_field/subcomponents/max_30.hpp>
#include <nil/blueprint/zkevm_bbf/small_field/subcomponents/max_chunk.hpp>

#include <nil/blueprint/zkevm_bbf/types/copy_event.hpp>
#include <nil/blueprint/zkevm_bbf/types/zkevm_word.hpp>

namespace nil::blueprint::bbf::zkevm_small_field {
    template<typename FieldType, GenerationStage stage>
    class zkevm_codecopy_bbf : generic_component<FieldType, stage> {
        using typename generic_component<FieldType, stage>::context_type;
        using generic_component<FieldType, stage>::allocate;
        using generic_component<FieldType, stage>::copy_constrain;
        using generic_component<FieldType, stage>::constrain;
        using generic_component<FieldType, stage>::lookup;
        using generic_component<FieldType, stage>::lookup_table;

      public:
        using typename generic_component<FieldType, stage>::TYPE;

        zkevm_codecopy_bbf(context_type &context_object, const opcode_input_type<FieldType, stage> &current_state)
            : generic_component<FieldType, stage>(context_object, false)
        {
            using Memory_Cost = typename zkevm_small_field::memory_cost<FieldType, stage>;
            using Memory_Range = typename zkevm_small_field::memory_range<FieldType, stage>;
            using Word_Size = typename zkevm_small_field::word_size<FieldType, stage>;
            using Max_30 = typename zkevm_small_field::max_30<FieldType, stage>;
            using Max_Chunk = typename zkevm_small_field::max_chunk<FieldType, stage>;

            typename Memory_Range::input_type d_input;
            typename Memory_Range::input_type l_input;
            TYPE     current_memory, current_gas;
            TYPE     memory_after;
            TYPE     bytecode_size;

            std::vector<std::size_t> memory_range_area;
            for(std::size_t i = 0; i < Memory_Range::range_checked_witness_amount; i++) {
                memory_range_area.push_back(i);
            }
            for(std::size_t i = 0; i < Memory_Range::non_range_checked_witness_amount; i++) {
                memory_range_area.push_back(i+32);
            }

            // 1. Process destination offset and length
            context_type memory_d_ct = context_object.subcontext(memory_range_area, 0, 1);
            context_type memory_l_ct = context_object.subcontext(memory_range_area, 1, 1);

            if constexpr (stage == GenerationStage::ASSIGNMENT) {
                d_input = current_state.stack_top();
                l_input = current_state.stack_top(2);
            }

            Memory_Range d_range(memory_d_ct, d_input);
            Memory_Range l_range(memory_l_ct, l_input);
            TYPE length = l_range.value;

            // 2. constrain is_length_zero.
            TYPE length_inv;
            TYPE is_length_zero;
            if constexpr (stage == GenerationStage::ASSIGNMENT) {
                length_inv = l_range.chunks_sum == 0 ? 0 : l_range.chunks_sum.inversed();
                is_length_zero = l_range.chunks_sum == 0 ? 1 : 0;
            }
            allocate(length_inv, 44, 1);
            allocate(is_length_zero, 45, 1);

            constrain(is_length_zero * (is_length_zero - 1));
            constrain(l_range.chunks_sum * length_inv - (1 - is_length_zero));
            constrain(is_length_zero * l_range.chunks_sum);
            constrain(is_length_zero * length_inv);

            // 3. Allocate bytecode size
            if constexpr (stage == GenerationStage::ASSIGNMENT) {
                bytecode_size = current_state.bytecode_size();
            }
            allocate(bytecode_size, 17, 2);

            TYPE is_overflow = d_range.is_overflow + l_range.is_overflow - d_range.is_overflow * l_range.is_overflow - d_range.is_overflow * is_length_zero;
            allocate(is_overflow, 47, 2);

            // 4. Process offset
            std::array<TYPE, 16> offset_chunks;
            if constexpr (stage == GenerationStage::ASSIGNMENT) {
                // BOOST_LOG_TRIVIAL(trace)
                //     << "\td_overflow: " << d_range.is_overflow
                //     << ", l_overflow: " << l_range.is_overflow
                //     << ", is_length_zero: " << is_length_zero
                //     << ", overflow: " << is_overflow;
                auto o_chunks = w_to_16(current_state.stack_top(1));
                for (std::size_t i = 0; i < 16; i++) {
                    offset_chunks[i] = o_chunks[i];
                }
            }
            for (std::size_t i = 0; i < 16; i++) {
                allocate(offset_chunks[i], i, 2);
            }

            // 5. Constrain is_offset_overflow
            TYPE offset_hi_chunks_sum;
            for( std::size_t i = 0; i < 15; i++ ) {
                offset_hi_chunks_sum += offset_chunks[i];
            }
            TYPE offset_hi_chunks_sum_inv;
            TYPE is_offset_overflow;
            if constexpr( stage == GenerationStage::ASSIGNMENT ) {
                offset_hi_chunks_sum_inv = offset_hi_chunks_sum == 0 ? 0 : offset_hi_chunks_sum.inversed();
                is_offset_overflow = offset_hi_chunks_sum == 0 ? 0 : 1;
            }
            allocate(is_offset_overflow, 43, 2);
            allocate(offset_hi_chunks_sum_inv, 44, 2);

            constrain(is_offset_overflow * (is_offset_overflow - 1));
            constrain(offset_hi_chunks_sum * offset_hi_chunks_sum_inv - is_offset_overflow);
            constrain((1-is_offset_overflow) * offset_hi_chunks_sum);
            constrain((1-is_offset_overflow) * offset_hi_chunks_sum_inv);

            // 6. Calculate maximum memory word index touched by this operation
            std::vector<std::size_t> word_size_area = {29, 30, 31};
            context_type new_memory_word_size_ct = context_object.subcontext(word_size_area, 0, 1);
            Word_Size max_written_obj(new_memory_word_size_ct, (d_range.value + l_range.value) * (1 - is_length_zero - is_overflow + is_length_zero * is_overflow));
            TYPE max_written = max_written_obj.size;
            // if constexpr (stage == GenerationStage::ASSIGNMENT) {
            //     BOOST_LOG_TRIVIAL(trace) << "\tmax_written word: " << std::hex << max_written << std::dec;
            // }

            // 7. Calculate length in words (need for gas consumption calculation)
            context_type length_words_ct = context_object.subcontext(word_size_area, 1, 1);
            Word_Size length_words_obj(length_words_ct, l_range.value);
            TYPE length_words = length_words_obj.size;

            // 8. Calculate new memory size
            if constexpr (stage == GenerationStage::ASSIGNMENT) {
                current_memory = (current_state.memory_size() + 31)/32; // In words
            }
            allocate(current_memory, 47, 0);
            std::vector<std::size_t> max_area = {25,26,27, 36, 37, 38};
            context_type new_memory_ct = context_object.subcontext(max_area, 0, 1);
            Max_30 new_memory_words_obj(new_memory_ct, current_memory, max_written);
            TYPE new_memory = new_memory_words_obj.max;
            allocate(new_memory, 39, 1);

            // 9. Compute current and new memory cost
            std::vector<std::size_t> memory_cost_area;
            for(
                std::size_t i = Memory_Range::range_checked_witness_amount;
                i < Memory_Range::range_checked_witness_amount + Memory_Cost::range_checked_witness_amount();
                i++
            ) {
                memory_cost_area.push_back(i);
            }
            context_type cur_memory_cost_ct = context_object.subcontext(memory_cost_area, 0, 1);
            Memory_Cost cur_memory_obj(cur_memory_cost_ct, current_memory);
            TYPE current_memory_cost = cur_memory_obj.cost;

            context_type new_memory_cost_ct = context_object.subcontext(memory_cost_area, 1, 1);
            Memory_Cost new_memory_cost_obj(new_memory_cost_ct, new_memory);
            TYPE new_memory_cost = new_memory_cost_obj.cost;

            // 10. Calculate and allocate gas cost
            TYPE pre_cost = (3 + 3 * length_words + new_memory_cost - current_memory_cost);
            allocate(pre_cost, 46, 2);

            // 11. Compare gas cost and current gas, constrain is_gas_error = is_overflow || (current_gas < pre_cost)
            if constexpr (stage == GenerationStage::ASSIGNMENT) {
                current_gas = current_state.gas();
            }
            allocate(current_gas, 47, 1);
            context_type is_gas_error_ct = context_object.subcontext(max_area, 2, 1);
            Max_30 is_gas_error_obj(is_gas_error_ct, pre_cost, current_gas);
            TYPE is_gas_error = is_overflow + is_gas_error_obj.gt - is_overflow * is_gas_error_obj.gt;
            allocate(is_gas_error, 45, 2);

            // if constexpr (stage == GenerationStage::ASSIGNMENT) {
            //     BOOST_LOG_TRIVIAL(trace)
            //         << "\tcurrent_gas: "<< current_gas
            //         << " current memory cost: " << current_memory_cost
            //         << " new memory cost: " << new_memory_cost
            //         << " pre-cost: " << pre_cost
            //         << " current_memory: " << current_memory
            //         << " new_memory: " << new_memory
            //         << " is_gas_error: " << is_gas_error;
            // }

            // 12. Check offset+length ? bytecode_size
            TYPE offset = offset_chunks[15];
            context_type offset_last_cmp_ct = context_object.subcontext(max_area, 1, 1);
            Max_30 offset_last_cmp_obj(offset_last_cmp_ct, offset + l_range.value, bytecode_size);

            // 13. Check bytecode_size ? offset
            context_type offset_first_cmp_ct = context_object.subcontext({28, 40, 41, 42}, 1, 1);
            Max_Chunk offset_first_cmp_obj(offset_first_cmp_ct, bytecode_size, offset);

            // 14. Constrain need_copy_lookups -- do we need any lookups to bytecode tables, or not
            TYPE need_copy_lookups = (1 - is_gas_error) * (1 - is_length_zero);
            allocate(need_copy_lookups, 42, 2);

            // 15. Constrain need_bytecode_copy_lookup = need_copy_lookups * (1 - is_offset_overflow) * (offset < bytecode_size)
            TYPE need_bytecode_copy_lookup_step1 = need_copy_lookups * (1 - is_offset_overflow);
            allocate(need_bytecode_copy_lookup_step1, 41, 2);

            TYPE need_bytecode_copy_lookup = need_bytecode_copy_lookup_step1 * offset_first_cmp_obj.gt;
            allocate(need_bytecode_copy_lookup, 40, 2);

            // 16. Constrain is_offset_for_zero_lookup = is_offset_overflow || offset + length >= bytecode_size
            TYPE is_offset_for_zero_lookup = is_offset_overflow + offset_last_cmp_obj.gt - is_offset_overflow * offset_last_cmp_obj.gt;
            allocate(is_offset_for_zero_lookup, 39, 2);

            // 17. Constrain need_zero_copy_lookup = need_copy_lookups * is_offset_for_zero_lookup
            TYPE need_zero_copy_lookup = need_copy_lookups * is_offset_for_zero_lookup;
            allocate(need_zero_copy_lookup, 46, 1);

            // 18. Constrain bytecode copy lookup length
            TYPE bytecode_lookup_length = need_bytecode_copy_lookup * (offset_last_cmp_obj.min - offset);
            allocate(bytecode_lookup_length, 43, 1);

            // 19. Constrain start for zero copy lookup
            TYPE zero_lookup_start = need_zero_copy_lookup * (offset_first_cmp_obj.max); // TODO: Do we really need this?
            allocate(zero_lookup_start, 44, 0);

            // 20. Constrain length for zero copy lookup
            TYPE zero_lookup_length = need_zero_copy_lookup * (length - bytecode_lookup_length);
            allocate(zero_lookup_length, 45, 0);

            // if constexpr( stage == GenerationStage::ASSIGNMENT){
            //     BOOST_LOG_TRIVIAL(trace) << "\t"
            //         << "offset: " << offset
            //         << " length: " << length
            //         << " bytecode_size: " << bytecode_size
            //         << " is_offset_overflow: " << is_offset_overflow;
            //     BOOST_LOG_TRIVIAL(trace) << "\t"
            //         << "need_bytecode_copy_lookup: " << need_bytecode_copy_lookup
            //         << " need_zero_copy_lookup: " << need_zero_copy_lookup
            //         << " zero_lookup_length: " << zero_lookup_length
            //         << " bytecode_lookup_length: " << bytecode_lookup_length;
            // }

            if constexpr (stage == GenerationStage::CONSTRAINTS) {
                constrain(current_state.pc_next() - current_state.pc(2) - 1); // PC transition
                constrain(is_overflow * (current_state.gas_next() + 1)); // Gas transition in oveflow case
                constrain((1 - is_overflow) * (current_state.gas(2) - current_state.gas_next() - pre_cost)); // Gas transition without overflow
                constrain(
                    is_gas_error * (current_state.memory_size_next() - current_state.memory_size(2)) +
                    (1 - is_gas_error) * (current_state.memory_size_next() - new_memory)
                ); // Memory transition
                constrain(current_state.stack_size(1) - current_state.stack_size_next() - 3);     // stack_size transition
                constrain(current_state.rw_counter_next() - current_state.rw_counter(2) - 3 - (1 - is_gas_error) * l_range.value); // rw_counter transition

                // Stack lookup even if there is an overflow
                using RwTable = rw_256_table<FieldType, stage>;
                lookup(RwTable::stack_16_bit_lookup(
                    current_state.call_id(0),
                    current_state.stack_size(0) - 1,
                    current_state.rw_counter(0),
                    TYPE(0),  // is_write
                    d_range.chunks
                ), "zkevm_rw_256");
                lookup(RwTable::stack_16_bit_lookup(
                    current_state.call_id(2),
                    current_state.stack_size(2) - 2,
                    current_state.rw_counter(2) + 1,
                    TYPE(0),  // is_write
                    offset_chunks
                ), "zkevm_rw_256");
                lookup(RwTable::stack_16_bit_lookup(
                    current_state.call_id(1),
                    current_state.stack_size(1) - 3,
                    current_state.rw_counter(1) + 2,
                    TYPE(0),  // is_write
                    l_range.chunks
                ), "zkevm_rw_256");

                // Prove bytecode size
                lookup({
                    TYPE(1), // HEADER
                    TYPE(0), // PC
                    bytecode_size, // bytecode_size
                    TYPE(0), // is_opcode
                    current_state.bytecode_id(2)
                }, "zkevm_bytecode");

                // Bytecode copy lookup
                using CopyTable  = copy_table<FieldType, stage>;
                auto bytecode_copy_lookup =  CopyTable::codecopy_lookup(
                    current_state.bytecode_id(1),
                    offset,
                    current_state.call_id(1),
                    d_range.value,
                    current_state.rw_counter(1) + 3,
                    bytecode_lookup_length
                );
                for( std::size_t i = 0; i < bytecode_copy_lookup.size(); i++) {
                    bytecode_copy_lookup[i] = need_bytecode_copy_lookup * bytecode_copy_lookup[i];
                }
                lookup(bytecode_copy_lookup, "zkevm_copy");

                // Zero copy lookup
                auto zero_copy_lookup =  CopyTable::zero_memory_lookup(
                    current_state.call_id(1),
                    d_range.value + bytecode_lookup_length,
                    current_state.rw_counter(1) + 3 + bytecode_lookup_length,
                    zero_lookup_length
                );
                for( std::size_t i = 0; i < zero_copy_lookup.size(); i++) {
                    zero_copy_lookup[i] = need_zero_copy_lookup * zero_copy_lookup[i];
                }
                lookup(zero_copy_lookup, "zkevm_copy");
            }
        }
    };

    template<typename FieldType>
    class zkevm_codecopy_operation : public opcode_abstract<FieldType> {
      public:
        virtual std::size_t rows_amount() override { return 3; }
        virtual void fill_context(
            typename generic_component<
                FieldType, GenerationStage::ASSIGNMENT>::context_type &context,
            const opcode_input_type<FieldType, GenerationStage::ASSIGNMENT>
                &current_state) override {
            zkevm_codecopy_bbf<FieldType, GenerationStage::ASSIGNMENT> bbf_obj(
                context, current_state);
        }
        virtual void fill_context(
            typename generic_component<
                FieldType, GenerationStage::CONSTRAINTS>::context_type &context,
            const opcode_input_type<FieldType, GenerationStage::CONSTRAINTS>
                &current_state) override {
            zkevm_codecopy_bbf<FieldType, GenerationStage::CONSTRAINTS> bbf_obj(
                context, current_state);
        }
    };
}  // namespace nil::blueprint::bbf::zkevm_small_field
