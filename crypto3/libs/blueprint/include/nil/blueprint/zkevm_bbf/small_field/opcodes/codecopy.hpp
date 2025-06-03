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
#include <nil/blueprint/zkevm_bbf/small_field/subcomponents/memory_cost.hpp>
#include <nil/blueprint/zkevm_bbf/small_field/subcomponents/word_size.hpp>
#include <nil/blueprint/zkevm_bbf/types/zkevm_word.hpp>

namespace nil::blueprint::bbf::zkevm_big_field {
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

        zkevm_codecopy_bbf(context_type &context_object,
                           const opcode_input_type<FieldType, stage> &current_state)
            : generic_component<FieldType, stage>(context_object, false) {
            using Word_Size = typename zkevm_big_field::word_size<FieldType, stage>;
            using Memory_Cost = typename zkevm_big_field::memory_cost<FieldType, stage>;

            constexpr static const typename FieldType::value_type two_16 = 65536;
            constexpr static const typename FieldType::value_type two_23 = 8388608;

            // 6M memory bytes gives 60M+ gas cost
            // max gas cost is 36M for now, might go up to 60M
            constexpr static std::size_t max_dest_offset = two_23;
            // max contract size is 24,576 bytes, so offset and length need to fit in
            // first chunk
            constexpr static std::size_t max_offset = 65536;
            constexpr static std::size_t max_length = 65536;

            std::vector<TYPE> DEST_OFFSET(16);  // 16-bit chunks of destination offset
            std::vector<TYPE> OFFSET(16);       // 16-bit chunks of offset
            std::vector<TYPE> LENGTH(16);       // 16-bit chunks of length
            std::vector<TYPE> dest_offset_bits(16);  // 16 bits of the 2nd chunk
            // TODO
            // describe variables
            TYPE dest_offset, offset, length, current_mem, next_mem,
                memory_expansion_cost, memory_expansion_size, S, length_inv,
                is_length_non_zero, valid_dest_offset, valid_offset, valid_length,
                all_valid;

            if constexpr (stage == GenerationStage::ASSIGNMENT) {
                // SIZE OF THEM
                dest_offset = w_lo<FieldType>(current_state.stack_top());
                offset = w_lo<FieldType>(current_state.stack_top(1));
                length = w_lo<FieldType>(current_state.stack_top(2));

                current_mem = current_state.memory_size();
                next_mem = length.is_zero() ? current_mem
                                            : std::max(dest_offset + length, current_mem);
                S = next_mem > current_mem;
                length_inv = length == 0 ? 0 : length.inversed();
                is_length_non_zero = length == 0 ? 0 : 1;

                DEST_OFFSET = w_to_16(current_state.stack_top());
                OFFSET = w_to_16(current_state.stack_top(1));
                LENGTH = w_to_16(current_state.stack_top(2));

                valid_dest_offset = dest_offset < max_dest_offset ? 1 : 0;
                valid_offset = offset < max_offset ? 1 : 0;
                valid_length = length < max_length ? 1 : 0;

                size_t value = DEST_OFFSET[1];
                for (std::size_t i = 0; i < 16; i++) {
                    dest_offset_bits[i] = value % 2;
                    value /= 2;
                }
            }
            all_valid = valid_dest_offset * valid_offset * valid_length;

            // ALLOCATION
            for (std::size_t j = 0; j < 16; j++) {
                allocate(DEST_OFFSET[j], j, 0);
                allocate(OFFSET[j], j + 16, 0);
                allocate(LENGTH[j], j + 16, 1);
                allocate(dest_offset_bits[j], j + 16, 0);
            }
            allocate(dest_offset, 32, 0);
            allocate(offset, 33, 0);
            allocate(length, 34, 0);
            allocate(current_mem, 35, 0);
            allocate(next_mem, 36, 0);
            allocate(S, 37, 0);
            allocate(length_inv, 38, 0);
            allocate(is_length_non_zero, 39, 0);
            allocate(valid_dest_offset, 40, 16);
            allocate(valid_offset, 41, 17);
            allocate(valid_length, 42, 18);
            allocate(all_valid, 0, 0);

            // CONSTRAINTS
            // high chunks are not 0
            for (std::size_t j = 1; j < 16; j++) {
                constrain(OFFSET[i] * valid_offset);
                constrain(LENGTH[i] * valid_length);
                allocate(DEST_OFFSET[j], j, 0);
            }
            for (std::size_t j = 2; j < 16; j++) {
                constrain(DEST_OFFSET[i] * valid_dest_offset);
            }

            // Decompose DEST_OFFSET[1] in bits
            int pow = 1;
            TYPE dest_offset_chunk = 0;
            for (std::size_t i = 0; i < 16; i++) {
                dest_offset_chunk += dest_offset_bits[i] * pow;
                pow *= 2;
            }
            constrain(dest_offset_chunk - DEST_OFFSET[1]);
            // high 9 bits of 2nd dest_offset chunk are not 0
            for (std::size_t i = 9; i < 16; i++) {
                constrain(dest_offset_bits[i] * valid_dest_offset);
            }

            // If within range, lower chunks == whole chunks
            constrain((OFFSET[0] - offset) * valid_offset);
            constrain((LENGTH[0] - length) * valid_length);
            constrain((DEST_OFFSET[0] + DEST_OFFSET[1] * two_16 - dest_offset) *
                      valid_dest_offset);

            // TODO
            //  COMMENT CONSTRAINTS
            constrain(is_length_non_zero - length_inv * length);
            constrain(length_inv * (1 - is_length_non_zero));
            constrain(length * (1 - is_length_non_zero));

            constrain(S * (S - 1));
            constrain(S * (next_mem - dest_offset - length) +
                      (1 - S) * (next_mem - current_mem));

            constrain(valid_dest_offset * (1 - valid_dest_offset));
            constrain(valid_offset * (1 - valid_offset));
            constrain(valid_length * (1 - valid_length));

            std::vector<std::size_t> word_size_lookup_area = {32, 33, 34};
            allocate(memory_expansion_cost, 35, 1);
            allocate(memory_expansion_size, 36, 1);
            std::vector<std::size_t> memory_cost_lookup_area = {42, 43, 44, 45, 46, 47};

            context_type word_size_ct =
                context_object.subcontext(word_size_lookup_area, 1, 1);

            context_type current_memory_ct =
                context_object.subcontext(memory_cost_lookup_area, 0, 1);
            context_type next_memory_ct =
                context_object.subcontext(memory_cost_lookup_area, 1, 1);

            Memory_Cost current_memory = Memory_Cost(current_memory_ct, current_mem);
            Memory_Cost next_memory = Memory_Cost(next_memory_ct, next_mem);
            memory_expansion_cost = next_memory.cost - current_memory.cost;
            memory_expansion_size =
                (next_memory.word_size - current_memory.word_size) * 32;

            Word_Size minimum_word = Word_Size(word_size_ct, length);

            if constexpr (stage == GenerationStage::CONSTRAINTS) {
                // PC transition
                constrain(current_state.pc_next() - current_state.pc(0) - 1);
                // GAS transition
                //Not nuliified but -1 instead
                constrain((current_state.gas(0) - current_state.gas_next() - 3 -
                           3 * minimum_word.size - memory_expansion_cost) *
                          all_valid);
                // stack_size transition
                constrain(current_state.stack_size(0) - current_state.stack_size_next() -
                          3);
                // memory_size transition
                constrain((current_state.memory_size(0) -
                           current_state.memory_size_next() - memory_expansion_size) *
                          all_valid);
                // rw_counter transition
                constrain(current_state.rw_counter_next() - current_state.rw_counter(0) -
                          3 - length);

                using RwTable = rw_256_table<FieldType, stage>;
                lookup(RwTable::stack_16_bit_lookup(current_state.call_id(0),
                                                    current_state.stack_size(0) - 1,
                                                    current_state.rw_counter(0),
                                                    TYPE(0),  // is_write
                                                    DEST_OFFSET),
                       "zkevm_rw_256");
                lookup(RwTable::stack_16_bit_lookup(current_state.call_id(0),
                                                    current_state.stack_size(0) - 2,
                                                    current_state.rw_counter(0) + 1,
                                                    TYPE(0),  // is_write
                                                    OFFSET),
                       "zkevm_rw_256");
                lookup(RwTable::stack_16_bit_lookup(current_state.call_id(0),
                                                    current_state.stack_size(0) - 3,
                                                    current_state.rw_counter(0) + 2,
                                                    TYPE(0),  // is_write
                                                    LENGTH),
                       "zkevm_rw_256");
                // using CopyTable = copy_table<FieldType, stage>;
                // lookup(
                //     CopyTable::copy_16_bit_lookup(
                //         TYPE(0),  // is_write
                //         is_length_non_zero *
                //             TYPE(copy_op_to_num(copy_operand_type::bytecode)),  // cp_type
                //         current_state.bytecode_hash,                            // id
                //         is_length_non_zero * offset,  // counter_1
                //         0,                            // counter_2
                //         length),
                //     "zkevm_copy");
                // lookup(
                //     CopyTable::copy_16_bit_lookup(
                //         TYPE(1),  // is_write
                //         is_length_non_zero *
                //             TYPE(copy_op_to_num(copy_operand_type::memory)),  // cp_type
                //         current_state.call_id(0),                             // id
                //         is_length_non_zero * dest_offset,                     // counter_1
                //         current_state.rw_counter(0) + 3,                      // counter_2
                //         length),
                //     "zkevm_copy");
            }
        }
    };

    template<typename FieldType>
    class zkevm_codecopy_operation : public opcode_abstract<FieldType> {
      public:
        virtual std::size_t rows_amount() override { return 2; }
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
}  // namespace nil::blueprint::bbf::zkevm_big_field
