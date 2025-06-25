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

        zkevm_codecopy_bbf(context_type &context_object,
                           const opcode_input_type<FieldType, stage> &current_state)
            : generic_component<FieldType, stage>(context_object, false) {
            using Word_Size = typename zkevm_small_field::word_size<FieldType, stage>;
            using Memory_Cost = typename zkevm_small_field::memory_cost<FieldType, stage>;

            constexpr static const typename FieldType::value_type two_16 = 65536;

            // 6M memory bytes gives 60M+ gas cost
            // max gas cost is 36M for now, might go up to 60M
            constexpr static const std::size_t max_dest_offset = 1 << 22;
            constexpr static const std::size_t max_length = 1 << 22;
            //  max contract size is 24,576 bytes, so offset need to fit in first chunk
            constexpr static const std::size_t max_offset = 65536;

            // constrain that (length+dest_offset)^2 is smaller than 60M
            // max_dest_offset < 65536 as well

            std::vector<TYPE> DEST_OFFSET(16);  // 16-bit chunks of destination offset
            std::vector<TYPE> OFFSET(16);       // 16-bit chunks of offset
            std::vector<TYPE> LENGTH(16);       // 16-bit chunks of length
            std::vector<TYPE> dest_offset_bits(16);  // 16 bits of the 2nd chunk
            std::vector<TYPE> length_bits(16);       // 16 bits of the 2nd chunk

            // If max offset, we just copy 0 bits

            // Variables
            TYPE dest_offset,             // destination memory offset
                offset,                   // bytecode offset
                length,                   // number of bytes to copy
                current_mem,              // current memory size
                next_mem,                 // memory size after operation
                memory_expansion_cost,    // gas cost for memory expansion
                memory_expansion_size,    // bytes of memory expansion
                S,                        // memory expansion flag
                real_length_inv,          // multiplicative inverse of length
                is_real_length_non_zero,  // length > 0 flag
                valid_dest_offset,        // destination offset within range
                valid_offset,             // offset within range
                valid_length,             // length within range
                overflow,                 // all parameters valid
                valid_lookup,             // overflow and length non zero
                valid_offset_lookup,      // valid lookup and valid offset
                minimum_word_size,        // minimum word size
                next_memory_cost,         // gas cost for next memory size
                current_memory_cost,      // gas cost for current memory size
                next_memory_size,         // next memory size
                current_memory_size,      // current memory size
                bytecode_size,            // bytecode size
                real_length,              // copied bytes length
                false_length,             // copied 0 bytes length
                length_S,                 // length in S
                BO,                       // bytecode < offset
                BOL,                      // bytecode - offset > length
                BO_rc1,                   // range checks
                BO_rc2, BOL_rc1, BOL_rc2;

            // lookup((length - (bytecode_size - offset) - 1) * BOL,
            // "chunk_16_bits/full"); lookup(((bytecode_size - offset) - length) * (1 -
            // BOL), "chunk_16_bits/full");
            if constexpr (stage == GenerationStage::ASSIGNMENT) {
                dest_offset = w_lo<FieldType>(current_state.stack_top());
                offset = w_lo<FieldType>(current_state.stack_top(1));
                length = w_lo<FieldType>(current_state.stack_top(2));

                current_mem = current_state.memory_size();
                next_mem = length.is_zero() ? current_mem
                                            : std::max(dest_offset + length, current_mem);
                S = next_mem > current_mem;

                auto d = w_to_16(current_state.stack_top());
                auto o = w_to_16(current_state.stack_top(1));
                auto l = w_to_16(current_state.stack_top(2));
                for (std::size_t i = 0; i < 16; i++) {
                    DEST_OFFSET[i] = d[i];
                    OFFSET[i] = o[i];
                    LENGTH[i] = l[i];
                }

                valid_dest_offset = dest_offset < max_dest_offset ? 1 : 0;
                valid_offset = offset < max_offset ? 1 : 0;
                valid_length = length < max_length ? 1 : 0;

                if (valid_dest_offset == TYPE(0) || valid_length == TYPE(0)) {
                    next_mem = current_mem;
                    S = 0;
                }

                auto value = DEST_OFFSET[14].to_integral();
                for (int i = 15; i >= 0; i--) {
                    dest_offset_bits[i] = value % 2;
                    value /= 2;
                }

                value = LENGTH[14].to_integral();
                for (int i = 15; i >= 0; i--) {
                    length_bits[i] = value % 2;
                    value /= 2;
                }

                bytecode_size = current_state.bytecode_size();
                real_length = (offset >= bytecode_size)
                                  ? 0
                                  : std::min(length, bytecode_size - offset);
                BO = (bytecode_size < offset) ? 1 : 0;
                BOL = (length >= bytecode_size - offset) ? 1 : 0;

                real_length_inv = real_length == 0 ? 0 : real_length.inversed();
                is_real_length_non_zero = real_length == 0 ? 0 : 1;
            }

            // ALLOCATION
            for (std::size_t i = 0; i < 16; i++) {
                allocate(OFFSET[i], i, 0);
                allocate(DEST_OFFSET[i], i, 1);
                allocate(dest_offset_bits[i], i, 2);
                allocate(LENGTH[i], i, 3);
                allocate(length_bits[i], i, 4);
            }
            allocate(current_mem, 38, 1);
            allocate(S, 39, 1);
            allocate(real_length_inv, 40, 1);
            allocate(is_real_length_non_zero, 41, 1);
            allocate(valid_dest_offset, 42, 1);
            allocate(valid_offset, 43, 1);

            allocate(offset, 47, 2);

            allocate(overflow, 35, 3);
            allocate(valid_offset_lookup, 39, 3);
            allocate(next_mem, 40, 3);
            allocate(valid_length, 41, 3);
            allocate(false_length, 42, 3);
            allocate(dest_offset, 43, 3);
            allocate(length, 44, 3);
            allocate(valid_lookup, 45, 3);

            allocate(bytecode_size, 44, 4);
            allocate(BO, 45, 4);
            allocate(BOL, 46, 4);

            // range checks
            allocate(real_length, 16, 4);
            allocate(BO_rc1, 17, 4);
            allocate(BO_rc2, 18, 4);
            allocate(BOL_rc1, 19, 4);
            allocate(BOL_rc2, 20, 4);

            false_length = length - real_length;

            std::vector<std::size_t> word_size_lookup_area = {35, 36, 37};

            std::vector<std::size_t> memory_cost_lookup_area(19);
            std::iota(memory_cost_lookup_area.begin(), memory_cost_lookup_area.end(), 16);

            context_type word_size_ct =
                context_object.subcontext(word_size_lookup_area, 2, 1);

            context_type current_memory_ct =
                context_object.subcontext(memory_cost_lookup_area, 0, 2);
            context_type next_memory_ct =
                context_object.subcontext(memory_cost_lookup_area, 2, 2);

            Memory_Cost current_memory = Memory_Cost(current_memory_ct, current_mem);
            Memory_Cost next_memory = Memory_Cost(next_memory_ct, next_mem);

            next_memory_cost = next_memory.cost;
            allocate(next_memory_cost, 39, 2);

            current_memory_cost = current_memory.cost;
            allocate(current_memory_cost, 40, 2);

            memory_expansion_cost = next_memory_cost - current_memory_cost;
            allocate(memory_expansion_cost, 36, 3);

            next_memory_size = next_memory.word_size;
            allocate(next_memory_size, 41, 2);
            current_memory_size = current_memory.word_size;
            allocate(current_memory_size, 42, 2);

            memory_expansion_size = (next_memory_size - current_memory_size) * 32;
            allocate(memory_expansion_size, 37, 3);

            Word_Size minimum_word = Word_Size(word_size_ct, length * valid_length);
            minimum_word_size = minimum_word.size;
            allocate(minimum_word_size, 38, 3);

            // Validity constraints
            // valid_dest_offset is 0 or 1
            constrain(valid_dest_offset * (1 - valid_dest_offset));
            // valid_offset is 0 or 1
            constrain(valid_offset * (1 - valid_offset));
            // valid_length is 0 or 1
            constrain(valid_length * (1 - valid_length));
            // high chunks are not 0
            for (std::size_t i = 0; i < 15; i++) {
                constrain(OFFSET[i] * valid_offset);
            }
            for (std::size_t i = 0; i < 14; i++) {
                constrain(DEST_OFFSET[i] * valid_dest_offset);
                constrain(LENGTH[i] * valid_length);
            }

            // Decompose DEST_OFFSET[14] in bits
            int pow = 1;
            TYPE dest_offset_chunk = 0;
            TYPE length_chunk = 0;
            for (int i = 15; i >= 0; i--) {
                dest_offset_chunk += dest_offset_bits[i] * pow;
                length_chunk += length_bits[i] * pow;
                pow *= 2;
            }
            constrain(dest_offset_chunk - DEST_OFFSET[14]);
            constrain(length_chunk - LENGTH[14]);
            // high 9 bits of 2nd dest_offset chunk are 0
            for (std::size_t i = 0; i < 9; i++) {
                constrain(dest_offset_bits[i] * valid_dest_offset);
                constrain(length_bits[i] * valid_length);
            }

            // If within range, lower chunks == whole chunks
            constrain((OFFSET[15] - offset) * valid_offset);
            constrain((DEST_OFFSET[15] + DEST_OFFSET[14] * two_16 - dest_offset) *
                      valid_dest_offset);
            constrain((LENGTH[15] + LENGTH[14] * two_16 - length) * valid_length);

            // Length inverse constraints
            // if real_length > 0, then is_length_non_zero = 1
            constrain(is_real_length_non_zero - real_length_inv * real_length);
            // if real_length = 0, then length_inv = 0
            constrain(real_length_inv * (1 - is_real_length_non_zero));
            // if real_length = 0, then is_length_non_zero = 0
            constrain(real_length * (1 - is_real_length_non_zero));

            // Memory expansion constraints
            // S is 0 or 1
            constrain(S * (S - 1));
            // if S = 1, next_mem = dest_offset + length
            // if S = 0, next_mem = current_mem
            constrain(S * (next_mem - dest_offset - length) +
                      (1 - S) * (next_mem - current_mem));


            // Length constraints
            // bytecode.size() - offset);
            constrain(BO * (1 - BO));
            constrain(BOL * (1 - BOL));
            // BO: if offset >= bytecode_size, real_length = 0
            constrain(real_length * (BO));
            // BOL: if !BO and length < bytecode_size - offset
            // real_length = length
            constrain((real_length - length) * (1 - BO) * (1 - BOL));
            // else real_length = bytecode_size - offset
            constrain((real_length - (bytecode_size - offset)) * (1 - BO) * BOL);

            overflow = valid_dest_offset * valid_length;
            valid_lookup = overflow * is_real_length_non_zero;
            valid_offset_lookup = valid_lookup * valid_offset;

            // range checks
            BO_rc1 = (offset - bytecode_size - 1) * BO * valid_offset;
            BO_rc2 = (bytecode_size - offset) * (1 - BO) * valid_offset;
            BOL_rc1 = (length - (bytecode_size - offset) - 1) * BOL * valid_offset *
                      valid_length;
            BOL_rc2 = ((bytecode_size - offset) - length) * (1 - BOL) * valid_offset *
                      valid_length;

            if constexpr (stage == GenerationStage::CONSTRAINTS) {
                // PC transition
                constrain((current_state.pc_next() - current_state.pc(4) - 1) * overflow +
                          (overflow - 1) * current_state.pc_next());
                // GAS transition
                // next -1 if out of range
                constrain((current_state.gas(4) - current_state.gas_next() - 3 -
                           3 * minimum_word_size - memory_expansion_cost) *
                              overflow +
                          (overflow - 1) * current_state.gas_next());
                // stack_size transition
                constrain(current_state.stack_size(4) - current_state.stack_size_next() -
                          3);
                // memory_size transition
                // next - 1 if out of range
                constrain((current_state.memory_size_next() -
                           current_state.memory_size(4) - memory_expansion_size) *
                              overflow +
                          (overflow - 1) * current_state.memory_size_next());
                // rw_counter transition
                constrain(current_state.rw_counter_next() - current_state.rw_counter(4) -
                          3 - length * overflow);

                using RwTable = rw_256_table<FieldType, stage>;
                lookup(RwTable::stack_16_bit_lookup(current_state.call_id(0),
                                                    current_state.stack_size(0) - 1,
                                                    current_state.rw_counter(0),
                                                    TYPE(0),  // is_write
                                                    DEST_OFFSET),
                       "zkevm_rw_256");
                lookup(RwTable::stack_16_bit_lookup(current_state.call_id(1),
                                                    current_state.stack_size(1) - 2,
                                                    current_state.rw_counter(1) + 1,
                                                    TYPE(0),  // is_write
                                                    OFFSET),
                       "zkevm_rw_256");
                lookup(RwTable::stack_16_bit_lookup(current_state.call_id(2),
                                                    current_state.stack_size(2) - 3,
                                                    current_state.rw_counter(2) + 2,
                                                    TYPE(0),  // is_write
                                                    LENGTH),
                       "zkevm_rw_256");
                // using CopyTable = copy_table<FieldType, stage>;
                // Bytecode copy
                // lookup(
                //     CopyTable::copy_16_bit_lookup(
                //         TYPE(0),  // is_write
                //         valid_offset_lookup *
                //             TYPE(copy_op_to_num(copy_operand_type::bytecode)),  // cp_type
                //         valid_offset_lookup * current_state.bytecode_id(4),     // id
                //         valid_offset_lookup * offset,  // counter_1
                //         0,                             // counter_2
                //         valid_offset_lookup * real_length),
                //     "zkevm_copy");
                // lookup(CopyTable::copy_16_bit_lookup(
                //            valid_lookup,  // is_write
                //            valid_lookup * TYPE(copy_op_to_num(
                //                               copy_operand_type::memory)),    // cp_type
                //            valid_lookup * current_state.call_id(4),           // id
                //            valid_lookup * dest_offset,                        // counter_1
                //            valid_lookup * (current_state.rw_counter(4) + 3),  // counter_2
                //            valid_lookup * real_length),
                //        "zkevm_copy");
                // 0 byte copy
            }
        }
    };

    template<typename FieldType>
    class zkevm_codecopy_operation : public opcode_abstract<FieldType> {
      public:
        virtual std::size_t rows_amount() override { return 5; }
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
