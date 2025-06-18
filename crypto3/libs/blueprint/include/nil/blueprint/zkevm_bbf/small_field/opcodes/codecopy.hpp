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
            constexpr static const std::size_t max_dest_offset = 1<<25;  // 2^25
            //  max contract size is 24,576 bytes, so offset and length need to fit in
            //  first chunk
            constexpr static const std::size_t max_offset = 65536;
            constexpr static const std::size_t max_length = 65536;

            std::vector<TYPE> DEST_OFFSET(16);  // 16-bit chunks of destination offset
            std::vector<TYPE> OFFSET(16);       // 16-bit chunks of offset
            std::vector<TYPE> LENGTH(16);       // 16-bit chunks of length
            std::vector<TYPE> dest_offset_bits(16);  // 16 bits of the 2nd chunk

            // Variables
            TYPE dest_offset,           // destination memory offset
                offset,                 // bytecode offset
                length,                 // number of bytes to copy
                current_mem,            // current memory size
                next_mem,               // memory size after operation
                memory_expansion_cost,  // gas cost for memory expansion
                memory_expansion_size,  // bytes of memory expansion
                S,                      // memory expansion flag
                length_inv,             // multiplicative inverse of length
                is_length_non_zero,     // length > 0 flag
                valid_dest_offset,      // destination offset within range
                valid_offset,           // offset within range
                valid_length,           // length within range
                all_valid,              // all parameters valid
                valid_lookup;           // all_valid and length non zero

            if constexpr (stage == GenerationStage::ASSIGNMENT) {
                dest_offset = w_lo<FieldType>(current_state.stack_top());
                offset = w_lo<FieldType>(current_state.stack_top(1));
                length = w_lo<FieldType>(current_state.stack_top(2));

                BOOST_LOG_TRIVIAL(trace)
                    << "Codecopy: dest_offset = " << std::hex << dest_offset
                    << ", offset = " << offset
                    << ", length = " << length << std::dec;

                current_mem = current_state.memory_size();
                next_mem = length.is_zero() ? current_mem
                                            : std::max(dest_offset + length, current_mem);
                S = next_mem > current_mem;
                length_inv = length == 0 ? 0 : length.inversed();
                is_length_non_zero = length == 0 ? 0 : 1;

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

                auto value = DEST_OFFSET[14].to_integral();
                for (int i = 15; i >= 0; i--) {
                    dest_offset_bits[i] = value % 2;
                    value /= 2;
                }
            }
            all_valid = valid_dest_offset * valid_offset * valid_length;
            valid_lookup = all_valid * is_length_non_zero;

            // ALLOCATION
            for (std::size_t i = 0; i < 16; i++) {
                allocate(DEST_OFFSET[i], i, 0);
                allocate(OFFSET[i], i + 16, 0);
                allocate(LENGTH[i], i, 1);
                allocate(dest_offset_bits[i], i + 16, 1);
            }
            allocate(dest_offset, 32, 0);
            allocate(offset, 33, 0);
            allocate(length, 34, 0);
            allocate(current_mem, 35, 0);
            allocate(next_mem, 36, 0);
            allocate(S, 37, 0);
            allocate(length_inv, 38, 0);
            allocate(is_length_non_zero, 39, 0);
            allocate(valid_dest_offset, 40, 0);
            allocate(valid_offset, 41, 0);
            allocate(valid_length, 32, 1);
            allocate(all_valid, 33, 1);
            allocate(valid_lookup, 34, 1);

            std::vector<std::size_t> word_size_lookup_area = {37, 38, 39};
            allocate(memory_expansion_cost, 40, 1);
            allocate(memory_expansion_size, 41, 1);
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
                constrain(LENGTH[i] * valid_length);
            }
            for (std::size_t i = 0; i < 14; i++) {
                constrain(DEST_OFFSET[i] * valid_dest_offset);
            }

            // Decompose DEST_OFFSET[14] in bits
            int pow = 1;
            TYPE dest_offset_chunk = 0;
            for (int i = 15; i >= 0; i--) {
                dest_offset_chunk += dest_offset_bits[i] * pow;
                pow *= 2;
            }
            constrain(dest_offset_chunk - DEST_OFFSET[14]);
            // high 7 bits of 2nd dest_offset chunk are 0
            for (std::size_t i = 0; i < 7; i++) {
                constrain(dest_offset_bits[i] * valid_dest_offset);
            }

            // If within range, lower chunks == whole chunks
            constrain((OFFSET[15] - offset) * valid_offset);
            constrain((LENGTH[15] - length) * valid_length);
            constrain((DEST_OFFSET[15] + DEST_OFFSET[14] * two_16 - dest_offset) *
                      valid_dest_offset);

            // Length inverse constraints
            // if length > 0, then is_length_non_zero = 1
            constrain(is_length_non_zero - length_inv * length);
            // if length = 0, then length_inv = 0
            constrain(length_inv * (1 - is_length_non_zero));
            // if length = 0, then is_length_non_zero = 0
            constrain(length * (1 - is_length_non_zero));

            // Memory expansion constraints
            // S is 0 or 1
            constrain(S * (S - 1));
            // if S = 1, next_mem = dest_offset + length
            // if S = 0, next_mem = current_mem
            constrain(S * (next_mem - dest_offset - length) +
                      (1 - S) * (next_mem - current_mem));

            if constexpr (stage == GenerationStage::CONSTRAINTS) {
                // PC transition
                constrain(current_state.pc_next() - current_state.pc(0) - 1);
                // GAS transition
                // next -1 if out of range
                constrain((current_state.gas(0) - current_state.gas_next() - 3 -
                           3 * minimum_word.size - memory_expansion_cost) *
                              all_valid +
                          (all_valid - 1) *
                              (current_state.gas(0) - current_state.gas_next() + 1));
                // stack_size transition
                constrain(current_state.stack_size(0) - current_state.stack_size_next() -
                          3);
                // memory_size transition
                // next - 1 if out of range
                constrain((current_state.memory_size_next() -
                           current_state.memory_size(0) - memory_expansion_size) *
                              all_valid +
                          (all_valid - 1) * (current_state.memory_size_next() -
                                             current_state.memory_size(0) + 1));
                // rw_counter transition
                constrain(current_state.rw_counter_next() - current_state.rw_counter(0) -
                          3 - length * all_valid);

                using RwTable = rw_256_table<FieldType, stage>;
                lookup(RwTable::stack_16_bit_lookup(
                    current_state.call_id(0),
                    current_state.stack_size(0) - 1,
                    current_state.rw_counter(0),
                    TYPE(0),  // is_write
                    DEST_OFFSET
                ), "zkevm_rw_256");
                lookup(RwTable::stack_16_bit_lookup(
                    current_state.call_id(0),
                    current_state.stack_size(0) - 2,
                    current_state.rw_counter(0) + 1,
                    TYPE(0),  // is_write
                    OFFSET
                ), "zkevm_rw_256");
                lookup(RwTable::stack_16_bit_lookup(
                    current_state.call_id(0),
                    current_state.stack_size(0) - 3,
                    current_state.rw_counter(0) + 2,
                    TYPE(0),  // is_write
                    LENGTH
                ), "zkevm_rw_256");

                using CopyTable = copy_table<FieldType, stage>;
                auto tmp = CopyTable::codecopy_lookup(
                    current_state.bytecode_id(0),       // src_id
                    offset,                             // src_counter_1
                    current_state.call_id(0),           // dst_id
                    dest_offset,                        // dst_counter_1
                    (current_state.rw_counter(0) + 3),  // dst_counter_2
                    length                              // length
                );
                for( std::size_t i = 0; i < tmp.size(); i++ ) {tmp[i] = tmp[i] * valid_lookup;}
                lookup(tmp,"zkevm_copy");
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
}
