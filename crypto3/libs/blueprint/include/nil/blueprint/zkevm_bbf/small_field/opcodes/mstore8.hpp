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
// #include <nil/blueprint/zkevm_bbf/big_field/subcomponents/memory_cost.hpp>
// #include <nil/blueprint/zkevm_bbf/big_field/subcomponents/word_size.hpp>
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
            const std::size_t two_25 = 1 << 25;
            // ! Gas calculation not implemented yet
            // using Word_Size = typename zkevm_big_field::word_size<FieldType, stage>;
            // using Memory_Cost = typename zkevm_big_field::memory_cost<FieldType, stage>;
            // TYPE offset, length, current_mem, next_mem, memory_expansion_cost,
            //     memory_expansion_size, S;

            std::array<TYPE, 32> bytes;
            std::array<TYPE, 16> offset_chunks;

            TYPE subchunk_14_0, diff_14_0;    // < 2^9
            TYPE subchunk_14_1, diff_14_1;    // < 2^7
            TYPE offset; // offset == offset_chunks[15] + chunk_14_0 * 0x10000

            TYPE high_chunks_sum; // sum of 14 high chunks and chunk_14_1
            TYPE high_chunks_sum_inv; // 1 / high_chunks_sum
            TYPE is_offset_in_range; // 1 if offset < 2^25, 0 otherwise

            if constexpr (stage == GenerationStage::ASSIGNMENT) {
                BOOST_LOG_TRIVIAL(trace) << "\t"
                    << "address = " << std::hex << current_state.stack_top()
                    << " value = " << current_state.stack_top(1) << std::dec;
                auto a_chunks = w_to_16(current_state.stack_top());
                for( std::size_t i = 0; i < 16; i++ ) { offset_chunks[i] = TYPE(a_chunks[i]); }

                subchunk_14_0 = a_chunks[14] >> 9; // 0x1ff = 511
                subchunk_14_1 = a_chunks[14] & 0x1ff; // 0x1ff = 511
                diff_14_0 = 0x7f - subchunk_14_0; // 0x7f = 127
                diff_14_1 = 0x1ff - subchunk_14_1; // 0x1ff = 511
                is_offset_in_range = (current_state.stack_top() <= 0x2000000 - 1) ? TYPE(1) : TYPE(0); // 0x2000000 = 2^25
                std::size_t address = (a_chunks[14] & 0x1ff) * 0x10000 + a_chunks[15];
                offset = address;

                auto b = w_to_8(current_state.stack_top(1));
                for (std::size_t i = 0; i < 32; i++) { bytes[i] = b[i]; }

                for (std::size_t i = 0; i < 16; i++) {
                    offset_chunks[i] = TYPE(a_chunks[i]);
                }
                for ( std::size_t i = 0; i < 14; i++ ) {
                    high_chunks_sum += offset_chunks[i];
                }
                high_chunks_sum += subchunk_14_0;
                high_chunks_sum_inv = (high_chunks_sum != 0) ? TYPE(1) / high_chunks_sum : TYPE(0);
            }
            for (std::size_t i = 0; i < 16; i++) {
                allocate(offset_chunks[i], i, 0);
                allocate(bytes[i], i + 16, 0);
                allocate(bytes[i + 16], i + 16, 1);
            }

            // Range-checked
            allocate(subchunk_14_0, 0, 1);
            allocate(diff_14_0, 1, 1);
            allocate(subchunk_14_1, 2, 1);
            allocate(diff_14_1, 3, 1);

            // Non-range checked
            allocate(offset, 32, 1);
            allocate(is_offset_in_range, 33, 1);
            allocate(high_chunks_sum, 34, 0);
            allocate(high_chunks_sum_inv, 35, 0);

            TYPE high_chunks_sum_constraint;
            for( std::size_t i = 0; i < 14; i++ ){
                high_chunks_sum_constraint += offset_chunks[i];
            }
            high_chunks_sum_constraint += subchunk_14_0;
            constrain(high_chunks_sum_constraint - high_chunks_sum); // high_chunks_sum decomposition

            constrain(is_offset_in_range * (is_offset_in_range - 1));                    // offset_in_range is 0 or 1
            constrain(high_chunks_sum * high_chunks_sum_inv - (1 - is_offset_in_range)); // high_chunks_sum_inv is 0 or 1
            constrain(is_offset_in_range * high_chunks_sum);                             // offset_in_range is 0 if high_chunks_sum is not
            constrain(is_offset_in_range * high_chunks_sum_inv);                         // offset_in_range is 0 high_chunks_sum_inv is not
            constrain(subchunk_14_0 + diff_14_0 - 0x7f);                                 // Range-check for subchunk_14_1
            constrain(subchunk_14_1 + diff_14_1 - 0x1ff);                                // Range-check for subchunk_14_0
            constrain(subchunk_14_0 * 0x200 + subchunk_14_1 - offset_chunks[14]);        // offset_chunks[14] decomposition
            constrain(offset_chunks[15] + subchunk_14_1 * 0x10000 - offset);

            if constexpr (stage == GenerationStage::CONSTRAINTS) {
                constrain(current_state.pc_next() - current_state.pc(1) - 1);  // PC transition
            //     constrain(current_state.gas(0) - current_state.gas_next() - 3 - memory_expansion_cost);  // GAS transition
                constrain(current_state.stack_size(1) - current_state.stack_size_next() - 2);  // stack_size transition
            //     constrain(current_state.memory_size(0) - current_mem);  // memory_size transition
            //     constrain(current_state.memory_size_next() - next_mem);  // memory_size transition
                constrain(current_state.rw_counter_next() - current_state.rw_counter(1) - 2 - is_offset_in_range);  // rw_counter transition

                lookup(rw_256_table<FieldType, stage>::stack_16_bit_lookup(
                    current_state.call_id(1),
                    current_state.stack_size(1) - 1,
                    current_state.rw_counter(1),
                    TYPE(0),                                               // hi bytes are 0
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
                    offset,
                    current_state.rw_counter(0) + 2,
                    TYPE(1),                                               // is_write
                    bytes[31]
                );
                for( std::size_t j = 0; j < tmp.size(); j++ ) tmp[j] = tmp[j] * is_offset_in_range;
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