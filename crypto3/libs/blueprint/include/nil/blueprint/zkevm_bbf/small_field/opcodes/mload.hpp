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
    class zkevm_mload_bbf : generic_component<FieldType, stage> {
        using typename generic_component<FieldType, stage>::context_type;
        using generic_component<FieldType, stage>::allocate;
        using generic_component<FieldType, stage>::copy_constrain;
        using generic_component<FieldType, stage>::constrain;
        using generic_component<FieldType, stage>::lookup;
        using generic_component<FieldType, stage>::lookup_table;

        public:
        using typename generic_component<FieldType, stage>::TYPE;

        // 1. Read offset from stack
        // 2. If offset < 2^25, then need_lookup = 1, else need_lookup = 0
        // 3. If need_lookup = 0 then throw gas_error
        // 4. If need_lookup = 1 Read 32 bytes from memory
        // 5. If need_lookup = 1, then write 32-bytes value to stack
        zkevm_mload_bbf(
            context_type &context_object,
            const opcode_input_type<FieldType, stage> &current_state
        ) : generic_component<FieldType, stage>(context_object, false) {
            // ! Gas and memory size are not constrained yet
            const std::size_t two_25 = 1 << 25;
            // // using Word_Size = typename zkevm_big_field::word_size<FieldType, stage>;
            // // using Memory_Cost = typename zkevm_big_field::memory_cost<FieldType, stage>;
            // // TYPE offset, length, current_mem, next_mem, memory_expansion_cost,
            // //     memory_expansion_size, S;
            std::vector<TYPE> bytes(32);
            std::vector<TYPE> offset_chunks(16);

            TYPE subchunk_14_0, diff_14_0;    // < 2^9
            TYPE subchunk_14_1, diff_14_1;    // < 2^7
            TYPE offset0, offset1; // offset0 == offset1 == offset_chunks[15] + chunk_14_0 * 0x10000

            TYPE high_chunks_sum; // sum of 14 high chunks and chunk_14_1
            TYPE high_chunks_sum_inv; // 1 / high_chunks_sum
            TYPE is_offset_in_range; // 1 if offset < 2^25, 0 otherwise

            // offset + 31 = last_offset_lo + last_offset_hi * 0x10000 + carry * 2^25
            TYPE last_offset_lo; // (offset + 31)% 0x10000< 2^16
            TYPE last_offset_hi, diff_last_offset_hi; // ((offset + 31) / 0x10000) % 2^9
            TYPE carry; // 1 if offset + 31 >= 2^25, 0 otherwise

            // need_lookup0 == need_lookup1 == is_offset_in_range * (1 - carry)
            TYPE need_lookup0, need_lookup1;  // 1 if offset+31 < 2^25, 0 otherwise

            if constexpr (stage == GenerationStage::ASSIGNMENT) {
                auto a_chunks = w_to_16(current_state.stack_top());
                subchunk_14_0 = a_chunks[14] >> 9; // 0x1ff = 511
                subchunk_14_1 = a_chunks[14] & 0x1ff; // 0x1ff = 511
                diff_14_0 = 0x7f - subchunk_14_0; // 0x7f = 127
                diff_14_1 = 0x1ff - subchunk_14_1; // 0x1ff = 511
                is_offset_in_range = (current_state.stack_top() <= 0x2000000 - 1) ? TYPE(1) : TYPE(0); // 0x2000000 = 2^25

                std::size_t address = (a_chunks[14] & 0x1ff) * 0x10000 + a_chunks[15];
                offset0 = offset1 = address;

                // current_mem = current_state.memory_size();
                //     next_mem = std::max(offset + length, current_mem);
                //     S = next_mem > current_mem;
                if( current_state.stack_top() < 0x2000000 - 31 ) { // 0x2000000 = 2^25
                    for (std::size_t i = 0; i < 32; i++) {
                        auto b = w_to_8(current_state.memory(address + i))[31];
                        bytes[i] = TYPE(b);
                    }
                }
                for (std::size_t i = 0; i < 16; i++) {
                    offset_chunks[i] = TYPE(a_chunks[i]);
                }
                for ( std::size_t i = 0; i < 14; i++ ) {
                    high_chunks_sum += offset_chunks[i];
                }
                high_chunks_sum += subchunk_14_0;
                high_chunks_sum_inv = (high_chunks_sum != 0) ? TYPE(1) / high_chunks_sum : TYPE(0);

                last_offset_lo = (address + 31) & 0xffff; // < 2^16
                last_offset_hi = ((address + 31) >> 16) & 0x1ff; // < 2^9
                diff_last_offset_hi = 0x1ff - last_offset_hi; // < 2^9
                carry = (address + 31) >> 25; // 0 or 1

                need_lookup0 = need_lookup1 = (current_state.stack_top() <= 0x2000000 - 32) ? TYPE(1) : TYPE(0); // 0x2000000 = 2^25
            }

            for (std::size_t i = 0; i < 16; i++) {
                allocate(offset_chunks[i], i, 0);
                allocate(bytes[i], i + 16, 0);
                allocate(bytes[i + 16], i + 16, 1);
            }

            allocate(subchunk_14_0, 0, 1);
            allocate(diff_14_0, 1, 1);
            allocate(subchunk_14_1, 2, 1);
            allocate(diff_14_1, 3, 1);
            allocate(last_offset_hi, 4, 1);
            allocate(diff_last_offset_hi, 5, 1);
            allocate(last_offset_lo, 6, 1);
            allocate(carry, 7, 1);
            allocate(is_offset_in_range, 8, 1);

            allocate(offset0, 32, 0);
            allocate(offset1, 32, 1);
            allocate(need_lookup0, 33, 0);
            allocate(need_lookup1, 33, 1);
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
            constrain(offset_chunks[15] + subchunk_14_1 * 0x10000 - offset0);
            constrain(offset0 - offset1);

            constrain(carry * (carry - 1));                                      // carry is 0 or 1
            constrain(last_offset_lo + last_offset_hi * 0x10000 + carry * two_25 - offset0 - 31); // last_offset_lo = offset + 31
            constrain(last_offset_hi + diff_last_offset_hi - 0x1ff);            // last_offset_hi + diff_last_offset_hi = 0x1ff
            constrain(need_lookup0 - is_offset_in_range * (1 - carry));         // need_lookup0 is 0 if offset is not in range
            constrain(need_lookup0 - need_lookup1);

            if constexpr (stage == GenerationStage::CONSTRAINTS) {
                BOOST_LOG_TRIVIAL(warning) << "\tMLOAD gas constraints are not ready yet";

                constrain(current_state.pc_next() - current_state.pc(1) - 1);  // PC transition
                // constrain(current_state.gas(0) - current_state.gas_next() - 3 - memory_expansion_cost);  // GAS transition
                // Result is written to stack only if operation offset is in range
                constrain(current_state.stack_size(1) - current_state.stack_size_next() - 1 + need_lookup1);  // stack_size transition
                // constrain(current_state.memory_size(0) - current_mem);  // memory_size transition
                // constrain(current_state.memory_size_next() - next_mem);  // memory_size transition
                constrain(current_state.rw_counter_next() - current_state.rw_counter(1) - 1 - need_lookup1 * 33);  // rw_counter transition

                lookup(rw_256_table<FieldType, stage>::stack_16_bit_lookup(
                    current_state.call_id(1),
                    current_state.stack_size(1) - 1,
                    current_state.rw_counter(1),
                    TYPE(0),                                               // is_write
                    offset_chunks
                ), "zkevm_rw_256");
                // for( std::size_t i = 0; i < 32; i++ ){
                //     if( i < 16 ){
                //         std::vector<TYPE> tmp = rw_8_table<FieldType, stage>::memory_lookup(
                //             current_state.call_id(0),
                //             offset0 + i,
                //             current_state.rw_counter(0) + i + 1,
                //             TYPE(0),                                               // is_write
                //             bytes[i]
                //         );
                //         for( std::size_t j = 0; j < tmp.size(); j++ ) tmp[j] = tmp[j] * need_lookup0;
                //         lookup(tmp, "zkevm_rw_8");
                //     } else {
                //         std::vector<TYPE> tmp = rw_8_table<FieldType, stage>::memory_lookup(
                //             current_state.call_id(1),
                //             offset1 + i,
                //             current_state.rw_counter(1) + i + 1,
                //             TYPE(0),                                               // is_write
                //             bytes[i]
                //         );
                //         for( std::size_t j = 0; j < tmp.size(); j++ ) tmp[j] = tmp[j] * need_lookup1;
                //         lookup(tmp, "zkevm_rw_8");
                //     }
                // }
            //     tmp = rw_table<FieldType, stage>::stack_8_bit_lookup(
            //         current_state.call_id(1),
            //         current_state.stack_size(1) - 1,
            //         current_state.rw_counter(1) + 33,
            //         TYPE(1),                                               // is_write
            //         bytes
            //     );
            //     for( std::size_t j = 0; j < tmp.size(); j++ ) tmp[j] = tmp[j] * need_lookup1;
            //     lookup(tmp, "zkevm_rw");
            }
        }
    };

    template<typename FieldType>
    class zkevm_mload_operation : public opcode_abstract<FieldType> {
        public:
        virtual void fill_context(
            typename generic_component<
                FieldType, GenerationStage::ASSIGNMENT>::context_type &context,
            const opcode_input_type<FieldType, GenerationStage::ASSIGNMENT>
                &current_state) override {
            zkevm_mload_bbf<FieldType, GenerationStage::ASSIGNMENT> bbf_obj(
                context, current_state);
        }
        virtual void fill_context(
            typename generic_component<
                FieldType, GenerationStage::CONSTRAINTS>::context_type &context,
            const opcode_input_type<FieldType, GenerationStage::CONSTRAINTS>
                &current_state) override {
            zkevm_mload_bbf<FieldType, GenerationStage::CONSTRAINTS> bbf_obj(
                context, current_state);
        }
        virtual std::size_t rows_amount() override { return 2; }
    };
}