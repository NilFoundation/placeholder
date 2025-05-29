//---------------------------------------------------------------------------//
// Copyright (c) 2024 Alexey Yashunsky <a.yashunsky@nil.foundation>
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
#include <nil/blueprint/zkevm_bbf/small_field/opcodes/abstract_opcode.hpp>
#include <numeric>

namespace nil::blueprint::bbf::zkevm_small_field {
    /*
    *    Opcode: 0x1A BYTE
    *    Description: Retrieve single byte from word (x >> (248 - i * 8)) && 0xFF
    *    GAS: 3
    *    PC: +1
    *    Memory: Unchanged
    // *    Stack Input: i, x
    *    Stack Output: b
    *    Stack Read    Lookup: i, x
    *    Stack Write Lookup: b
    *    rw_counter: +3
    */
    template<typename FieldType, GenerationStage stage>
    class zkevm_byte_bbf : generic_component<FieldType, stage> {
        using typename generic_component<FieldType, stage>::context_type;
        using generic_component<FieldType, stage>::allocate;
        using generic_component<FieldType, stage>::copy_constrain;
        using generic_component<FieldType, stage>::constrain;
        using generic_component<FieldType, stage>::lookup;
        using generic_component<FieldType, stage>::lookup_table;

      public:
        using typename generic_component<FieldType, stage>::TYPE;

        zkevm_byte_bbf(
            context_type &context_object,
            const opcode_input_type<FieldType, stage> &current_state
        ) : generic_component<FieldType, stage>(context_object, false) {
            std::vector<TYPE> X(16);  // 16-bit chunks of x
            std::vector<TYPE> I(16);  // 16-bit chunks of i, i is the offset from the MOST
            // SIGNIFICANT BYTE
            std::vector<TYPE> I_bits(16);  // 16 bits at position i
            TYPE x16, x16_hi, x16_lo, minus_x16_hi, minus_x16_lo, i_last_bit, i_sum, i_hi,
                i_lo, i_sum_inv, b;

            if constexpr (stage == GenerationStage::ASSIGNMENT) {
                // split i and b into 16-bit chunks
                auto N = current_state.stack_top();  // copy of i
                auto i = w_to_16(current_state.stack_top());
                auto x = w_to_16(current_state.stack_top(1));
                for (std::size_t j = 0; j < 16; j++) {
                    X[j] = x[j];
                    I[j] = i[j];
                    I_bits[j] =
                        (N >= 0 && N < 32) && (i[15] / 2 == j);  // chunk indicator
                    if (j != 15) i_sum += i[j];  // i chunks sum except last chunk
                }
                i_last_bit = (0 <= N && N < 32) && ((i[15] & 1) != 0);
                // i is in range 0-31, therefore, we need the least significant 5 bits of
                // the last 16-bit chunk
                i_hi = i[15] / 32;
                i_lo = i[15] % 32;

                // if i is in range 0-31, first 15 chunks and 11 bits of last chunk (i_hi)
                // should be zero
                i_sum += i_hi;
                i_sum_inv =
                    i_sum == 0 ? 0 : i_sum.inversed();  // if i > 31, i_sum_inv != 0
                // i[15] is index of i'th byte (8-bit) of x ==> i[15]/2 is the index of
                // 16-bit chunk of x
                std::size_t chunk = (0 <= N && N < 32) ? x[i[15] / 2] : 0;
                x16 = chunk;
                x16_lo = chunk & 0xFF;           // low byte
                x16_hi = (chunk & 0xFF00) >> 8;  // high byte
                minus_x16_hi = 255 - x16_hi;     // 8-bit inverse of x16_hi
                minus_x16_lo = 255 - x16_lo;     // 8-bit inverse of x16_lo
                // if i is odd, choose low 8-bits of chunk, otherwise high 8-bits
                b = (i_last_bit == 0) ? x16_hi : x16_lo;
            }

            /* Layout: range_checked_opcode_area not_range_checked_opcode_area 0         1
            2                    3                        4                5             6
            7                8            ...        15            16        ...        31
            32            33         ...     47
            +------+------+------+------------+------------+------+------+----------+------+------+-------+------+-----+-----+-----+---------+------+------+
            | X[0] | X[1] | X[2] |        X[3]        |         X[4]     | X[5] | X[6] |
            X[7]     | X[8] |    ... | X[15] | I[0] | ... |I[15]|i_sum|i_sum_inv| | |
            +------+------+------+------------+------------+------+------+----------+------+------+-------+------+-----+-----+-----+---------+------+------+
            | x16    |x16_hi|x16_lo|minus_x16_hi|minus_x16_lo| i_hi | i_lo |i_last_bit| b
            |            |             |            |         |         |         | | | |
            +------+------+------+------------+------------+------+------+----------+------+------+-------+------+-----+-----+-----+---------+------+------+
            */
            for (std::size_t j = 0; j < 16; j++) {
                allocate(X[j], j, 0);
                allocate(I[j], j + 16, 0);
                allocate(I_bits[j], j + 16, 1);
            }
            allocate(x16, 0, 1);
            allocate(x16_hi, 1, 1);
            allocate(x16_lo, 2, 1);
            allocate(minus_x16_hi, 3, 1);
            allocate(minus_x16_lo, 4, 1);
            allocate(i_hi, 5, 1);
            allocate(i_lo, 6, 1);
            allocate(i_last_bit, 7, 1);
            allocate(b, 8, 1);
            allocate(i_sum, 32, 0);
            allocate(i_sum_inv, 33, 0);

            // constraint correctness of x16 = x16_hi || x16_lo
            constrain(x16_hi + minus_x16_hi - 255);
            constrain(x16_lo + minus_x16_lo - 255);
            constrain(x16 - x16_hi * 256 - x16_lo);

            TYPE i_sum_constraint;
            TYPE i_bits_composition;
            TYPE i_bits_sum;
            TYPE chunk;
            for (std::size_t j = 0; j < 16; j++) {
                constrain(I_bits[j] * (I_bits[j] - 1));
                if (j != 15) i_sum_constraint += I[j];
                i_bits_composition += j * I_bits[j];
                i_bits_sum += I_bits[j];
                chunk += I_bits[j] * X[j];
            }
            i_sum_constraint += i_hi;
            i_bits_composition *= 2;
            i_bits_composition += i_last_bit;
            constrain(i_bits_composition - i_bits_sum * i_lo);
            constrain(i_sum_constraint - i_sum);         // i_sum == 0
            constrain(i_sum * (i_sum * i_sum_inv - 1));  // i_sum_inv * i_sum = 1
            constrain(i_sum_inv *
                      (i_sum * i_sum_inv - 1));  // if i_sum == 0 then i_sum_inv = 0
            constrain(i_sum * i_sum_inv * b);    // if i_sum != 0 then b = 0
            constrain(i_last_bit *
                      (i_last_bit - 1));  // i_last_bit is 0 or 1 (parity check)
            constrain(i_bits_sum + i_sum * i_sum_inv - 1);
            constrain(i_hi * 32 + i_lo -
                      I[15]);        // i[15] = i_hi (11-bits) || i_lo (5-bits)
            constrain(chunk - x16);  // last chunk is chosen correctly from i-bits
            constrain(
                i_bits_sum *
                (i_last_bit * (x16_lo - b) +
                 (1 - i_last_bit) *
                     (x16_hi - b)));  // result is x16_hi if is_last_bit = 0 or x16_lo

            if constexpr (stage == GenerationStage::CONSTRAINTS) {
                constrain(current_state.pc_next() - current_state.pc(1) -  1);  // PC transition
                constrain(current_state.gas(1) - current_state.gas_next() - 3);  // GAS transition
                constrain(current_state.stack_size(1) - current_state.stack_size_next() - 1);  // stack_size transition
                constrain(current_state.memory_size(1) - current_state.memory_size_next());    // memory_size transition
                constrain(current_state.rw_counter_next() - current_state.rw_counter(1) - 3);  // rw_counter transition

                using RwTable = rw_256_table<FieldType, stage>;
                lookup(RwTable::stack_16_bit_lookup(
                    current_state.call_id(0),
                    current_state.stack_size(0) - 1,
                    current_state.rw_counter(0),
                    TYPE(0),    // is_write
                    I
                ), "zkevm_rw_256");

                lookup(RwTable::stack_16_bit_lookup(
                    current_state.call_id(0),
                    current_state.stack_size(0) - 2,
                    current_state.rw_counter(0) + 1,
                    TYPE(0),    // is_write
                    X
                ), "zkevm_rw_256");

                lookup(RwTable::stack_one_chunk_lookup(
                    current_state.call_id(1),
                    current_state.stack_size(1) - 2,
                    current_state.rw_counter(1) + 2,
                    TYPE(1),    // is_write
                    b
                ), "zkevm_rw_256");
            }
        }
    };

    template<typename FieldType>
    class zkevm_byte_operation : public opcode_abstract<FieldType> {
      public:
        virtual std::size_t rows_amount() override { return 2; }
        virtual void fill_context(
            typename generic_component<
                FieldType, GenerationStage::ASSIGNMENT>::context_type &context,
            const opcode_input_type<FieldType, GenerationStage::ASSIGNMENT>
                &current_state) override {
            zkevm_byte_bbf<FieldType, GenerationStage::ASSIGNMENT> bbf_obj(context,
                                                                           current_state);
        }
        virtual void fill_context(
            typename generic_component<
                FieldType, GenerationStage::CONSTRAINTS>::context_type &context,
            const opcode_input_type<FieldType, GenerationStage::CONSTRAINTS>
                &current_state) override {
            zkevm_byte_bbf<FieldType, GenerationStage::CONSTRAINTS> bbf_obj(
                context, current_state);
        }
    };
}  // namespace nil::blueprint::bbf::zkevm_small_field
