//---------------------------------------------------------------------------//
// Copyright (c) 2024 Dmitrii Tabalin <d.tabalin@nil.foundation>
// Copyright (c) 2024 Alexey Yashunsky <a.yashunsky@nil.foundation>
// Copyright (c) 2025 Javier Silva <javier.silva@nil.foundation>
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

#include <alloca.h>
#include <unistd.h>
#include <cstddef>
#include <numeric>
#include <algorithm>

#include <nil/blueprint/zkevm_bbf/small_field/opcodes/abstract_opcode.hpp>
#include <vector>
#include "nil/blueprint/bbf/enums.hpp"
#include "nil/blueprint/zkevm_bbf/types/zkevm_word.hpp"

namespace nil::blueprint::bbf::zkevm_small_field {
    template<typename FieldType>
    class opcode_abstract;

    template<typename FieldType, GenerationStage stage>
    class zkevm_mul_bbf : generic_component<FieldType, stage> {
        using generic_component<FieldType, stage>::allocate;
        using generic_component<FieldType, stage>::copy_constrain;
        using generic_component<FieldType, stage>::constrain;
        using generic_component<FieldType, stage>::lookup;
        using generic_component<FieldType, stage>::lookup_table;

        using value_type = typename FieldType::value_type;

        constexpr static const std::size_t chunk_amount = 16;
        constexpr static const std::size_t chunk_size = 256 / chunk_amount;
        constexpr static const std::size_t chunk_8_amount = 32;
        constexpr static const value_type two_15 = 32768;
        constexpr static const value_type two_16 = 65536;

    public:
        using typename generic_component<FieldType,stage>::TYPE;
        using typename generic_component<FieldType, stage>::context_type;

        // NOTE ON OVERALL APPROACH: unlike in the SHL, SHR, SAR opcodes, here we perform multiplication
        // by splitting both inputs into 8-bit chunks, as opposed to one in 16-bit chunks and the other in
        // 8-bit chunks. This is because the 16-8 approach produces carries that are in general larger than
        // 16 bits, so they need to be split for range-checking. This was not necessary in the shift opcodes,
        // as the special nature of one of the factors ensured that there was never a 16-bit overflow.
        // Because of this, the 16-8 approach ends up taking as much space as the 8-8 approach. We favor
        // the 8-8 approach for conceptual simplicity.

        // Computes the terms of a*b with coefficient 2^(8 * chunk_index)
        TYPE carryless_mul(const std::vector<TYPE> &a_8_chunks,
                                    const std::vector<TYPE> &b_8_chunks,
                                    const unsigned char chunk_index) const {
            TYPE res = 0;
            // std::cout << "chunk_index = " << chunk_index << std::endl;
            for (int i = 0; i <= chunk_index; i++) {
                int j = chunk_index - i;
                if ((i < chunk_8_amount) && (j >= 0) && (j < chunk_8_amount)) {
                    // std::cout << "i = " << i << ", j = " << j << std::endl;
                    res += a_8_chunks[i] * b_8_chunks[j];
                }
            }
            return res;
        }

        // Counts the number of cross terms a_chunks[i] * b_chunks[j] involved in the i-th carryless
        // chunk of the multiplication a * b. This is useful for range-checking later.
        int count_cross_terms(const unsigned char chunk_index) const {
            // the result is the amount of pairs (i, j) such that i + j == chunk_index, for 0 <= i, j < chunk_8_amount.
            int i = chunk_index + 1;
            return (i <= 32) ? i : 2 * chunk_8_amount - i;
        }

        // Given a carryless chunk, we will separate it into an 8-bit chunk and a carry, which
        // contains whatever overflows 8 bits. This function computes the maximal value of such
        // carry, for accurate range-checking.
        int max_carry(const unsigned char chunk_index) const {
            // r8_carryless_chunks[i] + prev_carry == r8_chunks[i] + r8_carries[i] * 256
            // To bound r8_carries[i], we need to bound r8_carryless_chunks[i] and prev_carry.
            // r8_carryless_chunks[i] == (sum of some cross terms a_chunks[i] * b_chunks[j]).
            // The largest carries happen when a_chunks[i] == b_chunks[i] == 2^8 - 1 for all 0 <= i < 32.
            int max_cross_term = 255 * 255;
            // r8_carryless_chunks[i] <= number_of_cross_terms * max_cross_terms
            int number_of_cross_terms = count_cross_terms(chunk_index);
            // Finally, we also take into account the maximal value of the previous carry
            int prev_carry = (chunk_index > 0) ? max_carry(chunk_index - 1) : 0;
            // Putting it all together and taking the carry (discarding the lowest 8 bits)
            int max_carry = (number_of_cross_terms * max_cross_term + prev_carry) >> 8;
            return max_carry;
        }

        std::vector<TYPE> res;

        zkevm_mul_bbf(context_type &context_object, const opcode_input_type<FieldType, stage> &current_state)
            : generic_component<FieldType,stage>(context_object, false),
            res(chunk_amount) {

            // 16-bit chunks
            std::vector<TYPE> a_chunks(chunk_amount);                      // First input
            std::vector<TYPE> b_chunks(chunk_amount);                      // Second input
            std::vector<TYPE> r_chunks(chunk_amount);                      // Result of a*b

            // 8-bit chunks
            std::vector<TYPE> a8_chunks(chunk_8_amount);
            std::vector<TYPE> b8_chunks(chunk_8_amount);
            std::vector<TYPE> r8_chunks(chunk_8_amount);                   // Result of a*b in 8-bit chunks
            std::vector<TYPE> r8_carryless_chunks(chunk_8_amount);         // r8_carryless_chunks[i] = carryless_mul(a8_chunks, b8_chunks, i)
            std::vector<TYPE> r8_carries(chunk_8_amount);                  // Carries containing whatever overflows 8 bits:
                                                                            // r8_carryless_chunks[i] = r8_chunks[i] + r8_carries[i]
            std::vector<TYPE> r8_carries_copy1(chunk_8_amount);
            std::vector<TYPE> r8_carries_copy2(chunk_8_amount);

            // Range checks associated with the values above
            std::vector<TYPE> a8_chunks_check(chunk_8_amount);
            std::vector<TYPE> b8_chunks_check(chunk_8_amount);
            std::vector<TYPE> r8_chunks_check(chunk_8_amount);
            std::vector<TYPE> r8_carries_check(chunk_8_amount);


            // PART 1: computing the opcode and splitting values in chunks
            if constexpr (stage == GenerationStage:: ASSIGNMENT) {
                // Extract input values from stack
                zkevm_word_type a = current_state.stack_top();
                zkevm_word_type b = current_state.stack_top(1);
                zkevm_word_type r = wrapping_mul(a, b);      // Result

                // 16-bit chunks
                a_chunks = zkevm_word_to_field_element<FieldType>(a);
                b_chunks = zkevm_word_to_field_element<FieldType>(b);
                r_chunks = zkevm_word_to_field_element<FieldType>(r);

                // 8-bit chunks
                a8_chunks = zkevm_word_to_field_element_flexible<FieldType>(a, chunk_8_amount, 8);
                b8_chunks = zkevm_word_to_field_element_flexible<FieldType>(b, chunk_8_amount, 8);
            }

            // 16-bit chunks allocation
            for (std::size_t i = 0; i < chunk_amount; i++) {
                allocate(a_chunks[i], 2 * chunk_amount + i, 6);
                allocate(b_chunks[i], 2 * chunk_amount + i, 7);
                allocate(r_chunks[i], 2 * chunk_amount + i, 8);
            }

            // 8-bit chunks allocation
            for (std::size_t i = 0; i < chunk_8_amount; i++) {
                allocate(a8_chunks[i], i, 4);
                allocate(b8_chunks[i], i, 5);
                a8_chunks_check[i] = a8_chunks[i] * 256;
                b8_chunks_check[i] = b8_chunks[i] * 256;
                allocate(a8_chunks_check[i], i, 2);
                allocate(b8_chunks_check[i], i, 3);
            }

            // PART 2: enforcing the multiplication a*b = r (mod 2^256)
            for (std::size_t i = 0; i < chunk_8_amount; i++) {
                r8_carryless_chunks[i] = carryless_mul(a8_chunks, b8_chunks, i);
                TYPE prev_carry = (i > 0) ? r8_carries[i-1] : 0;
                if constexpr (stage == GenerationStage::ASSIGNMENT) {
                    auto mask8 = (1 << 8) - 1;
                    r8_chunks[i] = (r8_carryless_chunks[i] + prev_carry).to_integral() & mask8;
                    r8_carries[i] = (r8_carryless_chunks[i] + prev_carry).to_integral() >> 8;
                }
                allocate(r8_chunks[i], i, 6);
                r8_chunks_check[i] = r8_chunks[i] * 256;
                allocate(r8_chunks_check[i], i, 7);

                // The carries are stored in two columns
                int column_offset = i % chunk_amount;
                int row_offset = i / chunk_amount;
                allocate(r8_carries[i], 2 * chunk_amount + column_offset, 4 + row_offset);

                // Copy the carries to range-checked columns
                r8_carries_copy1[i] = r8_carries[i];
                allocate(r8_carries_copy1[i], 2 * chunk_amount + column_offset, 2 + row_offset);    // This copy also uses two rows
                r8_carries_copy2[i] = r8_carries_copy1[i];
                allocate(r8_carries_copy2[i], i, 1);                                                // This copy fits in a single row

                // Main constraint enforcing the multiplication and carry propagation
                constrain(r8_carryless_chunks[i] + prev_carry - r8_chunks[i] - r8_carries[i] * 256);
            }

            // Range checks for the multiplication carries.
            for (std::size_t i = 0; i < chunk_8_amount; i++) {
                r8_carries_check[i] = r8_carries_copy2[i] + (two_16 - 1 - max_carry(i));
                allocate(r8_carries_check[i], i, 0);
            }

            for (std::size_t i = 0; i < chunk_amount; i++) {
                // Ensure consistency between the 16-bit chunks and 8-bit chunks of a, b, r.
                constrain(a_chunks[i] - a8_chunks[2*i] - a8_chunks[2*i + 1] * 256);
                constrain(b_chunks[i] - b8_chunks[2*i] - b8_chunks[2*i + 1] * 256);
                constrain(r_chunks[i] - r8_chunks[2*i] - r8_chunks[2*i + 1] * 256);
                // Link r to the final result
                res[i] = r_chunks[i];
            }

            // PART 3: consistency with the stack
            if constexpr( stage == GenerationStage::CONSTRAINTS ){
                // State transition constraints
                // The arguments for pc, gas, stack_size, memory-size and rw_counter correspond to number_of_rows - 1
                constrain(current_state.pc_next() - current_state.pc(8) - 1);                   // PC transition
                constrain(current_state.gas(8) - current_state.gas_next() - 5);                 // GAS transition
                constrain(current_state.stack_size(8) - current_state.stack_size_next() - 1);   // stack_size transition
                constrain(current_state.memory_size(8) - current_state.memory_size_next());     // memory_size transition
                constrain(current_state.rw_counter_next() - current_state.rw_counter(8) - 3);   // rw_counter transition

                // Stack lookup constraints
                // The arguments for call_id, stack_size and rw_counter corresponds to the indices of the rows that contains the data read from the rw_table
                std::vector<TYPE> tmp;
                lookup(rw_256_table<FieldType, stage>::stack_16_bit_lookup_reversed(
                    current_state.call_id(6),
                    current_state.stack_size(6) - 1,
                    current_state.rw_counter(6),
                    TYPE(0),// is_write
                    a_chunks
                ), "zkevm_rw_256");
                lookup(rw_256_table<FieldType, stage>::stack_16_bit_lookup_reversed(
                    current_state.call_id(7),
                    current_state.stack_size(7) - 2,
                    current_state.rw_counter(7) + 1,
                    TYPE(0),// is_write
                    b_chunks
                ), "zkevm_rw_256");
                lookup(rw_256_table<FieldType, stage>::stack_16_bit_lookup_reversed(
                    current_state.call_id(8),
                    current_state.stack_size(8) - 2,
                    current_state.rw_counter(8) + 2,
                    TYPE(1),// is_write
                    res
                ), "zkevm_rw_256");
            }
        }
    };

    template<typename FieldType>
    class zkevm_mul_operation : public opcode_abstract<FieldType> {
    public:
        virtual void fill_context(
            typename generic_component<FieldType, GenerationStage::ASSIGNMENT>::context_type &context,
            const opcode_input_type<FieldType, GenerationStage::ASSIGNMENT> &current_state
        ) override  {
            zkevm_mul_bbf<FieldType, GenerationStage::ASSIGNMENT> bbf_obj(context, current_state);
        }
        virtual void fill_context(
            typename generic_component<FieldType, GenerationStage::CONSTRAINTS>::context_type &context,
            const opcode_input_type<FieldType, GenerationStage::CONSTRAINTS> &current_state
        ) override  {
            zkevm_mul_bbf<FieldType, GenerationStage::CONSTRAINTS> bbf_obj(context, current_state);
        }
        virtual std::size_t rows_amount() override {
            return 9;
        }
    };
}   // namespace nil::blueprint::bbf
