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

#include <nil/blueprint/zkevm_bbf/types/opcode.hpp>
#include <vector>
#include "nil/blueprint/bbf/enums.hpp"
#include "nil/blueprint/zkevm_bbf/types/zkevm_word.hpp"

namespace nil::blueprint::bbf {
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

    // Computes the terms of r*b with coefficient 2^(8 * chunk_index)
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

    // TODO: add comment
    TYPE count_cross_terms(const unsigned char chunk_index) const {
        int i = chunk_index + 1;
        return (i <= 32) ? i : 2 * chunk_8_amount - i;
    }

    // NOTE ON OVERALL APPROACH: unlike in the SHL, SHR, SAR opcodes, here we perform multiplication
    // by splitting both inputs into 8-bit chunks, as opposed to one in 16-bit chunks and the other in
    // 8-bit chunks. This is because the 16-8 approach produces carries that are in general larger than
    // 16 bits, so they need to be split for range-checking. This was not necessary in the shift opcodes,
    // as the special nature of one of the factors ensured that there was never a 16-bit overflow.
    // Because of this, the 16-8 approach ends up taking as much space as the 8-8 approach. We favor 
    // the 8-8 approach for conceptual simplicity.
    zkevm_mul_bbf(context_type &context_object, const opcode_input_type<FieldType, stage> &current_state):
        generic_component<FieldType,stage>(context_object, false)
    {
        // 16-bit chunks
        std::vector<TYPE> a_chunks(chunk_amount);                      // First input chunks
        std::vector<TYPE> b_chunks(chunk_amount);                      // Second input chunks
        std::vector<TYPE> r_chunks(chunk_amount);                      // Result of a*b

        // 8-bit chunks
        std::vector<TYPE> a8_chunks(chunk_8_amount);
        std::vector<TYPE> b8_chunks(chunk_8_amount);
        std::vector<TYPE> r8_chunks(chunk_8_amount);                   // Result of a*b in 8-bit chunks
        std::vector<TYPE> r8_carryless_chunks(chunk_8_amount);         // a8_chunks[i] * b8_chunks[i] = r8_carryless_chunks[i]
        std::vector<TYPE> r8_carries(chunk_8_amount);                  // Carries containing whatever overflows 8 bits: 
                                                                       // a8_chunks[i] * b8_chunks[i] = r8_chunks[i] + r8_carries[i]
        std::vector<TYPE> r8_carries_copy1(chunk_8_amount);
        std::vector<TYPE> r8_carries_copy2(chunk_8_amount);

        // Range checks associated with the values above
        std::vector<TYPE> a8_chunks_check(chunk_8_amount);
        std::vector<TYPE> b8_chunks_check(chunk_8_amount);
        std::vector<TYPE> r8_chunks_check(chunk_8_amount);
        std::vector<TYPE> r8_carries_check(chunk_8_amount);

        allocate(a8_chunks[0], 0, 5);   // This one crashes the tests:
                                        // unknown location(0): fatal error: in "zkevm_opcode_test_suite/mul": std::runtime_error: Insufficient space for starting a new row.

        allocate(a8_chunks[0], 1, 5);   // All of these work fine
        allocate(a8_chunks[0], 0, 4);
        allocate(a8_chunks[0], 0, 6);


        // PART 1: computing the opcode and splitting values in chunks
        // if constexpr (stage == GenerationStage:: ASSIGNMENT) {
        //     // Extract input values from stack
        //     zkevm_word_type b = current_state.stack_top();    
        //     zkevm_word_type a = current_state.stack_top(1);   

        //     zkevm_word_type r = wrapping_mul(a, b);      // Result

        //     // 16-bit chunks
        //     a_chunks = zkevm_word_to_field_element<FieldType>(a);
        //     b_chunks = zkevm_word_to_field_element<FieldType>(b);
        //     r_chunks = zkevm_word_to_field_element<FieldType>(r);

        //     // 8-bit chunks
        //     a8_chunks = zkevm_word_to_field_element_flexible<FieldType>(a, chunk_8_amount, 8);
        //     b8_chunks = zkevm_word_to_field_element_flexible<FieldType>(b, chunk_8_amount, 8);
        //     r8_chunks = zkevm_word_to_field_element_flexible<FieldType>(r, chunk_8_amount, 8);

        //     for (std::size_t i = 0; i < chunk_amount; i++) {
        //         BOOST_ASSERT(r_chunks[i] == r8_chunks[2*i] + 256 * r8_chunks[2*i + 1]);
        //     }
        // }

        // 16-bit chunks allocation
        // for (std::size_t i = 0; i < chunk_amount; i++) {
        //     allocate(a_chunks[i], 2 * chunk_amount + i, 6);
        //     allocate(b_chunks[i], 2 * chunk_amount + i, 7);
        // }

        // 8-bit chunks allocation
        // for (std::size_t i = 0; i < chunk_8_amount; i++) {
        //     // allocate(a8_chunks[i], i, 4);
        //     // allocate(b8_chunks[i], i, 5);
        //     // a8_chunks_check[i] = a8_chunks[i] * 256;
        //     // b8_chunks_check[i] = b8_chunks[i] * 256;
        //     // allocate(a8_chunks_check[i], i, 2);
        //     // allocate(b8_chunks_check[i], i, 3);
        // }

        // PART 2: enforcing the multiplication a*b = r (mod 2^256)
        // for (std::size_t i = 0; i < chunk_8_amount; i++) {
        //     r8_carryless_chunks[i] = carryless_mul(a8_chunks, b8_chunks, i);
        //     TYPE prev_carry = (i > 0) ? r8_carries[i-1] : 0;
        //     if constexpr (stage == GenerationStage::ASSIGNMENT) {
        //         auto mask8 = (1 << 8) - 1;
        //         r8_chunks[i] = (r8_carryless_chunks[i] + prev_carry).to_integral() & mask8;
        //         r8_carries[i] = (r8_carryless_chunks[i] + prev_carry).to_integral() >> 8;
        //         // std::cout << r8_carryless_chunks[i] <<std::endl;
        //         BOOST_ASSERT(r8_carryless_chunks[i] + prev_carry == r8_chunks[i] + 256 * r8_carries[i]);
        //     }
        //     allocate(r8_chunks[i], i, 6);

        //     r8_chunks_check[i] = r8_chunks[i] * 256; 
        //     allocate(r8_chunks_check[i], i, 7);
        // }

        // for (std::size_t i = 0; i < chunk_8_amount; i++) {
        //     // The carries are stored in two columns
        //     int column_offset = i % chunk_amount;
        //     // int row_offset = i / chunk_amount;
        //     int row_offset = (i < 16) ? 0 : 1;
        //     allocate(r8_carries[i], 2 * chunk_amount + column_offset, 4 + row_offset);

        //     // Copy the carries to range-checked columns
        //     r8_carries_copy1[i] = r8_carries[i];
        //     allocate(r8_carries_copy1[i], 2 * chunk_amount + column_offset, 2 + row_offset);
        //     r8_carries_copy2[i] = r8_carries_copy1[i];
        //     allocate(r8_carries_copy2[i], i, 1);     // This copy fits in a single row
        // }

        // // TODO: these range checks fail for large a, b. Adjust them appropriately.
        // for (std::size_t i = 0; i < chunk_8_amount; i++) {
        //     // r8_carries_check[i] = r8_carries_copy2[i] * 256;
        //     allocate(r8_carries_check[i], i, 0);
        // }
    
        // // Ensure consistency between r_chunks and r8_chunks
        // // TODO: same for a, b
        // for (std::size_t i = 0; i < chunk_amount; i++) {
        //     constrain(r_chunks[i] - r8_chunks[2*i] - r8_chunks[2*i + 1] * 256);  // TODO: this constraint is not satisfied. Why? It should be!
        //     // TODO: link r_chunks with the actual result
        // }


        // PART 3: consistency with the stack
        // TODO. update this part
        // auto A_128 = chunks16_to_chunks128<TYPE>(A);
        // auto B_128 = chunks16_to_chunks128<TYPE>(B);
        // auto R_128 = chunks16_to_chunks128<TYPE>(R);
        // if constexpr( stage == GenerationStage::CONSTRAINTS ){
        //     constrain(current_state.pc_next() - current_state.pc(1) - 1);                   // PC transition
        //     constrain(current_state.gas(1) - current_state.gas_next() - 5);                 // GAS transition
        //     constrain(current_state.stack_size(1) - current_state.stack_size_next() - 1);   // stack_size transition
        //     constrain(current_state.memory_size(1) - current_state.memory_size_next());     // memory_size transition
        //     constrain(current_state.rw_counter_next() - current_state.rw_counter(1) - 3);   // rw_counter transition
        //     std::vector<TYPE> tmp;
        //     tmp = rw_table<FieldType, stage>::stack_lookup(
        //         current_state.call_id(0),
        //         current_state.stack_size(0) - 1,
        //         current_state.rw_counter(0),
        //         TYPE(0),// is_write
        //         A_128.first,
        //         A_128.second
        //     );
        //     lookup(tmp, "zkevm_rw");
        //     tmp = rw_table<FieldType, stage>::stack_lookup(
        //         current_state.call_id(0),
        //         current_state.stack_size(0) - 2,
        //         current_state.rw_counter(0) + 1,
        //         TYPE(0),// is_write
        //         B_128.first,
        //         B_128.second
        //     );
        //     lookup(tmp, "zkevm_rw");
        //     tmp = rw_table<FieldType, stage>::stack_lookup(
        //         current_state.call_id(1),
        //         current_state.stack_size(1) - 2,
        //         current_state.rw_counter(1) + 2,
        //         TYPE(1),// is_write
        //         R_128.first,
        //         R_128.second
        //     );
        //     lookup(tmp, "zkevm_rw");
        // }
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
