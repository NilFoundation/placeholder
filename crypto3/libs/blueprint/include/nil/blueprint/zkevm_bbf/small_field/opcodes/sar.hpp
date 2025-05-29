//---------------------------------------------------------------------------//
// Copyright (c) 2024 Alexey Yashunsky <a.yashunsky@nil.foundation>
// Copyright (c) 2024 Antoine Cyr <antoine.cyr@nil.foundation>
// Copyright (c) 2025 Maxim Nikolaev <maksim.n@nil.foundation
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

#include <algorithm>
#include <cstddef>
#include <cstdio>
#include <iostream>
#include <nil/blueprint/zkevm_bbf/small_field/opcodes/abstract_opcode.hpp>
#include <numeric>
#include "nil/blueprint/utils/connectedness_check.hpp"

namespace nil::blueprint::bbf::zkevm_small_field {
template<typename FieldType>
class opcode_abstract;

template<typename FieldType, GenerationStage stage>
class zkevm_sar_bbf : public generic_component<FieldType, stage> {
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
    using typename generic_component<FieldType, stage>::TYPE;
    using typename generic_component<FieldType, stage>::context_type;

    // Computes the terms of r*b with coefficient 2^(8 * chunk_index)
    TYPE carryless_mul(const std::vector<TYPE> &r_16_chunks,
                                const std::vector<TYPE> &b_8_chunks,
                                const unsigned char chunk_index) const {
        TYPE res = 0;
        for (int i = 0; i <= chunk_index; i++) {
            int j = chunk_index - 2 * i;
            if ((i < chunk_amount) && (j >= 0) && (j < chunk_8_amount)) {
                res += r_16_chunks[i] * b_8_chunks[j];
            }
        }
        return res;
    }

    // Computes the terms of rb + q - a with coefficient 2^(8 * chunk_index)
    TYPE carryless_construct(const std::vector<TYPE> &rb_8_chunks,
                                const std::vector<TYPE> &q_16_chunks,
                                const std::vector<TYPE> &a_16_chunks,
                                const unsigned char chunk_index) const {
        auto res = rb_8_chunks[2 * chunk_index] + rb_8_chunks[2 * chunk_index + 1] * 256 + q_16_chunks[chunk_index] - a_16_chunks[chunk_index];
        return res;
    }

    std::vector<TYPE> res;

  public:
    zkevm_sar_bbf(context_type &context_object,
                  const opcode_input_type<FieldType, stage> &current_state)
        : generic_component<FieldType, stage>(context_object, false),
          res(chunk_amount) {

        // Variables for shift amount decomposition and range checks
        TYPE shift_value;           // adjusted shift value, set to 255 if input_b > 255
        TYPE shift_lower;           // Lower 4 bits of shift amount (shift % 16)
        TYPE shift_upper;           // Upper 4 bits of shift amount (shift / 16)
        TYPE input_b0_lower;        // Lower bits of input_b[0] (b % 256)
        TYPE input_b0_upper;        // Upper bits of input_b[0] (b % 65536 / 256)
        TYPE shift_lower_check;     // Range check for shift_lower
        TYPE shift_upper_check;     // Range check for shift_upper
        TYPE input_b0_lower_check;  // Range check for input_b0_lower
        TYPE input_b0_upper_check;  // Range check for input_b0_upper

        // Inverse and zero check variables
        TYPE upper_inverse;        // Inverse of b0_upper
        TYPE input_b_partial_sum;  // Partial sum of input_b chunks
        TYPE sum_inverse_partial;  // Inverse of partial sum of input_b chunks
        TYPE is_shift_large;       // Indicates if shift >= 256
        TYPE shift_lower_power;    // Power of 2 corresponding to shift_lower

        // 16-bit chunk vectors
        std::vector<TYPE> input_b_chunks(chunk_amount);     // Input shift amount chunks
        std::vector<TYPE> a_chunks(chunk_amount);           // Input value chunks
        std::vector<TYPE> b_chunks(chunk_amount);           // Shift power chunks
        std::vector<TYPE> b_chunks_copy1(chunk_amount);     // Copy of the above
        std::vector<TYPE> b_chunks_copy2(chunk_amount);     // Copy of the above
        std::vector<TYPE> r_chunks(chunk_amount);           // Shift result chunks (without sign extension)
        std::vector<TYPE> r_chunks_copy1(chunk_amount);     // Copy of the above
        std::vector<TYPE> r_chunks_copy2(chunk_amount);     // Copy of the above
        std::vector<TYPE> q_chunks(chunk_amount);           // Division remainder chunks
        std::vector<TYPE> v_chunks(chunk_amount);           // Difference chunks (q - b)
        std::vector<TYPE> b8_chunks(chunk_8_amount);        // Shift power in 8-bit chunks
        std::vector<TYPE> b8_chunks_check(chunk_8_amount);  // Range check for b8_chunks
        std::vector<TYPE> add_carries(chunk_amount - 1);    // Carries for v + b
        TYPE a_chunks15_copy1;                              // Copy of a_chunks[15]

        std::vector<TYPE> mul8_carryless_chunks(chunk_8_amount);        // carryless terms of r*b with coefficients 2^(8*i), 0 <= i < 32
        std::vector<TYPE> mul8_carryless_chunks_high(chunk_8_amount);   // carryless terms of r*b with coefficients 2^(8*i), 32 <= i < 62 (i = 62 and i = 63 are zero anyway)
        std::vector<TYPE> mul8_chunks(chunk_8_amount);                  // 8-bit chunks of r*b
        std::vector<TYPE> mul8_carries(chunk_8_amount);                 // Carries for the above
        std::vector<TYPE> mul8_chunk_check(chunk_8_amount);             // Range checks for mul8_chunks
        std::vector<TYPE> mul8_carries_check(chunk_8_amount);           // Range checks for mul8_carries (< 2^15)
        std::vector<TYPE> construct_carryless_chunks(chunk_amount);     // Chunks for the carryless terms of r*b + q - a

        // Indicator vectors for shift position
        std::vector<TYPE> indic_1(chunk_amount);  // First shift position indicators -- marks transition bit within transition chunk
        std::vector<TYPE> indic_2(chunk_amount);  // Second shift position indicators -- marks transition chunk

        // Result vector
        std::vector<TYPE> y_chunks(chunk_amount);  // Final result chunks

        // Sign extension variables
        TYPE sign_bit;          // Sign bit of input a
        TYPE transition_chunk;  // Transition chunk for sign extension
        TYPE lower_chunk_bits;  // Lower 15 bits of the highest chunk
        TYPE lower_bits_range;  // Range check for lower bits


        // PART 1: computing the opcode and splitting values in chunks
        if constexpr (stage == GenerationStage::ASSIGNMENT) {
            // Extract input values from stack
            zkevm_word_type input_b = current_state.stack_top();    // Shift amount
            zkevm_word_type a = current_state.stack_top(1);         // Value to shift

            // Calculate shift and result
            // any shift of 256 bits or more is equivalent
            // to a 255 (NB! not 256) bit shift, which leaves us with just the sign bit
            int shift = (input_b < 256) ? int(input_b) : 255;
            zkevm_word_type r = a >> shift;         // Shifted result
            zkevm_word_type sign_value = a >> 255;  // Sign bit
            sign_bit = sign_value;
            zkevm_word_type mask = wrapping_sub(0, sign_value)
                                   << (256 - shift);  // Sign extension mask
            zkevm_word_type result = r + mask;        // Final result

            zkevm_word_type b = zkevm_word_type(1)
                                << shift;             // Power of 2 for shift (shift < 256 => b != 0)

            zkevm_word_type q = a % b;  // Division remainder -- this results in the shift least significant bits of a,
                                        // i.e. those that will disappear as a result of the shift operation.
            // Now we have a = r * b + q
            zkevm_word_type v = wrapping_sub(q, b);   // Difference v = q-b
            // To prove that q < b, we'll show that v + b = q + 2^256 (i.e. there is always a carry)

            // Convert to field elements
            input_b_chunks = zkevm_word_to_field_element<FieldType>(input_b);
            a_chunks = zkevm_word_to_field_element<FieldType>(a);
            a_chunks15_copy1 = a_chunks[15];
            b_chunks = zkevm_word_to_field_element<FieldType>(b);
            b_chunks_copy1 = zkevm_word_to_field_element<FieldType>(b);
            b_chunks_copy2 = zkevm_word_to_field_element<FieldType>(b);
            r_chunks = zkevm_word_to_field_element<FieldType>(r);
            r_chunks_copy1 = zkevm_word_to_field_element<FieldType>(r);
            r_chunks_copy2 = zkevm_word_to_field_element<FieldType>(r);
            q_chunks = zkevm_word_to_field_element<FieldType>(q);
            v_chunks = zkevm_word_to_field_element<FieldType>(v);
            y_chunks = zkevm_word_to_field_element<FieldType>(result);

            // We also split b in 8-bit chunks to multiply without overflow
            // (16-bit value) * (8-bit value)
            b8_chunks = zkevm_word_to_field_element_flexible<FieldType>(b, 32, 8);

            // Decompose shift amount
            shift_value = shift;
            shift_lower = shift % 16;
            shift_upper = shift / 16;

            input_b0_lower = (input_b % 256);
            input_b0_upper = (input_b % 65536) / 256;
            upper_inverse = input_b0_upper.is_zero() ? 0 : input_b0_upper.inversed();
        }

        // Some values are copied around to satisfy the limitation of three adjacent rows per constraint
        // We enforce equality between copied values
        for (std::size_t i = 0; i < chunk_amount; i++) {
            allocate(input_b_chunks[i], i, 8);
            allocate(q_chunks[i], i + chunk_amount, 5);
            allocate(v_chunks[i], i + chunk_amount, 7);

            allocate(a_chunks[i], i, 5);

            allocate(r_chunks[i], i + 2 * chunk_amount, 4);
            allocate(r_chunks_copy1[i], i + 2 * chunk_amount, 6);
            allocate(r_chunks_copy2[i], i + chunk_amount, 8);
            constrain(r_chunks[i] - r_chunks_copy1[i]);
            constrain(r_chunks_copy1[i] - r_chunks_copy2[i]);

            allocate(b_chunks[i], i + 2 * chunk_amount, 3);
            allocate(b_chunks_copy1[i], i + 2 * chunk_amount, 5);
            allocate(b_chunks_copy2[i], i + 2 * chunk_amount, 7);
            constrain(b_chunks[i] - b_chunks_copy1[i]);
            constrain(b_chunks_copy1[i] - b_chunks_copy2[i]);
        }
        allocate(a_chunks15_copy1, 15, 7);
        constrain(a_chunks[15] - a_chunks15_copy1);

        for (std::size_t i = 0; i < chunk_8_amount; i++) {
            allocate(b8_chunks[i], i, 2);
            // Range checks are by default for 16 bits, so we adjust accordingly
            b8_chunks_check[i] = b8_chunks[i] * 256;
            allocate(b8_chunks_check[i], i, 0);
        }

        allocate(input_b0_lower, 0, 9);
        allocate(input_b0_upper, 1, 9);
        input_b0_lower_check = input_b0_lower * 256;
        input_b0_upper_check = input_b0_upper * 256;
        allocate(input_b0_lower_check, 2, 9);
        allocate(input_b0_upper_check, 3, 9);
        allocate(upper_inverse, 32, 8);

        // Ensure consistency between b_chunks and b8_chunks
        for (std::size_t i = 0; i < chunk_amount; i++) {
            constrain(b_chunks[i] - b8_chunks[2 * i] - b8_chunks[2 * i + 1] * 256);
        }


        // PART 2: ensuring that r*b + q - a == 0
        // mul == r*b (mod 2^256)
        // NOTE: only one of b_chunks[i] is non-zero. Maybe we can simplify this and not store all multiplication carries.
        for (std::size_t i = 0; i < chunk_8_amount; i++) {
            mul8_carryless_chunks[i] = carryless_mul(r_chunks, b8_chunks, i);
            TYPE prev_carry = (i > 0) ? mul8_carries[i - 1] : 0;
            if constexpr (stage == GenerationStage::ASSIGNMENT) {
                auto mask8 = (1 << 8) - 1;
                mul8_chunks[i] = (mul8_carryless_chunks[i] + prev_carry).to_integral() & mask8;
                mul8_carries[i] = (mul8_carryless_chunks[i] + prev_carry).to_integral() >> 8;
                BOOST_ASSERT(mul8_carryless_chunks[i] + prev_carry == mul8_chunks[i] + 256 * mul8_carries[i]);
            }
            allocate(mul8_chunks[i], i, 3);
            mul8_chunk_check[i] = mul8_chunks[i] * 256;
            allocate(mul8_carries[i], i, 4);
            mul8_carries_check[i] = mul8_carries[i] * 2;// Note that this bound only works because only one of the chunks of b is non-zero. In general, it would be a bit higher
            allocate(mul8_chunk_check[i], i, 1);
            allocate(mul8_carries_check[i], i, 6);
            constrain(mul8_carryless_chunks[i] + prev_carry - mul8_chunks[i] - mul8_carries[i] * 256);
        }

        // To extend the result modulo 2^256 to the integers, we check that all higher-order carryless chunks are 0.
        // Note the -2 in the index range. This is because the highest-order non-zero term is
        // r_chunks[15] * b8_chunks[30] * 2^(8 * 61).
        // The terms corresponding to chunk_index = 62 and 63 are 0, so we skip them to avoid empty constraints.
        for (std::size_t i = 0; i < chunk_8_amount - 2; i++) {
            mul8_carryless_chunks_high[i] = carryless_mul(r_chunks, b8_chunks, i + chunk_8_amount);
            constrain(mul8_carryless_chunks_high[i]);
        }

        // mul + q - a == 0
        // Normally, for independent mul, q, a, we would need to separate the carryless chunks into carries and strict 16-bit chunks, and then check that all 16-bit chunks are 0.
        // However, in this case, recall that we have:
        // r = a >> shift
        // b = 2^shift
        // q = a % b = a & (mask of shift 1's)
        // so, for the ith bit of a = r*b + q, either:
        //  - the ith bit r*b is zero (if i <= shift), or
        //  - the ith bit of q is zero (if i > shift).
        // Due to this no overlap situation, the operation generates no carries.
        // Thus, checking that the strict 16-bit chunks are 0 is equivalent to checking that the carryless constructs are 0.
        // Therefore, we don't need to separate the carries from the strict 16-bit chunks.
        for (std::size_t i = 0; i < chunk_amount; i++) {
            construct_carryless_chunks[i] = carryless_construct(mul8_chunks, q_chunks, a_chunks, i);
            constrain(construct_carryless_chunks[i]);
        }

        // Carry propagation constraints for the v + b == q + 2^256 equality
        for (std::size_t i = 0; i < chunk_amount - 1; i++) {
            if constexpr (stage == GenerationStage::ASSIGNMENT) {
                TYPE prev_carry = (i > 0) ? add_carries[i-1] : 0;
                add_carries[i] = (v_chunks[i] + b_chunks_copy1[i] + prev_carry).to_integral() >> 16;
            }
            allocate(add_carries[i], i, 7);
            constrain(add_carries[i] * (1 - add_carries[i]));
        }

        for (std::size_t i = 0; i < chunk_amount; i++) {
            TYPE prev_carry = (i > 0) ? add_carries[i - 1] : 0;
            TYPE current_carry = (i < chunk_amount - 1) ? add_carries[i] : 1; // Force the last carry to be 1
            constrain(v_chunks[i] + b_chunks_copy1[i] + prev_carry - q_chunks[i] - current_carry * two_16);
        }


        // PART 3: the shift (without sign extension)
        // input_b_chunks[0] is decomposed into input_b0_lower, input_b0_upper
        constrain(input_b_chunks[0] - input_b0_lower - 256 * input_b0_upper);

        // allocation and decomposition of shift_value
        allocate(shift_value, 37, 8);
        allocate(shift_lower, 4, 9);
        allocate(shift_upper, 5, 9);

        // shift_lower and shift_upper are 4-bit values
        shift_lower_check = 4096 * shift_lower;
        shift_upper_check = 4096 * shift_upper;
        allocate(shift_lower_check, 6, 9);
        allocate(shift_upper_check, 7, 9);

        // shift_value is decomposed into shift_lower, shift_higher
        constrain(shift_value - shift_lower - 16 * shift_upper);

        // b_partial_sum is the sum of all 16-bit chunks of input_b, except for the least significant chunk.
        // We use b_partial_sum as an aggregate way of checking whether all of these chunks are 0.
        // This works because it is a sum of non-negative values that cannot overflow.
        // b_partial_sum < (chunk_amount-1) * max_i {input_b_chunks[i]} < 2^4 * 2^16 == 2^20.

        // Calculate partial sum and inverse
        input_b_partial_sum = 0;
        for (std::size_t i = 1; i < chunk_amount; i++) {
             input_b_partial_sum += input_b_chunks[i];
        }

        if constexpr (stage == GenerationStage::ASSIGNMENT) {
            sum_inverse_partial = input_b_partial_sum.is_zero() ? 0 : input_b_partial_sum.inversed();
        }

        // sum_inverse_partial is the inverse of b_partial_sum, unless this is zero
        allocate(sum_inverse_partial, 34, 8);
        // partial_sum_check == 0  <=>  input_b_partial_sum > 0,
        // partial_sum_check == 1  <=>  input_b_partial_sum == 0.
        TYPE partial_sum_check = 1 - input_b_partial_sum * sum_inverse_partial;
        allocate(partial_sum_check, 35, 8);
        // either input_b_partial_sum == 0 (i.e. all chunks except for the least significant are 0), or partial_sum_check == 0
        constrain(input_b_partial_sum * partial_sum_check);

        // connection of shift_value with input_b_chunks[0]
        // is_shift_large == 0  <=>  input_b > 255
        // is_shift_large == 1  <=>  input_b <= 255

        // the shift is large (> 255 bits) if one of these conditions hold:
        //  - b0_upper has an inverse, and thus is non-zero.
        //  - partial_sum_check == 0, which means that some 16-bit chunk of input_b beyond the least significant one is non-zero.
        is_shift_large = (1 - input_b0_upper * upper_inverse) * partial_sum_check; // 0 if shift >= 256, 1 otherwise
        allocate(is_shift_large, 36, 8);

        // Ensure that shift_value matches input_b, or 255 in the case of a large shift.
        constrain( (1 - is_shift_large) * (shift_value - 255) + is_shift_large * (shift_value - input_b_chunks[0]) );

        // indicator functions
        for (std::size_t i = 0; i < chunk_amount; i++) {
            if constexpr (stage == GenerationStage::ASSIGNMENT) {
                // is zero when shift_lower = i.
                indic_1[i] = (shift_lower - i).is_zero()
                                    ? 0
                                    : (shift_lower - i).inversed();
                // same as above, but for shift_upper
                indic_2[i] = (shift_upper - i).is_zero()
                                    ? 0
                                    : (shift_upper - i).inversed();
            }
            allocate(indic_1[i], i + 2 * chunk_amount, 10);
            allocate(indic_2[i], i + 2 * chunk_amount, 9);
            // indic_1[i] == 0                        =>  shift_lower == i
            // indic_1[i] == (shift_lower - i)^(-1)  <=>  shift_lower != i
            // same for indic_2.
            constrain((shift_lower - i) * (1 - (shift_lower - i) * indic_1[i]));
            constrain((shift_upper - i) * (1 - (shift_upper - i) * indic_2[i]));
        }

        // Calculate power series for shift_lower.
        // We will place this in the correct chunk to recover b == 2^(shift_value)
        shift_lower_power = 0;
        unsigned int pow = 1;
        // shift_lower_power == 2^(shift_lower)
        for (std::size_t i = 0; i < chunk_amount; i++) {
            shift_lower_power += (1 - (shift_lower - i) * indic_1[i]) * pow;
            pow *= 2;
        }
        allocate(shift_lower_power, 38, 8);

        // connection between b_chunks and input_b_chunks (implicitly via shift_lower & shift_upper)
        // Recall that b is the actual shift performed, in power-of-2 form.
        for (std::size_t i = 0; i < chunk_amount; i++) {
            // b_chunks[i] == shift_lower_power * (1 - (shift_upper - i) * indic_2[i])
            // shift_upper == i  <=>  b_chunks[i] == shift_lower_power == 2^(shift_lower)
            // shift_upper != i  <=>  b_chunks[i] == 0
            constrain(b_chunks_copy2[i] - shift_lower_power * (1 - (shift_upper - i) * indic_2[i]));
        }

        // Example of the above: 167-bit shift.
        // 167 == 10 * 2^4 + 7
        // shift_lower == 7
        // shift_upper == 10
        // indic_1[7]  == 0, and indic_1[i] == (shift_lower - 7)^(-1)  for all other i.
        // indic_2[10] == 0, and indic_2[i] == (shift_upper - 10)^(-1) for all other i.
        // shift_lower_power == 2^7
        // b_chunks[10] == 2^7, and b_chunks[i] = 0 for all other i.
        // That is, b == 2^7..(followed by 10 chunks of 16 zeros) == 2^7 * 2^(10*16) == 2^167.

        // PART 4: sign extension
        for (std::size_t i = 0; i < chunk_amount; i++) {
            allocate(y_chunks[i], i + chunk_amount, 9);
            res[i] = y_chunks[i];
        }

        allocate(sign_bit, 41, 8);
        constrain(sign_bit * (1 - sign_bit));  // Ensure sign_bit is 0 or 1
        lower_chunk_bits = a_chunks15_copy1 - sign_bit * two_15;
        allocate(lower_chunk_bits, 8, 9);
        // Ensure that the highest chunk (without the sign bit) is 15-bits.
        lower_bits_range = 2 * lower_chunk_bits;
        allocate(lower_bits_range, 9, 9);

        // Sign extension logic
        // is_sign[i] signals whether a chunk should be completely filled with sign bits
        // is_transition[i] signals whether a chunk has some sign bits and some "meaningful" bits
        std::vector<TYPE> is_transition(chunk_amount);
        std::vector<TYPE> is_sign(chunk_amount);
        for (std::size_t i = 0; i < chunk_amount; i++) {
            // To know in which chunk the transition happens, we just need to look at shift_upper
            // Small shift means the transition happens in most significant chunks, and vice versa. Hence the index reversal.
            // indic_2[i_inv] == 0                           => shift_upper == i_inv  => is_transition[i] == 1
            // indic_2[i_inv] == (shift_upper - i_inv)^(-1)  => shift_upper != i     => is_transition[i] == 0
            size_t i_inv = chunk_amount - 1 - i;
            is_transition[i] = (1 - (shift_upper - i_inv) * indic_2[i_inv]);
            // Let i* be the unique index such that is_transition[i*] = 1.
            // is_sign[i] == {
            //      0 <=> i <= i*
            //      1 <=> i > i*
            // }
            for (std::size_t j = i + 1; j < chunk_amount; j++) {
                is_sign[j] += is_transition[i];
            }
        }

        // Calculate transition chunk
        // indic_2[i_inv] = (shift_upper - i_inv)^(-1)  => transition_chunk = r_chunks[i] + (sign mask -- more on this below)
        transition_chunk = 0;
        // shift_upper determines which chunk is the transition chunk
        for (std::size_t i = 0; i < chunk_amount; i++) {
            size_t i_inv = chunk_amount - 1 - i;
            transition_chunk +=
                r_chunks_copy2[i] * (1 - (shift_upper - i_inv) * indic_2[i_inv]);
        }
        // shift_lower determines which exact mask should be added (how many sign bits)
        for (std::size_t i = 0; i < chunk_size; i++) {
            unsigned int mask = ((1 << i) - 1) << (chunk_size - i); // 11...1100...00 = 1{i}0{chunk_size - i}
            transition_chunk +=
                (1 - (shift_lower - i) * indic_1[i]) * mask * sign_bit;
        }
        allocate(transition_chunk, 39, 8);

        // connect the result (y_chunks) with r_chunks and sign_bit
        for (std::size_t i = 0; i < chunk_amount; i++) {
            constrain(
                // Recall that y = r + sign extension. We adjust the chunks of y accordingly.
                // is_sign[i] == 1          => y_chunks[i] == 0x0000 or 0xFFFF (depending on sign_bit)
                // is_transition[i] == 1    => y_chunks[i] == transition
                // both of the above are 0  => y_chunks[i] == r_chunks[i]
                y_chunks[i] - is_sign[i] * sign_bit * 0xFFFF  // Sign fill
                - is_transition[i] * transition_chunk  // Transition chunk
                - (1 - is_sign[i] - is_transition[i]) * r_chunks_copy2[i]);  // Original chunks
        }

        if constexpr (stage == GenerationStage::CONSTRAINTS) {
            // State transition constraints
            // The arguments for pc, gas, stack_size, memory-size and rw_counter correspond to number_of_rows - 1
            constrain(current_state.pc_next() - current_state.pc(10) -
                      1);  // PC increment
            constrain(current_state.gas(10) - current_state.gas_next() -
                      3);  // Gas cost
            constrain(current_state.stack_size(10) -
                      current_state.stack_size_next() - 1);  // Stack pop
            constrain(current_state.memory_size(10) -
                      current_state.memory_size_next());  // Memory unchanged
            constrain(current_state.rw_counter_next() -
                      current_state.rw_counter(10) - 3);  // RW counter

            // Stack lookup constraints
            // The arguments for call_id, stack_size and rw_counter corresponds to the indices of the rows that contains the data read from the rw_table
            lookup(rw_256_table<FieldType, stage>::stack_16_bit_lookup_reversed(
                current_state.call_id(8),
                current_state.stack_size(8) - 1,
                current_state.rw_counter(8),
                TYPE(0),// is_write
                input_b_chunks
            ), "zkevm_rw_256");
            lookup(rw_256_table<FieldType, stage>::stack_16_bit_lookup_reversed(
                current_state.call_id(5),
                current_state.stack_size(5) - 2,
                current_state.rw_counter(5) + 1,
                TYPE(0),// is_write
                a_chunks
            ), "zkevm_rw_256");
            lookup(rw_256_table<FieldType, stage>::stack_16_bit_lookup_reversed(
                current_state.call_id(9),
                current_state.stack_size(9) - 2,
                current_state.rw_counter(9) + 2,
                TYPE(1),// is_write
                res
            ), "zkevm_rw_256");
        }
    }
};

template<typename FieldType>
class zkevm_sar_operation : public opcode_abstract<FieldType> {
  public:
    virtual void fill_context(
        typename generic_component<
            FieldType, GenerationStage::ASSIGNMENT>::context_type &context,
        const opcode_input_type<FieldType, GenerationStage::ASSIGNMENT>
            &current_state) override {
        zkevm_sar_bbf<FieldType, GenerationStage::ASSIGNMENT> bbf_obj(
            context, current_state);
    }
    virtual void fill_context(
        typename generic_component<
            FieldType, GenerationStage::CONSTRAINTS>::context_type &context,
        const opcode_input_type<FieldType, GenerationStage::CONSTRAINTS>
            &current_state) override {
        zkevm_sar_bbf<FieldType, GenerationStage::CONSTRAINTS> bbf_obj(
            context, current_state);
    }
    virtual std::size_t rows_amount() override { return 11; }
};
}  // namespace nil::blueprint::bbf

