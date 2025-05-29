//---------------------------------------------------------------------------//
// Copyright (c) 2024 Alexey Yashunsky <a.yashunsky@nil.foundation>
// Copyright (c) 2024 Antoine Cyr <antoine.cyr@nil.foundation>
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
#include <iostream>
#include <nil/blueprint/zkevm_bbf/big_field/opcodes/abstract_opcode.hpp>
#include <numeric>

namespace nil::blueprint::bbf::zkevm_big_field{
    template<typename FieldType, GenerationStage stage>
    class zkevm_sar_bbf : public generic_component<FieldType, stage> {
        using generic_component<FieldType, stage>::allocate;
        using generic_component<FieldType, stage>::copy_constrain;
        using generic_component<FieldType, stage>::constrain;
        using generic_component<FieldType, stage>::lookup;
        using generic_component<FieldType, stage>::lookup_table;

        using value_type = typename FieldType::value_type;

        constexpr static const std::size_t chunk_amount = 16;
        constexpr static const std::size_t carry_amount = 16 / 3 + 1;
        constexpr static const value_type two_15 = 32768;
        constexpr static const value_type two_16 = 65536;
        constexpr static const value_type two_32 = 4294967296;
        constexpr static const value_type two_48 = 281474976710656;
        constexpr static const value_type two_64 = 0x10000000000000000_big_uint254;
        constexpr static const value_type two_128 =
            0x100000000000000000000000000000000_big_uint254;
        constexpr static const value_type two_192 =
            0x1000000000000000000000000000000000000000000000000_big_uint254;

    public:
        using typename generic_component<FieldType, stage>::TYPE;
        using typename generic_component<FieldType, stage>::context_type;

        template<typename T, typename V = T>
        T chunk_sum_64(const std::vector<V> &chunks,
                    const unsigned char chunk_idx) const {
            BOOST_ASSERT(chunk_idx < 4);
            return chunks[4 * chunk_idx] + chunks[4 * chunk_idx + 1] * two_16 +
                chunks[4 * chunk_idx + 2] * two_32 +
                chunks[4 * chunk_idx + 3] * two_48;
        }

        template<typename T>
        T first_carryless_construct(const std::vector<T> &a_64_chunks,
                                    const std::vector<T> &b_64_chunks,
                                    const std::vector<T> &r_64_chunks,
                                    const std::vector<T> &q_64_chunks) const {
            return r_64_chunks[0] * b_64_chunks[0] + q_64_chunks[0] +
                two_64 * (r_64_chunks[0] * b_64_chunks[1] +
                            r_64_chunks[1] * b_64_chunks[0] + q_64_chunks[1]) -
                a_64_chunks[0] - two_64 * a_64_chunks[1];
        }

        template<typename T>
        T second_carryless_construct(const std::vector<T> &a_64_chunks,
                                    const std::vector<T> &b_64_chunks,
                                    const std::vector<T> &r_64_chunks,
                                    const std::vector<T> &q_64_chunks) const {
            return (r_64_chunks[0] * b_64_chunks[2] +
                    r_64_chunks[1] * b_64_chunks[1] +
                    r_64_chunks[2] * b_64_chunks[0] + q_64_chunks[2] -
                    a_64_chunks[2]) +
                two_64 * (r_64_chunks[0] * b_64_chunks[3] +
                            r_64_chunks[1] * b_64_chunks[2] +
                            r_64_chunks[2] * b_64_chunks[1] +
                            r_64_chunks[3] * b_64_chunks[0] + q_64_chunks[3] -
                            a_64_chunks[3]);
        }

        template<typename T>
        T third_carryless_construct(const std::vector<T> &b_64_chunks,
                                    const std::vector<T> &r_64_chunks) const {
            return (r_64_chunks[1] * b_64_chunks[3] +
                    r_64_chunks[2] * b_64_chunks[2] +
                    r_64_chunks[3] * b_64_chunks[1]) +
                two_64 * (r_64_chunks[2] * b_64_chunks[3] +
                            r_64_chunks[3] * b_64_chunks[2]);
        }

        TYPE carry_on_addition_constraint(TYPE a_0, TYPE a_1, TYPE a_2, TYPE b_0,
                                        TYPE b_1, TYPE b_2, TYPE r_0, TYPE r_1,
                                        TYPE r_2, TYPE last_carry,
                                        TYPE result_carry,
                                        bool first_constraint = false) {
            TYPE res;
            if (first_constraint) {
                // no last carry for first constraint
                res = (a_0 + b_0) + (a_1 + b_1) * two_16 + (a_2 + b_2) * two_32 -
                    r_0 - r_1 * two_16 - r_2 * two_32 - result_carry * two_48;
            } else {
                res = last_carry + (a_0 + b_0) + (a_1 + b_1) * two_16 +
                    (a_2 + b_2) * two_32 - r_0 - r_1 * two_16 - r_2 * two_32 -
                    result_carry * two_48;
            }
            return res;
        };
        TYPE last_carry_on_addition_constraint(TYPE a_0, TYPE b_0, TYPE r_0,
                                            TYPE last_carry,
                                            TYPE result_carry) {
            TYPE res = (last_carry + a_0 + b_0 - r_0 - result_carry * two_16);
            return res;
        };

        std::vector<TYPE> res;

    public:
        zkevm_sar_bbf(context_type &context_object,
                    const opcode_input_type<FieldType, stage> &current_state)
            : generic_component<FieldType, stage>(context_object, false),
            res(chunk_amount) {
            TYPE first_carryless;
            TYPE second_carryless;
            TYPE third_carryless;

            // Variables for shift amount decomposition and range checks
            TYPE shift_value;  // adjusted shift value, set to 255 if input_b > 255
            TYPE shift_lower;  // Lower 4 bits of shift amount (shift % 16)
            TYPE shift_upper;  // Upper 4 bits of shift amount (shift / 16)
            TYPE b0_lower;   // Lower bits of input_b[0] (b % 256)
            TYPE b0_upper;   // Upper bits of input_b[0] (b % 65536 / 256)
            TYPE shift_lower_check;  // Range check for shift_lower
            TYPE shift_upper_check;  // Range check for shift_upper
            TYPE b0_lower_check;   // Range check for b0_lower
            TYPE b0_upper_check;   // Range check for b0_upper

            // Inverse and zero check variables
            TYPE upper_inverse;        // Inverse of b0_upper
            TYPE b_partial_sum;        // Partial sum of input_b chunks
            TYPE sum_inverse_partial;  // Inverse of partial sum of input_b chunks
            TYPE is_shift_large;       // Indicates if shift >= 256
            TYPE shift_power;          // Power of 2 corresponding to shift

            // 64-bit chunk vectors
            std::vector<TYPE> a_64_chunks(4);  // Input a in 64-bit chunks
            std::vector<TYPE> b_64_chunks(4);  // Shift amount b in 64-bit chunks
            std::vector<TYPE> r_64_chunks(4);  // Result r in 64-bit chunks
            std::vector<TYPE> q_64_chunks(4);  // Quotient q in 64-bit chunks

            // Carry and intermediate result vectors
            std::vector<TYPE> c_1_chunks(4);  // First carry chunks
            TYPE c_1;                         // First carry value
            TYPE c_2;                         // Second carry value
            TYPE c_1_64;                      // First carry in 64-bit form

            // 16-bit chunk vectors
            std::vector<TYPE> input_b_chunks(chunk_amount);  // Input shift amount chunks
            std::vector<TYPE> a_chunks(chunk_amount);  // Input value chunks
            std::vector<TYPE> b_chunks(chunk_amount);  // Shift amount chunks
            std::vector<TYPE> r_chunks(chunk_amount);  // Result chunks
            std::vector<TYPE> q_chunks(chunk_amount);  // Quotient chunks
            std::vector<TYPE> v_chunks(chunk_amount);  // Difference chunks (q - b)

            // Indicator vectors for shift position
            std::vector<TYPE> indic_1(chunk_amount);  // First shift position indicators
            std::vector<TYPE> indic_2(chunk_amount);  // Second shift position indicators

            // Result vector
            std::vector<TYPE> y_chunks(chunk_amount);  // Final result chunks

            // Sign extension variables
            TYPE sign_bit;          // Sign bit of input a
            TYPE transition_chunk;  // Transition chunk for sign extension
            TYPE lower_chunk_bits;  // Lower bits of the highest chunk
            TYPE lower_bits_range;  // Range check for lower bits

            TYPE carry[carry_amount + 1];  // Carry bits array

            if constexpr (stage == GenerationStage::ASSIGNMENT) {
                // Extract input values from stack
                zkevm_word_type input_b = current_state.stack_top(); // Shift amount
                zkevm_word_type a = current_state.stack_top(1);  // Value to shift

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
                zkevm_word_type q = a % b;  // Quotient
                // Now we have a = r * b + q
                zkevm_word_type v = wrapping_sub(q, b);   // Difference v = q-b
                // To prove that q < b, we'll show that v + b = q + 2^256 (i.e. there is always a carry)

                // Convert to field elements
                input_b_chunks = zkevm_word_to_field_element<FieldType>(input_b);
                a_chunks = zkevm_word_to_field_element<FieldType>(a);
                b_chunks = zkevm_word_to_field_element<FieldType>(b);
                r_chunks = zkevm_word_to_field_element<FieldType>(r);
                q_chunks = zkevm_word_to_field_element<FieldType>(q);
                v_chunks = zkevm_word_to_field_element<FieldType>(v);
                y_chunks = zkevm_word_to_field_element<FieldType>(result);

                // Decompose shift amount
                shift_value = shift;
                shift_lower = shift % 16;
                shift_upper = shift / 16;

                b0_lower = (input_b % 256);
                b0_upper = (input_b % 65536) / 256;
                upper_inverse = b0_upper.is_zero() ? 0 : b0_upper.inversed();

            }
            // Allocate chunk vectors
            for (std::size_t i = 0; i < chunk_amount; i++) {
                allocate(input_b_chunks[i], i, 2);
                allocate(r_chunks[i], i + chunk_amount, 2);
                allocate(a_chunks[i], i, 1);
                allocate(b_chunks[i], i + chunk_amount, 1);
                allocate(q_chunks[i], i, 0);
                allocate(v_chunks[i], i + chunk_amount, 0);
            }

            // note that we don't assign 64-chunks for a/b, as we can build
            // them from 16-chunks with constraints under the same logic we
            // only assign the 16 - bit Convert 16-bit chunks to 64-bit chunks
            for (std::size_t i = 0; i < 4; i++) {
                a_64_chunks[i] = chunk_sum_64<TYPE>(a_chunks, i);
                b_64_chunks[i] = chunk_sum_64<TYPE>(b_chunks, i);
                r_64_chunks[i] = chunk_sum_64<TYPE>(r_chunks, i);
                q_64_chunks[i] = chunk_sum_64<TYPE>(q_chunks, i);
            }
            // decomposition of input_b_chunks[0], upper_inverse = 1 / b0_upper
            allocate(b0_lower, 10, 3);
            allocate(b0_upper, 11, 3);
            allocate(upper_inverse, 40, 1);

            b0_lower_check = 256 * b0_lower;
            b0_upper_check = 256 * b0_upper;
            allocate(b0_lower_check, 2, 3);
            allocate(b0_upper_check, 3, 3);

            constrain(input_b_chunks[0] - b0_lower - 256 * b0_upper);
            constrain(b0_upper * (1 - b0_upper * upper_inverse));

            // allocation and decomposition of shift_value
            allocate(shift_value, 32, 1);
            allocate(shift_lower, 8, 3);
            allocate(shift_upper, 9, 3);

            shift_lower_check = 4096 * shift_lower;
            shift_upper_check = 4096 * shift_upper;
            allocate(shift_lower_check, 0, 3);
            allocate(shift_upper_check, 1, 3);

            constrain(shift_value - shift_lower - 16 * shift_upper);

            // Calculate partial sum and inverse
            b_partial_sum = 0;
            for (std::size_t i = 1; i < chunk_amount; i++) {
                b_partial_sum += input_b_chunks[i];
            }

            if constexpr (stage == GenerationStage::ASSIGNMENT) {
                sum_inverse_partial = b_partial_sum.is_zero() ? 0 : b_partial_sum.inversed();
            }

            allocate(sum_inverse_partial, 41, 1);
            TYPE partial_sum_check = 1 - b_partial_sum * sum_inverse_partial;
            allocate(partial_sum_check, 42, 1);
            constrain(b_partial_sum * partial_sum_check);

            // connection of shift_value with input_b_chunks[0]
            is_shift_large = (1 - b0_upper * upper_inverse) * partial_sum_check; // 0 if shift >= 256, 1 otherwise
            allocate(is_shift_large, 44, 1);

            constrain( (1-is_shift_large) * (shift_value - 255) + is_shift_large*(shift_value - input_b_chunks[0]) );

            // indicator functions
            for (std::size_t i = 0; i < chunk_amount; i++) {
                if constexpr (stage == GenerationStage::ASSIGNMENT) {
                    indic_1[i] = (shift_lower - i).is_zero()
                                    ? 0
                                    : (shift_lower - i).inversed();
                    indic_2[i] = (shift_upper - i).is_zero()
                                    ? 0
                                    : (shift_upper - i).inversed();
                }
                allocate(indic_1[i], i + 2 * chunk_amount, 2);
                allocate(indic_2[i], i + 2 * chunk_amount, 3);
                constrain((shift_lower - i) * (1 - (shift_lower - i) * indic_1[i]));
                constrain((shift_upper - i) * (1 - (shift_upper - i) * indic_2[i]));
            }

            // Calculate power series for shift
            shift_power = 0;
            unsigned int pow = 1;
            for (std::size_t i = 0; i < chunk_amount; i++) {
                shift_power += (1 - (shift_lower - i) * indic_1[i]) * pow;
                pow *= 2;
            }
            allocate(shift_power, 12, 3);

            // connection between b_chunks and input_b_chunks (implicitly via shift_lower & shift_upper)
            for (std::size_t i = 0; i < chunk_amount; i++) {
                constrain(b_chunks[i] - shift_power * (1 - (shift_upper - i) * indic_2[i]));
            }

            // Set up carryless constraints
            first_carryless = first_carryless_construct<TYPE>(
                a_64_chunks, b_64_chunks, r_64_chunks, q_64_chunks);
            second_carryless = second_carryless_construct<TYPE>(
                a_64_chunks, b_64_chunks, r_64_chunks, q_64_chunks);
            third_carryless =
                third_carryless_construct<TYPE>(b_64_chunks, r_64_chunks);

            if constexpr (stage == GenerationStage::ASSIGNMENT) {
                // Calculate carries for first row
                auto first_row_carries = first_carryless.to_integral() >> 128;
                c_1 = value_type(first_row_carries & (two_64 - 1).to_integral());
                c_2 = value_type(first_row_carries >> 64);
                BOOST_ASSERT(first_carryless - c_1 * two_128 - c_2 * two_192 == 0);
                c_1_chunks = chunk_64_to_16<FieldType>(c_1);

                // Calculate carry bits
                carry[0] = 0;
                for (std::size_t i = 0; i < carry_amount - 1; i++) {
                    carry[i + 1] =
                        (carry[i] + b_chunks[3 * i] + v_chunks[3 * i] +
                        (b_chunks[3 * i + 1] + v_chunks[3 * i + 1]) * two_16 +
                        (b_chunks[3 * i + 2] + v_chunks[3 * i + 2]) * two_32) >=
                        two_48;
                }
                carry[carry_amount] =
                    (carry[carry_amount - 1] + b_chunks[3 * (carry_amount - 1)] +
                    v_chunks[3 * (carry_amount - 1)]) >= two_16;
                BOOST_ASSERT(carry[carry_amount] == 1); // should always be 1 for q < b
            }

            for (std::size_t i = 0; i < 4; i++) {
                allocate(c_1_chunks[i], 4 + i, 3);
            }
            c_1_64 = chunk_sum_64<TYPE>(c_1_chunks, 0);
            allocate(c_1_64, 43, 1);
            allocate(c_2, 39, 1);

            // Carryless constraints
            constrain(first_carryless - c_1_64 * two_128 - c_2 * two_192);
            constrain(second_carryless + c_1_64 + c_2 * two_64);
            constrain(c_2 * (c_2 - 1));
            constrain(third_carryless);
            constrain(b_64_chunks[3] * r_64_chunks[3]);

            // Carry propagation constraints for the v + b = q + 2^256 equality
            for (std::size_t i = 0; i < carry_amount - 1; i++) {
                allocate(carry[i + 1], 33 + i, 1);
                constrain(carry_on_addition_constraint(
                    b_chunks[3 * i], b_chunks[3 * i + 1], b_chunks[3 * i + 2],
                    v_chunks[3 * i], v_chunks[3 * i + 1], v_chunks[3 * i + 2],
                    q_chunks[3 * i], q_chunks[3 * i + 1], q_chunks[3 * i + 2],
                    carry[i], carry[i + 1], i == 0));
                constrain(carry[i + 1] * (1 - carry[i + 1]));
            }
            // allocate(carry[carry_amount], 38, 1);
            constrain(last_carry_on_addition_constraint(
                b_chunks[3 * (carry_amount - 1)],
                v_chunks[3 * (carry_amount - 1)],
                q_chunks[3 * (carry_amount - 1)], carry[carry_amount - 1],
                1)); // = carry[carry_amount]

            // Sign extension handling
            for (std::size_t i = 0; i < chunk_amount; i++) {
                allocate(y_chunks[i], i + chunk_amount, 3);
                res[i] = y_chunks[i];
            }

            allocate(sign_bit, 15, 3);
            constrain(sign_bit * (1 - sign_bit));  // Ensure sign_bit is 0 or 1
            lower_chunk_bits = a_chunks[15] - sign_bit * two_15;
            allocate(lower_chunk_bits, 14, 3);
            lower_bits_range = 2 * lower_chunk_bits;
            allocate(lower_bits_range, 13, 3);

            // Sign extension logic
            std::vector<TYPE> is_transition(chunk_amount);
            std::vector<TYPE> is_sign(chunk_amount);
            for (std::size_t i = 0; i < chunk_amount; i++) {
                size_t i_inv = chunk_amount - 1 - i;
                is_transition[i] = (1 - (shift_upper - i_inv) * indic_2[i_inv]);
                for (std::size_t j = i + 1; j < chunk_amount; j++) {
                    is_sign[j] += is_transition[i];
                }
            }

            // Calculate transition chunk
            transition_chunk = 0;
            for (std::size_t i = 0; i < chunk_amount; i++) {
                size_t i_inv = chunk_amount - 1 - i;
                transition_chunk +=
                    r_chunks[i] * (1 - (shift_upper - i_inv) * indic_2[i_inv]);
            }
            for (std::size_t i = 0; i < chunk_amount; i++) {
                unsigned int mask = ((1 << i) - 1) << (chunk_amount - i); // 11...1100...00 = 1{i}0{chunk_amount - i}
                transition_chunk +=
                    (1 - (shift_lower - i) * indic_1[i]) * mask * sign_bit;
            }
            allocate(transition_chunk, 38, 1);

            // connect the result (y_chunks) with r_chunks and sign_bit
            for (std::size_t i = 0; i < chunk_amount; i++) {
                constrain(
                    y_chunks[i] - is_sign[i] * sign_bit * 0xFFFF  // Sign fill
                    - is_transition[i] * transition_chunk  // Transition chunk
                    - (1 - is_sign[i] - is_transition[i]) * r_chunks[i]);  // Original chunks
            }

            // Convert to 128-bit chunks for stack operations
            auto A_128 = chunks16_to_chunks128_reversed<TYPE>(a_chunks);
            auto B_128 = chunks16_to_chunks128_reversed<TYPE>(input_b_chunks);
            auto Res_128 = chunks16_to_chunks128_reversed<TYPE>(res);

            TYPE A0, A1, B0, B1, Res0, Res1;
            A0 = A_128.first;
            A1 = A_128.second;
            B0 = B_128.first;
            B1 = B_128.second;
            Res0 = Res_128.first;
            Res1 = Res_128.second;

            if constexpr (stage == GenerationStage::CONSTRAINTS) {
                // State transition constraints
                constrain(current_state.pc_next() - current_state.pc(3) -
                        1);  // PC increment
                constrain(current_state.gas(3) - current_state.gas_next() -
                        3);  // Gas cost
                constrain(current_state.stack_size(3) -
                        current_state.stack_size_next() - 1);  // Stack pop
                constrain(current_state.memory_size(3) -
                        current_state.memory_size_next());  // Memory unchanged
                constrain(current_state.rw_counter_next() -
                        current_state.rw_counter(3) - 3);  // RW counter

                // Stack lookup constraints
                std::vector<TYPE> tmp;
                tmp = rw_table<FieldType, stage>::stack_lookup(
                    current_state.call_id(1), current_state.stack_size(1) - 1,
                    current_state.rw_counter(1), TYPE(0), B0, B1);
                lookup(tmp, "zkevm_rw");
                tmp = rw_table<FieldType, stage>::stack_lookup(
                    current_state.call_id(1), current_state.stack_size(1) - 2,
                    current_state.rw_counter(1) + 1, TYPE(0), A0, A1);
                lookup(tmp, "zkevm_rw");
                tmp = rw_table<FieldType, stage>::stack_lookup(
                    current_state.call_id(3), current_state.stack_size(3) - 2,
                    current_state.rw_counter(3) + 2, TYPE(1), Res0, Res1);
                lookup(tmp, "zkevm_rw");
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
        virtual std::size_t rows_amount() override { return 4; }
    };
}  // namespace nil::blueprint::bbf
