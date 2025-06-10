//---------------------------------------------------------------------------//
// Copyright (c) 2024 Dmitrii Tabalin <d.tabalin@nil.foundation>
// Copyright (c) 2024 Alexey Yashunsky <a.yashunsky@nil.foundation>
// Copyright (c) 2024 Antoine Cyr <antoine.cyr@nil.foundation>
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
#include <nil/blueprint/zkevm_bbf/small_field/opcodes/abstract_opcode.hpp>
#include <numeric>
#include <vector>

namespace nil::blueprint::bbf::zkevm_small_field{
    template<typename FieldType, GenerationStage stage>
    class zkevm_div_mod_bbf : generic_component<FieldType, stage> {
        using generic_component<FieldType, stage>::allocate;
        using generic_component<FieldType, stage>::copy_constrain;
        using generic_component<FieldType, stage>::constrain;
        using generic_component<FieldType, stage>::lookup;
        using generic_component<FieldType, stage>::lookup_table;
        using value_type = typename FieldType::value_type;

        constexpr static const std::size_t chunk_amount = 16;
        constexpr static const std::size_t chunk_8_amount = 32;
        constexpr static const value_type two_16 = 65536;

        public:
        using typename generic_component<FieldType, stage>::TYPE;
        using typename generic_component<FieldType, stage>::context_type;

        // Computes the terms of q*b with coefficient 2^(8 * chunk_index)
        TYPE carryless_mul(const std::vector<TYPE> &q8_chunks,
                                    const std::vector<TYPE> &b8_chunks,
                                    const unsigned char chunk_index) const {
            TYPE res = 0;
            for (int i = 0; i <= chunk_index; i++) {
                int j = chunk_index - i;
                if ((i < chunk_8_amount) && (j >= 0) && (j < chunk_8_amount)) {
                    res += q8_chunks[i] * b8_chunks[j];
                }
            }
            return res;
        }

        // Computes the terms of mul + r - a with coefficient 2^(16 * chunk_index)
        TYPE carryless_construct(const std::vector<TYPE> &mul_chunks,
                                    const std::vector<TYPE> &r_chunks,
                                    const std::vector<TYPE> &a_chunks,
                                    const unsigned char chunk_index) const {
            TYPE res = mul_chunks[chunk_index] + r_chunks[chunk_index] - a_chunks[chunk_index];
            return res;
        }

        // Counts the number of cross terms q8_chunks[i] * b8_chunks[j] involved in the i-th carryless chunk of
        // the multiplication q * b, where q, b < 2^256 and q*b < 2^256. This is useful for range-checking later.
        int count_cross_terms(const unsigned char chunk_index) const {
            // For unrelated q, b < 2^256, the result would be the amount of pairs (i, j) such that
            // i + j == chunk_index, for 0 <= i, j < chunk_8_amount.

            // However, because we have the bound q*b < 2^256, they cannot both have non-zero higher-order chunks.
            // The number of cross-terms is maximized when both are balanced around 2^128.
            // In this case, q8_chunks[i] == b8_chunks[i] == 0 for all i >= 16.
            int res = 0;
                for (int i = 0; i < 16; i++) {
                    int j = chunk_index - i;
                    if ((j >= 0) && (j < 16)) {
                        res += 1;
                }
            }
            return res;
        }

        // Given a carryless chunk of the multiplication q*b, we will separate it into an 8-bit
        // chunk and a carry, which contains whatever overflows 8 bits. This function computes
        // the maximal value of such carry, for accurate range-checking.
        int max_carry(const unsigned char chunk_index) const {
            // mul8_carryless_chunks[i] + prev_carry == mul8_chunks[i] + mul8_carries[i] * 256
            // To bound mul8_carries[i], we need to bound mul8_carryless_chunks[i] and prev_carry.
            // mul8_carryless_chunks[i] == (sum of some cross terms q8_chunks[i] * b8_chunks[j]).

            // The largest carries happen when both chunks in a cross-term are 2^8 - 1.
            int max_cross_term = 255 * 255;

            // mul8_carryless_chunks[i] <= (number of cross terms) * (cross term value)
            int number_of_cross_terms = count_cross_terms(chunk_index);

            // We now have enough to compute the bounds on mul8_carryless_chunks.
            int carryless_bound = 0;
            if (chunk_index < 32) {
                carryless_bound = number_of_cross_terms * max_cross_term;
            }

            // Finally, we also take into account the maximal value of the previous carry
            int prev_carry = (chunk_index > 0) ? max_carry(chunk_index - 1) : 0;

            // Putting it all together and taking the carry (discarding the lowest 8 bits)
            int max_carry = (carryless_bound + prev_carry) >> 8;
            return max_carry;
        }

        std::vector<TYPE> res;

        public:
        zkevm_div_mod_bbf(context_type &context_object,
                            const opcode_input_type<FieldType, stage> &current_state,
                            bool is_div)
            : generic_component<FieldType, stage>(context_object, false),res(chunk_amount) {

            // 16-bit chunks
            std::vector<TYPE> a_chunks(chunk_amount);       // input value
            std::vector<TYPE> b_chunks(chunk_amount);       // input modulus
            std::vector<TYPE> b_chunks_copy(chunk_amount);
            std::vector<TYPE> q_chunks(chunk_amount);       // a / b (if b > 0)
            std::vector<TYPE> q_chunks_copy1(chunk_amount);
            std::vector<TYPE> q_chunks_copy2(chunk_amount);
            std::vector<TYPE> r_chunks(chunk_amount);       // a % b (if b > 0)
            std::vector<TYPE> v_chunks(chunk_amount);       // Needed to enforce r < b.
            std::vector<TYPE> y_chunks(chunk_amount);       // Final result: y == r or q (depending on is_div) when b >= 1, and y == 0 otherwise.

            // mul == q * b
            std::vector<TYPE> mul_chunks(chunk_amount);

            // a == mul + r (mod 2^256)
            // construct_carryless_chunks[i] = construct_chunks[i] + construct_carries[i] * 2^16
            std::vector<TYPE> construct_carryless_chunks(chunk_amount);
            std::vector<TYPE> construct_chunks(chunk_amount);
            std::vector<TYPE> construct_carries(chunk_amount);          // Carries containing whatever overflows 16 bits

            // b + v == r + 2^256
            std::vector<TYPE> add_carries(chunk_amount);

            // 8-bit chunks
            std::vector<TYPE> q8_chunks(chunk_8_amount);
            std::vector<TYPE> q8_chunks_check(chunk_8_amount);
            std::vector<TYPE> b8_chunks(chunk_8_amount);
            std::vector<TYPE> b8_chunks_check(chunk_8_amount);

            // mul8_carryless_chunks[i] = mul8_chunks[i] + mul8_carries[i] * 2^8
            std::vector<TYPE> mul8_carryless_chunks(chunk_8_amount);
            std::vector<TYPE> mul8_chunks(chunk_8_amount);
            std::vector<TYPE> mul8_chunks_check(chunk_8_amount);
            std::vector<TYPE> mul8_carries(chunk_8_amount);            // Carries containing whatever overflows 8 bits

            // We copy the mul8 carries to propagate them to range-checked columns, and then
            // we also range-check mul8_carries[i] * 256.
            std::vector<TYPE> mul8_carries_copy1(chunk_8_amount);
            std::vector<TYPE> mul8_carries_copy2(chunk_8_amount);
            std::vector<TYPE> mul8_carries_check(chunk_8_amount);


            // PART 1: computing the opcode and splitting values in chunks
            if constexpr (stage == GenerationStage:: ASSIGNMENT) {
                // Extract input values from stack
                zkevm_word_type a = current_state.stack_top();
                zkevm_word_type b = current_state.stack_top(1);

                zkevm_word_type q = (b > 0) ? (a / b) : 0;
                zkevm_word_type r = (b > 0) ? (a % b) : 0;

                // At this point, a = q * b + r, so q is the result of DIV and r is the result of MOD
                zkevm_word_type v = wrapping_sub(r, b);
                // To prove that r < b, we'll show that b + v = r + 2^256 (i.e. there is always a carry)

                // 16-bit chunks
                a_chunks = zkevm_word_to_field_element<FieldType>(a);
                b_chunks = zkevm_word_to_field_element<FieldType>(b);
                r_chunks = zkevm_word_to_field_element<FieldType>(r);
                q_chunks = zkevm_word_to_field_element<FieldType>(q);
                v_chunks = zkevm_word_to_field_element<FieldType>(v);

                // // 8-bit chunks
                q8_chunks = zkevm_word_to_field_element_flexible<FieldType>(q, chunk_8_amount, 8);
                b8_chunks = zkevm_word_to_field_element_flexible<FieldType>(b, chunk_8_amount, 8);
            }

            // 16-bit chunks allocation
            for (std::size_t i = 0; i < chunk_amount; i++) {
                allocate(a_chunks[i], 2 * chunk_amount + i, 8);
                allocate(r_chunks[i], chunk_amount + i, 9);
                allocate(v_chunks[i], i, 11);

                allocate(b_chunks[i], 2 * chunk_amount + i, 7);
                b_chunks_copy[i] = b_chunks[i];
                allocate(b_chunks_copy[i], 2 * chunk_amount + i, 9);

                allocate(q_chunks[i], 2 * chunk_amount + i, 6);
                q_chunks_copy1[i] = q_chunks[i];
                allocate(q_chunks_copy1[i], chunk_amount + i, 8);
                q_chunks_copy2[i] = q_chunks_copy1[i];
                allocate(q_chunks_copy2[i], chunk_amount + i, 10);
            }

            // 8-bit chunks allocation
            for (std::size_t i = 0; i < chunk_8_amount; i++) {
                allocate(q8_chunks[i], i, 4);
                q8_chunks_check[i] = q8_chunks[i] * 256;
                allocate(q8_chunks_check[i], i, 2);

                allocate(b8_chunks[i], i, 5);
                b8_chunks_check[i] = b8_chunks[i] * 256;
                allocate(b8_chunks_check[i], i, 3);
            }

            // Consistency between 8-bit and 16-bit chunks
            for (std::size_t i = 0; i < chunk_amount; i++) {
                constrain(q_chunks[i] - q8_chunks[2*i] - q8_chunks[2*i + 1] * 256);
                constrain(b_chunks[i] - b8_chunks[2*i] - b8_chunks[2*i + 1] * 256);
            }


            // PART 2: decide whether b == 0 (trivial case) or b != 0 (we need to actually compute the operation)
            TYPE b_sum = 0;
            for (std::size_t i = 0; i < chunk_amount; i++) {
                b_sum += b_chunks_copy[i];
            }
            allocate(b_sum, 32, 10);

            TYPE b_sum_inverse;
            if constexpr (stage == GenerationStage::ASSIGNMENT) {
                b_sum_inverse = b_sum.is_zero() ? 0 : b_sum.inversed();
            }
            allocate(b_sum_inverse, 33, 10);

            // nonzero_modulus == 0  <==>  b_sum != 0
            // nonzero_modulus == 1  <==>  b_sum == 0
            TYPE nonzero_modulus = 1 - b_sum * b_sum_inverse;
            allocate(nonzero_modulus, 34, 10);
            constrain(b_sum * nonzero_modulus);

            // zero_modulus == 0  <==>  b == 0
            // zero_modulus == 1  <==>  b != 0
            TYPE zero_modulus = 1 - nonzero_modulus;


            // PART 3: enforcing a = q * b + r
            // mul = q * b
            for (std::size_t i = 0; i < chunk_8_amount; i++) {
                mul8_carryless_chunks[i] = carryless_mul(q8_chunks, b8_chunks, i);
                TYPE prev_carry = (i > 0) ? mul8_carries[i - 1] : 0;
                if constexpr (stage == GenerationStage::ASSIGNMENT) {
                    auto mask8 = (1 << 8) - 1;
                    mul8_chunks[i] = (mul8_carryless_chunks[i] + prev_carry).to_integral() & mask8;
                    mul8_carries[i] = (mul8_carryless_chunks[i] + prev_carry).to_integral() >> 8;
                    BOOST_ASSERT(mul8_carryless_chunks[i] + prev_carry == mul8_chunks[i] + 256 * mul8_carries[i]);
                }
                allocate(mul8_chunks[i], i, 6);

                // Range-checking the chunks
                mul8_chunks_check[i] = mul8_chunks[i] * 256;
                allocate(mul8_chunks_check[i], i, 7);

                // Carries are stored in two columns
                if (i < chunk_8_amount) {
                    int column_offset = i % chunk_amount;
                    int row_offset = i / chunk_amount;
                    allocate(mul8_carries[i], 2 * chunk_amount + column_offset, 4 + row_offset);
                }

                // Main constraint -- carry propagation
                constrain(mul8_carryless_chunks[i] + prev_carry - mul8_chunks[i] - mul8_carries[i] * 256);
            }

            // Range-checking the carries
            for (std::size_t i = 0; i < chunk_8_amount; i++) {
                mul8_carries_copy1[i] = mul8_carries[i];
                int column_offset = i % chunk_amount;
                int row_offset = i / chunk_amount;
                allocate(mul8_carries_copy1[i], 2 * chunk_amount + column_offset, 2 + row_offset);

                mul8_carries_copy2[i] = mul8_carries_copy1[i];
                allocate(mul8_carries_copy2[i], i, 1);

                mul8_carries_check[i] = mul8_carries_copy2[i] + (two_16 - 1 - max_carry(i));
                allocate(mul8_carries_check[i], i, 0);
            }

            // Reconstruct 16-bit chunks mul_chunks from 8-bit chunks mul8_chunks
            for (std::size_t i = 0; i < chunk_amount; i++) {
                mul_chunks[i] = mul8_chunks[2 * i] + mul8_chunks[2 * i + 1] * 256;
                allocate(mul_chunks[i], i, 8);
            }

            // mul + r == a + b
            for (std::size_t i = 0; i < chunk_amount; i++) {
                construct_carryless_chunks[i] = carryless_construct(mul_chunks, r_chunks, a_chunks, i);
                TYPE prev_carry = (i > 0) ? construct_carries[i - 1] : 0;
                if constexpr (stage == GenerationStage::ASSIGNMENT) {
                    auto mask16 = (1 << 16) - 1;
                    construct_chunks[i] = (zero_modulus != 0) ? (construct_carryless_chunks[i] + prev_carry).to_integral() & mask16 : 0;
                    construct_carries[i] = (zero_modulus != 0) ? (construct_carryless_chunks[i] + prev_carry).to_integral() >> 16 : 0;
                    if ((zero_modulus != 0)) {
                        BOOST_ASSERT(construct_carryless_chunks[i] + prev_carry == construct_carries[i] * two_16);
                        BOOST_ASSERT(construct_chunks[i] == 0);
                    }
                }
                allocate(construct_carries[i], i, 9);
                // Carries are bits
                constrain(construct_carries[i] * (1 - construct_carries[i]));

                // No need to satisfy these constraints if b == 0, as we will enforce this case separately
                constrain((construct_carryless_chunks[i] + prev_carry - construct_carries[i] * two_16) * zero_modulus);
            }

            // Carry propagation constraints for the b + v = r + 2^256 equality
            // No need to compute and allocate the last carry, as we will force it to be 1
            for (std::size_t i = 0; i < chunk_amount - 1; i++) {
                TYPE prev_carry = (i > 0) ? add_carries[i-1] : 0;
                if constexpr (stage == GenerationStage::ASSIGNMENT) {
                    TYPE prev_carry = (i > 0) ? add_carries[i - 1] : 0;
                    add_carries[i] = (b_chunks_copy[i] + v_chunks[i] + prev_carry).to_integral() >> 16;
                }
                allocate(add_carries[i], i, 10);
                constrain(add_carries[i] * (1 - add_carries[i]));
            }

            for (std::size_t i = 0; i < chunk_amount; i++) {
                TYPE prev_carry = (i > 0) ? add_carries[i - 1] : 0;
                TYPE current_carry = (i < chunk_amount - 1) ? add_carries[i] : 1; // Force the last carry to be 1
                if constexpr (stage == GenerationStage::ASSIGNMENT) {
                    if (zero_modulus != 0) {
                        BOOST_ASSERT(b_chunks_copy[i] + v_chunks[i] + prev_carry == r_chunks[i] + current_carry * two_16);
                    }
                }
                constrain((b_chunks_copy[i] + v_chunks[i] + prev_carry - r_chunks[i] - current_carry * two_16) * zero_modulus);
            }


            // PART 4: selecting the result
            for (std::size_t i = 0; i < chunk_amount; i++) {
                // Keep the quotient in DIV and the remainder in MOD
                y_chunks[i] = (is_div) ? q_chunks_copy2[i] * zero_modulus : r_chunks[i] * zero_modulus;
                allocate(y_chunks[i], chunk_amount + i, 11);
                res[i] = y_chunks[i];
            }


            // PART 5: consistency with the stack
            if constexpr( stage == GenerationStage::CONSTRAINTS ){
                // State transition constraints
                // The arguments for pc, gas, stack_size, memory-size and rw_counter correspond to number_of_rows - 1
                constrain(current_state.pc_next() - current_state.pc(11) - 1);                   // PC transition
                constrain(current_state.gas(11) - current_state.gas_next() - 5);                 // GAS transition
                constrain(current_state.stack_size(11) - current_state.stack_size_next() - 1);   // stack_size transition
                constrain(current_state.memory_size(11) - current_state.memory_size_next());     // memory_size transition
                constrain(current_state.rw_counter_next() - current_state.rw_counter(11) - 3);   // rw_counter transition

                // Stack lookup constraints
                // The arguments for call_id, stack_size and rw_counter corresponds to the indices of the rows that contains the data read from the rw_table
                std::vector<TYPE> tmp;
                tmp = rw_256_table<FieldType, stage>::stack_16_bit_lookup_reversed(
                    current_state.call_id(8),
                    current_state.stack_size(8) - 1,
                    current_state.rw_counter(8),
                    TYPE(0),// is_write
                    a_chunks
                );
                lookup(tmp, "zkevm_rw_256");
                tmp = rw_256_table<FieldType, stage>::stack_16_bit_lookup_reversed(
                    current_state.call_id(7),
                    current_state.stack_size(7) - 2,
                    current_state.rw_counter(7) + 1,
                    TYPE(0),// is_write
                    b_chunks
                );
                lookup(tmp, "zkevm_rw_256");
                tmp = rw_256_table<FieldType, stage>::stack_16_bit_lookup_reversed(
                    current_state.call_id(11),
                    current_state.stack_size(11) - 2,
                    current_state.rw_counter(11) + 2,
                    TYPE(1),// is_write
                    res
                );
                lookup(tmp, "zkevm_rw_256");
            }
        }
    };

    template<typename FieldType>
    class zkevm_div_mod_operation : public opcode_abstract<FieldType> {
        public:
        zkevm_div_mod_operation(bool _is_div) : is_div(_is_div) {}
        virtual std::size_t rows_amount() override { return 12; }
        virtual void fill_context(
            typename generic_component<FieldType, GenerationStage::ASSIGNMENT>::context_type
                &context,
            const opcode_input_type<FieldType, GenerationStage::ASSIGNMENT>
                &current_state)  override  {
            zkevm_div_mod_bbf<FieldType, GenerationStage::ASSIGNMENT> bbf_obj(context, current_state, is_div);
        }
        virtual void fill_context(
            typename generic_component<FieldType,
                                        GenerationStage::CONSTRAINTS>::context_type &context,
            const opcode_input_type<FieldType, GenerationStage::CONSTRAINTS>
                &current_state) override  {
            zkevm_div_mod_bbf<FieldType, GenerationStage::CONSTRAINTS> bbf_obj(context, current_state, is_div);
        }

        protected:
        bool is_div;
    };
}
