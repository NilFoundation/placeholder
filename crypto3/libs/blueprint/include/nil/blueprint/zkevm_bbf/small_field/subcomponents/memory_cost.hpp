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

// #include <functional>

#pragma once

#include <nil/blueprint/bbf/generic.hpp>
#include <nil/blueprint/zkevm_bbf/small_field/subcomponents/word_size.hpp>
#include "nil/blueprint/zkevm_bbf/types/zkevm_word.hpp"

namespace nil::blueprint::bbf::zkevm_small_field {

    template<typename FieldType, GenerationStage stage>
    class memory_cost : public generic_component<FieldType, stage> {
        using generic_component<FieldType, stage>::allocate;
        using generic_component<FieldType, stage>::copy_constrain;
        using generic_component<FieldType, stage>::constrain;

        using value_type = typename FieldType::value_type;

        constexpr static const std::size_t chunk_amount = 6;
        constexpr static const value_type two_7 = 128;
        constexpr static const value_type two_15 = 32768;
        constexpr static const value_type two_16 = 65536;
        constexpr static const value_type two_18 = 262144;
        constexpr static const value_type two_23 = 8388608;

      public:
        using typename generic_component<FieldType, stage>::TYPE;
        using typename generic_component<FieldType, stage>::context_type;

      public:
        TYPE cost;
        TYPE word_size;

        // Computes the terms of a*b with coefficient 2^(8 * chunk_index)
        TYPE carryless_mul(const std::vector<TYPE> &a_chunks,
                           const std::vector<TYPE> &b_chunks,
                           const unsigned char chunk_index) const {
            TYPE res = 0;
            for (int i = 0; i <= chunk_index; i++) {
                int j = chunk_index - i;
                if ((i < chunk_amount) && (j >= 0) && (j < chunk_amount)) {
                    res += a_chunks[i] * b_chunks[j];
                }
            }
            return res;
        }

        // Counts the number of cross terms a_chunks[i] * b_chunks[j] involved in the i-th
        // carryless
        // chunk of the multiplication a * b. This is useful for range-checking later.
        int count_cross_terms(const unsigned char chunk_index) const {
            // the result is the amount of pairs (i, j) such that i + j == chunk_index,
            // for 0 <= i, j < chunk_8_amount.
            int i = chunk_index + 1;
            return (i <= 32) ? i : 2 * chunk_amount - i;
        }

        // Given a carryless chunk, we will separate it into an 8-bit chunk and a carry,
        // which contains whatever overflows 8 bits. This function computes the maximal
        // value of such carry, for accurate range-checking.
        int max_carry(const unsigned char chunk_index) const {
            // r8_carryless_chunks[i] + prev_carry == r8_chunks[i] + r8_carries[i] * 256
            // To bound r8_carries[i], we need to bound r8_carryless_chunks[i] and
            // prev_carry. r8_carryless_chunks[i] == (sum of some cross terms a_chunks[i]
            // * b_chunks[j]). The largest carries happen when a_chunks[i] == b_chunks[i]
            // == 2^8 - 1 for all 0 <= i < 32.
            int max_cross_term = 255 * 255;
            // r8_carryless_chunks[i] <= number_of_cross_terms * max_cross_terms
            int number_of_cross_terms = count_cross_terms(chunk_index);
            // Finally, we also take into account the maximal value of the previous carry
            int prev_carry = (chunk_index > 0) ? max_carry(chunk_index - 1) : 0;
            // Putting it all together and taking the carry (discarding the lowest 8 bits)
            int max_carry = (number_of_cross_terms * max_cross_term + prev_carry) >> 8;
            return max_carry;
        }

        memory_cost(context_type &context_object, TYPE memory_input)
            : generic_component<FieldType, stage>(context_object, false) {
            using integral_type = typename FieldType::integral_type;
            using Word_Size = typename zkevm_small_field::word_size<FieldType, stage>;

            // This is a 2X19 table where the first 16 rows need to be range checked

            TYPE mem_words, exponential_expansion, remainder, quotient;
            std::vector<std::size_t> word_size_lookup_area = {16, 17, 18};

            context_type word_size_ct =
                context_object.subcontext(word_size_lookup_area, 0, 1);

            Word_Size word = Word_Size(word_size_ct, memory_input);
            mem_words = word.size;

            // 8-bit chunks
            std::vector<TYPE> a_chunks(chunk_amount);
            std::vector<TYPE> r_chunks(chunk_amount);
            // r_carryless_chunks[i] = carryless_mul(a_chunks, a_chunks, i)
            std::vector<TYPE> r_carryless_chunks(chunk_amount);
            // Carries containing whatever overflows 8 bits :
            //  r_carryless_chunks[i] = r_chunks[i] + r_carries[i]
            std::vector<TYPE> r_carries(chunk_amount);

            // Range checks associated with the values above
            std::vector<TYPE> a_chunks_check(chunk_amount);
            std::vector<TYPE> r_chunks_check(chunk_amount);
            std::vector<TYPE> r_carries_check(chunk_amount);

            if constexpr (stage == GenerationStage::ASSIGNMENT) {
                // We fix mem_words to be 2^18 max
                BOOST_ASSERT(mem_words.to_integral() <= two_18);

                auto r = mem_words * mem_words;
                // 8-bit chunks
                // This needs to be constrained
                a_chunks = zkevm_word_to_field_element_flexible<FieldType>(
                    zkevm_word_type(mem_words.to_integral()), chunk_amount, 8);
            }

            // 8-bit chunks allocation
            for (std::size_t i = 0; i < 3; i++) {
                allocate(a_chunks[i], 2 * i, 0);
                a_chunks_check[i] = a_chunks[i] * 256;
                allocate(a_chunks_check[i], 2 * i + 1, 0);
            }

            // PART 2: enforcing the multiplication a * a = r
            for (std::size_t i = 0; i < chunk_amount; i++) {
                r_carryless_chunks[i] = carryless_mul(a_chunks, a_chunks, i);
                TYPE prev_carry = (i > 0) ? r_carries[i - 1] : 0;
                if constexpr (stage == GenerationStage::ASSIGNMENT) {
                    auto mask8 = (1 << 8) - 1;
                    r_chunks[i] =
                        (r_carryless_chunks[i] + prev_carry).to_integral() & mask8;
                    r_carries[i] =
                        (r_carryless_chunks[i] + prev_carry).to_integral() >> 8;
                }
                allocate(r_chunks[i], i, 1);
                r_chunks_check[i] = r_chunks[i] * 256;
                allocate(r_chunks_check[i], i + chunk_amount, 1);
                allocate(r_carries[i], i + 2 * chunk_amount, 1);

                // Main constraint enforcing the multiplication and carry propagation
                constrain(r_carryless_chunks[i] + prev_carry - r_chunks[i] -
                          r_carries[i] * 256);
            }

            // Range checks for the multiplication carries.
            for (std::size_t i = 0; i < chunk_amount; i++) {
                r_carries_check[i] = r_carries[i] + (two_16 - 1 - max_carry(i));
                allocate(r_carries_check[i], i + 6, 0);
            }
            allocate(mem_words, 12, 0);

            // Ensure consistency between the 8-bit chunks and the original value
            constrain(mem_words - a_chunks[0] - a_chunks[1] * 256 - a_chunks[2] * 65536);
            // r is at most 2^36:  last chunk is 0
            constrain(r_chunks[5]);

            if constexpr (stage == GenerationStage::ASSIGNMENT) {
                remainder = r_chunks[1].to_integral() % 2;
                quotient = r_chunks[1] / 2;
            }
            allocate(quotient, 13, 0);
            TYPE quotient_check = quotient * two_15;
            allocate(quotient_check, 14, 0);  // range_check quotient
            allocate(remainder, 15, 0);
            constrain(r_chunks[1] - remainder - quotient);

            allocate(exponential_expansion, 18, 1);
            // We need to shift by 9 the 5 remaining chunks, so we ignore the first_chunk
            exponential_expansion = quotient + r_chunks[2] * two_7 +
                                    r_chunks[3] * two_15 + r_chunks[4] * two_23;

            cost = exponential_expansion + 3 * mem_words;
            word_size = word.size;
        };
    };
}  // namespace nil::blueprint::bbf::zkevm_small_field
