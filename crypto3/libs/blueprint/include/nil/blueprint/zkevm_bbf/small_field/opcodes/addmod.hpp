//---------------------------------------------------------------------------//
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

#include <algorithm>
#include <nil/blueprint/zkevm_bbf/small_field/opcodes/abstract_opcode.hpp>
#include <numeric>
#include <vector>
#include "nil/blueprint/bbf/enums.hpp"
#include "nil/crypto3/multiprecision/detail/big_uint/arithmetic.hpp"

namespace nil::blueprint::bbf::zkevm_small_field {
template<typename FieldType>
class opcode_abstract;

template<typename FieldType, GenerationStage stage>
class zkevm_addmod_bbf : public generic_component<FieldType, stage> {
    using generic_component<FieldType, stage>::allocate;
    using generic_component<FieldType, stage>::copy_constrain;
    using generic_component<FieldType, stage>::constrain;
    using generic_component<FieldType, stage>::lookup;
    using generic_component<FieldType, stage>::lookup_table;

    using value_type = typename FieldType::value_type;
    using var = crypto3::zk::snark::plonk_variable<typename FieldType::value_type>;

    constexpr static const std::size_t chunk_amount = 16;
    constexpr static const std::size_t chunk_8_amount = 32;
    constexpr static const value_type two_16 = 65536;

    public:
    using typename generic_component<FieldType, stage>::TYPE;
    using typename generic_component<FieldType, stage>::context_type;

    // Computes the terms of q*N with coefficient 2^(8 * chunk_index)
    TYPE carryless_mul(const std::vector<TYPE> &q8_chunks,
                                const std::vector<TYPE> &N8_chunks,
                                const unsigned char chunk_index) const {
        TYPE res = 0;
        for (int i = 0; i <= chunk_index; i++) {
            int j = chunk_index - i;
            if ((i < chunk_8_amount) && (j >= 0) && (j < chunk_8_amount)) {
                res += q8_chunks[i] * N8_chunks[j];
            }
        }
        return res;
    }

    // Computes the terms of mul + r - s with coefficient 2^(16 * chunk_index)
    // Because mul has chunk_amount + 1 chunks, we need to handle this case as well
    TYPE carryless_construct(const std::vector<TYPE> &mul_chunks,
                                const std::vector<TYPE> &r_chunks,
                                const std::vector<TYPE> &s_chunks,
                                const unsigned char chunk_index) const {
        TYPE left_hand_side = mul_chunks[chunk_index] + ( (chunk_index < chunk_amount) ? r_chunks[chunk_index] : 0 );
        TYPE right_hand_side = s_chunks[chunk_index];
        TYPE res = left_hand_side - right_hand_side;
        return res;
    }

    // In the following code, cross-terms of the form q8_chunks[i] * N8_chunks[j] are said to be *full* when
    // they can reach their maximal value 255^2.

    // Counts the number of full cross-terms q8_chunks[i] * N8_chunks[j] involved in the i-th carryless chunk
    // of the multiplication q * N, where q, N < 2^256 and q*N < 2^257. This is useful for range-checking later.
    constexpr int count_full_cross_terms(const unsigned char chunk_index) const {
        // For unrelated q, N < 2^256, the result would be the amount of pairs (i, j) such that 
        // i + j == chunk_index, for 0 <= i, j < chunk_8_amount. 
        // However, because we have a bound on q*N, they cannot both have non-zero higher-order chunks.

        // For simplicity, suppose first that q*N < 2^256.
        // The number of cross-terms is maximized when both are balanced around 2^128.
        // In this case, q8_chunks[i] == N8_chunks[i] == 0 for all i >= 16.

        // In our real case, q*N < 2^257. In this case, we can also have 
        // q8_chunks[i] != 0 != N8_chunks[i] for all i < 16, and additionally
        // q8_chunks[16] == 1 or N8_chunks[16] == 1, with the other being 0. 
        // The cross-terms that originate from this extra 1 are not full,
        // so we will not consider them in this function, and account for them separately.

        int res = 0;
        for (int i = 0; i < 16; i++) {
            int j = chunk_index - i;
            if ((j >= 0) && (j < 16)) {
                res += 1;
            }
        }
        return res;
    }

    // Given a carryless chunk of the multiplication q*N, we will separate it into an 8-bit 
    // chunk and a carry, which contains whatever overflows 8 bits. This function computes 
    // the maximal value of such carry, for accurate range-checking.
    constexpr int max_carry(const unsigned char chunk_index) const {
        // mul8_carryless_chunks[i] + prev_carry == mul8_chunks[i] + mul8_carries[i] * 256
        // To bound mul8_carries[i], we need to bound mul8_carryless_chunks[i] and prev_carry.
        // mul8_carryless_chunks[i] == (sum of some cross terms q8_chunks[i] * N8_chunks[j]).

        // The largest carries happen when both chunks in a cross-term are 2^8 - 1.
        int max_cross_term = 255 * 255;

        // r8_carryless_chunks[i] <= (number of cross terms) * (cross term value)
        // We separate cross-terms into two types, those who reach the maximal value (full cross-terms),
        // and those that are smaller. We count the first type in the function below.
        int number_of_full_cross_terms = count_full_cross_terms(chunk_index);

        // The additional non-zero cross-terms originate from the fact that q8_chunks[16] or
        // N8_chunks[16] migth be 1 (while the others are zero), so this only influences 
        // carryless chunks 16 to 31. Suppose WLOG that q8_chunks[16] = 1, N8_chunks[16] = 0.
        // Then the extra cross terms not accounted for above are of the form
        // q8_chunks[16] * N8_chunks[j], j < 16. Thus, these are bounded by N8_chunks[j] < 2^8 - 1.
        // Also, because the index on q8_chunks is fixed, only one such term can appear in each
        // carryless chunk.

        // We now have enough to compute the bounds on mul8_carryless_chunks.
        int carryless_bound = 0;
        if (chunk_index < 16) {
            carryless_bound = number_of_full_cross_terms * max_cross_term;
        } else if (chunk_index < 32) {
            carryless_bound = number_of_full_cross_terms * max_cross_term + 255;
        }

        // Finally, we also take into account the maximal value of the previous carry
        int prev_carry = (chunk_index > 0) ? max_carry(chunk_index - 1) : 0;

        // Putting it all together and taking the carry (discarding the lowest 8 bits)
        int max_carry = (carryless_bound + prev_carry) >> 8;
        return max_carry;

        // NOTE: this bounds are tight. An example that maximizes them is:
        // a == 2^256 - 2^128
        // b == 2^256 - 2^128 - 1
        // N == 2^128 - 1
        // In this case, 
        // q8_chunks[i] == N8_chunks[i] == 2^8 - 1 for all i < 16,
        // q8_chunks[16] == 1 and N8_chunks[16] == 0,
        // q8_chunks[i] == N8_chunks[i] == 0 for all i > 16.
    }

    std::vector<TYPE> res;

    // Overall strategy: we separate the case N <= 1, which directly results in 0. 
    // When N >= 2, the compute the result r such that a + b = q*N + r, for 0 <= r < N.
    // We will use a variable trivial_modulus to keep track of in which of the two cases we are.
    public:
    zkevm_addmod_bbf(context_type &context_object,
                        const opcode_input_type<FieldType, stage> &current_state,
                        bool make_links = true)
        : generic_component<FieldType, stage>(context_object, false), res(chunk_amount) {

        // 16-bit chunks
        std::vector<TYPE> a_chunks(chunk_amount);                       // First factor 
        std::vector<TYPE> b_chunks(chunk_amount);                       // Second factor 
        std::vector<TYPE> N_chunks(chunk_amount);                       // Modulus 
        std::vector<TYPE> N_chunks_copy(chunk_amount);                  
        std::vector<TYPE> r_chunks(chunk_amount);                       // Result of ((a + b) mod N) mod 2^256 (if N >= 2)
        std::vector<TYPE> v_chunks(chunk_amount);                       // Needed to enforce r < N.
        std::vector<TYPE> y_chunks(chunk_amount);                       // Final result: y == r when N >= 2, y == 0 otherwise.

        // mul == q * N. Note the extra chunk, since q * N < 2^257.
        std::vector<TYPE> mul_chunks(chunk_amount + 1);   
        
        // s == a + b. Note the extra chunk, since s < 2^257.
        // s_carryless_chunks[i] == s_chunks[i] + s_carries[i] * 2^16, where s_carries[16] == 0
        std::vector<TYPE> s_carryless_chunks(chunk_amount + 1);                      
        std::vector<TYPE> s_chunks(chunk_amount + 1);                       // s = a + b
        std::vector<TYPE> s_carries(chunk_amount);                          // Carries containing whatever overflows 16 bits 
                                                                            // Carry 16 is forced to be 0, so we don't need to store it

        // s == mul + r (mod 2^256)
        // construct_carryless_chunks[i] == construct_chunks[i] + construct_carries[i] * 2^16
        std::vector<TYPE> construct_carryless_chunks(chunk_amount + 1); 
        std::vector<TYPE> construct_chunks(chunk_amount + 1);
        std::vector<TYPE> construct_carries(chunk_amount);          // Carries containing whatever overflows 16 bits   
                                                                    // Carry 16 is forced to be 0, so we don't need to store it

        // N + v == r + 2^256
        std::vector<TYPE> add_carries(chunk_amount);

        // 8-bit chunks
        std::vector<TYPE> q8_chunks(chunk_8_amount);                   // Quotient of integer division (a + b) / N (if N >= 2)
        std::vector<TYPE> q8_chunks_check(chunk_8_amount);             
        std::vector<TYPE> N8_chunks(chunk_8_amount);                   
        std::vector<TYPE> N8_chunks_check(chunk_8_amount);                   

        // mul8_carryless_chunks[i] = mul8_chunks[i] + mul8_carries[i] * 2^8
        std::vector<TYPE> mul8_carryless_chunks(chunk_8_amount + 1);
        std::vector<TYPE> mul8_chunks(chunk_8_amount + 1);             
        std::vector<TYPE> mul8_chunks_check(chunk_8_amount);           // Range checks for the above. The last one does not need a range
                                                                       // check well, since we will constrain it directly.
        std::vector<TYPE> mul8_carries(chunk_8_amount + 1);            // Carries containing whatever overflows 8 bits 

        // We copy the mul8 carries to propagate them to range-checked columns, and then
        // we also range-check mul8_carries[i] * 256. We do not need to do this for the 
        // 32nd carry, since we will separately enforce it to be a bit
        std::vector<TYPE> mul8_carries_copy1(chunk_8_amount);          
        std::vector<TYPE> mul8_carries_copy2(chunk_8_amount);          
        std::vector<TYPE> mul8_carries_check(chunk_8_amount);          


        // PART 1: computing the opcode and splitting values in chunks
        if constexpr (stage == GenerationStage:: ASSIGNMENT) {
            // Extract input values from stack
            zkevm_word_type a = current_state.stack_top();
            zkevm_word_type b = current_state.stack_top(1);
            zkevm_word_type N = current_state.stack_top(2);
            
            // addition and modulo operation
            auto s = nil::crypto3::multiprecision::big_uint<257>(a) + b;
            // If N == 0:
            //      q == 0
            //      r == 0
            // If N >= 2:
            //      q == s / N      (in this case, q < 2^256)
            //      r == (s - q*N) mod 2^256
            zkevm_word_type q = (N >= 2) ? (s / N).truncate<256>() : 0;       
            zkevm_word_type r = (N >= 2) ? (s % N).truncate<256>() : 0;   // the truncate method is necessary to convert to the 256-bit int type, although q, r do not overflow 256 bits for any N >= 2.
            
            // At this point, a + b = q * N + r, so r is our result
            zkevm_word_type v = wrapping_sub(r, N);   
            // To prove that r < N, we'll show that N + v = r + 2^256 (i.e. there is always a carry)

            // 16-bit chunks
            a_chunks = zkevm_word_to_field_element<FieldType>(a);
            b_chunks = zkevm_word_to_field_element<FieldType>(b);
            r_chunks = zkevm_word_to_field_element<FieldType>(r);
            N_chunks = zkevm_word_to_field_element<FieldType>(N);
            N_chunks_copy = zkevm_word_to_field_element<FieldType>(N);
            v_chunks = zkevm_word_to_field_element<FieldType>(v);

            // // 8-bit chunks
            N8_chunks = zkevm_word_to_field_element_flexible<FieldType>(N, chunk_8_amount, 8);
            q8_chunks = zkevm_word_to_field_element_flexible<FieldType>(q, chunk_8_amount, 8);
        }

        // 16-bit chunks allocation
        for (std::size_t i = 0; i < chunk_amount; i++) {
            allocate(a_chunks[i], 2 * chunk_amount + i, 10);
            allocate(b_chunks[i], 2 * chunk_amount + i, 11);
            allocate(r_chunks[i], chunk_amount + i, 10);
            allocate(N_chunks[i], 2 * chunk_amount + i, 7);
            allocate(N_chunks_copy[i], 2 * chunk_amount + i, 12);
            allocate(v_chunks[i], i, 12);
        }

        // 8-bit chunks allocation
        for (std::size_t i = 0; i < chunk_8_amount; i++) {
            allocate(q8_chunks[i], i, 4);
            q8_chunks_check[i] = q8_chunks[i] * 256;
            allocate(q8_chunks_check[i], i, 2);
            
            allocate(N8_chunks[i], i, 5);
            N8_chunks_check[i] = N8_chunks[i] * 256;
            allocate(N8_chunks_check[i], i, 3);
        }

        // Consistency between 8-bit and 16-bit chunks
        for (std::size_t i = 0; i < chunk_amount; i++) {
            constrain(N_chunks[i] - N8_chunks[2*i] - N8_chunks[2*i + 1] * 256);
        }


        // PART 2: figure out in which case we are: N <= 1 (trivial modulus) or N >= 2
        TYPE N_partial_sum = 0;         // sum of all chunks of N, except for the first one
        for (std::size_t i = 1; i < chunk_amount; i++) {
            N_partial_sum += N_chunks[i];
        }
        allocate(N_partial_sum, 32, 8);
        
        TYPE N_partial_sum_inverse;
        if constexpr (stage == GenerationStage::ASSIGNMENT) {
            N_partial_sum_inverse = N_partial_sum.is_zero() ? 0 : N_partial_sum.inversed();
        }
        allocate(N_partial_sum_inverse, 33, 8);
        
        // N_partial_sum_is_nonzero == 0  <==>  N_partial_sum != 0
        // N_partial_sum_is_nonzero == 1  <==>  N_partial_sum == 0
        TYPE N_partial_sum_is_nonzero = 1 - N_partial_sum * N_partial_sum_inverse;
        allocate(N_partial_sum_is_nonzero, 17, 9);
        // Either N_partial_sum is zero, or its inverse is the right one
        constrain(N_partial_sum * N_partial_sum_is_nonzero);
        
        TYPE N_chunk0_is_0_or_1 = N_chunks[0] * (N_chunks[0] - 1);
        TYPE N_chunk0_is_0_or_1_inverse;
        if constexpr (stage == GenerationStage::ASSIGNMENT) {
            N_chunk0_is_0_or_1_inverse = N_chunk0_is_0_or_1.is_zero() ? 0 : N_chunk0_is_0_or_1.inversed();
        }
        allocate(N_chunk0_is_0_or_1, 34, 8);
        allocate(N_chunk0_is_0_or_1_inverse, 35, 8);
        // N_chunk0_is_greater_than_1 == 0  <==>  N_chunk[0] > 1
        // N_chunk0_is_greater_than_1 == 1  <==>  N_chunk[0] <= 1
        TYPE N_chunk0_is_greater_than_1 = 1 - N_chunk0_is_0_or_1 * N_chunk0_is_0_or_1_inverse;
        allocate(N_chunk0_is_greater_than_1, 18, 9);
        constrain(N_chunk0_is_0_or_1 * N_chunk0_is_greater_than_1);
        
        // nontrivial_modulus == 0  ==>  N > 1
        TYPE nontrivial_modulus = N_chunk0_is_greater_than_1 * N_partial_sum_is_nonzero;

        // trivial_modulus == 0 ==> N <= 1
        // trivial_modulus == 1 <== N > 1
        TYPE trivial_modulus = 1 - nontrivial_modulus;  // both factors of nontrivial_modulus are bits, so this works
        allocate(trivial_modulus, 19, 9);
        TYPE trivial_modulus_copy1 = trivial_modulus;
        allocate(trivial_modulus_copy1, 15, 11); 

        
        // PART 3: enforcing a + b = q * N + r
        // mul == q * N
        // Note that there are chunk_8_amount + 1 chunks, since in general q*N < 2^257.
        for (std::size_t i = 0; i < chunk_8_amount + 1; i++) {
            mul8_carryless_chunks[i] = carryless_mul(q8_chunks, N8_chunks, i);
            TYPE prev_carry = (i > 0) ? mul8_carries[i - 1] : 0;
            if constexpr (stage == GenerationStage::ASSIGNMENT) {
                auto mask8 = (1 << 8) - 1;
                mul8_chunks[i] = (mul8_carryless_chunks[i] + prev_carry).to_integral() & mask8;
                mul8_carries[i] = (mul8_carryless_chunks[i] + prev_carry).to_integral() >> 8;
            }
            allocate(mul8_chunks[i], i, 6);

            // Chunks 0 to 31 are < 2^8
            if (i < chunk_8_amount) {
                mul8_chunks_check[i] = mul8_chunks[i] * 256; 
                allocate(mul8_chunks_check[i], i, 7);
            }
            // Chunk 32 is a bit
            else { 
                constrain(mul8_chunks[i] * (1 - mul8_chunks[i])); 
            }

            // Carries 0 to 31 are stored in two rows
            if (i < chunk_8_amount) {
                int column_offset = i % chunk_amount;
                int row_offset = i / chunk_amount;
                allocate(mul8_carries[i], 2 * chunk_amount + column_offset, 4 + row_offset);
            }
            // Carry 32 is stored separately
            else {
                allocate(mul8_carries[i], 33, 6);
            }

            constrain(mul8_carryless_chunks[i] + prev_carry - mul8_chunks[i] - mul8_carries[i] * 256);
        }

        // Range-checking the carries (except for the last one, which is handled separately)
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
        for (std::size_t i = 0; i < chunk_amount + 1; i++) {
            TYPE lower_half = mul8_chunks[2 * i];
            TYPE upper_half = (i < chunk_amount) ? mul8_chunks[2 * i + 1] : 0;
            mul_chunks[i] = lower_half + upper_half * 256;
            allocate(mul_chunks[i], i, 8);
        }

        // s = a + b
        for (std::size_t i = 0; i < chunk_amount + 1; i++) {
            TYPE prev_carry = (i > 0) ? s_carries[i - 1] : 0;
            s_carryless_chunks[i] = (i < chunk_amount) ? (a_chunks[i] + b_chunks[i]) : 0;
            if constexpr (stage == GenerationStage::ASSIGNMENT) {
                auto mask16 = (1 << 16) - 1;
                s_chunks[i] = (s_carryless_chunks[i] + prev_carry).to_integral() & mask16;
                if (i < chunk_amount) {
                    s_carries[i] = (s_carryless_chunks[i] + prev_carry).to_integral() >> 16;
                }
            }
            allocate(s_chunks[i], i, 9);
            
            // Allocate carries 0 to 15 and constrain them to bits
            if (i < chunk_amount) {
                allocate(s_carries[i], 2 * chunk_amount + i, 9);
                constrain(s_carries[i] * (1 - s_carries[i]));
            }
            
            // Main constraint
            TYPE current_carry = (i < chunk_amount) ? s_carries[i] : 0; // Force the last carry to be 0
            constrain(s_chunks[i] + current_carry * two_16 - (s_carryless_chunks[i] + prev_carry));
        }

        // mul + r == s
        for (std::size_t i = 0; i < chunk_amount + 1; i++) {
            construct_carryless_chunks[i] = carryless_construct(mul_chunks, r_chunks, s_chunks, i);
            TYPE prev_carry = (i > 0) ? construct_carries[i - 1] : 0;
            if constexpr (stage == GenerationStage::ASSIGNMENT) {
                auto mask16 = (1 << 16) - 1;
                // If N <= 1, we just assign these values to zero, since we will bypass their constraint anyways,
                // and this ensures that they still satisfy the range checks.
                construct_chunks[i] = (trivial_modulus != 0 ) ? (construct_carryless_chunks[i] + prev_carry).to_integral() & mask16 : 0;
                if (i < chunk_amount) {
                    construct_carries[i] = (trivial_modulus != 0) ? (construct_carryless_chunks[i] + prev_carry).to_integral() >> 16 : 0;
                }
            }

            // Allocate carries 0 to 15 and constrain them to bits
            if (i < chunk_amount) {
                allocate(construct_carries[i], i, 10);
                constrain(construct_carries[i] * (1 - construct_carries[i]));
            }

            TYPE current_carry = (i < chunk_amount) ? construct_carries[i] : 0; // Force the last carry to be 0
            // No need to satisfy these constraints if N <= 1 (trivial modulus), as we will enforce this case separately
            constrain((construct_carryless_chunks[i] + prev_carry - current_carry * two_16) * trivial_modulus);
        }

        // Carry propagation constraints for the N + v = r + 2^256 equality
        // No need to compute and allocate the last carry, as we will force it to be 1
        for (std::size_t i = 0; i < chunk_amount - 1; i++) {
            TYPE prev_carry = (i > 0) ? add_carries[i-1] : 0;
            if constexpr (stage == GenerationStage::ASSIGNMENT) {
                TYPE prev_carry = (i > 0) ? add_carries[i - 1] : 0;
                add_carries[i] = (N_chunks_copy[i] + v_chunks[i] + prev_carry).to_integral() >> 16;
            }
            allocate(add_carries[i], i, 11);
            constrain(add_carries[i] * (1 - add_carries[i]));
        }
        for (std::size_t i = 0; i < chunk_amount; i++) {
            TYPE prev_carry = (i > 0) ? add_carries[i - 1] : 0;
            TYPE current_carry = (i < chunk_amount - 1) ? add_carries[i] : 1; // Force the last carry to be 1
            constrain((N_chunks_copy[i] + v_chunks[i] + prev_carry - r_chunks[i] - current_carry * two_16) * trivial_modulus_copy1);
        }


        // PART 4: selecting the result
        for (std::size_t i = 0; i < chunk_amount; i++) {
            y_chunks[i] = r_chunks[i] * trivial_modulus_copy1;
            allocate(y_chunks[i], chunk_amount + i, 12);
            res[i] = y_chunks[i];
        }

        // PART 5: consistency with the stack
        if constexpr( stage == GenerationStage::CONSTRAINTS ){
            // State transition constraints
            // The arguments for pc, gas, stack_size, memory-size and rw_counter correspond to number_of_rows - 1
            constrain(current_state.pc_next() - current_state.pc(11) - 1);                   // PC transition
            constrain(current_state.gas(11) - current_state.gas_next() - 8);                 // GAS transition
            constrain(current_state.stack_size(11) - current_state.stack_size_next() - 2);   // stack_size transition
            constrain(current_state.memory_size(11) - current_state.memory_size_next());     // memory_size transition
            constrain(current_state.rw_counter_next() - current_state.rw_counter(11) - 4);   // rw_counter transition

            // Stack lookup constraints
            // The arguments for call_id, stack_size and rw_counter corresponds to the indices of the rows that contains the data read from the rw_table
            std::vector<TYPE> tmp;
            tmp = rw_256_table<FieldType, stage>::stack_16_bit_lookup_reversed(
                current_state.call_id(9),
                current_state.stack_size(9) - 1,
                current_state.rw_counter(9),
                TYPE(0),// is_write
                a_chunks
            );
            lookup(tmp, "zkevm_rw_256");
            tmp = rw_256_table<FieldType, stage>::stack_16_bit_lookup_reversed(
                current_state.call_id(10),
                current_state.stack_size(10) - 2,
                current_state.rw_counter(10) + 1,
                TYPE(0),// is_write
                b_chunks
            );
            lookup(tmp, "zkevm_rw_256");
            tmp = rw_256_table<FieldType, stage>::stack_16_bit_lookup_reversed(
                current_state.call_id(7),
                current_state.stack_size(7) - 3,
                current_state.rw_counter(7) + 2,
                TYPE(0),// is_write
                N_chunks
            );
            lookup(tmp, "zkevm_rw_256");
            tmp = rw_256_table<FieldType, stage>::stack_16_bit_lookup_reversed(
                current_state.call_id(11),
                current_state.stack_size(11) - 3,
                current_state.rw_counter(11) + 2,
                TYPE(0),// is_write
                N_chunks
            );
            lookup(tmp, "zkevm_rw_256");
            tmp = rw_256_table<FieldType, stage>::stack_16_bit_lookup_reversed(
                current_state.call_id(11),
                current_state.stack_size(11) - 3,
                current_state.rw_counter(11) + 3,
                TYPE(1),// is_write
                res
            );
            lookup(tmp, "zkevm_rw_256");
        }
    }
};

template<typename FieldType>
class zkevm_addmod_operation : public opcode_abstract<FieldType> {
    public:
    virtual void fill_context(
        typename generic_component<FieldType, GenerationStage::ASSIGNMENT>::context_type
            &context,
        const opcode_input_type<FieldType, GenerationStage::ASSIGNMENT>
            &current_state
    ) override  {
        zkevm_addmod_bbf<FieldType, GenerationStage::ASSIGNMENT> bbf_obj(context,
                                                                            current_state);
    }
    virtual void fill_context(
        typename generic_component<FieldType,
                                    GenerationStage::CONSTRAINTS>::context_type &context,
        const opcode_input_type<FieldType, GenerationStage::CONSTRAINTS>
            &current_state
    ) override  {
        zkevm_addmod_bbf<FieldType, GenerationStage::CONSTRAINTS> bbf_obj(
            context, current_state);
    }
    virtual std::size_t rows_amount() override { return 13; }
};
}  // namespace nil::blueprint:bbf::zkevm_small_field
