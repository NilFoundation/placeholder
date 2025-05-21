//---------------------------------------------------------------------------//
// Copyright (c) 2024 Dmitrii Tabalin <d.tabalin@nil.foundation>
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

#include <numeric>
#include <algorithm>

#include <nil/blueprint/zkevm_bbf/big_field/opcodes/abstract_opcode.hpp>

namespace nil::blueprint::bbf::zkevm_big_field{
    template<typename FieldType, GenerationStage stage>
    class zkevm_mul_bbf : generic_component<FieldType, stage> {
        using typename generic_component<FieldType, stage>::context_type;
        using generic_component<FieldType, stage>::allocate;
        using generic_component<FieldType, stage>::copy_constrain;
        using generic_component<FieldType, stage>::constrain;
        using generic_component<FieldType, stage>::lookup;
        using generic_component<FieldType, stage>::lookup_table;
    public:
        using typename generic_component<FieldType,stage>::TYPE;

        constexpr static const typename FieldType::value_type two_64 =
            0x10000000000000000_big_uint256;
        constexpr static const typename FieldType::value_type two_128 = 0x100000000000000000000000000000000_big_uint254;
        constexpr static const typename FieldType::value_type two_192 = 0x1000000000000000000000000000000000000000000000000_big_uint254;

        TYPE chunk_sum_64(const std::vector<TYPE> &chunks, const unsigned char chunk_idx) const {
            BOOST_ASSERT(chunk_idx < 4);
            TYPE result;
            result =  chunks[4 * chunk_idx];     result *= 0x10000;
            result += chunks[4 * chunk_idx + 1]; result *= 0x10000;
            result += chunks[4 * chunk_idx + 2]; result *= 0x10000;
            result += chunks[4 * chunk_idx + 3];
            return result;
        }

        TYPE lo_carryless_construct(
            const std::vector<TYPE> &a_64_chunks,
            const std::vector<TYPE> &b_64_chunks,
            const std::vector<TYPE> &r_64_chunks
        ) const {
            return
                a_64_chunks[3] * b_64_chunks[3] +
                two_64 * (a_64_chunks[3] * b_64_chunks[2] + a_64_chunks[2] * b_64_chunks[3]) - r_64_chunks[3] - two_64 * r_64_chunks[2];
        }


        TYPE hi_carryless_construct(
            const std::vector<TYPE> &a_64_chunks,
            const std::vector<TYPE> &b_64_chunks,
            const std::vector<TYPE> &r_64_chunks
        ) {
            return
                (a_64_chunks[3] * b_64_chunks[1] + a_64_chunks[2] * b_64_chunks[2] + a_64_chunks[1] * b_64_chunks[3] - r_64_chunks[1]) +
                two_64 * (a_64_chunks[3] * b_64_chunks[0] + a_64_chunks[1] * b_64_chunks[2] + a_64_chunks[2] * b_64_chunks[1] + a_64_chunks[0] * b_64_chunks[3] - r_64_chunks[0]);
        }

        zkevm_mul_bbf(context_type &context_object, const opcode_input_type<FieldType, stage> &current_state):
            generic_component<FieldType,stage>(context_object, false)
        {
            std::vector<TYPE> A(16);
            std::vector<TYPE> B(16);
            std::vector<TYPE> R(16);
            std::vector<TYPE> A_64(4);
            std::vector<TYPE> B_64(4);
            std::vector<TYPE> R_64(4);
            TYPE C0;
            TYPE C0_check;
            std::vector<TYPE> C1(4);
            TYPE C2;
            std::vector<TYPE> C3(4);

            if constexpr( stage == GenerationStage::ASSIGNMENT ){
                auto a = w_to_16(current_state.stack_top());
                auto b = w_to_16(current_state.stack_top(1));
                auto r = w_to_16(wrapping_mul(current_state.stack_top(), current_state.stack_top(1)));
                for( std::size_t i = 0; i < 16; i++){
                    A[i] = a[i];
                    B[i] = b[i];
                    R[i] = r[i];
                }
                BOOST_LOG_TRIVIAL(trace) << "\tA = " << std::hex << current_state.stack_top();
                BOOST_LOG_TRIVIAL(trace) << "\tB = " << std::hex << current_state.stack_top(1);
                BOOST_LOG_TRIVIAL(trace) << "\tR = " << std::hex << wrapping_mul(current_state.stack_top(), current_state.stack_top(1));
            }
            for( std::size_t i = 0; i < 16; i++){
                allocate(A[i], i, 0);
                allocate(B[i], i + 16, 0);
                allocate(R[i], i, 1);
            }

            A_64[0] = chunk_sum_64(A, 0);
            A_64[1] = chunk_sum_64(A, 1);
            A_64[2] = chunk_sum_64(A, 2);
            A_64[3] = chunk_sum_64(A, 3);

            B_64[0] = chunk_sum_64(B, 0);
            B_64[1] = chunk_sum_64(B, 1);
            B_64[2] = chunk_sum_64(B, 2);
            B_64[3] = chunk_sum_64(B, 3);

            R_64[0] = chunk_sum_64(R, 0);
            R_64[1] = chunk_sum_64(R, 1);
            R_64[2] = chunk_sum_64(R, 2);
            R_64[3] = chunk_sum_64(R, 3);


            if constexpr( stage == GenerationStage::ASSIGNMENT ){
                TYPE lo_carries = lo_carryless_construct(A_64, B_64, R_64);
                TYPE hi_carries = hi_carryless_construct(A_64, B_64, R_64);

                zkevm_word_type c_first_i = ((lo_carries.to_integral()) >> 128);
                auto c_first = w_to_16(c_first_i);

                zkevm_word_type c_second_i = (((hi_carries + c_first_i).to_integral()) >> 128);
                auto c_second = w_to_16(c_second_i);

                C3[3] = c_first[15]; C3[2] = c_first[14]; C3[1] = c_first[13]; C3[0] = c_first[12];
                C2 = c_first[11];
                C1[3] = c_second[15]; C1[2] = c_second[14]; C1[1] = c_second[13]; C1[0] = c_second[12];
                C0 = c_second[11];
            }

            TYPE lo_carries = lo_carryless_construct(A_64, B_64, R_64);
            TYPE hi_carries = hi_carryless_construct(A_64, B_64, R_64);

            allocate(C3[0], 17, 1);
            allocate(C3[1], 18, 1);
            allocate(C3[2], 19, 1);
            allocate(C3[3], 20, 1);
            TYPE C3_64 = chunk_sum_64(C3, 0);
            allocate(C2, 21, 1);

            allocate(C1[0], 22, 1);
            allocate(C1[1], 23, 1);
            allocate(C1[2], 24, 1);
            allocate(C1[3], 25, 1);
            TYPE C1_64 = chunk_sum_64(C1, 0);
            allocate(C0, 26, 1);

            constrain(C2 * (C2 - 1));
            // constrain(C0 * (C0 - 1) * (C0 - 2) * (C0 - 3));
            C0_check = C0 * 16384; // 16-bit range-check on C0_check <=> C0 < 4
            allocate(C0_check, 27, 1);

            constrain(lo_carries - C3_64 * two_128 - C2 * two_192);
            constrain(hi_carries + C3_64 + C2 * two_64 - C1_64 * two_128 - C0 * two_192);

            auto A_128 = chunks16_to_chunks128<TYPE>(A);
            auto B_128 = chunks16_to_chunks128<TYPE>(B);
            auto R_128 = chunks16_to_chunks128<TYPE>(R);
            if constexpr( stage == GenerationStage::CONSTRAINTS ){
                constrain(current_state.pc_next() - current_state.pc(1) - 1);                   // PC transition
                constrain(current_state.gas(1) - current_state.gas_next() - 5);                 // GAS transition
                constrain(current_state.stack_size(1) - current_state.stack_size_next() - 1);   // stack_size transition
                constrain(current_state.memory_size(1) - current_state.memory_size_next());     // memory_size transition
                constrain(current_state.rw_counter_next() - current_state.rw_counter(1) - 3);   // rw_counter transition
                std::vector<TYPE> tmp;
                tmp = rw_table<FieldType, stage>::stack_lookup(
                    current_state.call_id(0),
                    current_state.stack_size(0) - 1,
                    current_state.rw_counter(0),
                    TYPE(0),// is_write
                    A_128.first,
                    A_128.second
                );
                lookup(tmp, "zkevm_rw");
                tmp = rw_table<FieldType, stage>::stack_lookup(
                    current_state.call_id(0),
                    current_state.stack_size(0) - 2,
                    current_state.rw_counter(0) + 1,
                    TYPE(0),// is_write
                    B_128.first,
                    B_128.second
                );
                lookup(tmp, "zkevm_rw");
                tmp = rw_table<FieldType, stage>::stack_lookup(
                    current_state.call_id(1),
                    current_state.stack_size(1) - 2,
                    current_state.rw_counter(1) + 2,
                    TYPE(1),// is_write
                    R_128.first,
                    R_128.second
                );
                lookup(tmp, "zkevm_rw");
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
            return 2;
        }
    };
}