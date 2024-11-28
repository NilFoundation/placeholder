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

#include <numeric>
#include <algorithm>

#include <nil/blueprint/zkevm/zkevm_word.hpp>
#include <nil/blueprint/zkevm_bbf/types/opcode.hpp>

namespace nil {
    namespace blueprint {
        namespace bbf{
            template<typename FieldType>
            class opcode_abstract;

            template<typename FieldType, GenerationStage stage>
            class zkevm_byte_bbf : generic_component<FieldType, stage> {
                using typename generic_component<FieldType, stage>::context_type;
                using generic_component<FieldType, stage>::allocate;
                using generic_component<FieldType, stage>::copy_constrain;
                using generic_component<FieldType, stage>::constrain;
                using generic_component<FieldType, stage>::lookup;
                using generic_component<FieldType, stage>::lookup_table;
            public:
                using typename generic_component<FieldType,stage>::TYPE;
                using integral_type = boost::multiprecision::number<boost::multiprecision::backends::cpp_int_modular_backend<257>>;

                zkevm_byte_bbf(context_type &context_object, const opcode_input_type<FieldType, stage> &current_state):
                    generic_component<FieldType,stage>(context_object, false)
                {
                    std::vector<TYPE> A(16);
                    std::vector<TYPE> B(16);
                    std::vector<TYPE> B_bits(16);
                    TYPE a16, a16_hi, a16_lo, minus_a16_hi, minus_a16_lo, b_last_bit, b_sum, b_hi, b_lo, b_sum_inv, result;

                    if constexpr( stage == GenerationStage::ASSIGNMENT ){
                        auto N = current_state.stack_top();
                        auto b = w_to_16(current_state.stack_top());
                        auto a = w_to_16(current_state.stack_top(1));
                        std::cout << "\tb = " << std::hex << current_state.stack_top() << std::dec << std::endl;
                        std::cout << "\ta = " << std::hex << current_state.stack_top(1) << std::dec << std::endl;
                        for( std::size_t i = 0; i < 16; i++){
                            A[i] = a[i];
                            B[i] = b[i];
                            B_bits[i] = (N >= 0 && N < 32) && (b[15]/2 == i);
                            if( i != 15 ) b_sum += b[i];
                        }
                        b_last_bit = (0 <= N && N < 32) && ((b[15] & 1) != 0);
                        b_hi = b[15] / 32;
                        b_lo = b[15] % 32;
                        b_sum += b_hi;
                        b_sum_inv = b_sum == 0? 0: b_sum.inversed();
                        std::size_t chunk = (0<=N && N<32) ? a[b[15]/2] : 0;
                        a16 = chunk;
                        a16_lo = chunk & 0xFF;
                        a16_hi = (chunk & 0xFF00) >> 8;
                        minus_a16_hi = 255 - a16_hi;
                        minus_a16_lo = 255 - a16_lo;
                        result = (b_last_bit == 0)? a16_hi: a16_lo;
                        std::cout << "\ta16 = " << std::hex << a16 << std::endl;
                        std::cout << "\ta16_hi = " << a16_hi << std::endl;
                        std::cout << "\ta16_lo = " << a16_lo << std::endl;
                        std::cout << "\tresult = " << result << std::endl;
                        std::cout << "\tb_sum = " << b_sum << std::dec << std::endl;
                    }
                    for( std::size_t i = 0; i < 16; i++ ){
                        allocate(A[i], i, 0);
                        allocate(B[i], i+16, 0);
                        allocate(B_bits[i], i + 16, 1);
                    }
                    allocate(a16, 0, 1);
                    allocate(a16_hi, 1, 1);
                    allocate(a16_lo, 2, 1);
                    allocate(minus_a16_hi, 3, 1);
                    allocate(minus_a16_lo, 4, 1);
                    allocate(b_hi, 5, 1);
                    allocate(b_lo, 6, 1);
                    allocate(b_last_bit, 7, 1);
                    allocate(result, 8, 1);
                    allocate(b_sum, 32, 0);
                    allocate(b_sum_inv, 33, 0);

                    constrain(a16_hi + minus_a16_hi - 255);
                    constrain(a16_lo + minus_a16_lo - 255);
                    constrain(a16 - a16_hi * 256 - a16_lo);
                    TYPE b_sum_constraint;
                    TYPE b_bits_composition;
                    TYPE b_bits_sum;
                    TYPE chunk;
                    for(std::size_t i = 0; i < 16; i++){
                        constrain(B_bits[i] * (B_bits[i] - 1));
                        if( i != 15) b_sum_constraint += B[i];
                        b_bits_composition += i * B_bits[i];
                        b_bits_sum += B_bits[i];
                        chunk += B_bits[i] * A[i];
                    }
                    b_sum_constraint += b_hi;
                    b_bits_composition *= 2;
                    b_bits_composition += b_last_bit;
                    std::cout << "\tb_bits_composition = " << std::hex << b_bits_composition << std::dec << std::endl;
                    std::cout << "\tb_sum_constraint = " << std::hex << b_sum_constraint << std::dec << std::endl;
                    constrain(b_bits_composition - b_bits_sum * b_lo);
                    constrain(b_sum_constraint - b_sum);
                    constrain(b_sum * (b_sum * b_sum_inv - 1));
                    constrain(b_sum_inv * (b_sum * b_sum_inv - 1));
                    constrain(b_sum * b_sum_inv * result);
                    constrain(b_last_bit * (b_last_bit - 1));
                    constrain(b_bits_sum + b_sum * b_sum_inv - 1);
                    constrain(b_hi * 32 + b_lo - B[15]);
                    constrain(a16_hi * 256 + a16_lo - a16);
                    constrain(chunk - a16);
                    constrain(b_bits_sum * (b_last_bit * (a16_lo - result) + (1 - b_last_bit) * (a16_hi - result)));

                    auto A_128 = chunks16_to_chunks128<TYPE>(A);
                    auto B_128 = chunks16_to_chunks128<TYPE>(B);
                    std::cout << "\tA128 = " << std::hex << A_128.first << ", " << A_128.second << std::dec << std::endl;
                    std::cout << "\tB128 = " << std::hex << B_128.first << ", " << B_128.second << std::dec << std::endl;
                    if constexpr( stage == GenerationStage::CONSTRAINTS ){
                        constrain(current_state.pc_next() - current_state.pc(1) - 1);                   // PC transition
                        constrain(current_state.gas(1) - current_state.gas_next() - 3);                 // GAS transition
                        constrain(current_state.stack_size(1) - current_state.stack_size_next() - 1);   // stack_size transition
                        constrain(current_state.memory_size(1) - current_state.memory_size_next());     // memory_size transition
                        constrain(current_state.rw_counter_next() - current_state.rw_counter(1) - 3);   // rw_counter transition
                        std::vector<TYPE> tmp;
                        tmp = {
                            TYPE(rw_op_to_num(rw_operation_type::stack)),
                            current_state.call_id(0),
                            current_state.stack_size(0) - 1,
                            TYPE(0),// storage_key_hi
                            TYPE(0),// storage_key_lo
                            TYPE(0),// field
                            current_state.rw_counter(0),
                            TYPE(0),// is_write
                            B_128.first,
                            B_128.second
                        };
                        lookup(tmp, "zkevm_rw");
                        tmp = {
                            TYPE(rw_op_to_num(rw_operation_type::stack)),
                            current_state.call_id(0),
                            current_state.stack_size(0) - 2,
                            TYPE(0),// storage_key_hi
                            TYPE(0),// storage_key_lo
                            TYPE(0),// field
                            current_state.rw_counter(0) + 1,
                            TYPE(0),// is_write
                            A_128.first,
                            A_128.second
                        };
                        lookup(tmp, "zkevm_rw");
                        tmp = {
                            TYPE(rw_op_to_num(rw_operation_type::stack)),
                            current_state.call_id(1),
                            current_state.stack_size(1) - 2,
                            TYPE(0),// storage_key_hi
                            TYPE(0),// storage_key_lo
                            TYPE(0),// field
                            current_state.rw_counter(1) + 2,
                            TYPE(1),// is_write
                            TYPE(0),
                            result
                        };
                        lookup(tmp, "zkevm_rw");
                    } else {
                        std::cout << "\tAssignment implemented" << std::endl;
                    }
                }
            };

            template<typename FieldType>
            class zkevm_byte_operation : public opcode_abstract<FieldType> {
            public:
                virtual std::size_t rows_amount() override {
                    return 2;
                }
                virtual void fill_context(
                    typename generic_component<FieldType, GenerationStage::ASSIGNMENT>::context_type &context,
                    const opcode_input_type<FieldType, GenerationStage::ASSIGNMENT> &current_state
                ) {
                    zkevm_byte_bbf<FieldType, GenerationStage::ASSIGNMENT> bbf_obj(context, current_state);
                }
                virtual void fill_context(
                    typename generic_component<FieldType, GenerationStage::CONSTRAINTS>::context_type &context,
                    const opcode_input_type<FieldType, GenerationStage::CONSTRAINTS> &current_state
                ) {
                    zkevm_byte_bbf<FieldType, GenerationStage::CONSTRAINTS> bbf_obj(context, current_state);
                }
            };
        } // namespace bbf
    }   // namespace blueprint
}   // namespace nil
