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

            enum bitwise_type { B_AND, B_OR, B_XOR };

            template<typename FieldType, GenerationStage stage>
            class zkevm_bitwise_bbf : generic_component<FieldType, stage> {
                using typename generic_component<FieldType, stage>::context_type;
                using generic_component<FieldType, stage>::allocate;
                using generic_component<FieldType, stage>::copy_constrain;
                using generic_component<FieldType, stage>::constrain;
                using generic_component<FieldType, stage>::lookup;
                using generic_component<FieldType, stage>::lookup_table;
            public:
                using typename generic_component<FieldType,stage>::TYPE;
                using integral_type = boost::multiprecision::number<boost::multiprecision::backends::cpp_int_modular_backend<257>>;

                zkevm_bitwise_bbf(context_type &context_object, const opcode_input_type<FieldType, stage> &current_state, bitwise_type bitwise_operation):
                    generic_component<FieldType,stage>(context_object, false)
                {
                    std::vector<TYPE> A(32);
                    std::vector<TYPE> B(32);
                    std::vector<TYPE> AND(32);
                    std::vector<TYPE> XOR(32);

                    if constexpr( stage == GenerationStage::ASSIGNMENT ){
                        zkevm_word_type a_word = current_state.stack_top();
                        zkevm_word_type b_word = current_state.stack_top(1);
                        auto a = w_to_8(a_word);
                        auto b = w_to_8(b_word);
                        auto and_chunks = w_to_8(a_word&b_word);
                        auto xor_chunks = w_to_8(a_word^b_word);

                        for(std::size_t i = 0; i <32; i++){
                            A[i] = a[i];
                            B[i] = b[i];
                            AND[i] = and_chunks[i];
                            XOR[i] = xor_chunks[i];
                        }
                    }
                    for(std::size_t i = 0; i < 32; i++){
                        allocate(A[i], i%16, 2 * (i/16));
                        allocate(B[i], i%16 + 16, 2 * (i/16));
                        allocate(AND[i], i%16, 2 * (i/16) + 1);
                        allocate(XOR[i], i%16 + 16, 2 * (i/16) + 1);
                    }
                    std::vector<TYPE> tmp;
                    for(std::size_t i = 0; i < 32; i++){
                        tmp = {
                            A[i],
                            B[i],
                            AND[i],
                            XOR[i]
                        };
                        lookup(tmp, "byte_and_xor_table/full");
                    }
                    auto A_128 = chunks8_to_chunks128(A);
                    auto B_128 = chunks8_to_chunks128(B);
                    auto AND_128 = chunks8_to_chunks128(AND);
                    auto XOR_128 = chunks8_to_chunks128(XOR);
                    auto OR_128 = std::make_pair(AND_128.first + XOR_128.first,AND_128.second + XOR_128.second);
                    if constexpr( stage == GenerationStage::CONSTRAINTS ){
                        constrain(current_state.pc_next() - current_state.pc(3) - 1);                   // PC transition
                        constrain(current_state.gas(3) - current_state.gas_next() - 3);                 // GAS transition
                        constrain(current_state.stack_size(3) - current_state.stack_size_next() - 1);   // stack_size transition
                        constrain(current_state.memory_size(3) - current_state.memory_size_next());     // memory_size transition
                        constrain(current_state.rw_counter_next() - current_state.rw_counter(3) - 3);   // rw_counter transition
                        tmp = {
                            TYPE(rw_op_to_num(rw_operation_type::stack)),
                            current_state.call_id(1),
                            current_state.stack_size(1) - 1,
                            TYPE(0),// storage_key_hi
                            TYPE(0),// storage_key_lo
                            TYPE(0),// field
                            current_state.rw_counter(1),
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
                            current_state.rw_counter(1) + 1,
                            TYPE(0),// is_write
                            B_128.first,
                            B_128.second
                        };
                        lookup(tmp, "zkevm_rw");
                        tmp = {
                            TYPE(rw_op_to_num(rw_operation_type::stack)),
                            current_state.call_id(2),
                            current_state.stack_size(2) - 2,
                            TYPE(0),// storage_key_hi
                            TYPE(0),// storage_key_lo
                            TYPE(0),// field
                            current_state.rw_counter(2) + 2,
                            TYPE(1)// is_write
                        };
                        switch(bitwise_operation){
                        case B_AND:
                            tmp.push_back(AND_128.first);
                            tmp.push_back(AND_128.second);
                            break;
                        case B_OR:
                            tmp.push_back(OR_128.first);
                            tmp.push_back(OR_128.second);
                            break;
                        case B_XOR:
                            tmp.push_back(XOR_128.first);
                            tmp.push_back(XOR_128.second);
                            break;
                        }
                        lookup(tmp, "zkevm_rw");
                    } else {
                        std::cout << "\tASSIGNMENT implemented" << std::endl;
                    }
                }
            };

            template<typename FieldType>
            class zkevm_bitwise_operation : public opcode_abstract<FieldType> {
            public:
                zkevm_bitwise_operation(bitwise_type _bit_operation): bit_operation(_bit_operation) { }
                virtual std::size_t rows_amount() override {
                    // It may be three if we don't want to minimize lookup constraints amount.
                    // It's a tradeoff between rows_amount and lookup constraints amount
                    return 4;
                }
                virtual void fill_context(
                    typename generic_component<FieldType, GenerationStage::ASSIGNMENT>::context_type &context,
                    const opcode_input_type<FieldType, GenerationStage::ASSIGNMENT> &current_state
                ) {
                    zkevm_bitwise_bbf<FieldType, GenerationStage::ASSIGNMENT> bbf_obj(context, current_state, bit_operation);
                }
                virtual void fill_context(
                    typename generic_component<FieldType, GenerationStage::CONSTRAINTS>::context_type &context,
                    const opcode_input_type<FieldType, GenerationStage::CONSTRAINTS> &current_state
                ) {
                    zkevm_bitwise_bbf<FieldType, GenerationStage::CONSTRAINTS> bbf_obj(context, current_state, bit_operation);
                }
            private:
                bitwise_type bit_operation;
            };
        } // namespace bbf
    }   // namespace blueprint
}   // namespace nil
