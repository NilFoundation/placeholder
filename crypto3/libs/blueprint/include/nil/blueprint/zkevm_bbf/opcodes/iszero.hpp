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
            class zkevm_iszero_bbf : generic_component<FieldType, stage> {
                using typename generic_component<FieldType, stage>::context_type;
                using generic_component<FieldType, stage>::allocate;
                using generic_component<FieldType, stage>::copy_constrain;
                using generic_component<FieldType, stage>::constrain;
                using generic_component<FieldType, stage>::lookup;
                using generic_component<FieldType, stage>::lookup_table;
            public:
                using typename generic_component<FieldType,stage>::TYPE;

                zkevm_iszero_bbf(context_type &context_object, const opcode_input_type<stage> &current_state):
                    generic_component<FieldType,stage>(context_object)
                {
                    std::vector<TYPE> a_chunks(16);
                    TYPE chunks_sum;
                    TYPE chunks_sum_inv;
                    TYPE result;
                    if constexpr( stage == GenerationStage::ASSIGNMENT ){
                        std::cout << "\tISZERO bbf object assigns its area" << std::endl;
                        zkevm_word_type A = current_state.stack_top();
                        a_chunks = zkevm_word_to_field_element<FieldType>(A);
                        for( std::size_t i = 0; i < a_chunks.size(); i++ ){
                            chunks_sum += a_chunks[i];
                        }
                        chunks_sum_inv = chunks_sum_inv == 0? 0 : chunks_sum.inversed();
                        result = 1 - chunks_sum * chunks_sum_inv;
                    }
                    TYPE chunks_sum_expr;
                    for( std::size_t i = 0; i < a_chunks.size(); i++ ){
                        allocate(a_chunks[i], i, 0);
                        chunks_sum_expr+=a_chunks[i];
                    }
                    allocate(chunks_sum, 32, 0);
                    allocate(chunks_sum_inv, 33, 0);
                    allocate(result, 34, 0);
                    constrain(chunks_sum_expr - chunks_sum);
                    constrain(result + chunks_sum * chunks_sum_inv - 1);
                    constrain(result * (result - 1));
                    std::cout << "\tResult = " << result << std::endl;
                }
            };

            template<typename FieldType>
            class zkevm_iszero_operation : public opcode_abstract<FieldType> {
            public:
                virtual void fill_context(
                    typename generic_component<FieldType, GenerationStage::ASSIGNMENT>::context_type &context,
                    const opcode_input_type<GenerationStage::ASSIGNMENT> &current_state
                ) {
                    std::cout << "\tAssign ISZERO input = " << current_state.stack_top() << std::endl;
                    zkevm_iszero_bbf<FieldType, GenerationStage::ASSIGNMENT> bbf_obj(context, current_state);
                }
                virtual void fill_context(
                    typename generic_component<FieldType, GenerationStage::CONSTRAINTS>::context_type &context,
                    const opcode_input_type<GenerationStage::CONSTRAINTS> &current_state
                ) {
                    std::cout << "\tBuild ISZERO constraints" << std::endl;
                    zkevm_iszero_bbf<FieldType, GenerationStage::CONSTRAINTS> bbf_obj(context, current_state);
                }
                virtual std::size_t rows_amount() override {
                    return 1;
                }
            };
        } // namespace bbf
    }   // namespace blueprint
}   // namespace nil
