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

#include <nil/blueprint/zkevm_bbf/types/opcode.hpp>

namespace nil {
    namespace blueprint {
        namespace bbf{
            template<typename FieldType>
            class opcode_abstract;

            enum cmp_type { C_LT, C_GT };

            template<typename FieldType, GenerationStage stage>
            class zkevm_cmp_bbf : generic_component<FieldType, stage> {
                using typename generic_component<FieldType, stage>::context_type;
                using generic_component<FieldType, stage>::allocate;
                using generic_component<FieldType, stage>::copy_constrain;
                using generic_component<FieldType, stage>::constrain;
                using generic_component<FieldType, stage>::lookup;
                using generic_component<FieldType, stage>::lookup_table;
            public:
                using typename generic_component<FieldType,stage>::TYPE;

                zkevm_cmp_bbf(context_type &context_object, const opcode_input_type<FieldType, stage> &current_state, cmp_type cmp_operation):
                    generic_component<FieldType,stage>(context_object, false)
                {
                    std::vector<TYPE> A(16);
                    std::vector<TYPE> B(16);
                    std::vector<TYPE> S(16);
                    TYPE diff;
                    TYPE diff_inv;
                    TYPE lt;
                    TYPE gt;
                    TYPE result;
                    if constexpr( stage == GenerationStage::ASSIGNMENT ){
                        auto a = w_to_16(current_state.stack_top());
                        auto b = w_to_16(current_state.stack_top(1));
                        bool eq = true;
                        result = false;
                        lt = false;
                        gt = false;
                        for( std::size_t i = 0; i < 16; i++ ){
                            A[i] = a[i];
                            B[i] = b[i];
                        }
                        for( std::size_t i = 0; i < 16; i++ ){
                            if( a[i] != b[i] ) {
                                std::cout << "\tNOT equal" << std::endl;
                                if( eq ) S[i] = 1;
                                eq = false;
                                diff = a[i] < b[i]? b[i] - a[i]: a[i] - b[i];
                                diff_inv = diff.inversed();
                                lt = a[i] < b[i];
                                gt = a[i] > b[i];
                                result = cmp_operation == cmp_type::C_LT ? a[i] < b[i]: a[i] > b[i];
                                break;
                            }
                        }
                        if( cmp_operation == cmp_type::C_LT ) std::cout << "\t" << current_state.stack_top() << "<" <<  current_state.stack_top(1) << " = " << result << std::endl;
                        if( cmp_operation == cmp_type::C_GT ) std::cout << "\t" << current_state.stack_top() << ">" <<  current_state.stack_top(1) << " = " << result << std::endl;                    }
                    TYPE s_sum;
                    for( std::size_t i = 0; i < 16; i++ ){
                        allocate(A[i], i, 0);
                        allocate(B[i], i + 16, 0);
                        allocate(S[i], i, 1);
                    }
                    allocate(diff, 16, 1 );
                    allocate(diff_inv, 32, 0);
                    allocate(lt, 17, 1);
                    allocate(gt, 18, 1);
                    allocate(result, 19, 1);

                    for( std::size_t i = 0; i < 16; i++ ){
                        constrain(S[i] * (S[i] - 1));
                        s_sum += S[i];
                    }

                    constrain(gt * (gt - 1));
                    constrain(lt * (lt - 1));
                    constrain(s_sum * (s_sum - 1));
                    constrain(gt + lt - s_sum);
                    constrain(result * (result - 1));
                    if( cmp_operation == cmp_type::C_LT ){
                        constrain(result - lt);
                    } else {
                        constrain(result - gt);
                    }
                    std::vector<TYPE> zero_constraints(15);
                    for( std::size_t i = 0; i < 15; i++ ){
                        for( std::size_t j = i+1; j < 16; j++){
                            zero_constraints[i] += S[j];
                        }
                        zero_constraints[i] *= A[i] - B[i];
                        constrain(zero_constraints[i]);
                    }
                    TYPE diff_constraint;
                    for( std::size_t i = 0; i < 16; i++ ){
                        diff_constraint += S[i] * (gt * (A[i] - B[i]) + lt *(B[i] - A[i]));
                    }
                    constrain(diff - diff_constraint);
                    constrain(diff * (diff * diff_inv - 1));
                    constrain(diff_inv * (diff * diff_inv - 1));
                    constrain(diff * diff_inv - lt - gt);
                    auto A_128 = chunks16_to_chunks128<TYPE>(A);
                    auto B_128 = chunks16_to_chunks128<TYPE>(B);
                    if constexpr( stage == GenerationStage::CONSTRAINTS ){
                        constrain(current_state.pc_next() - current_state.pc(1) - 1);                   // PC transition
                        constrain(current_state.gas(1) - current_state.gas_next() - 3);                 // GAS transition
                        constrain(current_state.stack_size(1) - current_state.stack_size_next() - 1);   // stack_size transition
                        constrain(current_state.memory_size(1) - current_state.memory_size_next());     // memory_size transition
                        constrain(current_state.rw_counter_next() - current_state.rw_counter(1) - 3);   // rw_counter transition
                        std::vector<TYPE> tmp;
                        tmp = rw_table<FieldType, stage>::stack_lookup(
                            current_state.call_id(1),
                            current_state.stack_size(1) - 1,
                            current_state.rw_counter(1),
                            TYPE(0),// is_write
                            A_128.first,
                            A_128.second
                        );
                        lookup(tmp, "zkevm_rw");
                        tmp = rw_table<FieldType, stage>::stack_lookup(
                            current_state.call_id(1),
                            current_state.stack_size(1) - 2,
                            current_state.rw_counter(1) + 1,
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
                            TYPE(0),// hi bytes are 0
                            result
                        );
                        lookup(tmp, "zkevm_rw");
                    }
                }
            };

            template<typename FieldType>
            class zkevm_cmp_operation : public opcode_abstract<FieldType> {
            public:
                zkevm_cmp_operation(cmp_type _cmp_operation) : cmp_operation(_cmp_operation) {}
                virtual std::size_t rows_amount() override {
                    return 2;
                }
                virtual void fill_context(
                    typename generic_component<FieldType, GenerationStage::ASSIGNMENT>::context_type &context,
                    const opcode_input_type<FieldType, GenerationStage::ASSIGNMENT> &current_state
                ) override  {
                    zkevm_cmp_bbf<FieldType, GenerationStage::ASSIGNMENT> bbf_obj(context, current_state, cmp_operation);
                }
                virtual void fill_context(
                    typename generic_component<FieldType, GenerationStage::CONSTRAINTS>::context_type &context,
                    const opcode_input_type<FieldType, GenerationStage::CONSTRAINTS> &current_state
                ) override  {
                    zkevm_cmp_bbf<FieldType, GenerationStage::CONSTRAINTS> bbf_obj(context, current_state, cmp_operation);
                }
            private:
                cmp_type cmp_operation;
            };
        } // namespace bbf
    }   // namespace blueprint
}   // namespace nil
