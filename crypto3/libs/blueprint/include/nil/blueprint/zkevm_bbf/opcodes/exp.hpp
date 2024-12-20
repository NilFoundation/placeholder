//---------------------------------------------------------------------------//
// Copyright (c) 2024 Elena Tatuzova <e.tatuzova@nil.foundation>
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
            class zkevm_exp_bbf : generic_component<FieldType, stage> {
                using typename generic_component<FieldType, stage>::context_type;
                using generic_component<FieldType, stage>::allocate;
                using generic_component<FieldType, stage>::copy_constrain;
                using generic_component<FieldType, stage>::constrain;
                using generic_component<FieldType, stage>::lookup;
                using generic_component<FieldType, stage>::lookup_table;
            public:
                using typename generic_component<FieldType,stage>::TYPE;

                zkevm_exp_bbf(context_type &context_object, const opcode_input_type<FieldType, stage> &current_state):
                    generic_component<FieldType,stage>(context_object, false)
                {
                    std::vector<TYPE> A(16);
                    std::vector<TYPE> D(16);
                    std::vector<TYPE> R(16);
                    std::vector<TYPE> d_log(8);
                    std::vector<TYPE> d_inv(8);
                    TYPE d_sum;
                    TYPE d_sum_inv;
                    TYPE d_sum_inv_1;
                    TYPE s;

                    if constexpr( stage == GenerationStage::ASSIGNMENT ){
                        auto a = w_to_16(current_state.stack_top());
                        auto d = w_to_16(current_state.stack_top(1));
                        auto r = w_to_16(exp_by_squaring(current_state.stack_top(), current_state.stack_top(1)));
                        s = 1;
                        if( current_state.stack_top(1) == 0 ) s = 0;
                        if( current_state.stack_top(1) == 1 ) s = 0;

                        std::cout << "\t"
                            << current_state.stack_top() << " ^ "
                            << current_state.stack_top(1) << " = "
                            << exp_by_squaring(current_state.stack_top(), current_state.stack_top(1))
                            << std::endl;
                        for( std::size_t i = 0; i < 16; i++){
                            A[i] = a[i];
                            D[i] = d[i];
                            R[i] = r[i];
                            d_sum += d[i];
                        }
                        d_sum_inv = d_sum == 0? 0: d_sum.inversed();
                        d_sum_inv_1 = d_sum == 1 ? 0: (d_sum - 1).inversed();
                    }
                    for( std::size_t i = 0; i < 16; i++){
                        allocate(A[i], i, 0);
                        allocate(D[i], i + 16, 0);
                        allocate(R[i], i, 1);
                    }
                    allocate(d_sum, 32, 0);
                    allocate(d_sum_inv, 33, 0);
                    allocate(d_sum_inv_1, 34, 0);
                    allocate(s, 35, 0);

                    TYPE d_sum_constraint;
                    for( std::size_t i = 0; i < 16; i++){
                        d_sum_constraint += D[i];
                    }

                    constrain(s * (s-1));
                    constrain(d_sum_constraint - d_sum);
                    constrain(d_sum * (d_sum_inv * d_sum - 1));
                    constrain(d_sum_inv * (d_sum_inv * d_sum - 1));
                    constrain(d_sum_inv_1 * (d_sum_inv_1 * (d_sum - 1) - 1));

                    auto A_128 = chunks16_to_chunks128<TYPE>(A);
                    auto D_128 = chunks16_to_chunks128<TYPE>(D);
                    auto R_128 = chunks16_to_chunks128<TYPE>(R);
                    constrain( (1 - (d_sum - 1) * d_sum_inv_1) * (A_128.first - R_128.first) );
                    constrain( (1 - (d_sum - 1) * d_sum_inv_1) * (A_128.second - R_128.second) );
                    constrain( (1 - (d_sum - 1) * d_sum_inv_1) * s );

                    if constexpr( stage == GenerationStage::CONSTRAINTS ){
                        constrain(current_state.pc_next() - current_state.pc(1) - 1);                   // PC transition
//                        constrain(current_state.gas(1) - current_state.gas_next() - 5);                 // GAS transition
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
                            A_128.first,
                            A_128.second
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
                            D_128.first,
                            D_128.second
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
                            R_128.first,
                            R_128.second
                        };
                        lookup(tmp, "zkevm_rw");
                        tmp = {
                            s,
                            s * A_128.first,
                            s * A_128.second,
                            s * D_128.first,
                            s * D_128.second,
                            s * R_128.first,
                            s * R_128.second
                        };
                        lookup(tmp, "zkevm_exp");
                    } else {
                        std::cout << "\tAssignment implemented" << std::endl;
                    }
                }
            };

            template<typename FieldType>
            class zkevm_exp_operation : public opcode_abstract<FieldType> {
            public:
                virtual void fill_context(
                    typename generic_component<FieldType, GenerationStage::ASSIGNMENT>::context_type &context,
                    const opcode_input_type<FieldType, GenerationStage::ASSIGNMENT> &current_state
                )  override {
                    zkevm_exp_bbf<FieldType, GenerationStage::ASSIGNMENT> bbf_obj(context, current_state);
                }
                virtual void fill_context(
                    typename generic_component<FieldType, GenerationStage::CONSTRAINTS>::context_type &context,
                    const opcode_input_type<FieldType, GenerationStage::CONSTRAINTS> &current_state
                ) override  {
                    zkevm_exp_bbf<FieldType, GenerationStage::CONSTRAINTS> bbf_obj(context, current_state);
                }
                virtual std::size_t rows_amount() override {
                    return 2;
                }
            };
        } // namespace bbf
    }   // namespace blueprint
}   // namespace nil
