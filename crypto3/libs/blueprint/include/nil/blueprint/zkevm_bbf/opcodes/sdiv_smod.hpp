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
            template<typename FieldType, GenerationStage stage>
            class zkevm_sdiv_smod_bbf : generic_component<FieldType, stage> {
                using typename generic_component<FieldType, stage>::context_type;
                using generic_component<FieldType, stage>::allocate;
                using generic_component<FieldType, stage>::copy_constrain;
                using generic_component<FieldType, stage>::constrain;
                using generic_component<FieldType, stage>::lookup;
                using generic_component<FieldType, stage>::lookup_table;
            public:
                using typename generic_component<FieldType,stage>::TYPE;

                zkevm_sdiv_smod_bbf(context_type &context_object, const opcode_input_type<FieldType, stage> &current_state, bool is_div):
                    generic_component<FieldType,stage>(context_object, false)
                {
                    // std::vector<TYPE> A(16);
                    // std::vector<TYPE> B(16);
                    // std::vector<TYPE> C(16);

                    // if constexpr( stage == GenerationStage::ASSIGNMENT ){
                    //     auto a = w_to_16(current_state.stack_top());
                    //     auto b = w_to_16(current_state.stack_top(1));
                    //     for( std::size_t i = 0; i < 16; i++){
                    //         A[i] = a[i];
                    //         B[i] = b[i];
                    //     }
                    // }
                    // for( std::size_t i = 0; i < 16; i++){
                    //     allocate(A[i], i, 0);
                    //     allocate(B[i], i + 16, 0);
                    //     allocate(C[i], i, 1);
                    // }
                    // auto A_128 = chunks16_to_chunks128<TYPE>(A);
                    // auto B_128 = chunks16_to_chunks128<TYPE>(B);
                    // if constexpr( stage == GenerationStage::CONSTRAINTS ){
                    //     constrain(current_state.pc_next() - current_state.pc(5) - 1);                   // PC transition
                    //     constrain(current_state.gas(5) - current_state.gas_next() - 3);                 // GAS transition
                    //     constrain(current_state.stack_size(5) - current_state.stack_size_next() - 1);   // stack_size transition
                    //     constrain(current_state.memory_size(5) - current_state.memory_size_next());     // memory_size transition
                    //     constrain(current_state.rw_counter_next() - current_state.rw_counter(5) - 3);   // rw_counter transition
                    //     std::vector<TYPE> tmp;
                    //     tmp = {
                    //         TYPE(rw_op_to_num(rw_operation_type::stack)),
                    //         current_state.call_id(5),
                    //         current_state.stack_size(5) - 1,
                    //         TYPE(0),// storage_key_hi
                    //         TYPE(0),// storage_key_lo
                    //         TYPE(0),// field
                    //         current_state.rw_counter(5),
                    //         TYPE(0),// is_write
                    //         A_128.first,
                    //         A_128.second
                    //     };
                    //     lookup(tmp, "zkevm_rw");
                    //     tmp = {
                    //         TYPE(rw_op_to_num(rw_operation_type::stack)),
                    //         current_state.call_id(5),
                    //         current_state.stack_size(5) - 2,
                    //         TYPE(0),// storage_key_hi
                    //         TYPE(0),// storage_key_lo
                    //         TYPE(0),// field
                    //         current_state.rw_counter(5) + 1,
                    //         TYPE(0),// is_write
                    //         B_128.first,
                    //         B_128.second
                    //     };
                    //     lookup(tmp, "zkevm_rw");
                    //}
                }
            };

            template<typename FieldType>
            class zkevm_sdiv_smod_operation : public opcode_abstract<FieldType> {
            public:
                zkevm_sdiv_smod_operation(bool _is_div) : is_div(_is_div) {}
                virtual std::size_t rows_amount() override {
                    return 6 + !is_div;
                }
                virtual void fill_context(
                    typename generic_component<FieldType, GenerationStage::ASSIGNMENT>::context_type &context,
                    const opcode_input_type<FieldType, GenerationStage::ASSIGNMENT> &current_state
                ) override {
                    zkevm_sdiv_smod_bbf<FieldType, GenerationStage::ASSIGNMENT> bbf_obj(context, current_state, is_div);
                }
                virtual void fill_context(
                    typename generic_component<FieldType, GenerationStage::CONSTRAINTS>::context_type &context,
                    const opcode_input_type<FieldType, GenerationStage::CONSTRAINTS> &current_state
                ) override {
                    zkevm_sdiv_smod_bbf<FieldType, GenerationStage::CONSTRAINTS> bbf_obj(context, current_state, is_div);
                }
            protected:
                bool is_div;
            };
        } // namespace bbf
    }   // namespace blueprint
}   // namespace nil
