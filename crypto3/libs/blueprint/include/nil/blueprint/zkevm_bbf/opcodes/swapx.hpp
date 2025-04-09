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

#include <nil/blueprint/zkevm_bbf/types/opcode.hpp>
#include <nil/blueprint/zkevm_bbf/types/rw_operation.hpp>

namespace nil {
    namespace blueprint {
        namespace bbf{
            template<typename FieldType>
            class opcode_abstract;

            template<typename FieldType, GenerationStage stage>
            class zkevm_swapx_bbf : generic_component<FieldType, stage> {
                using typename generic_component<FieldType, stage>::context_type;
                using generic_component<FieldType, stage>::allocate;
                using generic_component<FieldType, stage>::copy_constrain;
                using generic_component<FieldType, stage>::constrain;
                using generic_component<FieldType, stage>::lookup;
                using generic_component<FieldType, stage>::lookup_table;
            public:
                using typename generic_component<FieldType,stage>::TYPE;

                zkevm_swapx_bbf(context_type &context_object, const opcode_input_type<FieldType, stage> &current_state, std::size_t x):
                    generic_component<FieldType,stage>(context_object, false)
                {
                    std::vector<TYPE> A_chunks(16);
                    std::vector<TYPE> B_chunks(16);
                    if constexpr( stage == GenerationStage::ASSIGNMENT ){
                        // std::cout << "\tinput=" << std::hex << current_state.additional_input << std::dec << std::endl;
                        auto A = current_state.stack_top();
                        auto A16 = nil::blueprint::w_to_16(A);
                        auto B = current_state.stack_top(x);
                        auto B16 = nil::blueprint::w_to_16(B);
                        for( std::size_t i = 0; i < 16; i++ ){
                            A_chunks[i] = A16[i];
                            B_chunks[i] = B16[i];
                        }
                    }
                    for( std::size_t i = 0; i < 16; i++){
                        allocate(A_chunks[i], i, 0);
                        allocate(B_chunks[i], i+16, 0);
                    }
                    if constexpr( stage == GenerationStage::CONSTRAINTS ){
                        constrain(current_state.pc_next() - current_state.pc(0) - 1);                   // PC transition
                        constrain(current_state.gas(0) - current_state.gas_next() - 3);                 // GAS transition
                        constrain(current_state.stack_size_next() - current_state.stack_size(0));       // stack_size transition
                        constrain(current_state.memory_size(0) - current_state.memory_size_next());     // memory_size transition
                        constrain(current_state.rw_counter_next() - current_state.rw_counter(0) - 4);   // rw_counter transition
                        auto A_128 = chunks16_to_chunks128<TYPE>(A_chunks);
                        auto B_128 = chunks16_to_chunks128<TYPE>(B_chunks);
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
                            current_state.stack_size(0) - x - 1,
                            current_state.rw_counter(0) + 1,
                            TYPE(0),// is_write
                            B_128.first,
                            B_128.second
                        );
                        lookup(tmp, "zkevm_rw");
                        tmp = rw_table<FieldType, stage>::stack_lookup(
                            current_state.call_id(0),
                            current_state.stack_size(0) - x - 1,
                            current_state.rw_counter(0) + 2,
                            TYPE(1),// is_write
                            A_128.first,
                            A_128.second
                        );
                        lookup(tmp, "zkevm_rw");
                        tmp = rw_table<FieldType, stage>::stack_lookup(
                            current_state.call_id(0),
                            current_state.stack_size(0) - 1,
                            current_state.rw_counter(0) + 3,
                            TYPE(1),// is_write
                            B_128.first,
                            B_128.second
                        );
                        lookup(tmp, "zkevm_rw");
                    }
                }
            };


            template<typename FieldType>
            class zkevm_swapx_operation : public opcode_abstract<FieldType> {
            public:
                virtual void fill_context(
                    typename generic_component<FieldType, GenerationStage::ASSIGNMENT>::context_type &context,
                    const opcode_input_type<FieldType, GenerationStage::ASSIGNMENT> &current_state
                ) override  {
                    zkevm_swapx_bbf<FieldType, GenerationStage::ASSIGNMENT> bbf_obj(context, current_state, x);
                }
                virtual void fill_context(
                    typename generic_component<FieldType, GenerationStage::CONSTRAINTS>::context_type &context,
                    const opcode_input_type<FieldType, GenerationStage::CONSTRAINTS> &current_state
                ) override  {
                    zkevm_swapx_bbf<FieldType, GenerationStage::CONSTRAINTS> bbf_obj(context, current_state, x);
                }

                virtual std::size_t rows_amount() override {
                    return 1;
                }
                zkevm_swapx_operation(std::size_t _x):x(_x){
                }
            protected:
                std::size_t x;
            };
        } // namespace bbf
    }   // namespace blueprint
}   // namespace nil
