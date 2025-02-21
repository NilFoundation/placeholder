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
            class zkevm_calldatacopy_bbf : generic_component<FieldType, stage> {
                using typename generic_component<FieldType, stage>::context_type;
                using generic_component<FieldType, stage>::allocate;
                using generic_component<FieldType, stage>::copy_constrain;
                using generic_component<FieldType, stage>::constrain;
                using generic_component<FieldType, stage>::lookup;
                using generic_component<FieldType, stage>::lookup_table;
            public:
                using typename generic_component<FieldType,stage>::TYPE;

                zkevm_calldatacopy_bbf(context_type &context_object, const opcode_input_type<FieldType, stage> &current_state):
                    generic_component<FieldType,stage>(context_object, false)
                {
                    TYPE destOffset;
                    TYPE offset;
                    TYPE length;
                    if constexpr( stage == GenerationStage::ASSIGNMENT ){
                        destOffset = w_lo<FieldType>(current_state.stack_top());
                        offset = w_lo<FieldType>(current_state.stack_top(1));
                        length = w_lo<FieldType>(current_state.stack_top(2));
                    }
                    allocate(destOffset,32,0);
                    allocate(offset,33,0);
                    allocate(length,34,0);
                    if constexpr( stage == GenerationStage::CONSTRAINTS ){
                    //    constrain(current_state.pc_next() - current_state.pc(0) - 1);                   // PC transition
                    //    constrain(current_state.gas(0) - current_state.gas_next() - 3);                 // GAS transition
                    //    constrain(current_state.stack_size_next() - current_state.stack_size(0) - 3);   // stack_size transition
                    //    constrain(current_state.memory_size(0) - current_state.memory_size_next());     // memory_size transition
                    //    constrain(current_state.rw_counter_next() - current_state.rw_counter(0) - 2);   // rw_counter transition
                        // std::vector<TYPE> tmp;
                        // tmp = {
                        //     TYPE(rw_op_to_num(rw_operation_type::stack)),
                        //     current_state.call_id(0),
                        //     current_state.stack_size(0) - 1,
                        //     TYPE(0),// storage_key_hi
                        //     TYPE(0),// storage_key_lo
                        //     TYPE(0),// field
                        //     current_state.rw_counter(0),
                        //     TYPE(0),// is_write
                        //     TYPE(0),
                        //     destOffset
                        // };
                        // lookup(tmp, "zkevm_rw");
                        // tmp = {
                        //     TYPE(rw_op_to_num(rw_operation_type::stack)),
                        //     current_state.call_id(0),
                        //     current_state.stack_size(0) - 2,
                        //     TYPE(0),// storage_key_hi
                        //     TYPE(0),// storage_key_lo
                        //     TYPE(0),// field
                        //     current_state.rw_counter(0) + 1,
                        //     TYPE(0),// is_write
                        //     TYPE(0),
                        //     offset
                        // };
                        // lookup(tmp, "zkevm_rw");
                        // tmp = {
                        //     TYPE(rw_op_to_num(rw_operation_type::stack)),
                        //     current_state.call_id(0),
                        //     current_state.stack_size(0) - 3,
                        //     TYPE(0),// storage_key_hi
                        //     TYPE(0),// storage_key_lo
                        //     TYPE(0),// field
                        //     current_state.rw_counter(0) + 2,
                        //     TYPE(0),// is_write
                        //     TYPE(0),
                        //     length
                        // };
                        // lookup(tmp, "zkevm_rw");
                    } else {
                        std::cout << "\tSTATE transition implemented" << std::endl;
                    }
                }
            };

            template<typename FieldType>
            class zkevm_calldatacopy_operation : public opcode_abstract<FieldType> {
            public:
                virtual std::size_t rows_amount() override {
                    return 1;
                }
                virtual void fill_context(
                    typename generic_component<FieldType, GenerationStage::ASSIGNMENT>::context_type &context,
                    const opcode_input_type<FieldType, GenerationStage::ASSIGNMENT> &current_state
                ) override  {
                    zkevm_calldatacopy_bbf<FieldType, GenerationStage::ASSIGNMENT> bbf_obj(context, current_state);
                }
                virtual void fill_context(
                    typename generic_component<FieldType, GenerationStage::CONSTRAINTS>::context_type &context,
                    const opcode_input_type<FieldType, GenerationStage::CONSTRAINTS> &current_state
                ) override  {
                    zkevm_calldatacopy_bbf<FieldType, GenerationStage::CONSTRAINTS> bbf_obj(context, current_state);
                }
            };
        } // namespace bbf
    }   // namespace blueprint
}   // namespace nil
