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

namespace nil {
    namespace blueprint {
        namespace bbf{
            template<typename FieldType>
            class opcode_abstract;

            template<typename FieldType, GenerationStage stage>
            class zkevm_calldatasize_bbf : generic_component<FieldType, stage> {
                using typename generic_component<FieldType, stage>::context_type;
                using generic_component<FieldType, stage>::allocate;
                using generic_component<FieldType, stage>::copy_constrain;
                using generic_component<FieldType, stage>::constrain;
                using generic_component<FieldType, stage>::lookup;
                using generic_component<FieldType, stage>::lookup_table;
            public:
                using typename generic_component<FieldType,stage>::TYPE;

                zkevm_calldatasize_bbf(context_type &context_object, const opcode_input_type<FieldType, stage> &current_state):
                    generic_component<FieldType,stage>(context_object, false)
                {
                    TYPE calldatasize;
                    if constexpr( stage == GenerationStage::ASSIGNMENT ){
                        calldatasize = current_state.calldatasize();
                    }
                    allocate(calldatasize, 0, 0);

                    if constexpr( stage == GenerationStage::CONSTRAINTS ){
                        constrain(current_state.pc_next() - current_state.pc(0) - 1);                   // PC transition
                        constrain(current_state.gas(0) - current_state.gas_next() - 2);                 // GAS transition
                        constrain(current_state.stack_size_next() - current_state.stack_size(0) - 1);   // stack_size transition
                        constrain(current_state.memory_size(0) - current_state.memory_size_next());     // memory_size transition
                        constrain(current_state.rw_counter_next() - current_state.rw_counter(0) - 1);   // rw_counter transition

                        // CALLDATASIZE is correct for current call_id
                        lookup(rw_table<FieldType, stage>::call_context_lookup(
                            current_state.call_id(0),
                            std::size_t(call_context_field::calldata_size),
                            TYPE(0),
                            calldatasize
                        ), "zkevm_rw");

                        // calldatasize was successfully written to stack
                        lookup(rw_table<FieldType, stage>::stack_lookup(
                            current_state.call_id(0),
                            current_state.stack_size(0),
                            current_state.rw_counter(0),
                            TYPE(1),                                               // is_write
                            TYPE(0),
                            calldatasize
                        ), "zkevm_rw");
                    }
                }
            };

            template<typename FieldType>
            class zkevm_calldatasize_operation : public opcode_abstract<FieldType> {
            public:
                virtual std::size_t rows_amount() override {
                    return 1;
                }
                virtual void fill_context(
                    typename generic_component<FieldType, GenerationStage::ASSIGNMENT>::context_type &context,
                    const opcode_input_type<FieldType, GenerationStage::ASSIGNMENT> &current_state
                ) override  {
                    zkevm_calldatasize_bbf<FieldType, GenerationStage::ASSIGNMENT> bbf_obj(context, current_state);
                }
                virtual void fill_context(
                    typename generic_component<FieldType, GenerationStage::CONSTRAINTS>::context_type &context,
                    const opcode_input_type<FieldType, GenerationStage::CONSTRAINTS> &current_state
                ) override  {
                    zkevm_calldatasize_bbf<FieldType, GenerationStage::CONSTRAINTS> bbf_obj(context, current_state);
                }
            };
        } // namespace bbf
    }   // namespace blueprint
}   // namespace nil
