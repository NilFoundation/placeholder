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

#include <nil/blueprint/zkevm_bbf/big_field/opcodes/abstract_opcode.hpp>

namespace nil::blueprint::bbf::zkevm_big_field{
    template<typename FieldType, GenerationStage stage>
    class zkevm_calldataload_bbf : generic_component<FieldType, stage> {
        using typename generic_component<FieldType, stage>::context_type;
        using generic_component<FieldType, stage>::allocate;
        using generic_component<FieldType, stage>::copy_constrain;
        using generic_component<FieldType, stage>::constrain;
        using generic_component<FieldType, stage>::lookup;
        using generic_component<FieldType, stage>::lookup_table;
    public:
        using typename generic_component<FieldType,stage>::TYPE;

        zkevm_calldataload_bbf(context_type &context_object, const opcode_input_type<FieldType, stage> &current_state):
            generic_component<FieldType,stage>(context_object, false)
        {
            TYPE offset;                        // Offset
            std::vector<TYPE> bytes(32);        // Loaded value

            if constexpr( stage == GenerationStage::ASSIGNMENT ){
                auto address = w_to_16(current_state.stack_top())[15];
                offset = address;
                for (std::size_t i = 0; i < 32; i++) {
                    bytes[i] = current_state.calldata(address + i);
                }
            }
            // Allocate bytes in two rows to prevent too much of lookup constraints to rw_table
            for (std::size_t i = 0; i < 16; i++) {
                allocate(bytes[i], i + 16, 0);
                allocate(bytes[i + 16], i + 16, 1);
            }
            allocate(offset,0,0);
            auto V_128 = chunks8_to_chunks128<TYPE>(bytes);

            if constexpr( stage == GenerationStage::CONSTRAINTS ){
                constrain(current_state.pc_next() - current_state.pc(0) - 1);                   // PC transition
                constrain(current_state.gas(0) - current_state.gas_next() - 3);                 // GAS transition
                constrain(current_state.stack_size_next() - current_state.stack_size(0));   // stack_size transition
                constrain(current_state.memory_size(0) - current_state.memory_size_next());     // memory_size transition
                constrain(current_state.rw_counter_next() - current_state.rw_counter(0) - 34);   // rw_counter transition

                // Read offset from stack
                lookup(rw_table<FieldType, stage>::stack_lookup(
                    current_state.call_id(1),
                    current_state.stack_size(1) - 1,
                    current_state.rw_counter(1),
                    TYPE(0),                                               // is_write
                    TYPE(0),                                               // hi bytes are 0
                    offset
                ), "zkevm_rw");

                // Read 32 bytes from calldata
                for( std::size_t i = 0; i < 32; i++ ){
                    if( i < 16 ){
                        lookup(rw_table<FieldType, stage>::calldata_r_lookup(
                            current_state.call_id(0),
                            offset + i,
                            current_state.rw_counter(0) + i + 1,
                            bytes[i]
                        ), "zkevm_rw");
                    } else {
                        lookup(rw_table<FieldType, stage>::calldata_r_lookup(
                            current_state.call_id(1),
                            offset + i,
                            current_state.rw_counter(1) + i + 1,
                            bytes[i]
                        ), "zkevm_rw");
                    }
                }

                // Write result to stack
                lookup(rw_table<FieldType, stage>::stack_lookup(
                    current_state.call_id(1),
                    current_state.stack_size(1) - 1,
                    current_state.rw_counter(1) + 33,
                    TYPE(1),                                               // is_write
                    V_128.first,                                           // hi bytes are 0
                    V_128.second
                ), "zkevm_rw");
            }
        }
    };

    template<typename FieldType>
    class zkevm_calldataload_operation : public opcode_abstract<FieldType> {
    public:
        virtual std::size_t rows_amount() override {
            return 2;
        }
        virtual void fill_context(
            typename generic_component<FieldType, GenerationStage::ASSIGNMENT>::context_type &context,
            const opcode_input_type<FieldType, GenerationStage::ASSIGNMENT> &current_state
        ) override  {
            zkevm_calldataload_bbf<FieldType, GenerationStage::ASSIGNMENT> bbf_obj(context, current_state);
        }
        virtual void fill_context(
            typename generic_component<FieldType, GenerationStage::CONSTRAINTS>::context_type &context,
            const opcode_input_type<FieldType, GenerationStage::CONSTRAINTS> &current_state
        ) override  {
            zkevm_calldataload_bbf<FieldType, GenerationStage::CONSTRAINTS> bbf_obj(context, current_state);
        }
    };
}
