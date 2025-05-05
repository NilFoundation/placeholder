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

#include <nil/blueprint/zkevm_bbf/big_field/opcodes/abstract_opcode.hpp>

namespace nil::blueprint::bbf::zkevm_big_field{
    /*
    *  Opcode: 0x19 NOT
    *  Description: Bitwise NOT operation
    *  GAS: 3
    *  PC: +1
    *  Memory: Unchanged
    *  Stack Input: a
    *  Stack Output: ~a
    *  Stack Read  Lookup: a
    *  Stack Write Lookup: ~a
    *  rw_counter: +2
    */
    template<typename FieldType, GenerationStage stage>
    class zkevm_not_bbf : generic_component<FieldType, stage> {
        using typename generic_component<FieldType, stage>::context_type;
        using generic_component<FieldType, stage>::allocate;
        using generic_component<FieldType, stage>::copy_constrain;
        using generic_component<FieldType, stage>::constrain;
        using generic_component<FieldType, stage>::lookup;
        using generic_component<FieldType, stage>::lookup_table;
    public:
        using typename generic_component<FieldType,stage>::TYPE;

        zkevm_not_bbf(context_type &context_object, const opcode_input_type<FieldType, stage> &current_state):
            generic_component<FieldType,stage>(context_object, false)
        {

            std::vector<TYPE> A(16); // 16-bit chunks of a
            std::vector<TYPE> R(16); // 16-bit chunks of ~a

            if constexpr( stage == GenerationStage::ASSIGNMENT ){
                // split a (stack top) to 16-bit chunks
                auto a = w_to_16(current_state.stack_top());
                for( std::size_t i = 0; i < 16; i++ ){
                    A[i] = a[i];
                }
            }

            /* Layout:         range_checked_opcode_area
                    0      1     ...    15     16     17     ...    31
                +------+------+------+------+------+------+------+------+
                | A[0] | A[1] |  ... | A[15]| R[0] | R[1] |  ... | R[15]|
                +------+------+------|------+------+------+------|------+
            */
            for( std::size_t i = 0; i < 16; i++ ){
                allocate(A[i], i, 0);
                R[i] = 0xFFFF - A[i]; // 16-bit bitwise NOT
                allocate(R[i], i + 16, 0);  // implicit constraint R[i] - (0xFFFF - A[i])
            }

            // combine 16-bit chunks to make 128-bit chunks
            auto A_128 = chunks16_to_chunks128<TYPE>(A);  // 128-bit chunks of a
            auto R_128 = chunks16_to_chunks128<TYPE>(R);  // 128-bit chunks of ~a
            if constexpr( stage == GenerationStage::CONSTRAINTS ){
                constrain(current_state.pc_next() - current_state.pc(0) - 1);                   // PC transition
                constrain(current_state.gas(0) - current_state.gas_next() - 3);                 // GAS transition
                constrain(current_state.stack_size(0) - current_state.stack_size_next());       // stack_size transition
                constrain(current_state.memory_size(0) - current_state.memory_size_next());     // memory_size transition
                constrain(current_state.rw_counter_next() - current_state.rw_counter(0) - 2);   // rw_counter transition
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
                    current_state.stack_size(0) - 1,
                    current_state.rw_counter(0) + 1,
                    TYPE(1),// is_write
                    R_128.first,
                    R_128.second
                );
                lookup(tmp, "zkevm_rw");
            }
        }
    };

    template<typename FieldType>
    class zkevm_not_operation : public opcode_abstract<FieldType> {
    public:
        virtual void fill_context(
            typename generic_component<FieldType, GenerationStage::ASSIGNMENT>::context_type &context,
            const opcode_input_type<FieldType, GenerationStage::ASSIGNMENT> &current_state
        ) override  {
            zkevm_not_bbf<FieldType, GenerationStage::ASSIGNMENT> bbf_obj(context, current_state);
        }
        virtual void fill_context(
            typename generic_component<FieldType, GenerationStage::CONSTRAINTS>::context_type &context,
            const opcode_input_type<FieldType, GenerationStage::CONSTRAINTS> &current_state
        ) override  {
            zkevm_not_bbf<FieldType, GenerationStage::CONSTRAINTS> bbf_obj(context, current_state);
        }
        virtual std::size_t rows_amount() override {
            return 1;
        }
    };
}