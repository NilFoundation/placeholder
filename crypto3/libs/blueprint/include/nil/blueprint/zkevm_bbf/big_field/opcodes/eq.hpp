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
    template<typename FieldType, GenerationStage stage>
    class zkevm_eq_bbf : generic_component<FieldType, stage> {
        using typename generic_component<FieldType, stage>::context_type;
        using generic_component<FieldType, stage>::allocate;
        using generic_component<FieldType, stage>::copy_constrain;
        using generic_component<FieldType, stage>::constrain;
        using generic_component<FieldType, stage>::lookup;
        using generic_component<FieldType, stage>::lookup_table;
    public:
        using typename generic_component<FieldType,stage>::TYPE;

        zkevm_eq_bbf(context_type &context_object, const opcode_input_type<FieldType, stage> &current_state):
            generic_component<FieldType,stage>(context_object, false)
        {
            // | a | b | R_hi_inv | R_lo_inv | r_hi | r_lo | r
            std::vector<TYPE> A(16);
            std::vector<TYPE> B(16);
            TYPE R_hi_inv;
            TYPE R_lo_inv;
            TYPE r_hi;
            TYPE r_lo;
            TYPE r;
            if constexpr( stage == GenerationStage::ASSIGNMENT ){
                auto a = w_to_16(current_state.stack_top());
                auto b = w_to_16(current_state.stack_top(1));
                for( std::size_t i = 0; i < 16; i++ ){
                    A[i] = a[i];
                    B[i] = b[i];
                }
                TYPE A_hi, A_lo, B_hi, B_lo;
                for( std::size_t i = 0; i < 8; i++){
                    A_hi *= 0x10000; A_hi += A[i];
                    A_lo *= 0x10000; A_lo += A[i + 8];
                    B_hi *= 0x10000; B_hi += B[i];
                    B_lo *= 0x10000; B_lo += B[i + 8];
                }
                R_hi_inv = (A_hi - B_hi) == 0? 0: (A_hi - B_hi).inversed();
                R_lo_inv = (A_lo - B_lo) == 0? 0: (A_lo - B_lo).inversed();
                r_hi = ((A_hi - B_hi) == 0);
                r_lo = ((A_lo - B_lo) == 0);
                r = r_hi * r_lo;
            }
            for( std::size_t i = 0; i < 16; i++ ){
                allocate(A[i], i, 0);
                allocate(B[i], i + 16, 0);
            }
            allocate(R_hi_inv, 32, 0);
            allocate(R_lo_inv, 33, 0);
            allocate(r_hi, 34, 0);
            allocate(r_lo, 35, 0);
            allocate(r, 36, 0);

            auto A_128 = chunks16_to_chunks128<TYPE>(A);
            auto B_128 = chunks16_to_chunks128<TYPE>(B);
            constrain( R_hi_inv *((A_128.first - B_128.first) * R_hi_inv - 1));
            constrain( (A_128.first - B_128.first) *((A_128.first - B_128.first) * R_hi_inv - 1));
            // constrain( R_lo_inv *((A_128.second - B_128.second) * R_lo_inv - 1));
            // constrain( (A_128.second - B_128.second) *((A_128.second - B_128.second) * R_lo_inv - 1));
            // constrain( r_hi - 1 + (A_128.first - B_128.first) * R_hi_inv );
            // constrain( r_lo - 1 + (A_128.first - B_128.first) * R_lo_inv );
            // constrain( r - r_hi * r_lo);
            if constexpr( stage == GenerationStage::CONSTRAINTS ){
                constrain(current_state.pc_next() - current_state.pc(0) - 1);                   // PC transition
                constrain(current_state.gas(0) - current_state.gas_next() - 3);                 // GAS transition
                constrain(current_state.stack_size(0) - current_state.stack_size_next() - 1);   // stack_size transition
                constrain(current_state.memory_size(0) - current_state.memory_size_next());     // memory_size transition
                constrain(current_state.rw_counter_next() - current_state.rw_counter(0) - 3);   // rw_counter transition
                std::vector<TYPE> tmp;
                tmp = rw_table<FieldType, stage>::stack_lookup(
                    current_state.call_id(0),
                    current_state.stack_size(0) - 1,
                    current_state.rw_counter(0),
                    TYPE(0),                                               // is_write
                    A_128.first,
                    A_128.second
                );
                lookup(tmp, "zkevm_rw");
                tmp = rw_table<FieldType, stage>::stack_lookup(
                    current_state.call_id(0),
                    current_state.stack_size(0) - 2,
                    current_state.rw_counter(0) + 1,
                    TYPE(0),
                    B_128.first,
                    B_128.second
                );
                lookup(tmp, "zkevm_rw");
                tmp = rw_table<FieldType, stage>::stack_lookup(
                    current_state.call_id(0),
                    current_state.stack_size(0) - 2,
                    current_state.rw_counter(0) + 2,
                    TYPE(1),                                               // is_write
                    TYPE(0),                                               // hi bytes are 0
                    r
                );
                lookup(tmp, "zkevm_rw");
            }
        }
    };
    template<typename FieldType>
    class zkevm_eq_operation : public opcode_abstract<FieldType> {
    public:
        zkevm_eq_operation(){}
        virtual std::size_t rows_amount() override {
            return 1;
        }
        virtual void fill_context(
            typename generic_component<FieldType, GenerationStage::ASSIGNMENT>::context_type &context,
            const opcode_input_type<FieldType, GenerationStage::ASSIGNMENT> &current_state
        ) override  {
            zkevm_eq_bbf<FieldType, GenerationStage::ASSIGNMENT> bbf_obj(context, current_state);
        }
        virtual void fill_context(
            typename generic_component<FieldType, GenerationStage::CONSTRAINTS>::context_type &context,
            const opcode_input_type<FieldType, GenerationStage::CONSTRAINTS> &current_state
        ) override  {
            zkevm_eq_bbf<FieldType, GenerationStage::CONSTRAINTS> bbf_obj(context, current_state);
        }
    };
}