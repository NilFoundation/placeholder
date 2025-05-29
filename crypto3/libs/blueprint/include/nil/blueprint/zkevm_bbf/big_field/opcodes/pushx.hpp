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
    class zkevm_pushx_bbf : generic_component<FieldType, stage> {
        using typename generic_component<FieldType, stage>::context_type;
        using generic_component<FieldType, stage>::allocate;
        using generic_component<FieldType, stage>::copy_constrain;
        using generic_component<FieldType, stage>::constrain;
        using generic_component<FieldType, stage>::lookup;
        using generic_component<FieldType, stage>::lookup_table;
    public:
        using typename generic_component<FieldType,stage>::TYPE;

        zkevm_pushx_bbf(context_type &context_object, const opcode_input_type<FieldType, stage> &current_state, std::size_t x):
            generic_component<FieldType,stage>(context_object, false)
        {
            std::vector<TYPE> A_bytes(32);
            if constexpr( stage == GenerationStage::ASSIGNMENT ){
                auto bytes = nil::blueprint::w_to_8(current_state.additional_input());
                for( std::size_t i = 0; i < 32; i++ ){
                    A_bytes[i] = bytes[i];
                }
            }
            for( std::size_t i = 0; i < 16; i++){
                allocate(A_bytes[i], i, 0);
                allocate(A_bytes[i + 16], i, 1);
            }
            if constexpr( stage == GenerationStage::CONSTRAINTS ){
                constrain(current_state.pc_next() - current_state.pc(1) - x - 1);                   // PC transition
                if( x == 0 )
                    constrain(current_state.gas(1) - current_state.gas_next() - 2);                 // GAS transition
                else
                    constrain(current_state.gas(1) - current_state.gas_next() - 3);                 // GAS transition
                constrain(current_state.stack_size_next() - current_state.stack_size(1) - 1);       // stack_size transition
                constrain(current_state.memory_size(1) - current_state.memory_size_next());     // memory_size transition
                constrain(current_state.rw_counter_next() - current_state.rw_counter(1) - 1);   // rw_counter transition
                auto A_128 = chunks8_to_chunks128<TYPE>(A_bytes);
                std::vector<TYPE> tmp;
                tmp = rw_table<FieldType, stage>::stack_lookup(
                    current_state.call_id(0),
                    current_state.stack_size(0),
                    current_state.rw_counter(0),
                    TYPE(1),// is_write
                    A_128.first,
                    A_128.second
                );
                lookup(tmp, "zkevm_rw");
                for( std::size_t i = 0; i < 32 - x; i++){
                    constrain(A_bytes[i]);
                }
                for( std::size_t j = 32-x; j < 32; j++){
                    if( j < 16 ){
                        tmp = {
                            TYPE(1),
                            current_state.pc(0) + j - (32 - x) + 1,
                            A_bytes[j],
                            TYPE(0),
                            current_state.bytecode_hash_hi(0),
                            current_state.bytecode_hash_lo(0)
                        };
                    } else {
                        tmp = {
                            TYPE(1),
                            current_state.pc(1) + j - (32 - x) + 1,
                            A_bytes[j],
                            TYPE(0),
                            current_state.bytecode_hash_hi(1),
                            current_state.bytecode_hash_lo(1)
                        };
                    }
                    // TODO(oclaw): bytecode check is to be adjusted between nil and placeholder
                    // https://github.com/NilFoundation/placeholder/issues/205
                    lookup(tmp, "zkevm_bytecode");
                }
            }
        }
    };


    template<typename FieldType>
    class zkevm_pushx_operation : public opcode_abstract<FieldType> {
    public:
        zkevm_pushx_operation(std::size_t _x):x(_x){
        }
        virtual void fill_context(
            typename generic_component<FieldType, GenerationStage::ASSIGNMENT>::context_type &context,
            const opcode_input_type<FieldType, GenerationStage::ASSIGNMENT> &current_state
        ) override  {
            zkevm_pushx_bbf<FieldType, GenerationStage::ASSIGNMENT> bbf_obj(context, current_state, x);
        }
        virtual void fill_context(
            typename generic_component<FieldType, GenerationStage::CONSTRAINTS>::context_type &context,
            const opcode_input_type<FieldType, GenerationStage::CONSTRAINTS> &current_state
        ) override  {
            zkevm_pushx_bbf<FieldType, GenerationStage::CONSTRAINTS> bbf_obj(context, current_state, x);
        }
        virtual std::size_t rows_amount() override {
            return 2;
        }
    protected:
        std::size_t x;
    };
}