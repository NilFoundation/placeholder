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
    class zkevm_jumpi_bbf : generic_component<FieldType, stage> {
        using typename generic_component<FieldType, stage>::context_type;
        using generic_component<FieldType, stage>::allocate;
        using generic_component<FieldType, stage>::copy_constrain;
        using generic_component<FieldType, stage>::constrain;
        using generic_component<FieldType, stage>::lookup;
        using generic_component<FieldType, stage>::lookup_table;
    public:
        using typename generic_component<FieldType,stage>::TYPE;

        zkevm_jumpi_bbf(context_type &context_object, const opcode_input_type<FieldType, stage> &current_state):
            generic_component<FieldType,stage>(context_object, false)
        {
            std::vector<TYPE> condition(16);
            TYPE addr;
            TYPE chunks_sum;
            TYPE chunks_sum_inv;
            TYPE is_jump;
            TYPE new_pc;
            if constexpr( stage == GenerationStage::ASSIGNMENT ){
                addr = nil::blueprint::w_to_16(current_state.stack_top())[15];
                auto c_chunks = nil::blueprint::w_to_16(current_state.stack_top(1));
                for( std::size_t i = 0; i < 16; i++ ){
                    condition[i] = c_chunks[i];
                    chunks_sum += c_chunks[i];
                }
                chunks_sum_inv = chunks_sum == 0?0:chunks_sum.inversed();
                is_jump = chunks_sum * chunks_sum_inv;
            }
            TYPE chunks_sum_expr;
            for( std::size_t i = 0; i < 16; i++ ){
                allocate(condition[i], i, 0);
                chunks_sum_expr += condition[i];
            }
            allocate(addr, 16, 0);
            allocate(is_jump, 17, 0);
            allocate(chunks_sum,32, 0);
            allocate(chunks_sum_inv,33, 0);

            constrain(chunks_sum_expr - chunks_sum);
            constrain(chunks_sum * (chunks_sum * chunks_sum_inv - 1));
            constrain(chunks_sum_inv * (chunks_sum * chunks_sum_inv - 1));
            constrain(is_jump - chunks_sum*chunks_sum_inv);
            if constexpr( stage == GenerationStage::CONSTRAINTS ){
                new_pc = is_jump * addr + (1 - is_jump) * (current_state.pc(0) + 1);
                auto C_128 = chunks16_to_chunks128<TYPE>(condition);

                constrain(current_state.pc_next() - new_pc);                                    // PC transition
                constrain(current_state.gas(0) - current_state.gas_next() - 10);                // GAS transition
                constrain(current_state.stack_size(0) - current_state.stack_size_next() - 2);   // stack_size transition
                constrain(current_state.memory_size(0) - current_state.memory_size_next());     // memory_size transition
                constrain(current_state.rw_counter_next() - current_state.rw_counter(0) - 2);   // rw_counter transition
                std::vector<TYPE> tmp;
                tmp = rw_table<FieldType, stage>::stack_lookup(
                    current_state.call_id(0),
                    current_state.stack_size(0) - 1,
                    current_state.rw_counter(0),
                    TYPE(0),                                                                    // is_write
                    TYPE(0),                                                                    // hi bytes are 0
                    addr
                );
                lookup(tmp, "zkevm_rw");
                tmp = rw_table<FieldType, stage>::stack_lookup(
                    current_state.call_id(0),
                    current_state.stack_size(0) - 2,
                    current_state.rw_counter(0)+1,
                    TYPE(0),                                                                    // is_write
                    C_128.first,
                    C_128.second
                );
                lookup(tmp, "zkevm_rw");
                // JUMP may be done only to JUMPDEST destination
                tmp = {
                    is_jump * TYPE(1),
                    is_jump * addr,
                    is_jump * 0x5b, // JUMPDEST opcode
                    is_jump * TYPE(1),
                    is_jump * current_state.bytecode_hash_hi(0),
                    is_jump * current_state.bytecode_hash_lo(0)
                };
                // TODO(oclaw): bytecode check is to be adjusted between nil and placeholder
                // https://github.com/NilFoundation/placeholder/issues/205
                lookup(tmp, "zkevm_bytecode");
            }
        }
    };

    template<typename FieldType>
    class zkevm_jumpi_operation : public opcode_abstract<FieldType> {
    public:
        virtual void fill_context(
            typename generic_component<FieldType, GenerationStage::ASSIGNMENT>::context_type &context,
            const opcode_input_type<FieldType, GenerationStage::ASSIGNMENT> &current_state
        ) override  {
            zkevm_jumpi_bbf<FieldType, GenerationStage::ASSIGNMENT> bbf_obj(context, current_state);
        }
        virtual void fill_context(
            typename generic_component<FieldType, GenerationStage::CONSTRAINTS>::context_type &context,
            const opcode_input_type<FieldType, GenerationStage::CONSTRAINTS> &current_state
        ) override  {
            zkevm_jumpi_bbf<FieldType, GenerationStage::CONSTRAINTS> bbf_obj(context, current_state);
        }
        virtual std::size_t rows_amount() override {
            return 1;
        }
    };
}