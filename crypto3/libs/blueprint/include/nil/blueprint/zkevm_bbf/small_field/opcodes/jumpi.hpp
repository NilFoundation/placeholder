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

#include <nil/blueprint/zkevm_bbf/small_field/opcodes/abstract_opcode.hpp>

namespace nil::blueprint::bbf::zkevm_small_field{
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
            // ! Not finished
            // TODO: Current implementation does not process JUMP errors such as JUMP to non-JUMPDEST, e t.c.
            std::vector<TYPE> condition(16);
            std::vector<TYPE> addr_chunks(16);
            TYPE chunks_sum;
            TYPE chunks_sum_inv;
            TYPE is_jump;
            TYPE new_pc;
            if constexpr( stage == GenerationStage::ASSIGNMENT ){
                auto a_chunks = nil::blueprint::w_to_16(current_state.stack_top());
                auto c_chunks = nil::blueprint::w_to_16(current_state.stack_top(1));
                for( std::size_t i = 0; i < 16; i++ ){
                    addr_chunks[i] = a_chunks[i];
                    condition[i] = c_chunks[i];
                    chunks_sum += c_chunks[i];
                }
                chunks_sum_inv = chunks_sum == 0?0:chunks_sum.inversed();
                is_jump = chunks_sum * chunks_sum_inv;
            }
            TYPE chunks_sum_expr;
            for( std::size_t i = 0; i < 16; i++ ){
                allocate(condition[i], i, 0);
                allocate(addr_chunks[i], i + 16, 0);
                chunks_sum_expr += condition[i];
            }
            allocate(is_jump, 32, 0);
            allocate(chunks_sum,33, 0);
            allocate(chunks_sum_inv,34, 0);

            constrain(chunks_sum_expr - chunks_sum);
            constrain(chunks_sum * (is_jump - 1));
            constrain(chunks_sum_inv * (is_jump - 1));
            constrain(is_jump - chunks_sum*chunks_sum_inv);
            if constexpr( stage == GenerationStage::CONSTRAINTS ){
                auto addr = addr_chunks[15];
                new_pc = is_jump * addr + (1 - is_jump) * (current_state.pc(0) + 1);

                constrain(current_state.pc_next() - new_pc);                                    // PC transition
                constrain(current_state.gas(0) - current_state.gas_next() - 10);                // GAS transition
                constrain(current_state.stack_size(0) - current_state.stack_size_next() - 2);   // stack_size transition
                constrain(current_state.memory_size(0) - current_state.memory_size_next());     // memory_size transition
                constrain(current_state.rw_counter_next() - current_state.rw_counter(0) - 2);   // rw_counter transition
                std::vector<TYPE> tmp;
                lookup(rw_256_table<FieldType, stage>::stack_16_bit_lookup(
                    current_state.call_id(0),
                    current_state.stack_size(0) - 1,
                    current_state.rw_counter(0),
                    TYPE(0),                                                                    // is_write
                    addr_chunks
                ), "zkevm_rw_256");
                lookup(rw_256_table<FieldType, stage>::stack_16_bit_lookup(
                    current_state.call_id(0),
                    current_state.stack_size(0) - 2,
                    current_state.rw_counter(0)+1,
                    TYPE(0),                                                                    // is_write
                    condition
                ), "zkevm_rw_256");
                // JUMP may be done only to JUMPDEST destination
                lookup({
                    is_jump * TYPE(2),  // It's executed opcode, not header, not metadata
                    is_jump * addr,
                    is_jump * 0x5b,     // JUMPDEST opcode
                    is_jump * TYPE(1),  // is_opcode = 1
                    is_jump * current_state.bytecode_id(0),
                }, "zkevm_bytecode");
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