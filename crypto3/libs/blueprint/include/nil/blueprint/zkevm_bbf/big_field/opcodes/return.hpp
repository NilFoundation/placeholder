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

#include <nil/blueprint/zkevm_bbf/types/zkevm_word.hpp>
#include <nil/blueprint/zkevm_bbf/big_field/subcomponents/memory_cost.hpp>
#include <nil/blueprint/zkevm_bbf/types/copy_event.hpp>
#include <nil/blueprint/zkevm_bbf/big_field/opcodes/abstract_opcode.hpp>

namespace nil::blueprint::bbf::zkevm_big_field{
    template<typename FieldType, GenerationStage stage>
    class zkevm_return_bbf : generic_component<FieldType, stage> {
        using typename generic_component<FieldType, stage>::context_type;
        using generic_component<FieldType, stage>::allocate;
        using generic_component<FieldType, stage>::copy_constrain;
        using generic_component<FieldType, stage>::constrain;
        using generic_component<FieldType, stage>::lookup;
        using generic_component<FieldType, stage>::lookup_table;
    public:
        using typename generic_component<FieldType,stage>::TYPE;

        zkevm_return_bbf(context_type &context_object, const opcode_input_type<FieldType, stage> &current_state):
            generic_component<FieldType,stage>(context_object, false){
            using Memory_Cost = typename zkevm_big_field::memory_cost<FieldType, stage>;

            TYPE offset, length, length_inv, depth, depth_inv, is_length_zero;
            TYPE current_mem, next_mem, memory_expansion_cost, memory_expansion_size, S;

            if constexpr( stage == GenerationStage::ASSIGNMENT ){
                offset = w_lo<FieldType>(current_state.stack_top());
                length = w_lo<FieldType>(current_state.stack_top(1));
                current_mem = current_state.memory_size();
                next_mem = length.is_zero()? current_mem : std::max(offset + length, current_mem);
                S = next_mem > current_mem;
                length_inv = length == 0? 0: length.inversed();
                is_length_zero = length == 0? 0: 1;
                depth = current_state.depth() - 2;
                depth_inv = depth == 0? 0: depth.inversed();
            }
            allocate(depth, 0, 0);
            allocate(offset, 32, 0);
            allocate(length, 33, 0);
            allocate(current_mem, 34, 0);
            allocate(next_mem, 35, 0);
            allocate(S, 36, 0);

            allocate(memory_expansion_cost, 32, 1);
            allocate(memory_expansion_size, 33, 1);
            allocate(length_inv, 34, 1);
            allocate(depth_inv, 35, 1);
            allocate(is_length_zero, 1, 0);

            // length_inv is correct
            constrain(length * (length * length_inv - 1));
            constrain(length_inv * (length * length_inv - 1));
            constrain(is_length_zero - length * length_inv);

            // depth_inv is correct
            constrain(depth * (depth * depth_inv - 1));
            constrain(depth_inv * (depth * depth_inv - 1));
            // if depth == 0 then end_transaction else end_call
            TYPE next_opcode =
                depth * depth_inv * TYPE(std::size_t(opcode_to_number(zkevm_opcode::end_call))) +
                (1 - depth * depth_inv) * TYPE(std::size_t(opcode_to_number(zkevm_opcode::end_transaction)));
            // // std::cout << "Next opcode = " << std::hex << next_opcode << std::endl;
            // // std::cout << "Depth = " << depth << std::endl;
            allocate(next_opcode, 36, 1);

            std::vector<std::size_t> memory_cost_lookup_area = {42, 43, 44,
                                                                45, 46, 47};

            context_type current_memory_ct =
                context_object.subcontext(memory_cost_lookup_area, 0, 1);
            context_type next_memory_ct =
                context_object.subcontext(memory_cost_lookup_area, 1, 1);

            Memory_Cost current_memory =
                Memory_Cost(current_memory_ct, current_mem);
            Memory_Cost next_memory = Memory_Cost(next_memory_ct, next_mem);
            memory_expansion_cost = next_memory.cost - current_memory.cost;
            memory_expansion_size =
                (next_memory.word_size - current_memory.word_size) * 32;
            if constexpr( stage == GenerationStage::CONSTRAINTS ){
                // constrain(current_state.pc_next() - current_state.pc(0) - 1);                           // PC transition
                constrain(current_state.gas(0) - current_state.gas_next()  - memory_expansion_cost);       // GAS transition
                // constrain(current_state.stack_size(0) - current_state.stack_size_next());               // stack_size transition
                // constrain(current_state.memory_size(0) - current_state.memory_size_next());             // memory_size transition
                //constrain(current_state.rw_counter_next() - current_state.rw_counter(0) - 3 - 2 * length); // rw_counter transition
                constrain(current_state.opcode_next() - next_opcode); // Next opcode restrictions

                lookup(rw_table<FieldType, stage>::stack_lookup(
                    current_state.call_id(0),
                    current_state.stack_size(0) - 1,
                    current_state.rw_counter(0),
                    TYPE(0),// is_write
                    TYPE(0),// hi bytes are 0
                    offset
                ), "zkevm_rw");
                lookup(rw_table<FieldType, stage>::stack_lookup(
                    current_state.call_id(0),
                    current_state.stack_size(0) - 2,
                    current_state.rw_counter(0) + 1,
                    TYPE(0),// is_write
                    TYPE(0),// hi bytes are 0
                    length
                ), "zkevm_rw");
                lookup(rw_table<FieldType, stage>::call_context_lookup(
                    current_state.call_id(0),
                    std::size_t(call_context_field::depth),
                    TYPE(0),
                    depth + 2
                ), "zkevm_rw");
                lookup({
                    is_length_zero,                                                       // is_first
                    TYPE(0),                                                                   // is_write
                    is_length_zero * TYPE(copy_op_to_num(copy_operand_type::memory)),     // cp_type
                    TYPE(0),                                                                   // id_hi
                    is_length_zero * current_state.call_id(0),                            // id_lo
                    is_length_zero * offset,                                              // counter_1
                    is_length_zero * (current_state.rw_counter(0) + 2),                   // counter_2
                    length
                }, "zkevm_copy");
                lookup({
                    is_length_zero,                                                          // is_first
                    is_length_zero,                                                          // is_write
                    is_length_zero * TYPE(copy_op_to_num(copy_operand_type::returndata)),    // cp_type
                    TYPE(0),                                                                      // id_hi
                    is_length_zero * current_state.call_id(0),                               // id_lo
                    TYPE(0),                                                                      // counter_1
                    is_length_zero * (current_state.rw_counter(0) + length + 2),             // counter_2
                    length
                }, "zkevm_copy");
                lookup({
                    rw_table<FieldType, stage>::call_context_lookup(
                        current_state.call_id(0),
                        std::size_t(call_context_field::call_status),
                        TYPE(0),
                        TYPE(1)
                    )
                }, "zkevm_rw");
            }
        }
    };

    template<typename FieldType>
    class zkevm_return_operation : public opcode_abstract<FieldType> {
    public:
        virtual void fill_context(
            typename generic_component<FieldType, GenerationStage::ASSIGNMENT>::context_type &context,
            const opcode_input_type<FieldType, GenerationStage::ASSIGNMENT> &current_state
        ) override {
            zkevm_return_bbf<FieldType, GenerationStage::ASSIGNMENT> bbf_obj(context, current_state);
        }
        virtual void fill_context(
            typename generic_component<FieldType, GenerationStage::CONSTRAINTS>::context_type &context,
            const opcode_input_type<FieldType, GenerationStage::CONSTRAINTS> &current_state
        ) override {
            zkevm_return_bbf<FieldType, GenerationStage::CONSTRAINTS> bbf_obj(context, current_state);
        }
        virtual std::size_t rows_amount() override {
            return 2;
        }
    };
}