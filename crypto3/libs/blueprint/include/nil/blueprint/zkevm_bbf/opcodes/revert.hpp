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
            class zkevm_revert_bbf : generic_component<FieldType, stage> {
                using typename generic_component<FieldType, stage>::context_type;
                using generic_component<FieldType, stage>::allocate;
                using generic_component<FieldType, stage>::copy_constrain;
                using generic_component<FieldType, stage>::constrain;
                using generic_component<FieldType, stage>::lookup;
                using generic_component<FieldType, stage>::lookup_table;
            public:
                using typename generic_component<FieldType,stage>::TYPE;
                using value_type = typename FieldType::value_type;
                constexpr static const value_type two_128 = 0x100000000000000000000000000000000_big_uint254;

                zkevm_revert_bbf(context_type &context_object, const opcode_input_type<FieldType, stage> &current_state):
                    generic_component<FieldType,stage>(context_object, false)
                {
                    TYPE offset;
                    TYPE length, length_inv, is_length_zero;
                    TYPE N, N_inv, is_N_zero; // Number of changed items inside current CALL
                    TYPE block_id;
                    if constexpr( stage == GenerationStage::ASSIGNMENT ){
                        offset = w_lo<FieldType>(current_state.stack_top());
                        length = w_lo<FieldType>(current_state.stack_top(1));
                        length_inv = length == 0? 0: length.inversed();
                        is_length_zero = length == 0? 0: 1;
                        N = current_state.modified_items_amount();
                        N_inv = N == 0? 0: N.inversed();
                        is_N_zero = N == 0? 0: 1;
                        block_id = current_state.block_id();
                    }
                    allocate(block_id, 0, 0);
                    allocate(offset, 32, 0);
                    allocate(length, 33, 0);
                    allocate(length_inv, 34, 0);
                    allocate(is_length_zero, 35, 0);
                    allocate(N, 33, 1);
                    allocate(N_inv, 34, 1);
                    allocate(is_N_zero, 35, 1);

                    // is_length_zero correctness
                    constrain(length * (length *length_inv - 1));
                    constrain(length_inv * (length *length_inv - 1));
                    constrain(is_length_zero - length * length_inv);

                    // is_N_zero correctness
                    constrain(N * (N * N_inv - 1));
                    constrain(N_inv * (N * N_inv - 1));
                    constrain(is_N_zero - N * N_inv);

                    if constexpr( stage == GenerationStage::CONSTRAINTS ){
                        // constrain(current_state.pc_next() - current_state.pc(0) - 1);                   // PC transition
                        // constrain(current_state.gas(0) - current_state.gas_next() - gas_cost);               // GAS transition
                        // constrain(current_state.stack_size(0) - current_state.stack_size_next() - 2);   // stack_size transition
                        // constrain(current_state.memory_size(0) - current_state.memory_size_next());     // memory_size transition
                        // constrain(current_state.rw_counter_next() - current_state.rw_counter(0) - 3);   // rw_counter transition

                        // TODO: If we should process reverting transactions, append end_transaction option for next opcode.
                        // Now only CALL revert-s supported
                        constrain(
                            (current_state.opcode_next() - TYPE(std::size_t(opcode_to_number(zkevm_opcode::end_call))))
                        );

                        // Stack reading correctness
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
                            current_state.rw_counter(0) +1,
                            TYPE(0),// is_write
                            TYPE(0),// hi bytes are 0
                            length
                        ), "zkevm_rw");

                        // N, block_id, length correctness
                        lookup(rw_table<FieldType, stage>::call_context_lookup(
                            current_state.call_id(0),
                            std::size_t(call_context_field::modified_items),
                            TYPE(0),
                            N
                        ), "zkevm_rw");
                        lookup(rw_table<FieldType, stage>::call_context_lookup(
                            current_state.call_id(0),
                            std::size_t(call_context_field::returndata_size),
                            TYPE(0),
                            length
                        ), "zkevm_rw");
                        lookup(rw_table<FieldType, stage>::call_context_lookup(
                            current_state.call_id(0),
                            std::size_t(call_context_field::block_id),
                            TYPE(0),
                            block_id
                        ), "zkevm_rw");

                        // State reverting constraints. They should be applied to row 1.
                        lookup({
                            is_N_zero,                              // is_first
                            TYPE(0),                                // it is source
                            is_N_zero * TYPE(std::size_t(copy_operand_type::reverted) - 1),
                            TYPE(0),                                // id_hi
                            is_N_zero * current_state.call_id(1),
                            TYPE(0),                                // counter 0
                            TYPE(0),                                // counter 1
                            N
                        }, "zkevm_copy");
                        lookup({
                            is_N_zero,                              // is_first
                            is_N_zero,                              // it's destination
                            is_N_zero * TYPE(std::size_t(copy_operand_type::reverted) - 1),
                            TYPE(0),                                // id_hi
                            is_N_zero * block_id,                   // id_lo
                            is_N_zero * (current_state.rw_counter(1) + 2),    // counter 0
                            TYPE(0),                                // counter 1
                            N
                        }, "zkevm_copy");

                        // State reverting constraints. They should be applied to row 0.
                        lookup({
                            is_length_zero,                                                       // is_first
                            TYPE(0),                                                                   // is_write
                            is_length_zero * TYPE(copy_op_to_num(copy_operand_type::memory)),     // cp_type
                            TYPE(0),                                                                   // id_hi
                            is_length_zero * current_state.call_id(0),                            // id_lo
                            is_length_zero * offset,                                              // counter_1
                            is_length_zero * (current_state.rw_counter(0) + 2 + N),                   // counter_2
                            length
                        }, "zkevm_copy");
                        // lookup({
                        //     is_length_zero,                                                          // is_first
                        //     is_length_zero,                                                          // is_write
                        //     is_length_zero * TYPE(copy_op_to_num(copy_operand_type::returndata)),    // cp_type
                        //     TYPE(0),                                                                      // id_hi
                        //     is_length_zero * current_state.call_id(0),                               // id_lo
                        //     TYPE(0),                                                                      // counter_1
                        //     is_length_zero * (current_state.rw_counter(0) + length + 2 + N),             // counter_2
                        //     length
                        // }, "zkevm_copy");
                    }
                }
            };

            template<typename FieldType>
            class zkevm_revert_operation : public opcode_abstract<FieldType> {
            public:
                virtual void fill_context(
                    typename generic_component<FieldType, GenerationStage::ASSIGNMENT>::context_type &context,
                    const opcode_input_type<FieldType, GenerationStage::ASSIGNMENT> &current_state
                )  override {
                    zkevm_revert_bbf<FieldType, GenerationStage::ASSIGNMENT> bbf_obj(context, current_state);
                }
                virtual void fill_context(
                    typename generic_component<FieldType, GenerationStage::CONSTRAINTS>::context_type &context,
                    const opcode_input_type<FieldType, GenerationStage::CONSTRAINTS> &current_state
                )  override {
                    zkevm_revert_bbf<FieldType, GenerationStage::CONSTRAINTS> bbf_obj(context, current_state);
                }
                virtual std::size_t rows_amount() override {
                    return 2; // We use two rows because don't want to use 4 lookups to copy table instead of 2
                }
            };
        } // namespace bbf
    }   // namespace blueprint
}   // namespace nil

