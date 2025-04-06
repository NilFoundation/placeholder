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

#include <algorithm>
#include <numeric>

#include <nil/blueprint/zkevm_bbf/types/opcode.hpp>

namespace nil {
    namespace blueprint {
        namespace bbf {
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
                using typename generic_component<FieldType, stage>::TYPE;

                zkevm_calldatacopy_bbf(
                    context_type &context_object,
                    const opcode_input_type<FieldType, stage> &current_state)
                    : generic_component<FieldType, stage>(context_object, false) {
                    using Word_Size = typename bbf::word_size<FieldType, stage>;
                    using Memory_Cost = typename bbf::memory_cost<FieldType, stage>;

                    TYPE destOffset, offset, length, current_mem, next_mem, S, length_inv;

                    if constexpr (stage == GenerationStage::ASSIGNMENT) {
                        destOffset = w_lo<FieldType>(current_state.stack_top());
                        offset = w_lo<FieldType>(current_state.stack_top(1));
                        length = w_lo<FieldType>(current_state.stack_top(2));
                        current_mem = current_state.memory_size();
                        next_mem = length.is_zero()
                                       ? current_mem
                                       : std::max(destOffset + length, current_mem);
                        S = next_mem > current_mem;
                        length_inv = (length == 0 ? 0 : length.inversed());
                    }
                    allocate(destOffset, 32, 0);
                    allocate(offset, 33, 0);
                    allocate(length, 34, 0);
                    allocate(current_mem, 35, 0);
                    allocate(next_mem, 36, 0);
                    allocate(S, 37, 0);
                    allocate(length_inv, 38, 0);

                    // Length_inv is correct
                    constrain(length * (length * length_inv - 1));
                    constrain(length_inv * (length * length_inv - 1));

                    // Memory expansion correctness
                    constrain(S * (S - 1));
                    constrain(S * (next_mem - destOffset - length) +
                              (1 - S) * (next_mem - current_mem));

                    std::vector<std::size_t> word_size_lookup_area = {32, 33, 34};

                    auto word_size_ct = context_object.subcontext(
                            word_size_lookup_area, 1, 1);
                    Word_Size minimum_word(word_size_ct, length);

                    std::vector<std::size_t> memory_cost_lookup_area = {42, 43, 44,
                                                                        45, 46, 47};

                    auto current_memory_ct = context_object.subcontext(
                            memory_cost_lookup_area, 0, 1);
                    Memory_Cost current_memory(current_memory_ct, current_mem);

                    auto next_memory_ct = context_object.subcontext(
                            memory_cost_lookup_area, 1, 1);
                    Memory_Cost next_memory(next_memory_ct, next_mem);

                    TYPE memory_expansion_cost =
                        next_memory.cost - current_memory.cost;
                    TYPE memory_expansion_size =
                        (next_memory.word_size - current_memory.word_size) * 32;

                    if constexpr (stage == GenerationStage::CONSTRAINTS) {
                        constrain(current_state.pc_next() - current_state.pc(0) -
                                  1);  // PC transition
                        constrain(current_state.gas(0) - current_state.gas_next() - 3 -
                                  3 * minimum_word.size -
                                  memory_expansion_cost);  // GAS transition
                        constrain(current_state.stack_size(0) -
                                  current_state.stack_size_next() -
                                  3);  // stack_size transition
                        constrain(current_state.memory_size_next() -
                                  current_state.memory_size(0) -
                                  memory_expansion_size);  // memory_size transition
                        constrain(current_state.rw_counter_next() -
                                  current_state.rw_counter(0) - 3 -
                                  2*length);  // rw_counter transition
                        std::vector<TYPE> tmp;
                        tmp = rw_table<FieldType, stage>::stack_lookup(
                            current_state.call_id(0),
                            current_state.stack_size(0) - 1,
                            current_state.rw_counter(0),
                            TYPE(0),  // is_write
                            TYPE(0),
                            destOffset
                        );
                        lookup(tmp, "zkevm_rw");
                        tmp = rw_table<FieldType, stage>::stack_lookup(
                            current_state.call_id(0),
                            current_state.stack_size(0) - 2,
                            current_state.rw_counter(0) + 1,
                            TYPE(0),  // is_write
                            TYPE(0),
                            offset
                        );
                        lookup(tmp, "zkevm_rw");
                        tmp = rw_table<FieldType, stage>::stack_lookup(
                            current_state.call_id(0),
                            current_state.stack_size(0) - 3,
                            current_state.rw_counter(0) + 2,
                            TYPE(0),  // is_write
                            TYPE(0),
                            length
                        );
                        lookup(tmp, "zkevm_rw");
                        // Lookup to copy table only if length != 0
                        lookup({
                            length * length_inv,                                            // is_first
                            TYPE(0),                                                        // is_write
                            length * length_inv * TYPE(copy_op_to_num(copy_operand_type::calldata)),    // cp_type
                            TYPE(0),                                                        // id_hi
                            length * length_inv * current_state.call_id(0),                 // id_lo
                            length * length_inv * offset,                                   // counter_1
                            length * length_inv * (current_state.rw_counter(0) + 3),        // counter_2
                            length
                        }, "zkevm_copy");
                        lookup({
                            length * length_inv,                                            // is_first
                            length * length_inv,                                            // is_write
                            length * length_inv * TYPE(copy_op_to_num(copy_operand_type::memory)),    // cp_type
                            TYPE(0),                                                        // id_hi
                            length * length_inv * current_state.call_id(0),                 // id_lo
                            length * length_inv * destOffset,                                   // counter_1
                            length * length_inv * (current_state.rw_counter(0) + length + 3),        // counter_2
                            length
                        }, "zkevm_copy");
                    }
                }
            };

            template<typename FieldType>
            class zkevm_calldatacopy_operation : public opcode_abstract<FieldType> {
              public:
                virtual std::size_t rows_amount() override { return 2; }
                virtual void fill_context(
                    typename generic_component<
                        FieldType, GenerationStage::ASSIGNMENT>::context_type &context,
                    const opcode_input_type<FieldType, GenerationStage::ASSIGNMENT>
                        &current_state) override {
                    zkevm_calldatacopy_bbf<FieldType, GenerationStage::ASSIGNMENT>
                        bbf_obj(context, current_state);
                }
                virtual void fill_context(
                    typename generic_component<
                        FieldType, GenerationStage::CONSTRAINTS>::context_type &context,
                    const opcode_input_type<FieldType, GenerationStage::CONSTRAINTS>
                        &current_state) override {
                    zkevm_calldatacopy_bbf<FieldType, GenerationStage::CONSTRAINTS>
                        bbf_obj(context, current_state);
                }
            };
        }  // namespace bbf
    }  // namespace blueprint
}  // namespace nil
