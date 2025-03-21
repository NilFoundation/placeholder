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

#include <nil/blueprint/zkevm/zkevm_word.hpp>
#include <nil/blueprint/zkevm_bbf/subcomponents/memory_cost.hpp>
#include <nil/blueprint/zkevm_bbf/subcomponents/word_size.hpp>
#include <nil/blueprint/zkevm_bbf/types/opcode.hpp>

namespace nil {
    namespace blueprint {
        namespace bbf {
            template<typename FieldType>
            class opcode_abstract;

            template<typename FieldType, GenerationStage stage>
            class zkevm_keccak_bbf : generic_component<FieldType, stage> {
                using typename generic_component<FieldType, stage>::context_type;
                using generic_component<FieldType, stage>::allocate;
                using generic_component<FieldType, stage>::copy_constrain;
                using generic_component<FieldType, stage>::constrain;
                using generic_component<FieldType, stage>::lookup;
                using generic_component<FieldType, stage>::lookup_table;

              public:
                using typename generic_component<FieldType, stage>::TYPE;

                zkevm_keccak_bbf(context_type &context_object,
                                 const opcode_input_type<FieldType, stage> &current_state)
                    : generic_component<FieldType, stage>(context_object, false) {
                    using Word_Size = typename bbf::word_size<FieldType, stage>;
                    using Memory_Cost = typename bbf::memory_cost<FieldType, stage>;
                    TYPE hash_hi, hash_lo, offset, length, current_mem, next_mem,
                        memory_expansion_size, memory_expansion_cost, S;
                    ;
                    if constexpr (stage == GenerationStage::ASSIGNMENT) {
                        offset = w_lo<FieldType>(current_state.stack_top());
                        length = w_lo<FieldType>(current_state.stack_top(1));
                        std::size_t start_offset = std::size_t(current_state.stack_top());
                        std::size_t l = std::size_t(current_state.stack_top(1));
                        std::vector<std::uint8_t> buffer;
                        for (std::size_t i = 0; i < l; i++) {
                            buffer.push_back(
                                std::uint8_t(current_state.memory(start_offset + i)));
                        }
                        auto hash_value = zkevm_keccak_hash(buffer);
                        hash_hi = w_hi<FieldType>(hash_value);
                        hash_lo = w_lo<FieldType>(hash_value);

                        current_mem = current_state.memory_size;
                        next_mem = length.is_zero()
                                       ? current_mem
                                       : std::max(offset + length, current_mem);
                        S = next_mem > current_mem;
                    }
                    allocate(offset, 32, 0);
                    allocate(length, 33, 0);
                    allocate(hash_hi, 34, 0);
                    allocate(hash_lo, 35, 0);
                    allocate(current_mem, 36, 0);
                    allocate(next_mem, 37, 0);
                    allocate(S, 38, 0);

                    constrain(S * (S - 1));
                    constrain(S * (next_mem - offset - length) +
                              (1 - S) * (next_mem - current_mem));

                    std::vector<std::size_t> word_size_lookup_area = {32, 33, 34};
                    allocate(memory_expansion_cost, 35, 1);
                    allocate(memory_expansion_size, 36, 1);
                    std::vector<std::size_t> memory_cost_lookup_area = {42, 43, 44,
                                                                        45, 46, 47};

                    context_type word_size_ct =
                        context_object.subcontext(word_size_lookup_area, 1, 1);

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
                    Word_Size minimum_word = Word_Size(word_size_ct, length);

                    if constexpr (stage == GenerationStage::CONSTRAINTS) {
                        constrain(current_state.pc_next() - current_state.pc(0) -
                                  1);  // PC transition
                        constrain(current_state.gas(0) - current_state.gas_next() - 30 -
                                  6 * minimum_word.size -
                                  memory_expansion_cost);  // GAS transition
                        constrain(current_state.stack_size_next() -
                                  current_state.stack_size(0) +
                                  1);  // stack_size transition
                        constrain(current_state.memory_size_next() -
                                  current_state.memory_size(0) -
                                  memory_expansion_size);  // memory_size transition
                        constrain(current_state.rw_counter_next() -
                                  current_state.rw_counter(0) - 3 -
                                  length);  // rw_counter transition

                        std::vector<TYPE> tmp;
                        tmp = {
                            TYPE(rw_op_to_num(rw_operation_type::stack)),
                            current_state.call_id(0),
                            current_state.stack_size(0) - 1,
                            TYPE(0),  // storage_key_hi
                            TYPE(0),  // storage_key_lo
                            TYPE(0),  // field
                            current_state.rw_counter(0),
                            TYPE(0),  // is_write
                            TYPE(0),  // hi bytes are 0
                            offset    // addr is smaller than maximum contract size
                        };
                        lookup(tmp, "zkevm_rw");
                        tmp = {
                            TYPE(rw_op_to_num(rw_operation_type::stack)),
                            current_state.call_id(0),
                            current_state.stack_size(0) - 2,
                            TYPE(0),  // storage_key_hi
                            TYPE(0),  // storage_key_lo
                            TYPE(0),  // field
                            current_state.rw_counter(0) + 1,
                            TYPE(0),  // is_write
                            TYPE(0),  // hi bytes are 0
                            length    // addr is smaller than maximum contract size
                        };
                        lookup(tmp, "zkevm_rw");
                        tmp = {
                            TYPE(1),                   // is_first
                            TYPE(0),                   // source_id_hi
                            current_state.call_id(0),  // source_id_lo
                            TYPE(copy_op_to_num(copy_operand_type::memory)),  // cp_type
                            offset,
                            length,
                            TYPE(0),  // is_write
                            current_state.rw_counter(0) +
                                2  // addr is smaller than maximum contract size
                        };
                        lookup(tmp, "zkevm_copy");
                        tmp = {
                            TYPE(1),  // is_first
                            hash_hi,  // source_id_hi
                            hash_lo,  // source_id_lo
                            TYPE(copy_op_to_num(copy_operand_type::keccak)),  // cp_type
                            0,
                            length,
                            TYPE(1),  // is_write
                            current_state.rw_counter(0) + 2 +
                                length  // addr is smaller than maximum contract size
                        };
                        lookup(tmp, "zkevm_copy");
                        tmp = {TYPE(rw_op_to_num(rw_operation_type::stack)),
                               current_state.call_id(0),
                               current_state.stack_size(0) - 2,
                               TYPE(0),  // storage_key_hi
                               TYPE(0),  // storage_key_lo
                               TYPE(0),  // field
                               current_state.rw_counter(0) + 2 + length,
                               TYPE(1),  // is_write
                               hash_hi,
                               hash_lo};
                        lookup(tmp, "zkevm_rw");
                    } else {
                        std::cout << "\tASSIGNMENT implemented" << std::endl;
                    }
                }
            };

            template<typename FieldType>
            class zkevm_keccak_operation : public opcode_abstract<FieldType> {
              public:
                virtual std::size_t rows_amount() override { return 2; }
                virtual void fill_context(
                    typename generic_component<
                        FieldType, GenerationStage::ASSIGNMENT>::context_type &context,
                    const opcode_input_type<FieldType, GenerationStage::ASSIGNMENT>
                        &current_state) override {
                    zkevm_keccak_bbf<FieldType, GenerationStage::ASSIGNMENT> bbf_obj(
                        context, current_state);
                }
                virtual void fill_context(
                    typename generic_component<
                        FieldType, GenerationStage::CONSTRAINTS>::context_type &context,
                    const opcode_input_type<FieldType, GenerationStage::CONSTRAINTS>
                        &current_state) override {
                    zkevm_keccak_bbf<FieldType, GenerationStage::CONSTRAINTS> bbf_obj(
                        context, current_state);
                }
            };
        }  // namespace bbf
    }  // namespace blueprint
}  // namespace nil
