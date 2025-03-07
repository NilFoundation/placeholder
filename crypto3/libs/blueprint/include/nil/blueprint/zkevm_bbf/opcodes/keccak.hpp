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

#include <numeric>
#include <algorithm>

#include <nil/blueprint/zkevm_bbf/types/opcode.hpp>

namespace nil {
    namespace blueprint {
        namespace bbf{
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
                using typename generic_component<FieldType,stage>::TYPE;

                zkevm_keccak_bbf(context_type &context_object, const opcode_input_type<FieldType, stage> &current_state):
                    generic_component<FieldType,stage>(context_object, false)
                {
                    TYPE offset;
                    TYPE length;
                    TYPE hash_hi;
                    TYPE hash_lo;
                    if constexpr( stage == GenerationStage::ASSIGNMENT ){
                        offset = w_lo<FieldType>(current_state.stack_top());
                        length = w_lo<FieldType>(current_state.stack_top(1));
                        std::size_t start_offset = std::size_t(current_state.stack_top());
                        std::size_t l = std::size_t(current_state.stack_top(1));
                        std::vector<std::uint8_t> buffer;
                        for( std::size_t i = 0; i < l; i++ ){
                            buffer.push_back(std::uint8_t(current_state.memory(start_offset + i)));
                        }
                        auto hash_value = zkevm_keccak_hash(buffer);
                        hash_hi = w_hi<FieldType>(hash_value);
                        hash_lo = w_lo<FieldType>(hash_value);
                    }
                    allocate(offset, 32, 0);
                    allocate(length, 33, 0);
                    allocate(hash_hi, 34, 0);
                    allocate(hash_lo, 35, 0);
                    if constexpr( stage == GenerationStage::CONSTRAINTS ){
                        constrain(current_state.pc_next() - current_state.pc(0) - 1);                   // PC transition
                        // constrain(current_state.gas(0) - current_state.gas_next() - 2);                 // GAS transition
                        constrain(current_state.stack_size_next() - current_state.stack_size(0) + 1);   // stack_size transition
                        // constrain(current_state.memory_size(0) - current_state.memory_size_next());     // memory_size transition
                        constrain(current_state.rw_counter_next() - current_state.rw_counter(0) - 3 - length);   // rw_counter transition

                        std::vector<TYPE> tmp;
                        tmp = rw_table<FieldType, stage>::stack_lookup(
                            current_state.call_id(0),
                            current_state.stack_size(0) - 1,
                            current_state.rw_counter(0),
                            TYPE(0),// is_write
                            TYPE(0),// hi bytes are 0
                            offset
                        );
                        lookup(tmp, "zkevm_rw");
                        tmp = rw_table<FieldType, stage>::stack_lookup(
                            current_state.call_id(0),
                            current_state.stack_size(0) - 2,
                            current_state.rw_counter(0) +1,
                            TYPE(0),// is_write
                            TYPE(0),// hi bytes are 0
                            length
                        );
                        lookup(tmp, "zkevm_rw");
                        tmp = {
                            TYPE(1),                                            // is_first
                            TYPE(0),                                            // is_write
                            TYPE(copy_op_to_num(copy_operand_type::memory)),    // cp_type
                            TYPE(0),                                            // id_hi
                            current_state.call_id(0),                           // id_lo
                            offset,                                             // counter_1
                            current_state.rw_counter(0) + 2,                    // counter_2
                            length
                        };
                        lookup(tmp, "zkevm_copy");
                        tmp = {
                            TYPE(1),                                            // is_first
                            TYPE(1),                                            // is_write
                            TYPE(copy_op_to_num(copy_operand_type::keccak)),    // cp_type
                            hash_hi,                                            // id_hi
                            hash_lo,                                            // id_lo
                            TYPE(0),                                            // counter_1
                            TYPE(0),                                            // counter_2
                            length
                        };
                        lookup(tmp, "zkevm_copy");
                        tmp = rw_table<FieldType, stage>::stack_lookup(
                            current_state.call_id(0),
                            current_state.stack_size(0) - 2,
                            current_state.rw_counter(0) + 2 + length,
                            TYPE(1),// is_write
                            hash_hi,
                            hash_lo
                        );
                        lookup(tmp, "zkevm_rw");
                    }
                }
            };

            template<typename FieldType>
            class zkevm_keccak_operation : public opcode_abstract<FieldType> {
            public:
                virtual std::size_t rows_amount() override {
                    return 1;
                }
                virtual void fill_context(
                    typename generic_component<FieldType, GenerationStage::ASSIGNMENT>::context_type &context,
                    const opcode_input_type<FieldType, GenerationStage::ASSIGNMENT> &current_state
                ) override  {
                    zkevm_keccak_bbf<FieldType, GenerationStage::ASSIGNMENT> bbf_obj(context, current_state);
                }
                virtual void fill_context(
                    typename generic_component<FieldType, GenerationStage::CONSTRAINTS>::context_type &context,
                    const opcode_input_type<FieldType, GenerationStage::CONSTRAINTS> &current_state
                ) override  {
                    zkevm_keccak_bbf<FieldType, GenerationStage::CONSTRAINTS> bbf_obj(context, current_state);
                }
            };
        } // namespace bbf
    }   // namespace blueprint
}   // namespace nil
