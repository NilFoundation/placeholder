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

#include <nil/blueprint/zkevm/zkevm_word.hpp>
#include <nil/blueprint/zkevm_bbf/types/opcode.hpp>

namespace nil {
    namespace blueprint {
        namespace bbf{
            template<typename FieldType>
            class opcode_abstract;

            template<typename FieldType, GenerationStage stage>
            class zkevm_sload_bbf : generic_component<FieldType, stage> {
                using typename generic_component<FieldType, stage>::context_type;
                using generic_component<FieldType, stage>::allocate;
                using generic_component<FieldType, stage>::copy_constrain;
                using generic_component<FieldType, stage>::constrain;
                using generic_component<FieldType, stage>::lookup;
                using generic_component<FieldType, stage>::lookup_table;
            public:
                using typename generic_component<FieldType,stage>::TYPE;

                zkevm_sload_bbf(context_type &context_object, const opcode_input_type<FieldType, stage> &current_state):
                    generic_component<FieldType,stage>(context_object, false)
                {
                    TYPE K_hi;
                    TYPE K_lo;
                    std::vector<TYPE> V(16);
                    if constexpr( stage == GenerationStage::ASSIGNMENT ){
                        K_hi = w_hi<FieldType>(current_state.stack_top());
                        K_lo = w_lo<FieldType>(current_state.stack_top());
                        auto v = w_to_16(current_state.storage(current_state.stack_top()));
                        std::cout << "K = " << std::hex << K_hi << " " << K_lo << std::dec << std::endl;
                        std::cout << "v = " << std::hex << current_state.storage(current_state.stack_top()) << std::endl;
                        for(std::size_t i = 0; i < 16; i++) V[i] = v[i];
                    }
                    for(std::size_t i = 0; i < 16; i++)
                        allocate(V[i], i,0);
                    allocate(K_hi, 32, 0);
                    allocate(K_lo, 33, 0);
                    std::cout << "\tK_hi = " << K_hi << std::endl;
                    std::cout << "\tK_lo = " << K_lo << std::endl;
                    auto V_128 = chunks16_to_chunks128<TYPE>(V);
                    if constexpr( stage == GenerationStage::CONSTRAINTS ){
                        constrain(current_state.pc_next() - current_state.pc(0) - 1);                   // PC transition
                        //constrain(current_state.gas(0) - current_state.gas_next() - 3);               // GAS transition: TODO: update gas cost
                        constrain(current_state.stack_size(0) - current_state.stack_size_next());   // stack_size transition
                        constrain(current_state.memory_size(0) - current_state.memory_size_next());     // memory_size transition
                        constrain(current_state.rw_counter_next() - current_state.rw_counter(0) - 3);   // rw_counter transition
                        std::vector<TYPE> tmp;
                        tmp = {
                            TYPE(rw_op_to_num(rw_operation_type::stack)),
                            current_state.call_id(0),
                            current_state.stack_size(0) - 1,
                            TYPE(0),                                               // storage_key_hi
                            TYPE(0),                                               // storage_key_lo
                            TYPE(0),                                               // field
                            current_state.rw_counter(0),
                            TYPE(0),                                               // is_write
                            K_hi,                                                  // hi bytes are 0
                            K_lo                                                   // addr is smaller than maximum contract size
                        };
                        lookup(tmp, "zkevm_rw");
                        tmp = {
                            TYPE(rw_op_to_num(rw_operation_type::storage)),
                            current_state.call_id(0),
                            TYPE(0),
                            K_hi,                                                  // storage_key_hi
                            K_lo,                                                  // storage_key_lo
                            TYPE(0),                                               // field
                            current_state.rw_counter(0)+1,
                            TYPE(0),                                            // is_write
                            V_128.first,                                        // hi bytes are 0
                            V_128.second                                        // addr is smaller than maximum contract size
                        };
                        lookup(tmp, "zkevm_rw");
                        tmp = {
                            TYPE(rw_op_to_num(rw_operation_type::stack)),
                            current_state.call_id(0),
                            current_state.stack_size(0) - 1,
                            TYPE(0),                                               // storage_key_hi
                            TYPE(0),                                               // storage_key_lo
                            TYPE(0),                                               // field
                            current_state.rw_counter(0) + 2,
                            TYPE(1),                                               // is_write
                            V_128.first,                                           // hi bytes are 0
                            V_128.second                                           // addr is smaller than maximum contract size
                        };
                        lookup(tmp, "zkevm_rw");
                    }
                }
            };

            template<typename FieldType>
            class zkevm_sload_operation : public opcode_abstract<FieldType> {
            public:
                virtual void fill_context(
                    typename generic_component<FieldType, GenerationStage::ASSIGNMENT>::context_type &context,
                    const opcode_input_type<FieldType, GenerationStage::ASSIGNMENT> &current_state
                )  override {
                    zkevm_sload_bbf<FieldType, GenerationStage::ASSIGNMENT> bbf_obj(context, current_state);
                }
                virtual void fill_context(
                    typename generic_component<FieldType, GenerationStage::CONSTRAINTS>::context_type &context,
                    const opcode_input_type<FieldType, GenerationStage::CONSTRAINTS> &current_state
                )  override {
                    zkevm_sload_bbf<FieldType, GenerationStage::CONSTRAINTS> bbf_obj(context, current_state);
                }
                virtual std::size_t rows_amount() override {
                    return 1;
                }
            };
        } // namespace bbf
    }   // namespace blueprint
}   // namespace nil
