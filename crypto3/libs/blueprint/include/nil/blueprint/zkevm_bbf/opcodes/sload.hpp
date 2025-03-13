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
            class zkevm_sload_bbf : generic_component<FieldType, stage> {
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

                zkevm_sload_bbf(context_type &context_object, const opcode_input_type<FieldType, stage> &current_state):
                    generic_component<FieldType,stage>(context_object, false)
                {
                    TYPE K_hi;                  // Range checked by rw circuit
                    TYPE K_lo;                  // Range checked by rw circuit
                    std::vector<TYPE> V(16);
                    TYPE is_hot;               // boolean
                    TYPE is_dirty;              // boolean
                    TYPE call_context_address_hi;  // Range checked by rw circuit
                    TYPE call_context_address_lo;  // Range checked by rw circuit
                    TYPE block_id;              // Range checked by rw circuit
                    TYPE tx_id;                 // Range checked by rw circuit
                    TYPE state_w_id_before;
                    TYPE access_w_id_before;

                    if constexpr( stage == GenerationStage::ASSIGNMENT ){
                        auto storage_key = current_state.stack_top();
                        auto call_context_address = current_state.call_context_address();
                        K_hi = w_hi<FieldType>(storage_key);
                        K_lo = w_lo<FieldType>(storage_key);
                        block_id = current_state.block_id();
                        tx_id = current_state.tx_id();
                        call_context_address_hi = w_hi<FieldType>(call_context_address);
                        call_context_address_lo = w_lo<FieldType>(call_context_address);
                        state_w_id_before = current_state.last_write(rw_operation_type::state, call_context_address, 0, storage_key);
                        access_w_id_before = current_state.last_write(rw_operation_type::access_list, call_context_address, 0, storage_key);

                        is_hot = current_state.was_accessed(call_context_address, 0, storage_key);
                        is_dirty = current_state.was_written(call_context_address, 0, storage_key);

                        auto v = w_to_16(current_state.storage(current_state.stack_top()));
                        std::cout << "\taddress = " << std::hex << call_context_address_hi << " " <<call_context_address_lo << std::dec << std::endl;
                        std::cout << "\tK = " << std::hex << K_hi << " " << K_lo << std::dec << std::endl;
                        std::cout << "\tv = " << std::hex << current_state.storage(current_state.stack_top()) << std::dec << std::endl;
                        std::cout << "\tis_hot = " << is_hot << std::endl;
                        std::cout << "\tblock_id = " << block_id << std::endl;
                        std::cout << "\ttx_id = " << tx_id << std::endl;
                        for(std::size_t i = 0; i < 16; i++) V[i] = v[i];
                    }
                    for(std::size_t i = 0; i < 16; i++)
                        allocate(V[i], i,0);
                    allocate(is_hot, 16, 0);
                    allocate(is_dirty, 17, 0);
                    allocate(call_context_address_hi, 32, 0);
                    allocate(call_context_address_lo, 33, 0);
                    allocate(K_hi, 34, 0);
                    allocate(K_lo, 35, 0);
                    allocate(block_id, 36, 0);
                    allocate(tx_id, 37, 0);
                    allocate(state_w_id_before, 38, 0);
                    allocate(access_w_id_before, 39, 0);

                    auto V_128 = chunks16_to_chunks128<TYPE>(V);
                    if constexpr( stage == GenerationStage::CONSTRAINTS ){
                        constrain(current_state.pc_next() - current_state.pc(0) - 1);                       // PC transition
                        constrain(current_state.gas(0) - current_state.gas_next() - 100 - 2000 * (1 - is_hot));  // GAS transition: TODO: update gas cost
                        constrain(current_state.stack_size(0) - current_state.stack_size_next());           // stack_size transition
                        constrain(current_state.memory_size(0) - current_state.memory_size_next());         // memory_size transition
                        constrain(current_state.rw_counter_next() - current_state.rw_counter(0) - 4);       // rw_counter transition
                        std::vector<TYPE> tmp;
                        tmp = rw_table<FieldType, stage>::stack_lookup(
                            current_state.call_id(0),
                            current_state.stack_size(0) - 1,
                            current_state.rw_counter(0),
                            TYPE(0),                                               // is_write
                            K_hi,                                                  // hi bytes are 0
                            K_lo
                        );
                        lookup(tmp, "zkevm_rw");

                        // Prove block_id correctness
                        tmp = rw_table<FieldType, stage>::call_context_lookup(
                            current_state.call_id(0),
                            std::size_t(call_context_field::block_id),
                            TYPE(0),
                            block_id
                        );
                        lookup(tmp, "zkevm_rw");

                        tmp = rw_table<FieldType, stage>::call_context_lookup(
                            current_state.call_id(0),
                            std::size_t(call_context_field::tx_id),
                            TYPE(0),
                            tx_id
                        );
                        lookup(tmp, "zkevm_rw");

                        tmp = rw_table<FieldType, stage>::call_context_lookup(
                            current_state.call_id(0),
                            std::size_t(call_context_field::call_context_address),
                            call_context_address_hi,
                            call_context_address_lo
                        );
                        lookup(tmp, "zkevm_rw");


                        tmp = {
                            TYPE(rw_op_to_num(rw_operation_type::access_list)),
                            tx_id,                                              // All state changes are grouped by block
                            call_context_address_hi * two_128 + call_context_address_lo,
                            TYPE(0),                                               // field
                            K_hi,                                                  // storage_key_hi
                            K_lo,                                                  // storage_key_lo
                            current_state.rw_counter(0)+1,
                            TYPE(1),                                               // is_write
                            TYPE(0),                                               // value_hi
                            1 + is_dirty,                                          // value_lo
                            TYPE(0),                                               // value_before
                            is_hot + is_dirty,                                     // value_before
                            current_state.call_id(0),
                            access_w_id_before
                        };
                        lookup(tmp, "zkevm_rw");
                        tmp = {
                            TYPE(rw_op_to_num(rw_operation_type::state)),
                            block_id,                                              // All state changes are grouped by block
                            call_context_address_hi * two_128 + call_context_address_lo,
                            TYPE(0),                                               // field
                            K_hi,                                                  // storage_key_hi
                            K_lo,                                                  // storage_key_lo
                            current_state.rw_counter(0)+2,
                            TYPE(0),                                               // is_write
                            V_128.first,
                            V_128.second,
                            V_128.first,
                            V_128.second,
                            current_state.call_id(0),
                            state_w_id_before
                        };
                        lookup(tmp, "zkevm_rw");
                        tmp = rw_table<FieldType, stage>::stack_lookup(
                            current_state.call_id(0),
                            current_state.stack_size(0) - 1,
                            current_state.rw_counter(0) + 3,
                            TYPE(1),                                               // is_write
                            V_128.first,
                            V_128.second
                        );
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
