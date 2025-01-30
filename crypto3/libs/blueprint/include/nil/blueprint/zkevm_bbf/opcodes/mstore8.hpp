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
        namespace bbf {
            template<typename FieldType>
            class opcode_abstract;

            template<typename FieldType, GenerationStage stage>
            class zkevm_mstore8_bbf : generic_component<FieldType, stage> {
                using typename generic_component<FieldType, stage>::context_type;
                using generic_component<FieldType, stage>::allocate;
                using generic_component<FieldType, stage>::copy_constrain;
                using generic_component<FieldType, stage>::constrain;
                using generic_component<FieldType, stage>::lookup;
                using generic_component<FieldType, stage>::lookup_table;
            public:
                using typename generic_component<FieldType,stage>::TYPE;

                zkevm_mstore8_bbf(context_type &context_object, const opcode_input_type<FieldType, stage> &current_state):
                    generic_component<FieldType,stage>(context_object, false)
                {
                    TYPE addr;
                    TYPE addr1;
                    TYPE addr_mod;
                    TYPE addr_mod31;
                    TYPE addr_words;
                    TYPE memory_mod;
                    TYPE memory_mod31;
                    TYPE memory_words;
                    TYPE is_memory_size_changed;
                    TYPE new_memory_size;
                    // TYPE addr_quad_mod;
                    // TYPE addr_quad_mod512;
                    // TYPE addr_quad_r;
                    // TYPE memory_quad_mod;
                    // TYPE memory_quad_mod512;
                    // TYPE memory_quad_r;
                    std::vector<TYPE> value(32);
                    if constexpr( stage == GenerationStage::ASSIGNMENT ){
                        auto address = w_to_16(current_state.stack_top())[15];
                        addr = address;
                        addr1 = address;
                        auto bytes = w_to_8(current_state.stack_top(1));
                        for( std::size_t i = 0; i < 32; i++){
                            value[i] = bytes[i];
                        }
                        // addr + 31 -- maximum address
                        // memory_size -- previous memory_size
                        // if ( memory_size < addr + 31 ) then
                        //    new_memory_size = std::ceil(float(addr + 31) / 32) * 32
                        // else
                        //    new_memory_size = memory_size
                        // So, we have | addr | std::ceil(addr + 31) % 32 | (addr + 31) / 32 |
                        std::size_t last_address = address + 31;
                        addr_mod = last_address % 32;
                        addr_mod31 = 31 - addr_mod;
                        addr_words = last_address % 32 == 0? last_address/32 : last_address / 32 + 1;
                        memory_mod = current_state.memory_size %32;
                        memory_mod31 = 31 - memory_mod;
                        memory_words = current_state.memory_size %32 == 0? current_state.memory_size/32 : current_state.memory_size / 32 + 1;
                        // addr_quad_mod = ((std::size_t(addr_words) * std::size_t(addr_words)) % 512);
                        // addr_quad_r = ((std::size_t(addr_words) * std::size_t(addr_words)) / 512);
                        // addr_quad_mod512 = 512 - addr_quad_mod;
                        // memory_quad_mod = ((std::size_t(memory_words) * std::size_t(memory_words)) % 512);
                        // memory_quad_r = ((std::size_t(memory_words) * std::size_t(memory_words)) / 512);
                        // memory_quad_mod512 = 512 - memory_quad_mod;

                        std::cout << "\tMemory words = " << memory_words
                            <<  " memory size = " << current_state.memory_size
                            << " memory mod = " << memory_mod
                            << " address = " << address
                            << " last_address = " << last_address
                            << " addr_mod = " << addr_mod
                            << " addr_words = " << addr_words
                            << std::endl;
                        is_memory_size_changed = (addr_words > memory_words);
                        if( is_memory_size_changed != 0 ) {
                            std::cout << "\tMEMORY SIZE CHANGED "  << addr_words << " > " << memory_words << std::endl;
                        } else {
                            std::cout << "\tMEMORY SIZE NOT CHANGED " << addr_words << " <= " << memory_words << std::endl;
                        }
                    }
                    for( std::size_t i = 0; i < 16; i++){
                        allocate(value[i], i+16, 0); // Values are range-checked by RW circuit, so use non-range-checked columns
                        allocate(value[i + 16], i+16, 1); // Values are range-checked by RW circuit, so use non-range-checked columns
                    }

                    allocate(addr, 0, 0);
                    allocate(addr1, 0, 1);
                    allocate(addr_mod, 1, 0);
                    allocate(addr_mod31 , 2, 0);
                    allocate(addr_words, 3, 0);
                    allocate(memory_mod, 4, 0);
                    allocate(memory_mod31, 5, 0);
                    allocate(memory_words, 6, 0);
                    allocate(is_memory_size_changed, 7, 0);

                    // constrain( addr_mod + addr_mod31 - 31);
                    // constrain( memory_mod + memory_mod31 - 31);
                    if constexpr( stage == GenerationStage::CONSTRAINTS ){
                        // constrain((addr + 31 - 32 * addr_words)*(32 * addr_words - 32 + addr_mod - addr - 31));
                        // constrain( addr_mod * (32 * addr_words - 32 + addr_mod - addr - 31));
                        // constrain((current_state.memory_size(0) - 32 * memory_words)*(32 * memory_words - 32 - current_state.memory_size(0) + memory_mod));
                        // constrain( memory_mod * (32 * memory_words - 32 - current_state.memory_size(0) + memory_mod));
                        new_memory_size = is_memory_size_changed * addr_words * 32 + (1 - is_memory_size_changed) * current_state.memory_size(0);
                        TYPE old_memory_gas_cost =  3 * memory_words;   // TODO: check and test with large memory consumption
                        TYPE new_memory_gas_cost =  3 * addr_words;     // TODO: check and test with large memory consumption

                        constrain(current_state.pc_next() - current_state.pc(1) - 1);                   // PC transition
                        //constrain(current_state.gas(1) - current_state.gas_next() - 3 - is_memory_size_changed * (new_memory_gas_cost - old_memory_gas_cost));               // GAS transition
                        constrain(current_state.stack_size(1) - current_state.stack_size_next() - 2);   // stack_size transition
                        //constrain(new_memory_size - current_state.memory_size_next());               // memory_size transition
                        constrain(current_state.rw_counter_next() - current_state.rw_counter(1) - 3);  // rw_counter transition
                        auto V_128 = chunks8_to_chunks128<TYPE>(value);

                        std::vector<TYPE> tmp;
                        tmp = {
                            TYPE(rw_op_to_num(rw_operation_type::stack)),
                            current_state.call_id(1),
                            current_state.stack_size(1) - 1,
                            TYPE(0),                                               // storage_key_hi
                            TYPE(0),                                               // storage_key_lo
                            TYPE(0),                                               // field
                            current_state.rw_counter(1),
                            TYPE(0),                                               // is_write
                            TYPE(0),                                               // hi bytes are 0
                            addr                                                   // addr is smaller than maximum contract size
                        };
                        lookup(tmp, "zkevm_rw");
                        tmp = {
                            TYPE(rw_op_to_num(rw_operation_type::stack)),
                            current_state.call_id(1),
                            current_state.stack_size(1) - 2,
                            TYPE(0),                                               // storage_key_hi
                            TYPE(0),                                               // storage_key_lo
                            TYPE(0),                                               // field
                            current_state.rw_counter(1) + 1,
                            TYPE(0),                                               // is_write
                            V_128.first,                                           // hi bytes are 0
                            V_128.second                                           // addr is smaller than maximum contract size
                        };
                        lookup(tmp, "zkevm_rw");

                        tmp = {
                            TYPE(rw_op_to_num(rw_operation_type::memory)),
                            current_state.call_id(1),
                            addr,
                            TYPE(0),                                               // storage_key_hi
                            TYPE(0),                                               // storage_key_lo
                            TYPE(0),                                               // field
                            current_state.rw_counter(1) + 2,
                            TYPE(1),                                               // is_write
                            TYPE(0),                                               // hi bytes are 0
                            value[31]                                               // addr is smaller than maximum contract size
                        };
                        lookup(tmp, "zkevm_rw");
                    }
                }
            };

            template<typename FieldType>
            class zkevm_mstore8_operation : public opcode_abstract<FieldType> {
            public:
                virtual void fill_context(
                    typename generic_component<FieldType, GenerationStage::ASSIGNMENT>::context_type &context,
                    const opcode_input_type<FieldType, GenerationStage::ASSIGNMENT> &current_state
                ) override  {
                    zkevm_mstore8_bbf<FieldType, GenerationStage::ASSIGNMENT> bbf_obj(context, current_state);
                }
                virtual void fill_context(
                    typename generic_component<FieldType, GenerationStage::CONSTRAINTS>::context_type &context,
                    const opcode_input_type<FieldType, GenerationStage::CONSTRAINTS> &current_state
                )  override {
                    zkevm_mstore8_bbf<FieldType, GenerationStage::CONSTRAINTS> bbf_obj(context, current_state);
                }
                virtual std::size_t rows_amount() override {
                    return 2;
                }
            };
        } // namespace bbf
    }   // namespace blueprint
}   // namespace nil
