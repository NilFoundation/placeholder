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

#include <nil/blueprint/zkevm_bbf/types/short_rw_operation.hpp>
#include <nil/blueprint/zkevm_bbf/types/state_operation.hpp>
#include <nil/blueprint/zkevm_bbf/small_field/opcodes/abstract_opcode.hpp>

namespace nil::blueprint::bbf::zkevm_small_field{
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
            std::array<TYPE, 10> call_context_address;
            std::array<TYPE, 16> key;
            std::array<TYPE, 16> V;
            std::array<TYPE, 16> initial_V;
            TYPE is_warm;                   // boolean

            if constexpr( stage == GenerationStage::ASSIGNMENT ){
                auto call_context_address_chunks = w_to_16(current_state.call_context_address());
                auto storage_key_chunks = w_to_16(current_state.stack_top());
                is_warm = current_state.was_accessed(current_state.call_context_address(), 0, current_state.stack_top());
                auto v = w_to_16(current_state.storage(current_state.stack_top()));
                auto initial_v = w_to_16(current_state.initial_storage(current_state.stack_top()));

                BOOST_LOG_TRIVIAL(trace) << "\tcall_context_address = " << std::hex << current_state.call_context_address();
                BOOST_LOG_TRIVIAL(trace) << "\tkey = " << std::hex << current_state.stack_top();
                BOOST_LOG_TRIVIAL(trace) << "\tis_warm = " << is_warm;
                BOOST_LOG_TRIVIAL(trace) << "\tvalue = " << std::hex << current_state.storage(current_state.stack_top());
                for(std::size_t i = 0; i < 10; i++){
                    call_context_address[i] = call_context_address_chunks[i + 6];
                }
                for(std::size_t i = 0; i < 16; i++) {
                    V[i] = v[i];
                    initial_V[i] = initial_v[i];
                    key[i] = storage_key_chunks[i];
                }
            }

            for(std::size_t i = 0; i < 16; i++){
                allocate(V[i], i,0);
                allocate(initial_V[i], i+16, 0);
                allocate(key[i], i+16, 1);
            }
            for( std::size_t i = 0; i < 10; i++ ){
                allocate(call_context_address[i], i, 1);
            }
            allocate(is_warm, 10, 1);

            if constexpr( stage == GenerationStage::CONSTRAINTS ){
                constrain(current_state.pc_next() - current_state.pc(0) - 1);                       // PC transition
                constrain(current_state.gas(0) - current_state.gas_next() - 100 - 2000 * (1 - is_warm));  // GAS transition: TODO: update gas cost
                constrain(current_state.stack_size(0) - current_state.stack_size_next());           // stack_size transition
                constrain(current_state.memory_size(0) - current_state.memory_size_next());         // memory_size transition
                constrain(current_state.rw_counter_next() - current_state.rw_counter(0) - 4);       // rw_counter transition

                lookup(rw_256_table<FieldType, stage>::call_context_read_only_16_bit_lookup(
                    current_state.call_id(0),
                    std::size_t(call_context_field::call_context_address),
                    call_context_address
                ), "zkevm_rw_256");

                lookup(rw_256_table<FieldType, stage>::stack_16_bit_lookup(
                    current_state.call_id(0),
                    current_state.stack_size(0) - 1,
                    current_state.rw_counter(0),
                    TYPE(0),                                               // is_write
                    key
                ), "zkevm_rw_256");

                lookup(state_table<FieldType, stage>::access_list_lookup(
                    current_state.call_id(0),
                    call_context_address,
                    TYPE(0), // field
                    key,
                    current_state.rw_counter(0) + 1,
                    TYPE(1),    // value
                    is_warm,    // previous_value
                    TYPE(0)     // initial_value
                ), "zkevm_state_opcode");

                lookup(state_table<FieldType, stage>::storage_read_lookup(
                    current_state.call_id(0),
                    call_context_address,
                    key,
                    current_state.rw_counter(0) + 2,
                    V,
                    initial_V
                ), "zkevm_state_opcode");

                lookup(rw_256_table<FieldType, stage>::stack_16_bit_lookup(
                    current_state.call_id(0),
                    current_state.stack_size(0) - 1,
                    current_state.rw_counter(0) + 3,
                    TYPE(1),                                               // is_write
                    V
                ), "zkevm_rw_256");
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
            return 2;
        }
    };
}
