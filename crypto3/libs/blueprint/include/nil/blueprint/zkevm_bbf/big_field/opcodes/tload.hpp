//---------------------------------------------------------------------------//
// Copyright (c) 2024 Elena Tatuzova <e.tatuzova@nil.foundation>
// Copyright (c) 2025 Antoine Cyr <antoinecyr@nil.foundation>
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

#include <nil/blueprint/zkevm_bbf/big_field/opcodes/abstract_opcode.hpp>

namespace nil::blueprint::bbf::zkevm_big_field{
    template<typename FieldType, GenerationStage stage>
    class zkevm_tload_bbf : generic_component<FieldType, stage> {
        using typename generic_component<FieldType, stage>::context_type;
        using generic_component<FieldType, stage>::allocate;
        using generic_component<FieldType, stage>::copy_constrain;
        using generic_component<FieldType, stage>::constrain;
        using generic_component<FieldType, stage>::lookup;
        using generic_component<FieldType, stage>::lookup_table;

    public:
        using typename generic_component<FieldType, stage>::TYPE;
        using value_type = typename FieldType::value_type;
        constexpr static const value_type two_128 =
            0x100000000000000000000000000000000_big_uint254;

        zkevm_tload_bbf(context_type &context_object, const opcode_input_type<FieldType, stage> &current_state)
            : generic_component<FieldType, stage>(context_object, false)
        {
            TYPE K_hi;  // Storage key
            TYPE K_lo;
            TYPE call_context_address_hi;
            TYPE call_context_address_lo;
            TYPE tx_id;
            std::vector<TYPE> V(16);
            std::vector<TYPE> initial_V(16);

            if constexpr (stage == GenerationStage::ASSIGNMENT) {
                auto key = current_state.stack_top();
                auto call_context_address = current_state.call_context_address();
                K_hi = w_hi<FieldType>(key);
                K_lo = w_lo<FieldType>(key);
                call_context_address_hi = w_hi<FieldType>(call_context_address);
                call_context_address_lo = w_lo<FieldType>(call_context_address);

                auto v = w_to_16(current_state.storage(key));
                auto initial_v = w_to_16(current_state.initial_storage(key));

                BOOST_LOG_TRIVIAL(trace) << "\taddress = " << std::hex << call_context_address_hi << " "
                            << call_context_address_lo << std::dec;
                BOOST_LOG_TRIVIAL(trace) << "\tK = " << std::hex << K_hi << " " << K_lo << std::dec;
                BOOST_LOG_TRIVIAL(trace) << "\tv = " << std::hex << current_state.storage(key) << std::dec;

                for(std::size_t i = 0; i < 16; i++) { V[i] = v[i]; initial_V[i] = initial_v[i]; }
            }

            for(std::size_t i = 0; i < 16; i++){
                allocate(V[i], i,0);
                allocate(initial_V[i], i+16, 0);
            }
            allocate(call_context_address_hi, 32, 0);
            allocate(call_context_address_lo, 33, 0);
            allocate(K_hi, 34, 0);
            allocate(K_lo, 35, 0);

            auto V_128 = chunks16_to_chunks128<TYPE>(V);
            auto initial_V_128 = chunks16_to_chunks128<TYPE>(initial_V);

            if constexpr (stage == GenerationStage::CONSTRAINTS) {
                constrain(current_state.pc_next() - current_state.pc(0) - 1);      // PC transition
                constrain(current_state.gas(0) - current_state.gas_next() - 100);  // GAS transition
                constrain(current_state.stack_size(0) - current_state.stack_size_next());  // stack_size transition
                constrain(current_state.memory_size(0) - current_state.memory_size_next());  // memory_size transition
                constrain(current_state.rw_counter_next() - current_state.rw_counter(0) - 3);  // rw_counter transition

                // Prove call_context_address correctness
                lookup( rw_table<FieldType, stage>::call_context_lookup(
                    current_state.call_id(0), std::size_t(call_context_field::call_context_address),
                    call_context_address_hi, call_context_address_lo
                ), "zkevm_rw");

                // Read address from stack
                lookup( rw_table<FieldType, stage>::stack_lookup(
                    current_state.call_id(0),
                    current_state.stack_size(0) - 1,
                    current_state.rw_counter(0),
                    TYPE(0),  // is_write
                    K_hi, K_lo
                ), "zkevm_rw");

                // Read value from transient storage
                lookup({
                    TYPE(1),                                               // It's original change, not call_commit
                    TYPE(std::size_t(rw_operation_type::transient_storage)),
                    current_state.call_id(0),                              // All state changes are grouped by block
                    call_context_address_hi * two_128 + call_context_address_lo,
                    TYPE(0),                                               // field
                    K_hi,                                                  // storage_key_hi
                    K_lo,                                                  // storage_key_lo
                    current_state.rw_counter(0)+1,
                    TYPE(0),                                               // is_write
                    V_128.first,                                           // value_hi
                    V_128.second,                                          // value_lo
                    V_128.first,                                           // previous_value_hi -- it's read, so, it's similar to current
                    V_128.second,                                          // previous_value_lo -- it's read, so, it's similar to current
                    initial_V_128.first,                                   // initial_value_hi
                    initial_V_128.second,                                  // initial_value_lo
                }, "zkevm_state_opcode");

                // Write value to stack
                lookup( rw_table<FieldType, stage>::stack_lookup(
                    current_state.call_id(0),
                    current_state.stack_size(0) - 1,
                    current_state.rw_counter(0) + 2,
                    TYPE(1),  // is_write
                    V_128.first,
                    V_128.second
                ), "zkevm_rw");
            }
        }
    };

    template<typename FieldType>
    class zkevm_tload_operation : public opcode_abstract<FieldType> {
    public:
        virtual void fill_context(
            typename generic_component<FieldType, GenerationStage::ASSIGNMENT>::context_type
                &context,
            const opcode_input_type<FieldType, GenerationStage::ASSIGNMENT> &current_state)
            override {
            zkevm_tload_bbf<FieldType, GenerationStage::ASSIGNMENT> bbf_obj(context, current_state);
        }
        virtual void fill_context(
            typename generic_component<FieldType, GenerationStage::CONSTRAINTS>::context_type
                &context,
            const opcode_input_type<FieldType, GenerationStage::CONSTRAINTS> &current_state)
            override {
            zkevm_tload_bbf<FieldType, GenerationStage::CONSTRAINTS> bbf_obj(context, current_state);
        }
        virtual std::size_t rows_amount() override { return 1; }
    };
}