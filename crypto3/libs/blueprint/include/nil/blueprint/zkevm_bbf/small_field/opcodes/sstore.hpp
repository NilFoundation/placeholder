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

#include <nil/blueprint/zkevm_bbf/small_field/opcodes/abstract_opcode.hpp>

namespace nil::blueprint::bbf::zkevm_small_field{
    template<typename FieldType, GenerationStage stage>
    class zkevm_sstore_bbf : generic_component<FieldType, stage> {
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

        zkevm_sstore_bbf(context_type &context_object, const opcode_input_type<FieldType, stage> &current_state):
            generic_component<FieldType,stage>(context_object, false)
        {
            std::array<TYPE, 16> key;
            std::array<TYPE, 16> V;
            std::array<TYPE, 16> previous_V;
            std::array<TYPE, 16> initial_V;
            std::array<TYPE, 10> call_context_address;
            TYPE is_cold;                       // Not accessed during the transaction (should be reverted after revert)
            TYPE is_clean;                      // Previous value is equal to initial value (value before transaction)
            std::array<TYPE, 16> clean_chunks;
            TYPE                 clean_chunks_sum_inv;
            TYPE was_zero;
            TYPE chunks_sum_inv;
            TYPE is_equal;                      // Previous value is equal to current value
            std::array<TYPE, 16> equal_chunks;
            TYPE equal_chunks_sum_inv;

            if constexpr( stage == GenerationStage::ASSIGNMENT ){
                auto key_chunks = w_to_16(current_state.stack_top());
                auto call_context_address_chunks = w_to_16(current_state.call_context_address());
                auto v_chunks = w_to_16(current_state.stack_top(1));
                auto previous_v_chunks = w_to_16(current_state.storage(current_state.stack_top()));
                auto initial_v_chunks = w_to_16(current_state.initial_storage(current_state.stack_top()));

                for( std::size_t i = 0; i < 10; i++ ) call_context_address[i] = call_context_address_chunks[i + 6];

                TYPE equal_chunks_sum;
                TYPE clean_chunks_sum;
                TYPE chunks_sum;
                for( std::size_t i = 0; i < 16; i++ ) {
                    key[i] = key_chunks[i];
                    V[i] = v_chunks[i];
                    previous_V[i] = previous_v_chunks[i];
                    initial_V[i] = initial_v_chunks[i];
                    clean_chunks[i] =
                        initial_v_chunks[i] > previous_v_chunks[i]?
                        initial_v_chunks[i] - previous_v_chunks[i]:
                        previous_v_chunks[i] - initial_v_chunks[i];
                    equal_chunks[i] =
                        previous_v_chunks[i] > v_chunks[i]?
                        previous_v_chunks[i] - v_chunks[i]:
                        v_chunks[i] - previous_v_chunks[i];
                    clean_chunks_sum += clean_chunks[i];
                    equal_chunks_sum += equal_chunks[i];
                    chunks_sum += previous_V[i];
                }
                clean_chunks_sum_inv = clean_chunks_sum == 0? 0: clean_chunks_sum.inversed();
                equal_chunks_sum_inv = equal_chunks_sum == 0? 0: equal_chunks_sum.inversed();
                chunks_sum_inv = chunks_sum == 0? 0: chunks_sum.inversed();
                is_cold = 1 - current_state.was_accessed(current_state.call_context_address(), 0, current_state.stack_top());
                was_zero = (chunks_sum == 0)? 1: 0;
                is_clean = clean_chunks_sum == 0? 1: 0;
                is_equal = equal_chunks_sum == 0? 1: 0;

                BOOST_LOG_TRIVIAL(trace) << "\tKey = " << current_state.stack_top() << " value = " << current_state.stack_top(1) << std::endl;
            }

            // TYPE previous_V_sum_expr;
            for(std::size_t i = 0; i < 10; i++){
                allocate(call_context_address[i], i, 1);
            }

            TYPE equal_chunks_sum;
            TYPE clean_chunks_sum;
            TYPE chunks_sum;
            for(std::size_t i = 0; i < 16; i++) {
                allocate(key[i], i, 0);
                allocate(V[i], i+16, 0);
                allocate(previous_V[i], i+32, 0);
                allocate(initial_V[i], i, 2);
                allocate(clean_chunks[i], i+16, 2);
                allocate(equal_chunks[i], i+32, 2);

                constrain((clean_chunks[i] - initial_V[i] + previous_V[i]) * (clean_chunks[i] - previous_V[i] + initial_V[i])); // clean_chunks[i] = |initial_V[i] - previous_V[i]|
                constrain((equal_chunks[i] - previous_V[i] + V[i]) * (equal_chunks[i] - V[i] + previous_V[i])); // equal_chunks[i] = |previous_V[i] - V[i]|

                clean_chunks_sum += clean_chunks[i];
                equal_chunks_sum += equal_chunks[i];
                chunks_sum += previous_V[i];
            }
            allocate(is_cold, 11, 1);
            allocate(is_clean, 12, 1);
            allocate(was_zero, 13, 1);
            allocate(is_equal, 14, 1);
            allocate(chunks_sum, 32, 1);
            allocate(chunks_sum_inv, 33, 1);
            allocate(equal_chunks_sum_inv, 34, 1);
            allocate(clean_chunks_sum_inv, 35, 1);

            constrain(is_cold * (1 - is_cold));

            constrain(is_clean * (1 - is_clean));
            constrain(clean_chunks_sum * clean_chunks_sum_inv + is_clean - 1);
            constrain(is_clean * clean_chunks_sum);
            constrain(is_clean * clean_chunks_sum_inv);

            constrain(is_equal * (1 - is_equal));
            constrain(equal_chunks_sum * equal_chunks_sum_inv + is_equal - 1);
            constrain(is_equal * equal_chunks_sum);
            constrain(is_equal * equal_chunks_sum_inv);

            constrain(was_zero * (1 - was_zero));
            constrain(chunks_sum * chunks_sum_inv + was_zero - 1);
            constrain(was_zero * chunks_sum);
            constrain(was_zero* chunks_sum_inv);

            TYPE gas_cost =
                100 +                                             // is_clean anyway
                is_cold * 2100 +                                  // is_cold
                is_clean * (1 - is_equal) * was_zero * 19900 +   // is_clean => is_cold
                is_clean * (1 - is_equal) * (1 - was_zero) * 2800;
            if constexpr ( stage == GenerationStage::ASSIGNMENT ){
                BOOST_LOG_TRIVIAL(trace) << "\tGas cost = " << gas_cost << std::endl;
            }

            // TODO: Append refunds
            if constexpr( stage == GenerationStage::CONSTRAINTS ){
                constrain(current_state.pc_next() - current_state.pc(0) - 1);                   // PC transition
                constrain(current_state.gas(0) - current_state.gas_next() - gas_cost);               // GAS transition
                constrain(current_state.stack_size(0) - current_state.stack_size_next() - 2);   // stack_size transition
                constrain(current_state.memory_size(0) - current_state.memory_size_next());     // memory_size transition
                constrain(current_state.rw_counter_next() - current_state.rw_counter(0) - 4);   // rw_counter transition

                // 1. Read call_context_address from call_context
                lookup(rw_256_table<FieldType, stage>::call_context_read_only_16_bit_lookup(
                    current_state.call_id(0),
                    std::size_t(call_context_field::call_context_address),
                    call_context_address
                ), "zkevm_rw_256");

                // 2. Read key from stack
                lookup(rw_256_table<FieldType, stage>::stack_16_bit_lookup(
                    current_state.call_id(0),
                    current_state.stack_size(0) - 1,
                    current_state.rw_counter(0),
                    TYPE(0),                                               // is_write
                    key
                ), "zkevm_rw_256");

                // 3. Read value from stack
                lookup(rw_256_table<FieldType, stage>::stack_16_bit_lookup(
                    current_state.call_id(0),
                    current_state.stack_size(0) - 2,
                    current_state.rw_counter(0) + 1,
                    TYPE(0),                                               // is_write
                    V
                ), "zkevm_rw_256");

                // 4. Check access list
                lookup(state_table<FieldType, stage>::access_list_lookup(
                    current_state.call_id(0),
                    call_context_address,
                    TYPE(0),      // field
                    key,
                    current_state.rw_counter(0) + 2,
                    TYPE(1),      // value
                    1 - is_cold,  // previous_value
                    TYPE(0)       // initial_value
                ), "zkevm_state_opcode");

                // 5. Write storage value
                lookup(state_table<FieldType, stage>::storage_write_lookup(
                    current_state.call_id(0),
                    call_context_address,
                    key,
                    current_state.rw_counter(0) + 3,
                    V,
                    previous_V,
                    initial_V
                ), "zkevm_state_opcode");
            }
        }
    };

    template<typename FieldType>
    class zkevm_sstore_operation : public opcode_abstract<FieldType> {
    public:
        virtual void fill_context(
            typename generic_component<FieldType, GenerationStage::ASSIGNMENT>::context_type &context,
            const opcode_input_type<FieldType, GenerationStage::ASSIGNMENT> &current_state
        )  override {
            zkevm_sstore_bbf<FieldType, GenerationStage::ASSIGNMENT> bbf_obj(context, current_state);
        }
        virtual void fill_context(
            typename generic_component<FieldType, GenerationStage::CONSTRAINTS>::context_type &context,
            const opcode_input_type<FieldType, GenerationStage::CONSTRAINTS> &current_state
        )  override {
            zkevm_sstore_bbf<FieldType, GenerationStage::CONSTRAINTS> bbf_obj(context, current_state);
        }
        virtual std::size_t rows_amount() override {
            return 3;
        }
    };
}
