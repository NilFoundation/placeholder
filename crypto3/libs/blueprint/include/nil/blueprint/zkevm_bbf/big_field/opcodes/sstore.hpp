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

#include <nil/blueprint/zkevm_bbf/big_field/opcodes/abstract_opcode.hpp>

namespace nil::blueprint::bbf::zkevm_big_field{
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
            TYPE K_hi;
            TYPE K_lo;
            std::vector<TYPE> V(16);             // Value that we'll write
            std::vector<TYPE> previous_V(16);    // Value before SSTORE
            std::vector<TYPE> initial_V(16);     // Value before transaction
            TYPE call_context_address_hi;
            TYPE call_context_address_lo;
            TYPE is_cold;                       // Not accessed during the transaction (should be reverted after revert)
            TYPE is_clean_hi;
            TYPE is_clean_lo;
            TYPE is_clean;                      // Not equal to value before transaction
            TYPE previous_V_sum_inv;            // To check, is previous value 0
            TYPE was_zero;
            TYPE is_equal_hi;
            TYPE is_equal_lo;
            TYPE is_equal;
            TYPE D_hi_inv;                      //  (initial_V_hi - previous_V_hi).inversed()
            TYPE D_lo_inv;                      //  (initial_V_lo - previous_V_lo).inversed()
            TYPE R_hi_inv;                      //  (previous_V_hi - V_hi).inversed()
            TYPE R_lo_inv;                      //  (previous_V_lo - V_lo).inversed()


            if constexpr( stage == GenerationStage::ASSIGNMENT ){
                auto storage_key = current_state.stack_top();
                auto call_context_address = current_state.call_context_address();

                K_hi = w_hi<FieldType>(storage_key);
                K_lo = w_lo<FieldType>(storage_key);
                BOOST_LOG_TRIVIAL(trace) << "\tKey = " << current_state.stack_top() << "=[" <<storage_key << "] value = " << current_state.stack_top(1) << std::endl;
                auto initial_v = w_to_16(current_state.initial_storage(storage_key));
                auto previous_v = w_to_16(current_state.storage(current_state.stack_top()));
                auto v = w_to_16(current_state.stack_top(1));

                TYPE initial_V_hi = w_hi<FieldType>(current_state.initial_storage(current_state.stack_top()));
                TYPE initial_V_lo = w_lo<FieldType>(current_state.initial_storage(current_state.stack_top()));
                TYPE previous_V_hi = w_hi<FieldType>(current_state.storage(current_state.stack_top()));
                TYPE previous_V_lo = w_lo<FieldType>(current_state.storage(current_state.stack_top()));
                TYPE V_hi = w_hi<FieldType>(current_state.stack_top(1));
                TYPE V_lo = w_lo<FieldType>(current_state.stack_top(1));

                TYPE previous_V_sum;
                for(std::size_t i = 0; i < 16; i++) {
                    initial_V[i] = initial_v[i];
                    previous_V[i] = previous_v[i];  previous_V_sum += previous_v[i];
                    V[i] = v[i];
                }
                previous_V_sum_inv = previous_V_sum == 0? 0: previous_V_sum.inversed();
                was_zero = (previous_V_sum == 0);

                call_context_address_hi = w_hi<FieldType>(call_context_address);
                call_context_address_lo = w_lo<FieldType>(call_context_address);

                is_cold = 1 - current_state.was_accessed(call_context_address, 0, storage_key);
                is_clean_hi = (initial_V_hi == previous_V_hi);
                is_clean_lo = (initial_V_lo == previous_V_lo);
                is_clean = is_clean_hi * is_clean_lo;

                is_equal_hi = (previous_V_hi == V_hi);
                is_equal_lo = (previous_V_lo == V_lo);
                is_equal = is_equal_hi*is_equal_lo;

                D_hi_inv = (initial_V_hi - previous_V_hi) == 0? 0: (initial_V_hi - previous_V_hi).inversed();
                D_lo_inv = (initial_V_lo - previous_V_lo) == 0? 0: (initial_V_lo - previous_V_lo).inversed();
                R_hi_inv = (previous_V_hi - V_hi) == 0? 0: (previous_V_hi - V_hi).inversed();
                R_lo_inv = (previous_V_lo - V_lo) == 0? 0: (previous_V_lo - V_lo).inversed();

                BOOST_LOG_TRIVIAL(trace) << "\taddress = " << std::hex << call_context_address_hi << " " <<call_context_address_lo << std::dec << std::endl;
                BOOST_LOG_TRIVIAL(trace) << "\tK = " << std::hex << K_hi << " " << K_lo << std::dec << std::endl;
                BOOST_LOG_TRIVIAL(trace) << "\tinitial_v = " << std::hex << current_state.initial_storage(current_state.stack_top()) << std::dec << std::endl;
                BOOST_LOG_TRIVIAL(trace) << "\tprevious_v = " << std::hex << current_state.storage(current_state.stack_top()) << std::dec << std::endl;
                BOOST_LOG_TRIVIAL(trace) << "\tv = " << std::hex << current_state.stack_top(1) << std::dec << std::endl;
                BOOST_LOG_TRIVIAL(trace) << "\tis_cold = " << is_cold << std::endl;
                BOOST_LOG_TRIVIAL(trace) << "\tis_clean = " << is_clean << std::endl;
                BOOST_LOG_TRIVIAL(trace) << "\tis_equal = " << is_equal << std::endl;
            }

            TYPE previous_V_sum_expr;
            for(std::size_t i = 0; i < 16; i++) {
                allocate(initial_V[i], i, 0);
                allocate(previous_V[i], i+16, 0);
                allocate(V[i], i, 1);
                previous_V_sum_expr += previous_V[i];
            }
            allocate(is_cold, 20, 1);
            allocate(is_clean_hi, 21, 1);
            allocate(is_clean_lo, 22, 1);
            allocate(is_clean, 23, 1);
            allocate(was_zero, 24, 1);
            allocate(is_equal_hi, 26, 1);
            allocate(is_equal_lo, 27, 1);
            allocate(is_equal, 28, 1);

            allocate(call_context_address_hi, 32, 0);
            allocate(call_context_address_lo, 33, 0);
            allocate(K_hi, 34, 0);
            allocate(K_lo, 35, 0);
            allocate(previous_V_sum_inv, 40, 0);
            allocate(R_hi_inv, 42, 0);
            allocate(R_lo_inv, 43, 0);
            allocate(D_hi_inv, 44, 0);
            allocate(D_lo_inv, 45, 0);

            auto initial_V_128 = chunks16_to_chunks128<TYPE>(initial_V);
            auto previous_V_128 = chunks16_to_chunks128<TYPE>(previous_V);
            auto V_128 = chunks16_to_chunks128<TYPE>(V);

            constrain(is_cold * (1 - is_cold));
            constrain(previous_V_sum_expr * (previous_V_sum_expr * previous_V_sum_inv - 1));
            constrain(previous_V_sum_inv * (previous_V_sum_expr * previous_V_sum_inv - 1));
            constrain(was_zero + previous_V_sum_expr * previous_V_sum_inv - 1);

            constrain(R_hi_inv * ((previous_V_128.first - V_128.first) * R_hi_inv - 1));
            constrain((previous_V_128.first - V_128.first) * ((previous_V_128.first - V_128.first) * R_hi_inv - 1));
            constrain(is_equal_hi - (1 - (previous_V_128.first - V_128.first) * R_hi_inv));

            constrain(R_lo_inv * ((previous_V_128.second - V_128.second) * R_lo_inv - 1));
            constrain((previous_V_128.second - V_128.second) * ((previous_V_128.second - V_128.second) * R_lo_inv - 1));
            constrain(is_equal_lo - (1 - (previous_V_128.second - V_128.second) * R_lo_inv));

            constrain(D_hi_inv * ((initial_V_128.first - previous_V_128.first) * D_hi_inv - 1));
            constrain((initial_V_128.first - previous_V_128.first) * ((initial_V_128.first - previous_V_128.first) * D_hi_inv - 1));
            constrain(is_clean_hi - (1 - (initial_V_128.first - previous_V_128.first) * D_hi_inv));

            constrain(D_lo_inv * ((initial_V_128.second - previous_V_128.second) * D_lo_inv - 1));
            constrain((initial_V_128.second - previous_V_128.second) * ((initial_V_128.second - previous_V_128.second) * D_lo_inv - 1));
            constrain(is_clean_lo - (1 - (initial_V_128.second - previous_V_128.second) * D_lo_inv));

            constrain(is_equal - is_equal_hi * is_equal_lo);
            constrain(is_clean - is_clean_hi * is_clean_lo);

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

                // Prove call_context_address correctness
                lookup(rw_table<FieldType, stage>::call_context_lookup(
                    current_state.call_id(0),
                    std::size_t(call_context_field::call_context_address),
                    call_context_address_hi,
                    call_context_address_lo
                ), "zkevm_rw");
                // 1. Read key from stack
                lookup(rw_table<FieldType, stage>::stack_lookup(
                    current_state.call_id(0),
                    current_state.stack_size(0) - 1,
                    current_state.rw_counter(0),
                    TYPE(0),                                               // is_write
                    K_hi,
                    K_lo
                ), "zkevm_rw");
                // 2. Read new value from stack
                lookup(rw_table<FieldType, stage>::stack_lookup(
                    current_state.call_id(0),
                    current_state.stack_size(0) - 2,
                    current_state.rw_counter(0) + 1,
                    TYPE(0),                                               // is_write
                    V_128.first,
                    V_128.second
                ), "zkevm_rw");

                // 3. Check whether is it warm or cold access
                lookup({
                    TYPE(1),                                               // It's original change, not call_commit
                    TYPE(std::size_t(rw_operation_type::access_list)),
                    current_state.call_id(0),                              // All state changes are grouped by block
                    call_context_address_hi * two_128 + call_context_address_lo,
                    TYPE(0),                                               // field
                    K_hi,                                                  // storage_key_hi
                    K_lo,                                                  // storage_key_lo
                    current_state.rw_counter(0)+2,
                    TYPE(1),                                               // is_write -- always write for access_list
                    TYPE(0),                                               // value_hi -- is always 0 for boolean value
                    TYPE(1),                                               // value_lo
                    TYPE(0),                                               // previous_value_hi -- is always 0 for boolean value
                    1 - is_cold,                                           // previous_value_lo
                    TYPE(0),                                               // initial_value_hi -- 0
                    TYPE(0),                                               // initial_value_lo -- 0 for transaction
                }, "zkevm_state_opcode");

                // 4. Write new value to storage
                lookup({
                    TYPE(1),                                               // It's original change, not call_commit
                    TYPE(std::size_t(rw_operation_type::state)),
                    current_state.call_id(0),                          // All state changes are grouped by block
                    call_context_address_hi * two_128 + call_context_address_lo,
                    TYPE(0),                                               // field
                    K_hi,                                                  // storage_key_hi
                    K_lo,                                                  // storage_key_lo
                    current_state.rw_counter(0)+3,
                    TYPE(1),                                               // is_write
                    V_128.first,                                           // value_hi
                    V_128.second,                                          // value_lo
                    previous_V_128.first,                                  // previous_value_hi -- it's read, so, it's similar to current
                    previous_V_128.second,                                 // previous_value_lo -- it's read, so, it's similar to current
                    initial_V_128.first,                                   // initial_value_hi
                    initial_V_128.second,                                  // initial_value_lo
                }, "zkevm_state_opcode");
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
            return 2;
        }
    };
}
