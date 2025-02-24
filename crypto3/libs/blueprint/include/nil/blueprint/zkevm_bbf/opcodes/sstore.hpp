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
                    std::vector<TYPE> U(16);
                    std::vector<TYPE> V(16);
                    TYPE call_context_address_hi;
                    TYPE call_context_address_lo;
                    TYPE block_id;
                    TYPE tx_id;
                    TYPE rw_counter_before;
                    TYPE w_counter_before;
                    TYPE r_diff_0;
                    TYPE r_diff_1;
                    TYPE is_cold;   // Not accessed during the transaction
                    TYPE w_diff_0;
                    TYPE w_diff_1;
                    TYPE is_clean;  // Not changed during the transaction
                    TYPE U_sum_inv;
                    TYPE V_sum_inv;
                    TYPE is_U_zero;
                    TYPE is_V_zero;
                    TYPE is_equal_hi;
                    TYPE is_equal_lo;
                    TYPE is_equal;
                    TYPE R_hi_inv;
                    TYPE R_lo_inv;

                    if constexpr( stage == GenerationStage::ASSIGNMENT ){
                        K_hi = w_hi<FieldType>(current_state.stack_top());
                        K_lo = w_lo<FieldType>(current_state.stack_top());
                        std::cout << "\tKey = " << current_state.stack_top() << "=[" <<K_hi << "," << K_lo << "] value = " << current_state.stack_top(1) << std::endl;
                        auto u = w_to_16(current_state.storage(current_state.stack_top()));
                        auto v = w_to_16(current_state.stack_top(1));

                        TYPE U_hi = w_hi<FieldType>(current_state.storage(current_state.stack_top()));
                        TYPE U_lo = w_lo<FieldType>(current_state.storage(current_state.stack_top()));
                        TYPE V_hi = w_hi<FieldType>(current_state.stack_top(1));
                        TYPE V_lo = w_lo<FieldType>(current_state.stack_top(1));

                        TYPE U_sum, V_sum;
                        for(std::size_t i = 0; i < 16; i++) {
                            V[i] = v[i];  V_sum += v[i];
                            U[i] = u[i];  U_sum += u[i];
                        }
                        U_sum_inv = U_sum == 0? 0: U_sum.inversed();
                        V_sum_inv = V_sum == 0? 0: V_sum.inversed();
                        is_U_zero = (U_sum == 0);
                        is_V_zero = (V_sum == 0);

                        block_id = current_state.block_id;
                        tx_id = current_state.tx_id;
                        std::size_t rw_counter_before_num = current_state.last_access(
                            current_state.call_context_address, 0, current_state.stack_top()
                        );
                        rw_counter_before = TYPE(rw_counter_before_num);
                        std::size_t w_counter_before_num = current_state.last_write(
                            current_state.call_context_address, 0, current_state.stack_top()
                        );
                        w_counter_before = TYPE(w_counter_before_num);

                        call_context_address_hi = w_hi<FieldType>(current_state.call_context_address);
                        call_context_address_lo = w_lo<FieldType>(current_state.call_context_address);

                        std::size_t r_diff =
                            rw_counter_before_num > current_state.tx_id ?
                            rw_counter_before_num - current_state.tx_id :
                            current_state.tx_id - rw_counter_before_num;
                        r_diff_0 = ((r_diff & 0xFFFF0000) >> 16);
                        r_diff_1 = (r_diff & 0xFFFF);
                        is_cold = (rw_counter_before_num <  current_state.tx_id);

                        std::size_t w_diff =
                            w_counter_before_num > current_state.tx_id ?
                            w_counter_before_num - current_state.tx_id :
                            current_state.tx_id - w_counter_before_num;
                        w_diff_0 = ((w_diff & 0xFFFF0000) >> 16);
                        w_diff_1 = (w_diff & 0xFFFF);
                        is_clean = (w_counter_before_num <  current_state.tx_id);

                        is_equal_hi = (U_hi == V_hi);
                        is_equal_lo = (U_lo == V_lo);
                        is_equal = is_equal_hi * is_equal_lo;

                        R_hi_inv = (U_hi - V_hi) == 0? 0: (U_hi - V_hi).inversed();
                        R_lo_inv = (U_lo - V_lo) == 0? 0: (U_lo - V_lo).inversed();

                        std::cout << "\taddress = " << std::hex << call_context_address_hi << " " <<call_context_address_lo << std::dec << std::endl;
                        std::cout << "\tK = " << std::hex << K_hi << " " << K_lo << std::dec << std::endl;
                        std::cout << "\tu = " << std::hex << current_state.storage(current_state.stack_top()) << std::dec << std::endl;
                        std::cout << "\tv = " << std::hex << current_state.stack_top(1) << std::dec << std::endl;
                        std::cout << "\trw_counter_before = " << rw_counter_before << std::endl;
                        std::cout << "\tw_counter_before = " << w_counter_before << std::endl;
                        std::cout << "\tis_cold = " << is_cold << std::endl;
                        std::cout << "\tis_clean = " << is_clean << std::endl;
                        std::cout << "\tblock_id = " << block_id << std::endl;
                        std::cout << "\ttx_id = " << tx_id << std::endl;
                    }
                    TYPE U_sum_expr, V_sum_expr;
                    for(std::size_t i = 0; i < 16; i++) {
                        allocate(U[i], i, 0);
                        allocate(V[i], i, 1);
                        U_sum_expr += U[i];
                        V_sum_expr += V[i];
                    }
                    allocate(r_diff_0, 16, 0);
                    allocate(r_diff_1, 17, 0);
                    allocate(w_diff_0, 18, 0);
                    allocate(w_diff_1, 19, 0);
                    allocate(is_cold, 20, 0);
                    allocate(is_clean, 21, 0);
                    allocate(is_U_zero, 22, 0);
                    allocate(is_V_zero, 23, 0);
                    allocate(is_equal_hi, 24, 0);
                    allocate(is_equal_lo, 25, 0);
                    allocate(is_equal, 26, 0);

                    allocate(call_context_address_hi, 32, 0);
                    allocate(call_context_address_lo, 33, 0);
                    allocate(K_hi, 34, 0);
                    allocate(K_lo, 35, 0);
                    allocate(block_id, 36, 0);
                    allocate(tx_id, 37, 0);
                    allocate(rw_counter_before, 38, 0);
                    allocate(w_counter_before, 39, 0);
                    allocate(U_sum_inv, 40, 0);
                    allocate(V_sum_inv, 41, 0);
                    allocate(R_hi_inv, 42, 0);
                    allocate(R_lo_inv, 43, 0);

                    auto V_128 = chunks16_to_chunks128<TYPE>(V);
                    auto U_128 = chunks16_to_chunks128<TYPE>(U);

                    constrain(is_cold * (1 - is_cold));
                    constrain(is_cold * (tx_id - rw_counter_before - r_diff_0 * 0x10000 - r_diff_1) + (1 - is_cold) * (rw_counter_before - tx_id - r_diff_0 * 0x10000 - r_diff_1));
                    constrain(U_sum_expr * (U_sum_expr * U_sum_inv - 1));
                    constrain(U_sum_inv * (U_sum_expr * U_sum_inv - 1));
                    constrain(V_sum_expr * (V_sum_expr * V_sum_inv - 1));
                    constrain(V_sum_inv * (V_sum_expr * V_sum_inv - 1));
                    constrain(is_U_zero * U_sum_expr * U_sum_inv);
                    constrain(is_V_zero * V_sum_expr * V_sum_inv);
                    constrain(R_hi_inv * ((U_128.first - V_128.first) * R_hi_inv - 1));
                    constrain((U_128.first - V_128.first) * ((U_128.first - V_128.first) * R_hi_inv - 1));
                    constrain(R_lo_inv * ((U_128.second - V_128.second) * R_lo_inv - 1));
                    constrain((U_128.second - V_128.second) * ((U_128.second - V_128.second) * R_lo_inv - 1));
                    constrain(is_equal_hi - (1 - (U_128.first - V_128.first) * R_hi_inv));
                    constrain(is_equal_lo - (1 - (U_128.second - V_128.second) * R_lo_inv));
                    constrain(is_equal - is_equal_hi * is_equal_lo);

                    // TODO: Cluster has another formula
                    TYPE gas_cost =
                        is_equal * 200 +
                        is_cold *  1900 +
                        (1 - is_equal) * is_clean  * (is_U_zero * 20000 + (1 - is_U_zero) * 5000) +
                        (1 - is_equal) * (1 - is_clean) * 200;
                    std::cout << "\tGas cost = " << gas_cost << std::endl;

                    // TODO: Append refunds
                    if constexpr( stage == GenerationStage::CONSTRAINTS ){
                        constrain(current_state.pc_next() - current_state.pc(0) - 1);                   // PC transition
                        constrain(current_state.gas(0) - current_state.gas_next() - gas_cost);               // GAS transition
                        constrain(current_state.stack_size(0) - current_state.stack_size_next() - 2);   // stack_size transition
                        constrain(current_state.memory_size(0) - current_state.memory_size_next());     // memory_size transition
                        constrain(current_state.rw_counter_next() - current_state.rw_counter(0) - 4);   // rw_counter transition

                        std::vector<TYPE> tmp;
                        // Prove block_id correctness
                        tmp = rw_table<FieldType, stage>::call_context_lookup(
                            current_state.call_id(0),
                            std::size_t(call_context_field::block_id),
                            TYPE(0),
                            block_id
                        );
                        lookup(tmp, "zkevm_rw");
                        // Prove tx_id correctness
                        tmp = rw_table<FieldType, stage>::call_context_lookup(
                            current_state.call_id(0),
                            std::size_t(call_context_field::tx_id),
                            TYPE(0),
                            tx_id
                        );
                        lookup(tmp, "zkevm_rw");
                        // Prove call_context_address correctness
                        tmp = rw_table<FieldType, stage>::call_context_lookup(
                            current_state.call_id(0),
                            std::size_t(call_context_field::call_context_address),
                            call_context_address_hi,
                            call_context_address_lo
                        );
                        lookup(tmp, "zkevm_rw");
                        // 1. Read address from stack
                        tmp = rw_table<FieldType, stage>::stack_lookup(
                            current_state.call_id(0),
                            current_state.stack_size(0) - 1,
                            current_state.rw_counter(0),
                            TYPE(0),                                               // is_write
                            K_hi,
                            K_lo
                        );
                        lookup(tmp, "zkevm_rw");
                        // 2. Read previous value from storage
                        tmp = {
                            TYPE(rw_op_to_num(rw_operation_type::state)),
                            block_id,
                            call_context_address_hi * two_128 + call_context_address_lo,
                            K_hi,                                               // storage_key_hi
                            K_lo,                                               // storage_key_lo
                            TYPE(0),                                            // field
                            current_state.rw_counter(0)+1,
                            TYPE(0),                                            // is_write
                            U_128.first,
                            U_128.second,
                            rw_counter_before,                                  // rw_counter_before
                            w_counter_before,                                   // w_counter_before
                            current_state.call_id(0)                            // helper_id
                        };
                        lookup(tmp, "zkevm_rw");
                        // 3. Read new value from stack
                        tmp = rw_table<FieldType, stage>::stack_lookup(
                            current_state.call_id(0),
                            current_state.stack_size(0) - 2,
                            current_state.rw_counter(0) + 2,
                            TYPE(0),                                               // is_write
                            V_128.first,
                            V_128.second
                        );
                        lookup(tmp, "zkevm_rw");
                        // 4. Write new value to storage
                        tmp = {
                            TYPE(rw_op_to_num(rw_operation_type::state)),
                            block_id,
                            call_context_address_hi * two_128 + call_context_address_lo,
                            K_hi,                                               // storage_key_hi
                            K_lo,                                               // storage_key_lo
                            TYPE(0),                                            // field
                            current_state.rw_counter(0)+3,
                            TYPE(1),                                            // is_write
                            V_128.first,
                            V_128.second,
                            current_state.rw_counter(0)+1,                      // rw_counter_before
                            w_counter_before,                                   // w_counter_before
                            current_state.call_id(0)                            // helper_id
                        };
                        lookup(tmp, "zkevm_rw");
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
        } // namespace bbf
    }   // namespace blueprint
}   // namespace nil

