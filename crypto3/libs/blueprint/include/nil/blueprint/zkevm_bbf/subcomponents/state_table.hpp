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

#include<nil/blueprint/zkevm_bbf/types/state_operation.hpp>

namespace nil {
    namespace blueprint {
        namespace bbf {
            template<typename FieldType, GenerationStage stage>
            class state_table : public generic_component<FieldType, stage> {
                using typename generic_component<FieldType, stage>::context_type;
                using generic_component<FieldType, stage>::allocate;
                using generic_component<FieldType, stage>::copy_constrain;
                using generic_component<FieldType, stage>::constrain;
                using generic_component<FieldType, stage>::lookup;
                using generic_component<FieldType, stage>::lookup_table;
            public:
                using typename generic_component<FieldType,stage>::TYPE;
                using input_type = typename std::conditional<stage==GenerationStage::ASSIGNMENT, state_operations_vector, std::nullptr_t>::type;
                using integral_type =  nil::crypto3::multiprecision::big_uint<257>;
            public:
                // state_table
                std::vector<TYPE> op;                           // 0
                std::vector<TYPE> id;                           // 1
                std::vector<TYPE> address;                      // 2
                std::vector<TYPE> field_type;                   // 3
                std::vector<TYPE> storage_key_hi;               // 4
                std::vector<TYPE> storage_key_lo;               // 5
                std::vector<TYPE> rw_id;                        // 6
                std::vector<TYPE> is_write;                     // 7
                std::vector<TYPE> value_hi;                     // 8
                std::vector<TYPE> value_lo;                     // 9
                std::vector<TYPE> previous_value_hi;            // 10
                std::vector<TYPE> previous_value_lo;            // 11
                std::vector<TYPE> call_initial_value_hi;        // 12
                std::vector<TYPE> call_initial_value_lo;        // 13
                std::vector<TYPE> initial_value_hi;             // 14
                std::vector<TYPE> initial_value_lo;             // 15
                std::vector<TYPE> counter;                      // 16

                static std::size_t get_witness_amount(){ return 18; }

                state_table(context_type &context_object, const input_type &input, std::size_t max_state)
                    :generic_component<FieldType,stage>(context_object),
                    op(max_state),
                    id(max_state),
                    address(max_state),
                    field_type(max_state),
                    storage_key_hi(max_state),
                    storage_key_lo(max_state),
                    rw_id(max_state),
                    is_write(max_state),
                    value_hi(max_state),
                    value_lo(max_state),
                    previous_value_hi(max_state),
                    previous_value_lo(max_state),
                    call_initial_value_hi(max_state),
                    call_initial_value_lo(max_state),
                    initial_value_hi(max_state),
                    initial_value_lo(max_state),
                    counter(max_state)
                {
                    BOOST_LOG_TRIVIAL(trace) << "State table";
                    auto &state_trace = input;
                    if constexpr  (stage == GenerationStage::ASSIGNMENT) {
                        BOOST_ASSERT(state_trace.size() <= max_state);
                        BOOST_ASSERT(state_trace[0].op == rw_operation_type::start);
                        for( std::size_t i = 0; i < state_trace.size(); i++ ){
                            op[i] = std::size_t(state_trace[i].op);
                            id[i] = state_trace[i].id;
                            address[i] = integral_type(state_trace[i].address);
                            field_type[i] = state_trace[i].field;
                            storage_key_hi[i] = w_hi<FieldType>(state_trace[i].storage_key);
                            storage_key_lo[i] = w_lo<FieldType>(state_trace[i].storage_key);
                            rw_id[i] = state_trace[i].rw_counter;
                            is_write[i] = state_trace[i].is_write;
                            value_hi[i] = w_hi<FieldType>(state_trace[i].value);
                            value_lo[i] = w_lo<FieldType>(state_trace[i].value);
                            previous_value_hi[i] = w_hi<FieldType>(state_trace[i].previous_value);
                            previous_value_lo[i] = w_lo<FieldType>(state_trace[i].previous_value);
                            call_initial_value_hi[i] = w_hi<FieldType>(state_trace[i].call_initial_value);
                            call_initial_value_lo[i] = w_lo<FieldType>(state_trace[i].call_initial_value);
                            initial_value_hi[i] = w_hi<FieldType>(state_trace[i].initial_value);
                            initial_value_lo[i] = w_lo<FieldType>(state_trace[i].initial_value);
                            if( i == 0 ) continue;
                            if( state_trace[i].op == rw_operation_type::call_context ){
                                counter[i] = 0;
                            } else if( op[i] == op[i-1] &&
                                address[i] == address[i-1] &&
                                field_type[i] == field_type[i-1] &&
                                storage_key_hi[i] == storage_key_hi[i-1] &&
                                storage_key_lo[i] == storage_key_lo[i-1]
                            ){
                                counter[i] = counter[i-1];
                            } else {
                                counter[i] = counter[i-1] + 1;
                            }
                        }
                        for( std::size_t i = state_trace.size(); i < max_state; i++ ){
                            op[i] = std::size_t(rw_operation_type::padding);
                        }
                    }
                    for( std::size_t i = 0; i < max_state; i++ ){
                        std::size_t current_column = 0;
                        allocate(op[i], current_column++, i);
                        allocate(id[i], current_column++, i);
                        allocate(address[i], current_column++, i);
                        allocate(field_type[i], current_column++, i);
                        allocate(storage_key_hi[i], current_column++, i);
                        allocate(storage_key_lo[i], current_column++, i);
                        allocate(rw_id[i], current_column++, i);
                        allocate(is_write[i], current_column++, i);
                        allocate(value_hi[i], current_column++, i);
                        allocate(value_lo[i], current_column++, i);
                        allocate(previous_value_hi[i], current_column++, i);
                        allocate(previous_value_lo[i], current_column++, i);
                        allocate(call_initial_value_hi[i], current_column++, i);
                        allocate(call_initial_value_lo[i], current_column++, i);
                        allocate(initial_value_hi[i], current_column++, i);
                        allocate(initial_value_lo[i], current_column++, i);
                        allocate(counter[i], current_column++, i);
                    }
                    lookup_table("zkevm_state",std::vector<std::size_t>({0,1,2,3,4,5,6,7,8,9,10,11}),0,max_state);
                    lookup_table("zkevm_state_opcode",std::vector<std::size_t>({0,1,2,3,4,5,6,7,8,9,10,11,14,15}),0,max_state);
                }
            };
         }
    }
}
