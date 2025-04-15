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

#include<nil/blueprint/zkevm_bbf/types/rw_operation.hpp>

namespace nil {
    namespace blueprint {
        namespace bbf {
            template<typename FieldType, GenerationStage stage>
            class rw_table : public generic_component<FieldType, stage> {
                using typename generic_component<FieldType, stage>::context_type;
                using generic_component<FieldType, stage>::allocate;
                using generic_component<FieldType, stage>::copy_constrain;
                using generic_component<FieldType, stage>::constrain;
                using generic_component<FieldType, stage>::lookup;
                using generic_component<FieldType, stage>::lookup_table;
            public:
                using typename generic_component<FieldType,stage>::TYPE;
                using input_type = typename std::conditional<stage==GenerationStage::ASSIGNMENT, rw_operations_vector, std::nullptr_t>::type;
                using integral_type =  nil::crypto3::multiprecision::big_uint<257>;
            public:
                // rw_table
                std::vector<TYPE> op;
                std::vector<TYPE> id;
                std::vector<TYPE> address;
                std::vector<TYPE> field_type;
                std::vector<TYPE> storage_key_hi;
                std::vector<TYPE> storage_key_lo;
                std::vector<TYPE> rw_id;
                std::vector<TYPE> is_write;
                std::vector<TYPE> value_hi;
                std::vector<TYPE> value_lo;
                std::vector<TYPE> value_before_hi;    // For storage gas calculation, access_lists
                std::vector<TYPE> value_before_lo;
                std::vector<TYPE> call_id;
                std::vector<TYPE> w_id_before;    // For call_commit proving
\
                static std::size_t get_witness_amount(){ return 14; }

                static std::vector<TYPE> call_context_lookup(
                    TYPE call_id,
                    std::size_t field,
                    TYPE value_hi,
                    TYPE value_lo
                ){
                    return {
                        TYPE(rw_op_to_num(rw_operation_type::call_context)),
                        call_id,
                        TYPE(0),
                        TYPE(field),                                                          // field
                        TYPE(0),                                                              // storage_key_hi
                        TYPE(0),                                                              // storage_key_lo
                        call_id + field,                                                      // rw_counter
                        TYPE(0),                                                              // is_write
                        value_hi,
                        value_lo,
                        TYPE(0),                                               // value_before_hi
                        TYPE(0),                                               // value_before_lo
                        TYPE(0),                                               // call_id
                        TYPE(0)                                                // w_id_before
                    };
                }

                static std::vector<TYPE> call_context_editable_lookup(
                    TYPE call_id,
                    std::size_t field,
                    TYPE rw_counter,
                    TYPE is_write,
                    TYPE value_hi,
                    TYPE value_lo
                ){
                    return {
                        TYPE(rw_op_to_num(rw_operation_type::call_context)),
                        call_id,
                        TYPE(0),
                        TYPE(field),                                                          // field
                        TYPE(0),                                                              // storage_key_hi
                        TYPE(0),                                                              // storage_key_lo
                        rw_counter,                                                      // rw_counter
                        is_write,                                                              // is_write
                        value_hi,
                        value_lo,
                        TYPE(0),                                               // value_before_hi
                        TYPE(0),                                               // value_before_lo
                        TYPE(0),                                               // call_id
                        TYPE(0)                                                // w_id_before
                    };
                }

                static std::vector<TYPE> rw_item_lookup(
                    TYPE op,
                    TYPE id,
                    TYPE address,
                    TYPE field,
                    TYPE storage_key_hi,
                    TYPE storage_key_lo
                ){
                    return {op, id, address, field, storage_key_hi, storage_key_lo};
                }

                static std::vector<TYPE> stack_lookup(
                    TYPE call_id,
                    TYPE stack_pointer,
                    TYPE rw_counter,
                    TYPE is_write,
                    TYPE value_hi,
                    TYPE value_lo
                ){
                    return {
                        TYPE(rw_op_to_num(rw_operation_type::stack)),
                        call_id,
                        stack_pointer,
                        TYPE(0),                                               // storage_key_hi
                        TYPE(0),                                               // storage_key_lo
                        TYPE(0),                                               // field
                        rw_counter,
                        is_write,
                        value_hi,
                        value_lo,
                        TYPE(0),                                               // value_before_hi
                        TYPE(0),                                               // value_before_lo
                        TYPE(0),                                               // call_id
                        TYPE(0)                                                // w_id_before
                    };
                }

                static std::vector<TYPE> memory_lookup(
                    TYPE call_id,
                    TYPE memory_address,
                    TYPE rw_counter,
                    TYPE is_write,
                    TYPE value_lo
                ){
                    return {
                        TYPE(rw_op_to_num(rw_operation_type::memory)),
                        call_id,
                        memory_address,
                        TYPE(0),              // storage_key_hi
                        TYPE(0),              // storage_key_lo
                        TYPE(0),              // field
                        rw_counter,
                        is_write,
                        TYPE(0),              // hi bytes are 0
                        value_lo,
                        TYPE(0),              // value_before_hi
                        TYPE(0),              // value_before_lo
                        TYPE(0),              // call_id
                        TYPE(0)               // w_id_before
                    };
                }

                static std::vector<TYPE> calldata_lookup(
                    TYPE call_id,
                    TYPE calldata_address,
                    TYPE rw_counter,
                    TYPE value_lo
                ){
                    return {
                        TYPE(rw_op_to_num(rw_operation_type::calldata)),
                        call_id,
                        calldata_address,
                        TYPE(0),              // storage_key_hi
                        TYPE(0),              // storage_key_lo
                        TYPE(0),              // field
                        rw_counter,
                        TYPE(0),              // calldata is readonly
                        TYPE(0),              // hi bytes are 0
                        value_lo,
                        TYPE(0),              // value_before_hi
                        TYPE(0),              // value_before_lo
                        TYPE(0),              // call_id
                        TYPE(0)               // w_id_before
                    };
                }

                static std::vector<TYPE> returndata_lookup(
                    TYPE call_id,
                    TYPE returndata_address,
                    TYPE rw_counter,
                    TYPE value_lo
                ){
                    return {
                        TYPE(rw_op_to_num(rw_operation_type::returndata)),
                        call_id,
                        returndata_address,
                        TYPE(0),              // storage_key_hi
                        TYPE(0),              // storage_key_lo
                        TYPE(0),              // field
                        rw_counter,
                        TYPE(0),              // calldata is readonly
                        TYPE(0),              // hi bytes are 0
                        value_lo,
                        TYPE(0),              // value_before_hi
                        TYPE(0),              // value_before_lo
                        TYPE(0),              // call_id
                        TYPE(0)               // w_id_before
                    };
                }

                rw_table(context_type &context_object, const input_type &input, std::size_t max_rw_size, bool register_dynamic_lookup)
                    :generic_component<FieldType,stage>(context_object),
                    op(max_rw_size),
                    id(max_rw_size),
                    address(max_rw_size),
                    field_type(max_rw_size),
                    storage_key_hi(max_rw_size),
                    storage_key_lo(max_rw_size),
                    rw_id(max_rw_size),
                    is_write(max_rw_size),
                    value_hi(max_rw_size),
                    value_lo(max_rw_size),
                    value_before_hi(max_rw_size),
                    value_before_lo(max_rw_size),
                    call_id(max_rw_size),
                    w_id_before(max_rw_size)
                {
                    if constexpr  (stage == GenerationStage::ASSIGNMENT) {
                        auto rw_trace = input;
                        BOOST_ASSERT(rw_trace.size() <= max_rw_size);
                        BOOST_ASSERT(rw_trace[0].op == rw_operation_type::start);

                        std::map <std::size_t, std::pair<TYPE, TYPE>> state_value_before; // For STATE type rw_id=>value_prev
                        for( std::size_t i = 0; i < rw_trace.size(); i++ ){
                            // if( rw_trace[i].op != rw_operation_type::padding )
                            //     std::cout << "\t" << i << "." << rw_trace[i] << std::endl;
                            op[i] = rw_op_to_num(rw_trace[i].op);
                            id[i] = rw_trace[i].id;
                            address[i] = integral_type(rw_trace[i].address);
                            storage_key_hi[i] = w_hi<FieldType>(rw_trace[i].storage_key);
                            storage_key_lo[i] = w_lo<FieldType>(rw_trace[i].storage_key);
                            field_type[i] = rw_trace[i].field;
                            is_write[i] = rw_trace[i].is_write;
                            rw_id[i] = rw_trace[i].rw_counter;
                            value_hi[i] = w_hi<FieldType>(rw_trace[i].value);
                            value_lo[i] = w_lo<FieldType>(rw_trace[i].value);
                            call_id[i] = rw_trace[i].call_id;

                            if( i == 0 ) continue;
                            bool is_first =
                                op[i-1] != op[i] ||
                                id[i-1] != id[i] ||
                                address[i-1] != address[i] ||
                                storage_key_hi[i-1] != storage_key_hi[i] ||
                                storage_key_lo[i-1] != storage_key_lo[i] ||
                                field_type[i-1] != field_type[i];

                            if( rw_trace[i].op == rw_operation_type::state ||
                                rw_trace[i].op == rw_operation_type::access_list
                            ) {
                                value_before_hi[i] = w_hi<FieldType>(rw_trace[i].value_before);
                                value_before_lo[i] = w_lo<FieldType>(rw_trace[i].value_before);
                                w_id_before[i] = rw_trace[i].w_id_before;
                            }
                        }
                        for( std::size_t i = rw_trace.size(); i < max_rw_size; i++ ){
                            op[i] = rw_op_to_num(rw_operation_type::padding);
                        }
                    }
                    for( std::size_t i = 0; i < max_rw_size; i++ ){
                        allocate(op[i], 0, i);
                        allocate(id[i], 1, i);
                        allocate(address[i], 2, i);
                        allocate(field_type[i], 3, i);
                        allocate(storage_key_hi[i], 4, i);
                        allocate(storage_key_lo[i], 5, i);
                        allocate(rw_id[i], 6, i);
                        allocate(is_write[i], 7, i);
                        allocate(value_hi[i], 8, i);
                        allocate(value_lo[i], 9, i);
                        allocate(value_before_hi[i], 10, i);
                        allocate(value_before_lo[i], 11, i);
                        allocate(call_id[i], 12, i);
                        allocate(w_id_before[i], 13, i);
                    }
                    lookup_table("zkevm_rw",std::vector<std::size_t>({0,1,2,3,4,5,6,7,8,9,10,11,12,13}),0,max_rw_size);
                    lookup_table("zkevm_rw_short",std::vector<std::size_t>({0,1,2,3,4,5,6,7,8,9}),0,max_rw_size);
                }
            };
         }
    }
}
