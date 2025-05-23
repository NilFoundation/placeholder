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

#include<nil/blueprint/zkevm_bbf/types/short_rw_operation.hpp>

namespace nil::blueprint::bbf::zkevm_big_field{
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
        using input_type = typename std::conditional<stage==GenerationStage::ASSIGNMENT, short_rw_operations_vector, std::nullptr_t>::type;
        using integral_type =  nil::crypto3::multiprecision::big_uint<257>;
    public:
        // rw_table
        std::vector<TYPE> op;
        std::vector<TYPE> id;
        std::vector<TYPE> address;
        std::vector<TYPE> rw_id;
        std::vector<TYPE> is_write;
        std::vector<TYPE> value_hi;
        std::vector<TYPE> value_lo;
        std::vector<TYPE> internal_counter;
        std::vector<TYPE> is_filled;

        static std::size_t get_witness_amount(){ return 9; }

        static std::vector<TYPE> call_context_lookup(
            TYPE call_id,
            std::size_t field,
            TYPE value_hi,
            TYPE value_lo
        ){
            return {
                TYPE(std::size_t(rw_operation_type::call_context)),
                call_id,
                TYPE(field),                                          // address
                call_id + field,                                      // rw_id
                TYPE(0),                                              // is_write
                value_hi,
                value_lo
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
                TYPE(std::size_t(rw_operation_type::call_context)),
                call_id,
                TYPE(field),                                                          // address
                rw_counter,                                                           // rw_id
                is_write,                                                             // is_write
                value_hi,
                value_lo
            };
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
                TYPE(std::size_t(rw_operation_type::stack)),
                call_id,
                stack_pointer,
                rw_counter,
                is_write,
                value_hi,
                value_lo
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
                TYPE(std::size_t(rw_operation_type::memory)),
                call_id,
                memory_address,
                rw_counter,
                is_write,
                TYPE(0),              // value_hi
                value_lo
            };
        }

        static std::vector<TYPE> calldata_r_lookup(
            TYPE call_id,
            TYPE calldata_address,
            TYPE rw_counter,
            TYPE value_lo
        ){
            return {
                TYPE(std::size_t(rw_operation_type::calldata)),
                call_id,
                calldata_address,
                rw_counter,
                TYPE(0),              // calldata is readonly
                TYPE(0),              // hi bytes are 0
                value_lo
            };
        }

        static std::vector<TYPE> calldata_lookup(
            TYPE call_id,
            TYPE calldata_address,
            TYPE rw_counter,
            TYPE is_write,
            TYPE value_lo
        ){
            return {
                TYPE(std::size_t(rw_operation_type::calldata)),
                call_id,
                calldata_address,
                rw_counter,
                TYPE(0),              // calldata is readonly
                is_write,             // hi bytes are 0
                value_lo
            };
        }

        static std::vector<TYPE> returndata_r_lookup(
            TYPE call_id,
            TYPE returndata_address,
            TYPE rw_counter,
            TYPE value_lo
        ){
            return {
                TYPE(std::size_t(rw_operation_type::returndata)),
                call_id,
                returndata_address,
                rw_counter,
                TYPE(0),              // calldata is readonly
                TYPE(0),              // hi bytes are 0
                value_lo
            };
        }

        static std::vector<TYPE> returndata_lookup(
            TYPE call_id,
            TYPE returndata_address,
            TYPE rw_counter,
            TYPE is_write,
            TYPE value_lo
        ){
            return {
                TYPE(std::size_t(rw_operation_type::returndata)),
                call_id,
                returndata_address,
                rw_counter,
                is_write,
                TYPE(0),              // hi bytes are 0
                value_lo
            };
        }

        rw_table(context_type &context_object, const input_type &input, std::size_t max_rw_size, bool register_dynamic_lookup)
            :generic_component<FieldType,stage>(context_object),
            op(max_rw_size),
            id(max_rw_size),
            address(max_rw_size),
            rw_id(max_rw_size),
            is_write(max_rw_size),
            value_hi(max_rw_size),
            value_lo(max_rw_size),
            internal_counter(max_rw_size),
            is_filled(max_rw_size)
        {
            if constexpr  (stage == GenerationStage::ASSIGNMENT) {
                auto rw_trace = input;
                BOOST_ASSERT(rw_trace.size() <= max_rw_size);
                BOOST_ASSERT(rw_trace[0].op == rw_operation_type::start);

                std::map <std::size_t, std::pair<TYPE, TYPE>> state_value_before; // For STATE type rw_id=>value_prev
                for( std::size_t i = 0; i < rw_trace.size(); i++ ){
                    op[i] = std::size_t(rw_trace[i].op);
                    id[i] = rw_trace[i].id;
                    address[i] = integral_type(rw_trace[i].address);
                    is_write[i] = rw_trace[i].is_write;
                    rw_id[i] = rw_trace[i].rw_counter;
                    value_hi[i] = w_hi<FieldType>(rw_trace[i].value);
                    value_lo[i] = w_lo<FieldType>(rw_trace[i].value);
                    internal_counter[i] = rw_trace[i].internal_counter;
                    is_filled[i] = i == 0? 0 :1;
                }
                for( std::size_t i = rw_trace.size(); i < max_rw_size; i++ ){
                    op[i] = std::size_t(rw_operation_type::padding);
                }
            }
            for( std::size_t i = 0; i < max_rw_size; i++ ){
                std::size_t current_column = 0;
                allocate(op[i], current_column++, i);                       // 0
                allocate(id[i], current_column++, i);                       // 1
                allocate(address[i], current_column++, i);                  // 2
                allocate(rw_id[i], current_column++, i);                    // 3
                allocate(is_write[i], current_column++, i);                 // 4
                allocate(value_hi[i], current_column++, i);                 // 5
                allocate(value_lo[i], current_column++, i);                 // 6
                allocate(is_filled[i], current_column++, i);                // 7
                allocate(internal_counter[i], current_column++, i);         // 8
            }
            lookup_table("zkevm_rw",std::vector<std::size_t>({0,1,2,3,4,5,6}),0,max_rw_size);
            lookup_table("zkevm_rw_timeline",std::vector<std::size_t>({7,3,8}),0,max_rw_size);
        }
    };
}