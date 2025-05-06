//---------------------------------------------------------------------------//
// Copyright (c) 2025 Elena Tatuzova <e.tatuzova@nil.foundation>
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

namespace nil::blueprint::bbf::zkevm_small_field{
    template<typename FieldType, GenerationStage stage>
    class rw_8_table : public generic_component<FieldType, stage> {
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
        // rw_8
        std::vector<TYPE> op;                           // memory, calldata, returndata
        std::vector<TYPE> id;                           // 2 chunks fitted in field element less than 2^25
        std::vector<TYPE> address;                      // 1 chunk
        std::vector<TYPE> rw_id;                        // 2 chunks fitted in field element less than 2^25
        std::vector<TYPE> is_write;                     // bool
        std::vector<TYPE> value;                        // 1 byte
        std::vector<TYPE> internal_counter;             // 2  chunks fitted in field element less than 2^25
        std::vector<TYPE> is_filled;                    // bool

        static std::size_t get_witness_amount(){
            return 8;
        }

        rw_8_table(context_type &context_object, const input_type &input, std::size_t max_rw_size)
            :generic_component<FieldType,stage>(context_object),
            op(max_rw_size),
            id(max_rw_size),
            address(max_rw_size),
            rw_id(max_rw_size),
            is_write(max_rw_size),
            value(max_rw_size),
            internal_counter(max_rw_size),
            is_filled(max_rw_size)
        {
            if constexpr  (stage == GenerationStage::ASSIGNMENT) {
                auto rw_trace = input;
                BOOST_ASSERT(rw_trace[0].op == rw_operation_type::start);

                std::size_t current_row = 0;
                std::size_t starting_internal_counter = 0;
                for( std::size_t i = 0; i < rw_trace.size(); i++ ){
                    if( current_row >= max_rw_size ) BOOST_LOG_TRIVIAL(fatal) << "Not enougn rows in rw_8 table";
                    BOOST_ASSERT(current_row < max_rw_size);
                    if(
                        rw_trace[i].op != rw_operation_type::start
                        && rw_trace[i].op != rw_operation_type::memory
                        && rw_trace[i].op != rw_operation_type::calldata
                        && rw_trace[i].op != rw_operation_type::returndata
                    ) continue;
                    op[current_row] = std::size_t(rw_trace[i].op);
                    id[current_row] = rw_trace[i].id;
                    address[current_row] = integral_type(rw_trace[i].address);
                    is_write[current_row] = rw_trace[i].is_write;
                    rw_id[current_row] = rw_trace[i].rw_counter;
                    value[current_row] = rw_trace[i].value;
                    is_filled[current_row] = i == 0? 0 :1;
                    if( starting_internal_counter == 0 && current_row !=0 ) starting_internal_counter = rw_trace[i].internal_counter - 1;
                    internal_counter[current_row] = rw_trace[i].internal_counter - starting_internal_counter;
                    current_row++;
                }
                BOOST_LOG_TRIVIAL(trace) << "rw_8 filled rows amount = " << current_row;
                for( std::size_t i = current_row; i < max_rw_size; i++ ){
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
                allocate(value[i], current_column++, i);                    // 5
                allocate(is_filled[i], current_column++, i);                // 6
                allocate(internal_counter[i], current_column++, i);         // 7
            }
            lookup_table("zkevm_rw_8",std::vector<std::size_t>({0,1,2,3,4,5,}),0,max_rw_size);
            lookup_table("zkevm_rw_8_timeline",std::vector<std::size_t>({6,3,7}),0,max_rw_size);
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
                TYPE(0),              // is_write
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
                is_write,
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
                TYPE(0),              // is_write
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
                value_lo
            };
        }
    };
}