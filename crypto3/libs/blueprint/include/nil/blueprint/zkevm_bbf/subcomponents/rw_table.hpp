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
                using input_type = typename std::conditional<stage==GenerationStage::ASSIGNMENT, std::vector<rw_operation>, std::nullptr_t>::type;
                using integral_type =  boost::multiprecision::number<boost::multiprecision::backends::cpp_int_modular_backend<257>>;
            public:
                // For connection with upper-level circuits
                std::vector<TYPE> op;
                std::vector<TYPE> id;
                std::vector<TYPE> address;
                std::vector<TYPE> storage_key_hi;
                std::vector<TYPE> storage_key_lo;
                std::vector<TYPE> field_type;
                std::vector<TYPE> rw_id;
                std::vector<TYPE> is_write;
                std::vector<TYPE> value_hi;
                std::vector<TYPE> value_lo;

                static std::size_t get_witness_amount(){ return 10; }

                rw_table(context_type &context_object, const input_type &input, std::size_t max_rw_size, bool register_dynamic_lookup)
                    :generic_component<FieldType,stage>(context_object),
                    op(max_rw_size), id(max_rw_size), address(max_rw_size),
                    storage_key_hi(max_rw_size), storage_key_lo(max_rw_size),
                    field_type(max_rw_size), is_write(max_rw_size),
                    rw_id(max_rw_size), value_hi(max_rw_size), value_lo(max_rw_size)
                {
                    if constexpr (stage == GenerationStage::ASSIGNMENT) {
                        auto rw_trace = input;
                        //std::cout << "RW assign size = " << rw_trace.size() << std::endl;
                        for( std::size_t i = 0; i < rw_trace.size(); i++ ){
                            //if( rw_trace[i].op != nil::blueprint::PADDING_OP ) std::cout << "\t" << i << "." << rw_trace[i] << std::endl;
                            op[i] = rw_op_to_num(rw_trace[i].op);
                            id[i] = rw_trace[i].call_id;
                            address[i] = integral_type(rw_trace[i].address);
                            storage_key_hi[i] = w_hi<FieldType>(rw_trace[i].storage_key);
                            storage_key_lo[i] = w_lo<FieldType>(rw_trace[i].storage_key);
                            field_type[i] = 0; // TODO: fix it for different state updates
                            rw_id[i] = rw_trace[i].rw_counter;
                            is_write[i] = rw_trace[i].is_write;
                            value_hi[i] = w_hi<FieldType>(rw_trace[i].value);
                            value_lo[i] = w_lo<FieldType>(rw_trace[i].value);
                        }
                    }
                    for( std::size_t i = 0; i < max_rw_size; i++ ){
                        allocate(op[i], 0, i);
                        allocate(id[i], 1, i);
                        allocate(address[i], 2, i);
                        allocate(storage_key_hi[i], 3, i);
                        allocate(storage_key_lo[i], 4, i);
                        allocate(field_type[i], 5, i);
                        allocate(rw_id[i], 6, i);
                        allocate(is_write[i], 7, i);
                        allocate(value_hi[i], 8, i);
                        allocate(value_lo[i], 9, i);
                    }
                    if( register_dynamic_lookup )
                        lookup_table("zkevm_rw",std::vector<std::size_t>({0,1,2,3,4,5,6,7,8,9}),0,max_rw_size);
                }
            };
         }
    }
}