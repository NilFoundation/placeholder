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

#include<nil/blueprint/zkevm_bbf/types/call_commit.hpp>

namespace nil {
    namespace blueprint {
        namespace bbf {
            template<typename FieldType, GenerationStage stage>
            class call_commit_table : public generic_component<FieldType, stage> {
                using typename generic_component<FieldType, stage>::context_type;
                using generic_component<FieldType, stage>::allocate;
                using generic_component<FieldType, stage>::copy_constrain;
                using generic_component<FieldType, stage>::constrain;
                using generic_component<FieldType, stage>::lookup;
                using generic_component<FieldType, stage>::lookup_table;
            public:
                using typename generic_component<FieldType,stage>::TYPE;
                using input_type = typename std::conditional<stage==GenerationStage::ASSIGNMENT, std::map<std::size_t,zkevm_call_commit>, std::nullptr_t>::type;
                using integral_type =  nil::crypto3::multiprecision::big_uint<257>;
            public:
                // call_commit_items
                std::vector<TYPE> call_id;
                std::vector<TYPE> op;
                std::vector<TYPE> id;
                std::vector<TYPE> address;
                std::vector<TYPE> field_type;
                std::vector<TYPE> storage_key_hi;
                std::vector<TYPE> storage_key_lo;

                // call_commit_table
                std::vector<TYPE> counter;
                std::vector<TYPE> value_hi;
                std::vector<TYPE> value_lo;

                static std::size_t get_witness_amount(){ return 10; }

                call_commit_table(context_type &context_object, const input_type &input, std::size_t max_call_commit_size)
                    :generic_component<FieldType,stage>(context_object),
                    call_id(max_call_commit_size),
                    op(max_call_commit_size),
                    id(max_call_commit_size),
                    address(max_call_commit_size),
                    field_type(max_call_commit_size),
                    storage_key_hi(max_call_commit_size),
                    storage_key_lo(max_call_commit_size),
                    counter(max_call_commit_size),
                    value_hi(max_call_commit_size),
                    value_lo(max_call_commit_size)
                {
                    if constexpr  (stage == GenerationStage::ASSIGNMENT) {
                        auto call_commits = input;

                        std::size_t row = 0;
                        for( auto &[ind,call_commit]: call_commits){
                            for( std::size_t i = 0; i < call_commit.items.size(); i++, row++ ){
                                BOOST_ASSERT(row < max_call_commit_size);
                                BOOST_ASSERT(ind == call_commit.call_id);
                                call_id[row] = ind;
                                op[row] = rw_op_to_num(call_commit.items[i].op);
                                id[row] = call_commit.items[i].id;
                                address[row] = integral_type(call_commit.items[i].address);
                                storage_key_hi[row] = w_hi<FieldType>(call_commit.items[i].storage_key);
                                storage_key_lo[row] = w_lo<FieldType>(call_commit.items[i].storage_key);
                                field_type[row] = call_commit.items[i].field;
                                counter[row] = i+1;
                                value_hi[row] = w_hi<FieldType>(call_commit.items[i].value_before);
                                value_lo[row] = w_lo<FieldType>(call_commit.items[i].value_before);
                            }
                        }
                    }
                    for( std::size_t i = 0; i < max_call_commit_size; i++ ){
                        allocate(call_id[i], 0, i);
                        allocate(op[i], 1, i);
                        allocate(id[i], 2, i);
                        allocate(address[i], 3, i);
                        allocate(field_type[i], 4, i);
                        allocate(storage_key_hi[i], 5, i);
                        allocate(storage_key_lo[i], 6, i);
                        allocate(counter[i], 7, i);
                        allocate(value_hi[i], 8, i);
                        allocate(value_lo[i], 9, i);
                    }
                    lookup_table("zkevm_call_commit_items",std::vector<std::size_t>({0,1,2,3,4,5,6}),0,max_call_commit_size);
                    lookup_table("zkevm_call_commit_table",std::vector<std::size_t>({0,1,2,3,4,5,6,7,8,9}),0,max_call_commit_size);
                }
            };
         }
    }
}
