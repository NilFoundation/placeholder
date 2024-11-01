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

#include<nil/blueprint/zkevm/memory.hpp>

namespace nil {
    namespace blueprint {
        namespace bbf {
            template<typename FieldType, GenerationStage stage>
            class copy_table : public generic_component<FieldType, stage> {
                using typename generic_component<FieldType, stage>::context_type;
                using generic_component<FieldType, stage>::allocate;
                using generic_component<FieldType, stage>::copy_constrain;
                using generic_component<FieldType, stage>::constrain;
                using generic_component<FieldType, stage>::lookup_table;
            public:
                using typename generic_component<FieldType,stage>::TYPE;
                using input_type = typename std::conditional<stage==GenerationStage::ASSIGNMENT, std::vector<copy_event>, std::nullptr_t>::type;
                using integral_type =  boost::multiprecision::number<boost::multiprecision::backends::cpp_int_modular_backend<257>>;
            public:
                // For connection with upper-level circuits
                std::vector<TYPE> is_first;
                std::vector<TYPE> id_hi;
                std::vector<TYPE> id_lo;
                std::vector<TYPE> addr;
                std::vector<TYPE> src_addr_end;
                std::vector<TYPE> byte_left;
                std::vector<TYPE> rlc_acc;
                std::vector<TYPE> is_write;
                std::vector<TYPE> rw_counter;
                std::vector<TYPE> rw_inc_left;

                static std::size_t get_witness_amount(){
                    return 10;
                }

                copy_table(context_type &context_object, const input_type &input, std::size_t max_copy_size, bool register_dynamic_lookup)
                    :generic_component<FieldType,stage>(context_object),
                    is_first(max_copy_size), id_hi(max_copy_size), id_lo(max_copy_size),
                    addr(max_copy_size), src_addr_end(max_copy_size),
                    byte_left(max_copy_size), rlc_acc(max_copy_size),
                    is_write(max_copy_size), rw_counter(max_copy_size), rw_inc_left(max_copy_size)
                {
                    if constexpr (stage == GenerationStage::ASSIGNMENT) {
                        std::cout << "Copy table assignment " << std::endl;
                    } else {
                        std::cout << "Copy table circuit" << std::endl;
                    }
                    for( std::size_t i = 0; i < max_copy_size; i++ ){
                        allocate(is_first[i], 0, i);
                        allocate(id_hi[i], 1, i);
                        allocate(id_lo[i], 2, i);
                        allocate(addr[i], 3, i);
                        allocate(src_addr_end[i], 4, i);
                        allocate(byte_left[i], 5, i);
                        allocate(rlc_acc[i], 6, i);
                        allocate(is_write[i], 7, i);
                        allocate(rw_counter[i], 8, i);
                        allocate(rw_inc_left[i], 9, i);
                    }
                    if( register_dynamic_lookup )
                        lookup_table("zkevm_copy",std::vector<std::size_t>({0,1,2,3,4,5,6,7,8,9}),0,max_copy_size);
                }
            };
         }
    }
}