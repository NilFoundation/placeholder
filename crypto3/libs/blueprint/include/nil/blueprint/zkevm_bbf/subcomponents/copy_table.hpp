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

#include <nil/blueprint/zkevm_bbf/types/copy_event.hpp>

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
                using input_type = std::conditional_t<
                    stage == GenerationStage::ASSIGNMENT,
                    std::vector<copy_event>, std::monostate
                >;
                using integral_type =  nil::crypto3::multiprecision::big_uint<257>;

                // For connection with upper-level circuits
                std::vector<TYPE> is_first;
                std::vector<TYPE> id_hi;
                std::vector<TYPE> id_lo;
                std::vector<TYPE> cp_type;
                std::vector<TYPE> addr;
                std::vector<TYPE> length;
                std::vector<TYPE> is_write;
                std::vector<TYPE> rw_counter;

                static std::size_t get_witness_amount(){
                    return 8;
                }

                copy_table(context_type &context_object, const input_type &input, std::size_t max_copy_size, bool register_dynamic_lookup)
                    :generic_component<FieldType,stage>(context_object),
                    is_first(max_copy_size),
                    id_hi(max_copy_size), id_lo(max_copy_size), cp_type(max_copy_size), addr(max_copy_size),
                    length(max_copy_size), is_write(max_copy_size), rw_counter(max_copy_size)
                {
                    if constexpr (stage == GenerationStage::ASSIGNMENT) {
                        std::cout << "Copy table assignment " << input.size() << std::endl;
                        std::size_t current_row = 0;
                        for( auto &cp: input ){
                            // std::cout
                            //     << "\tCopy event " << copy_op_to_num(cp.source_type)
                            //     << " => " << copy_op_to_num(cp.destination_type)
                            //     << " bytes size" << cp.bytes.size()
                            //     << std::endl;
                            std::size_t src_rw_counter = cp.initial_rw_counter;
                            std::size_t dst_rw_counter = cp.initial_rw_counter;
                            if( cp.source_type == copy_operand_type::memory)
                                dst_rw_counter += cp.length;// Fake rw for some copy events
                            for( std::size_t i = 0; i < cp.bytes.size(); i++ ){
                                BOOST_ASSERT(current_row < max_copy_size);
                                if( i== 0) {
                                    is_first[current_row] = 1;
                                    is_first[current_row + 1] = 1;
                                }
                                length[current_row] = cp.length - i;
                                length[current_row+1] = cp.length - i;
                                rw_counter[current_row] = src_rw_counter;
                                rw_counter[current_row + 1] = dst_rw_counter;
                                cp_type[current_row] = copy_op_to_num(cp.source_type);
                                cp_type[current_row+1] = copy_op_to_num(cp.destination_type);
                                addr[current_row] = cp.src_address + i;
                                addr[current_row+1] = cp.dst_address + i;
                                id_hi[current_row] = w_hi<FieldType>(cp.source_id);
                                id_lo[current_row] = w_lo<FieldType>(cp.source_id);
                                id_hi[current_row+1] = w_hi<FieldType>(cp.destination_id);
                                id_lo[current_row+1] = w_lo<FieldType>(cp.destination_id);
                                src_rw_counter++;
                                dst_rw_counter++;
                                current_row += 2;
                            }
                        }
                    } else {
                    }
                    for( std::size_t i = 0; i < max_copy_size; i++ ){
                        if constexpr ( stage == GenerationStage::ASSIGNMENT )
                            is_write[i] = i%2 ? 1 : 0;

                        allocate(is_first[i], 0, i);
                        allocate(id_hi[i], 1, i);
                        allocate(id_lo[i], 2, i);
                        allocate(cp_type[i], 3, i);
                        allocate(addr[i], 4, i);
                        allocate(length[i], 5, i);
                        allocate(is_write[i], 6, i);
                        allocate(rw_counter[i], 7, i);
                    }
                    if( register_dynamic_lookup )
                        lookup_table("zkevm_copy", {{0,1,2,3,4,5,6,7}}, 0, max_copy_size);
                }
            };
         }
    }
}
