//---------------------------------------------------------------------------//
// Copyright (c) 2024 Elena Tatuzova <e.tatuzova@nil.foundation>
// Copyright (c) 2025 Antoine Cyr <antoinecyr@nil.foundation>
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

#include <nil/blueprint/zkevm_bbf/types/rw_operation.hpp>

namespace nil {
    namespace blueprint {
        namespace bbf {
            template<typename FieldType, GenerationStage stage>
            class rw_table_small_field : public generic_component<FieldType, stage> {
                using typename generic_component<FieldType, stage>::context_type;
                using generic_component<FieldType, stage>::allocate;
                using generic_component<FieldType, stage>::copy_constrain;
                using generic_component<FieldType, stage>::constrain;
                using generic_component<FieldType, stage>::lookup;
                using generic_component<FieldType, stage>::lookup_table;

              public:
                using typename generic_component<FieldType, stage>::TYPE;
                using input_type =
                    typename std::conditional<stage == GenerationStage::ASSIGNMENT,
                                              rw_operations_vector, std::nullptr_t>::type;
                using integral_type = nil::crypto3::multiprecision::big_uint<257>;

              public:
                // For connection with upper-level circuits
                std::vector<TYPE> op;
                std::vector<std::vector<TYPE>> id;
                std::vector<std::vector<TYPE>> address;
                std::vector<std::vector<TYPE>> storage_key;
                std::vector<TYPE> field_type;
                std::vector<std::vector<TYPE>> rw_id;
                std::vector<TYPE> is_write;
                std::vector<std::vector<TYPE>> value;

                static std::size_t get_witness_amount() { return 49; }

                rw_table_small_field(context_type &context_object,
                                     const input_type &input, std::size_t max_rw_size,
                                     bool register_dynamic_lookup)
                    : generic_component<FieldType, stage>(context_object),
                      op(max_rw_size),
                      id(max_rw_size, std::vector<TYPE>(2)),
                      address(max_rw_size, std::vector<TYPE>(10)),
                      storage_key(max_rw_size, std::vector<TYPE>(16)),
                      field_type(max_rw_size),
                      is_write(max_rw_size),
                      rw_id(max_rw_size, std::vector<TYPE>(2)),
                      value(max_rw_size, std::vector<TYPE>(16)) {
                    if constexpr (stage == GenerationStage::ASSIGNMENT) {
                        auto rw_trace = input;
                        // std::cout << "RW assign size = " << rw_trace.size() <<
                        // std::endl;
                        BOOST_ASSERT(rw_trace.size() <= max_rw_size);
                        for (std::size_t i = 0; i < rw_trace.size(); i++) {
                            // if( rw_trace[i].op != rw_operation_type::padding )
                            //     std::cout << "\t" << i << "." << rw_trace[i] <<
                            //     std::endl;
                            op[i] = rw_op_to_num(rw_trace[i].op);
                            id[i] = zkevm_word_to_field_element_flexible<FieldType>(
                                rw_trace[i].call_id, 2);
                            address[i] = zkevm_word_to_field_element_flexible<FieldType>(
                                rw_trace[i].address, 10);
                            storage_key[i] = zkevm_word_to_field_element<FieldType>(
                                rw_trace[i].storage_key);
                            field_type[i] =
                                0;  // TODO: fix it for different state updates
                            rw_id[i] = zkevm_word_to_field_element_flexible<FieldType>(
                                rw_trace[i].rw_counter, 2);
                            is_write[i] = rw_trace[i].is_write;
                            value[i] =
                                zkevm_word_to_field_element<FieldType>(rw_trace[i].value);
                        }
                        for (std::size_t i = rw_trace.size(); i < max_rw_size; i++) {
                            op[i] = rw_op_to_num(rw_operation_type::padding);
                        }
                    }
                    for (std::size_t i = 0; i < max_rw_size; i++) {
                        allocate(op[i], 0, i);
                        allocate(id[i][0], 1, i);
                        allocate(id[i][1], 2, i);
                        for (std::size_t j = 0; j < 10; j++) {
                            allocate(address[i][j], 3 + j, i);
                        }
                        for (std::size_t j = 0; j < 16; j++) {
                            allocate(storage_key[i][j], 13 + j, i);
                        }
                        allocate(field_type[i], 29, i);
                        allocate(rw_id[i][0], 30, i);
                        allocate(rw_id[i][1], 31, i);
                        allocate(is_write[i], 32, i);
                        for (std::size_t j = 0; j < 16; j++) {
                            allocate(value[i][j], 33 + j, i);
                        }
                    }
                    if (register_dynamic_lookup) {
                        std::vector<std::size_t> indices(48);
                        std::iota(indices.begin(), indices.end(), 0);
                        lookup_table("zkevm_rw", indices, 0, max_rw_size);
                    }
                }
            };
        }  // namespace bbf
    }  // namespace blueprint
}  // namespace nil
