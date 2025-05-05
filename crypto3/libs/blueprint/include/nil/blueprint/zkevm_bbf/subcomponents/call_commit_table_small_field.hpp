//---------------------------------------------------------------------------//
// Copyright (c) 2025 Elena Tatuzova <e.tatuzova@nil.foundation>
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

#include <nil/blueprint/zkevm_bbf/types/call_commit.hpp>

namespace nil {
    namespace blueprint {
        namespace bbf {
            template<typename FieldType, GenerationStage stage>
            class call_commit_table_small_field : public generic_component<FieldType, stage> {
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
                                              std::map<std::size_t, zkevm_call_commit>,
                                              std::nullptr_t>::type;
                using integral_type = nil::crypto3::multiprecision::big_uint<257>;

              public:
                // call_commit_items
                std::vector<std::vector<TYPE>> call_id;
                std::vector<TYPE> op;
                std::vector<std::vector<TYPE>> id;
                std::vector<std::vector<TYPE>> address;
                std::vector<TYPE> field_type;
                std::vector<std::vector<TYPE>> storage_key;

                // call_commit_table_small_field
                std::vector<TYPE> counter;
                std::vector<std::vector<TYPE>> value;

                static std::size_t get_witness_amount() { return 49; }

                call_commit_table_small_field(context_type &context_object, const input_type &input,
                                  std::size_t max_call_commit_size)
                    : generic_component<FieldType, stage>(context_object),
                      call_id(max_call_commit_size, std::vector<TYPE>(2)),
                      op(max_call_commit_size),
                      id(max_call_commit_size, std::vector<TYPE>(2)),
                      address(max_call_commit_size, std::vector<TYPE>(10)),
                      field_type(max_call_commit_size),
                      storage_key(max_call_commit_size, std::vector<TYPE>(16)),
                      counter(max_call_commit_size),
                      value(max_call_commit_size, std::vector<TYPE>(16)) {
                    if constexpr (stage == GenerationStage::ASSIGNMENT) {
                        auto call_commits = input;

                        std::size_t row = 0;
                        for (auto &[ind, call_commit] : call_commits) {
                            for (std::size_t i = 0; i < call_commit.items.size();
                                 i++, row++) {
                                BOOST_ASSERT(row < max_call_commit_size);
                                BOOST_ASSERT(ind == call_commit.call_id);
                                call_id[row] =
                                    zkevm_word_to_field_element_flexible<FieldType>(ind,
                                                                                    2);
                                op[row] = rw_op_to_num(call_commit.items[i].op);
                                id[row] = zkevm_word_to_field_element_flexible<FieldType>(
                                    call_commit.items[i].id, 2);
                                address[row] =
                                    zkevm_word_to_field_element_flexible<FieldType>(
                                        call_commit.items[i].address, 10);
                                storage_key[i] = zkevm_word_to_field_element<FieldType>(
                                    call_commit.items[i].storage_key);
                                field_type[row] = call_commit.items[i].field;
                                counter[row] = i + 1;
                                storage_key[i] = zkevm_word_to_field_element<FieldType>(
                                    call_commit.items[i].value_before);
                            }
                        }
                    }
                    for (std::size_t i = 0; i < max_call_commit_size; i++) {
                        allocate(call_id[i][0], 0, i);
                        allocate(call_id[i][1], 1, i);
                        allocate(op[i], 2, i);
                        allocate(id[i][0], 3, i);
                        allocate(id[i][1], 4, i);
                        for (std::size_t j = 0; j < 10; j++) {
                            allocate(address[i][j], 5 + j, i);
                        }
                        allocate(field_type[i], 15, i);
                        for (std::size_t j = 0; j < 16; j++) {
                            allocate(storage_key[i][j], 16 + j, i);
                        }
                        allocate(counter[i], 32, i);
                        for (std::size_t j = 0; j < 16; j++) {
                            allocate(value[i][j], 33 + j, i);
                        }
                    }
                    std::vector<std::size_t> items_indices(32);
                    std::vector<std::size_t> table_indices(49);
                    std::iota(items_indices.begin(), items_indices.end(), 0);
                    std::iota(table_indices.begin(), table_indices.end(), 0);
                    lookup_table("zkevm_call_commit_items", items_indices, 0, max_call_commit_size);
                    lookup_table("zkevm_call_commit_table_small_field", table_indices, 0, max_call_commit_size);
                }
            };
        }  // namespace bbf
    }  // namespace blueprint
}  // namespace nil
