//---------------------------------------------------------------------------//
// Copyright (c) 2024 Elena Tatuzova   <e.tatuzova@nil.foundation>
// Copyright (c) 2024 Alexey Yashunsky <a.yashunsky@nil.foundation>
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
#include <nil/crypto3/hash/type_traits.hpp>
#include <nil/crypto3/hash/algorithm/hash.hpp>

#include <nil/crypto3/bench/scoped_profiler.hpp>
#include <nil/crypto3/zk/snark/arithmetization/plonk/constraint_system.hpp>

#include <nil/blueprint/blueprint/plonk/assignment.hpp>
#include <nil/blueprint/blueprint/plonk/circuit.hpp>
#include <nil/blueprint/component.hpp>

#include <nil/blueprint/bbf/generic.hpp>
#include <nil/blueprint/zkevm_bbf/util.hpp>

namespace nil {
    namespace blueprint {
        namespace bbf {
            // Component for keccak table
            template<typename FieldType, GenerationStage stage>
            class rlp_table : public generic_component<FieldType, stage> {
                using typename generic_component<FieldType, stage>::context_type;
                using generic_component<FieldType, stage>::allocate;
                using generic_component<FieldType, stage>::copy_constrain;
                using generic_component<FieldType, stage>::constrain;
                using generic_component<FieldType, stage>::lookup;
                using generic_component<FieldType, stage>::lookup_table;


            public:
                using typename generic_component<FieldType,stage>::TYPE;

                std::size_t max_rows;

                std::vector<TYPE> rlp_prefix_0  = std::vector<TYPE>(max_rows);
                std::vector<TYPE> rlp_prefix_1  = std::vector<TYPE>(max_rows);
                std::vector<TYPE> rlp_prefix_2  = std::vector<TYPE>(max_rows);
                // if `first_element_flag` is one, `first_element` should be equal to the actual first element. 
                // otherwise `first_element` is zero and the actual first element can be arbitrary
                std::vector<TYPE> first_element_flag  = std::vector<TYPE>(max_rows);
                std::vector<TYPE> first_element       = std::vector<TYPE>(max_rows);
                std::vector<TYPE> element_type        = std::vector<TYPE>(max_rows); // 0 for array (used in node encoding) and 1 for string (used in child encoding)
                std::vector<TYPE> len_high            = std::vector<TYPE>(max_rows); // highest part of the length
                std::vector<TYPE> len_low             = std::vector<TYPE>(max_rows); // lowest part of the length
                std::vector<TYPE> rlp_prefix_1_is_zero    = std::vector<TYPE>(max_rows); // 0 if rlp_prefix_1 is zero, otherwise 1
                std::vector<TYPE> rlp_prefix_2_is_zero    = std::vector<TYPE>(max_rows); // 0 if rlp_prefix_2 is zero, otherwise 1

                static std::size_t get_witness_amount(){
                    return 10;
                }

                rlp_table(context_type &context_object) :
                    max_rows(2178),
                    generic_component<FieldType,stage>(context_object) {
                    size_t row_index = 0;
                    if constexpr (stage == GenerationStage::ASSIGNMENT) {
                        // string encoding with single bytes and value less than 128
                        for (size_t i = 0; i <= 127; i++) {
                            rlp_prefix_0[row_index] = 0;
                            rlp_prefix_1[row_index] = 0;
                            rlp_prefix_1_is_zero[row_index] = 1;
                            rlp_prefix_2_is_zero[row_index] = 1;
                            first_element[row_index] = i;
                            first_element_flag[row_index] = 1;
                            element_type[row_index] = 1;
                            if (i == 0)
                                len_low[row_index] = 0;
                            else
                                len_low[row_index] = 1;
                            len_high[row_index] = 0;
                            row_index++;
                        }

                        // string encoding with zero length
                        rlp_prefix_0[row_index] = 0x80;
                        rlp_prefix_1[row_index] = 0;
                        rlp_prefix_1_is_zero[row_index] = 1;
                        rlp_prefix_2_is_zero[row_index] = 1;
                        first_element[row_index] = 0;
                        first_element_flag[row_index] = 1;
                        element_type[row_index] = 1;
                        len_low[row_index] = 0;
                        len_high[row_index] = 0;
                        row_index++;

                        // string encoding with 1 to 55 bytes length
                        for (size_t i = 1; i <= 55; i++) {
                            rlp_prefix_0[row_index] = 0x80 + i;
                            rlp_prefix_1[row_index] = 0;
                            rlp_prefix_2[row_index] = 0;
                            rlp_prefix_1_is_zero[row_index] = 1;
                            rlp_prefix_2_is_zero[row_index] = 1;
                            first_element[row_index] = 0;
                            first_element_flag[row_index] = 0;
                            element_type[row_index] = 1;
                            len_low[row_index] = i;
                            len_high[row_index] = 0;
                            row_index++;
                        }

                        // string encoding with length more than 55 (1024 is not enough for transaction and receipt rlp encoding)
                        for (size_t i = 56; i <= 1024; i++) {
                            if (i < 256) {
                                rlp_prefix_0[row_index] = 0xB7 + 1;
                                rlp_prefix_1[row_index] = i;
                                rlp_prefix_2[row_index] = 0;
                                rlp_prefix_1_is_zero[row_index] = 0;
                                rlp_prefix_2_is_zero[row_index] = 1;
                            } else {
                                rlp_prefix_0[row_index] = 0xB7 + 2;
                                rlp_prefix_1[row_index] = (i >> 8) & 0xFF;
                                rlp_prefix_2[row_index] = i & 0xFF;
                                rlp_prefix_1_is_zero[row_index] = 0;
                                rlp_prefix_2_is_zero[row_index] = 0;
                            }
                            first_element[row_index] = 0;
                            first_element_flag[row_index] = 0;
                            element_type[row_index] = 1;
                            len_low[row_index] = i & 0xFF;
                            len_high[row_index] = (i >> 8) & 0xFF;
                            row_index++;
                        }

                        // array encoding with length less than 55 bytes
                        for (size_t i = 0; i <= 55; i++) {
                            rlp_prefix_0[row_index] = 0xC0 + i;
                            rlp_prefix_1[row_index] = 0;
                            rlp_prefix_2[row_index] = 0;
                            rlp_prefix_1_is_zero[row_index] = 1;
                            rlp_prefix_2_is_zero[row_index] = 1;
                            first_element[row_index] = 0;
                            first_element_flag[row_index] = 0;
                            element_type[row_index] = 0;
                            len_low[row_index] = i;
                            len_high[row_index] = 0;
                            row_index++;
                        }

                        // array encoding with length more than 55 (1024 is not enough for transaction and receipt rlp encoding)
                        for (size_t i = 56; i <= 1024; i++) {
                            if (i < 256) {
                                rlp_prefix_0[row_index] = 0xF7 + 1;
                                rlp_prefix_1[row_index] = i;
                                rlp_prefix_2[row_index] = 0;
                                rlp_prefix_1_is_zero[row_index] = 0;
                                rlp_prefix_2_is_zero[row_index] = 1;
                            } else {
                                rlp_prefix_0[row_index] = 0xF7 + 2;
                                rlp_prefix_1[row_index] = (i >> 8) & 0xFF;
                                rlp_prefix_2[row_index] = i & 0xFF;
                                rlp_prefix_1_is_zero[row_index] = 0;
                                rlp_prefix_2_is_zero[row_index] = 0;
                            }
                            first_element[row_index] = 0;
                            first_element_flag[row_index] = 0;
                            element_type[row_index] = 0;
                            len_low[row_index] = i & 0xFF;
                            len_high[row_index] = (i >> 8) & 0xFF;
                            row_index++;

                        }

                        for (size_t i = 0; i < row_index; i++)
                        {
                            allocate(rlp_prefix_0[i],           0, i);
                            allocate(rlp_prefix_1[i],           1, i);
                            allocate(rlp_prefix_2[i],           2, i);
                            allocate(first_element[i],          3, i);
                            allocate(first_element_flag[i],     4, i);
                            allocate(element_type[i],           5, i);
                            allocate(len_low[i],                6, i);
                            allocate(len_high[i],               7, i);
                            allocate(rlp_prefix_1_is_zero[i],   8, i);
                            allocate(rlp_prefix_2_is_zero[i],   9, i);
                        }
                    }
                    lookup_table("rlp_table",std::vector<std::size_t>({0, 1, 2, 3, 4, 5, 6, 7, 8, 9}),0,max_rows);
                };
            };
        } // namespace bbf
    } // namespace blueprint
} // namespace nil
